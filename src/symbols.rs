//! Local/offline Windows client symbol discovery. DbgHelp is serialized on the
//! DevTools analysis thread and never downloads symbols or probes game functions.
use std::{ffi::{c_void,CString,OsStr},fs::{self,File},io::{BufReader,Read},iter,
    mem,os::windows::ffi::OsStrExt,path::PathBuf,ptr,sync::Mutex};
use sha2::{Sha256,Digest};
use serde_json::{Value,json};
use windows_sys::Win32::{
    Foundation::{CloseHandle,INVALID_HANDLE_VALUE},
    System::{Diagnostics::ToolHelp::{CreateToolhelp32Snapshot,Module32FirstW,Module32NextW,
        MODULEENTRY32W,TH32CS_SNAPMODULE,TH32CS_SNAPMODULE32},
        Threading::GetCurrentProcessId},
};
use crate::memory;
const MAX_MODULES:usize=256;
const MAX_PROFILE_BYTES:u64=1024*1024;
static DBGHELP_LOCK:Mutex<()> = Mutex::new(());

#[derive(Debug,Clone)]
pub struct Module {
    pub name:String,
    pub path:PathBuf,
    pub base:usize,
    pub size:usize,
}
impl Module{
    pub fn contains(&self,addr:usize)->bool{
        addr>=self.base && addr-self.base<self.size
    }
    pub fn hash(&self)->Result<String,String>{
        let file=File::open(&self.path).map_err(|e|format!("{}: {e}",self.path.display()))?;
        let mut input=BufReader::new(file);
        let mut digest=Sha256::new();
        let mut bytes=[0u8;64*1024];
        loop {
            let n=input.read(&mut bytes).map_err(|e|e.to_string())?;
            if n==0{break;}
            digest.update(&bytes[..n]);
        }
        Ok(format!("{:x}",digest.finalize()))
    }
}
fn wstr(value:&[u16])->String {
    let n=value.iter().position(|b|*b==0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..n])
}
pub fn modules()->Result<Vec<Module>,String>{
    let snapshot=unsafe{CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,GetCurrentProcessId())};
    if snapshot==INVALID_HANDLE_VALUE {return Err("ToolHelp 无法枚举进程模块".into());}
    let mut entry:MODULEENTRY32W=unsafe{mem::zeroed()};
    entry.dwSize=mem::size_of::<MODULEENTRY32W>() as u32;
    let mut result=Vec::new();
    let mut valid=unsafe{Module32FirstW(snapshot,&mut entry)}!=0;
    while valid && result.len()<MAX_MODULES {
        if !entry.modBaseAddr.is_null() && entry.modBaseSize>0 {
            result.push(Module{
                name:wstr(&entry.szModule),
                path:PathBuf::from(wstr(&entry.szExePath)),
                base:entry.modBaseAddr as usize,
                size:entry.modBaseSize as usize,
            });
        }
        valid=unsafe{Module32NextW(snapshot,&mut entry)}!=0;
    }
    unsafe{CloseHandle(snapshot);}
    if result.is_empty(){return Err("没有可访问的模块".into());}
    Ok(result)
}
#[derive(Debug,Clone,PartialEq,Eq)]
pub enum Origin{ ExactProfile,DbgHelp }
#[derive(Debug,Clone)]
pub struct Located{
    pub symbol:String,
    pub module:String,
    pub module_sha256:String,
    pub rva:usize,
    pub address:usize,
    pub origin:Origin,
}
fn profile_path()->Result<PathBuf,String>{
    Ok(crate::project::root()?.join("symbol_profiles.json"))
}
fn safe_symbol(name:&str)->bool{
    !name.is_empty() && name.len()<=512 && !name.contains('\0') &&
    !name.contains("..") && !name.contains('/') && !name.contains('\\')
}
fn parse_rva(value:&Value)->Result<usize,String>{
    if let Some(n)=value.as_u64(){return usize::try_from(n).map_err(|_|"RVA 超限".into());}
    if let Some(s)=value.as_str(){
        let raw=s.strip_prefix("0x").or_else(||s.strip_prefix("0X")).unwrap_or(s);
        return usize::from_str_radix(raw,16).map_err(|_|"RVA 必须为十六进制".into());
    }
    Err("RVA 不是整数或十六进制字符串".into())
}
pub fn decode_profiles(text:&str)->Result<Vec<Value>,String>{
    let value:Value=serde_json::from_str(text).map_err(|e|format!("符号库 JSON: {e}"))?;
    if value["schema"]!=1 {return Err("符号库 schema 必须为 1".into());}
    let records=value["modules"].as_array().ok_or("符号库缺少 modules 数组")?;
    if records.len()>64 {return Err("模块配置不能超过 64 个".into());}
    for module in records {
        let hash=module["sha256"].as_str().ok_or("模块缺少 sha256")?;
        if hash.len()!=64|| !hash.bytes().all(|b|b.is_ascii_hexdigit()){
            return Err("模块 SHA-256 必须为 64 位十六进制".into());
        }
        let name=module["name"].as_str().ok_or("模块缺少文件名")?;
        if name.is_empty()||name.len()>256{return Err("模块名无效".into());}
        let symbols=module["symbols"].as_object().ok_or("缺少 symbols 映射")?;
        if symbols.len()>2048{return Err("单模块符号不能超过 2048 项".into());}
        for (symbol,value) in symbols{
            if !safe_symbol(symbol){return Err(format!("不安全的符号名称 {symbol}"));}
            let _=parse_rva(value)?;
        }
    }
    Ok(records.clone())
}
pub fn local_profiles()->Result<Vec<Value>,String>{
    let path=profile_path()?;
    let metadata=match fs::metadata(&path){
        Ok(v)=>v,
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(Vec::new()),
        Err(e)=>return Err(e.to_string()),
    };
    if metadata.len()>MAX_PROFILE_BYTES{return Err("符号库大小超过 1 MiB".into());}
    let text=fs::read_to_string(path).map_err(|e|e.to_string())?;
    decode_profiles(&text)
}
fn exact_profile(module:&Module,hash:&str,name:&str,records:&[Value])->Result<Option<Located>,String>{
    for entry in records {
        if !entry["name"].as_str().is_some_and(|v|v.eq_ignore_ascii_case(&module.name)) ||
            !entry["sha256"].as_str().is_some_and(|v|v.eq_ignore_ascii_case(hash)){continue;}
        let Some(value)=entry["symbols"].get(name) else{continue;};
        let rva=parse_rva(value)?;
        if rva>=module.size{return Err(format!("配置 {} 的 RVA 超出模块映像",name));}
        let address=module.base.checked_add(rva).ok_or("RVA 地址溢出")?;
        if memory::read(address,1).is_err(){return Err("RVA 所指内存不可读".into());}
        return Ok(Some(Located{
            symbol:name.into(),module:module.name.clone(),module_sha256:hash.into(),
            rva,address,origin:Origin::ExactProfile,
        }));
    }
    Ok(None)
}
// DbgHelp contains process-wide state and is not thread safe; only the one
// worker lock is owned by DevTools. Other unrelated hooks/mods may still use
// DbgHelp; this API is opt-in and only accepts local symbol files.
#[link(name="dbghelp")]
unsafe extern "system" {
    fn SymInitializeW(process:*mut c_void,path:*const u16,invade:i32)->i32;
    fn SymCleanup(process:*mut c_void)->i32;
    fn SymSetOptions(options:u32)->u32;
    fn SymLoadModuleExW(process:*mut c_void,file:*mut c_void,image:*const u16,
        module:*const u16,base:u64,size:u32,data:*const c_void,flags:u32)->u64;
    fn SymFromName(process:*mut c_void,name:*const i8,info:*mut SymbolInfo)->i32;
}
#[repr(C)]
struct SymbolInfo{
    size_of_struct:u32,type_index:u32,reserved:[u64;2],
    index:u32,size:u32,mod_base:u64,flags:u32,value:u64,address:u64,
    register:u32,scope:u32,tag:u32,name_len:u32,max_name_len:u32,
    name:[u8;1024],
}
fn wide_path(path:&OsStr)->Vec<u16>{path.encode_wide().chain(iter::once(0)).collect()}
fn pdb_lookup(module:&Module,name:&str)->Result<Option<usize>,String>{
    let _lock=DBGHELP_LOCK.lock().map_err(|_|"DbgHelp 锁已损坏")?;
    // A dedicated nonzero DbgHelp session identifier avoids interfering with
    // the game process's own symbol handler or other mods.
    static SESSION_KEY:u8=0;
    let process=(&SESSION_KEY as *const u8).cast_mut().cast::<c_void>();
    // No symbol-server path or automatic network download.
    let symbols_folder=module.path.parent().unwrap_or(std::path::Path::new("."));
    let path=wide_path(symbols_folder.as_os_str());
    let ok=unsafe{SymInitializeW(process,path.as_ptr(),0)};
    if ok==0{return Err(format!("SymInitializeW 失败：{}",std::io::Error::last_os_error()));}
    struct Cleanup(*mut c_void);
    impl Drop for Cleanup{fn drop(&mut self){unsafe{SymCleanup(self.0);}}}
    let _cleanup=Cleanup(process);
    const NO_PROMPTS:u32=0x0008_0000;
    const FAIL_CRITICAL:u32=0x0000_0200;
    const SECURE:u32=0x0004_0000;
    unsafe{SymSetOptions(NO_PROMPTS|FAIL_CRITICAL|SECURE);}
    let w=wide_path(module.path.as_os_str());
    let loaded=unsafe{SymLoadModuleExW(process,ptr::null_mut(),w.as_ptr(),
        ptr::null(),module.base as u64,module.size as u32,ptr::null(),0)};
    if loaded==0{return Ok(None);}
    let requested=CString::new(format!("{}!{}",module.name,name))
        .map_err(|_|"符号名含 NUL".to_owned())?;
    let mut result=Box::new(SymbolInfo{
        size_of_struct:((mem::offset_of!(SymbolInfo,name)+7)&!7) as u32,
        type_index:0,reserved:[0;2],index:0,size:0,mod_base:0,flags:0,
        value:0,address:0,register:0,scope:0,tag:0,name_len:0,
        max_name_len:1024,name:[0;1024],
    });
    let ok=unsafe{SymFromName(process,requested.as_ptr(),result.as_mut())};
    if ok==0{
        // DbgHelp normally removes .dll/.exe in its module selector.
        let stem=module.name.rsplit_once('.').map_or(module.name.as_str(),|v|v.0);
        let alt=CString::new(format!("{stem}!{name}")).map_err(|e|e.to_string())?;
        if unsafe{SymFromName(process,alt.as_ptr(),result.as_mut())}==0{return Ok(None);}
    }
    let address=result.address as usize;
    Ok(module.contains(address).then_some(address))
}
pub fn resolve(module_name:&str,symbol:&str,allow_dbghelp:bool)->Result<Option<Located>,String>{
    if !safe_symbol(symbol){return Err("符号名为空、过长或包含非法路径字符".into());}
    let list=modules()?;
    let module=list.into_iter().find(|m|m.name.eq_ignore_ascii_case(module_name))
        .ok_or_else(||format!("尚未加载模块：{module_name}"))?;
    let hash=module.hash()?;
    if let Some(located)=exact_profile(&module,&hash,symbol,&local_profiles()?)? {
        return Ok(Some(located));
    }
    if !allow_dbghelp{return Ok(None);}
    let Some(address)=pdb_lookup(&module,symbol)? else{return Ok(None);};
    Ok(Some(Located{
        symbol:symbol.into(),module:module.name,module_sha256:hash,
        rva:address-module.base,address,origin:Origin::DbgHelp,
    }))
}
pub fn inventory()->Result<Vec<String>,String>{
    let loaded=modules()?;
    let profiles=local_profiles()?;
    let mut results=Vec::new();
    for module in loaded.iter().take(64){
        let name=&module.name;
        let m=module.hash().ok();
        let count=profiles.iter().filter(|p|
            p["name"].as_str().is_some_and(|v|v.eq_ignore_ascii_case(name)) &&
            p["sha256"].as_str()==m.as_deref()
        ).count();
        results.push(format!("{name} | 0x{:X} | {:>7} KiB | profile={} | {}",
            module.base,module.size/1024,count,
            m.as_deref().map(|s|&s[..16]).unwrap_or("hash unavailable")));
    }
    Ok(results)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]fn exact_profiles_are_version_bound(){
        let hash="a".repeat(64);
        let input=json!({"schema":1,"modules":[{
            "name":"Minecraft.Windows.exe","sha256":hash,
            "symbols":{"?getLocalPlayer@ClientInstance@@QEAAPEAVLocalPlayer@@XZ":"0x1234"}
        }]});
        let profiles=decode_profiles(&input.to_string()).unwrap();
        let module=Module{name:"Minecraft.Windows.exe".into(),path:PathBuf::new(),
            base:0x7ff600000000,size:0x500000};
        // Demonstrates identity filtering independently of actual memory read.
        assert_ne!(profiles[0]["sha256"],"b".repeat(64));
        assert_eq!(parse_rva(&profiles[0]["symbols"]["?getLocalPlayer@ClientInstance@@QEAAPEAVLocalPlayer@@XZ"]).unwrap(),0x1234);
        assert!(!safe_symbol("../lib.dll"));
        assert!(matches!(exact_profile(&module,&"b".repeat(64),"name",&profiles),Ok(None)));
    }
    #[test]fn rejects_malformed_database(){
        assert!(decode_profiles(r#"{"schema":1,"modules":[{"name":"x","sha256":"nope","symbols":{}}]}"#).is_err());
        assert!(decode_profiles(r#"{"schema":2,"modules":[]}"#).is_err());
    }
}
