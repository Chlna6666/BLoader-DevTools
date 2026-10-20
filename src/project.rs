//! Self-contained offline feature manifests and cross-build AOB validation.
use serde_json::{json,Value};
use std::{fs,path::PathBuf,os::windows::ffi::OsStrExt,iter};
#[link(name="kernel32")]
unsafe extern "system" {
    fn MoveFileExW(source:*const u16,destination:*const u16,flags:u32)->i32;
}
fn replace_file_windows(temp:&std::path::Path,target:&std::path::Path)->Result<(),String>{
    // Replace existing feature DB atomically on NTFS; std::fs::rename fails when
    // the destination already exists under normal Windows semantics.
    let from=temp.as_os_str().encode_wide().chain(iter::once(0)).collect::<Vec<_>>();
    let to=target.as_os_str().encode_wide().chain(iter::once(0)).collect::<Vec<_>>();
    const REPLACE_EXISTING:u32=1;
    const WRITE_THROUGH:u32=8;
    if unsafe{MoveFileExW(from.as_ptr(),to.as_ptr(),REPLACE_EXISTING|WRITE_THROUGH)}==0 {
        return Err(format!("保存特征档案失败：{}",std::io::Error::last_os_error()));
    }
    Ok(())
}
use crate::{signature::Pattern,memory::{ValueKind,parse_address}};
const MAX_FILE:usize=160*1024*1024;
fn root()->Result<PathBuf,String>{
    let base=std::env::var_os("LOCALAPPDATA").ok_or("无法找到 LOCALAPPDATA")?;
    let folder=PathBuf::from(base).join("BLoader-DevTools");
    fs::create_dir_all(&folder).map_err(|e|e.to_string())?;
    Ok(folder)
}

/// Persisted tool-window layout. Values are in egui logical points and bounded
/// on load to prevent offscreen or unusably small IDE panels.
#[derive(Clone,Debug)]
pub struct LayoutSettings {
    pub explorer_width:f32,
    pub inspector_width:f32,
    pub console_height:f32,
    pub explorer_visible:bool,
    pub inspector_visible:bool,
    pub console_visible:bool,
}
impl Default for LayoutSettings {
    fn default()->Self{Self{
        explorer_width:185.,inspector_width:225.,console_height:155.,
        explorer_visible:true,inspector_visible:true,console_visible:true
    }}
}
fn decode_layout(raw:&str)->Result<LayoutSettings,String>{
    let doc:Value=serde_json::from_str(raw).map_err(|e|e.to_string())?;
    let default=LayoutSettings::default();
    let bound=|field:&str,initial:f32,lo:f32,hi:f32|{
        doc[field].as_f64().filter(|v|v.is_finite())
            .map_or(initial,|n|(n as f32).clamp(lo,hi))
    };
    Ok(LayoutSettings{
        explorer_width:bound("explorer_width",default.explorer_width,130.,400.),
        inspector_width:bound("inspector_width",default.inspector_width,165.,430.),
        console_height:bound("console_height",default.console_height,90.,340.),
        explorer_visible:doc["explorer_visible"].as_bool().unwrap_or(true),
        inspector_visible:doc["inspector_visible"].as_bool().unwrap_or(true),
        console_visible:doc["console_visible"].as_bool().unwrap_or(true),
    })
}
pub fn load_layout()->Result<LayoutSettings,String>{
    let path=root()?.join("layout.json");
    let raw=match fs::read_to_string(&path){
        Ok(s)=>s,
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(LayoutSettings::default()),
        Err(e)=>return Err(e.to_string()),
    };
    if raw.len()>8192{return Err("layout.json 超过 8 KiB 限制".into());}
    decode_layout(&raw)
}
pub fn save_layout(layout:&LayoutSettings)->Result<String,String>{
    let data=json!({
        "version":1,
        "explorer_width":layout.explorer_width.clamp(130.,400.),
        "inspector_width":layout.inspector_width.clamp(165.,430.),
        "console_height":layout.console_height.clamp(90.,340.),
        "explorer_visible":layout.explorer_visible,
        "inspector_visible":layout.inspector_visible,
        "console_visible":layout.console_visible
    });
    let folder=root()?;
    let target=folder.join("layout.json");
    let staging=folder.join("layout.json.tmp");
    fs::write(&staging,serde_json::to_vec(&data).map_err(|e|e.to_string())?)
        .map_err(|e|e.to_string())?;
    replace_file_windows(&staging,&target)?;
    Ok(target.display().to_string())
}
pub fn save_script(source:&str)->Result<String,String>{
    if source.len()>64*1024{return Err("脚本超过 64 KiB 上限".into());}
    let target=root()?.join("workspace.bldscript");
    fs::write(&target,source).map_err(|e|e.to_string())?;
    Ok(target.display().to_string())
}
pub fn load_script()->Result<String,String>{
    fs::read_to_string(root()?.join("workspace.bldscript")).map_err(|e|e.to_string())
}

/// Stores a build-scoped discovery *recipe*, never raw pointers. A heap address
/// changes with ASLR/world lifecycle and must not become a reusable Mod ABI.
pub fn save_local_player_recipe(
    candidate:&crate::local_player::Candidate,
)->Result<String,String>{
    if !candidate.build_id.starts_with("exe-sha256:") {
        return Err("当前游戏缺少可靠的 EXE 指纹，不能保存版本规则".into());
    }
    let (access,offset)=match candidate.access{
        crate::local_player::PlayerAccess::MemberOffset(n)=>("member_offset",n),
        crate::local_player::PlayerAccess::VtableIndex(n)=>("vtable_index",n),
    };
    let data=json!({
        "schema":1,
        "symbol":"LocalPlayer",
        "game_executable_sha256":candidate.build_id,
        "source_kind":match candidate.source_kind {
            crate::local_player::SourceKind::DirectInstance=>"runtime-instance",
            crate::local_player::SourceKind::PointerSlot=>"pointer-slot",
        },
        "access_kind":access,
        "access_value":offset,
        "reference_pattern":if access=="vtable_index"{
            crate::local_player::INDEX_REFERENCE_AOB
        }else{""},
        "verification":"candidate-only",
        "important":"No raw process pointer saved. Source acquisition and ABI verification remain necessary; do not call vtable methods from arbitrary threads."
    });
    let path=root()?.join("local_player_recipes.json");
    let mut entries=match fs::read_to_string(&path){
        Ok(v)=>serde_json::from_str::<Vec<Value>>(&v).map_err(|e|e.to_string())?,
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>Vec::new(),
        Err(e)=>return Err(e.to_string()),
    };
    if let Some(existing)=entries.iter_mut().find(|v|
        v["game_executable_sha256"].as_str()==Some(candidate.build_id.as_str()) &&
        v["access_kind"]==access) {
        *existing=data;
    }else{entries.push(data);}
    if entries.len()>128{return Err("候选版本记录超过 128 项，请先备份清理旧档案".into());}
    let tmp=root()?.join("local_player_recipes.json.tmp");
    fs::write(&tmp,serde_json::to_vec_pretty(&entries).map_err(|e|e.to_string())?)
        .map_err(|e|e.to_string())?;
    replace_file_windows(&tmp,&path)?;
    Ok(path.display().to_string())
}
pub fn local_player_recipes()->Result<Vec<String>,String>{
    let path=root()?.join("local_player_recipes.json");
    let source=match fs::read_to_string(path){
        Ok(s)=>s,
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(Vec::new()),
        Err(e)=>return Err(e.to_string()),
    };
    let entries:Vec<Value>=serde_json::from_str(&source).map_err(|e|e.to_string())?;
    Ok(entries.iter().map(|v|format!("{} | {} #{} | {}",
        v["game_executable_sha256"].as_str().unwrap_or("unknown"),
        v["access_kind"].as_str().unwrap_or("unknown"),
        v["access_value"].as_u64().unwrap_or(0),
        v["verification"].as_str().unwrap_or("unverified"),
    )).collect())
}

pub fn save_feature(name:&str,pattern:&str)->Result<String,String>{
    let rule=Pattern::parse(pattern).map_err(str::to_owned)?;
    if name.trim().len()>120||name.trim().is_empty(){return Err("请填写不超过 120 字的特征名称".into());}
    let payload=json!({
        "schema":1,
        "feature":name,
        "origin":"BLoader-DevTools",
        "aob":rule.canonical(),
        "validation":"unverified",
        "note":"静态候选，未包含 ABI/运行时兼容验证"
    });
    let path=root()?.join("features.json");
    let mut entries=if let Ok(raw)=fs::read_to_string(&path){
        serde_json::from_str::<Vec<Value>>(&raw).map_err(|e|format!("存量档案格式错误: {e}"))?
    }else{Vec::new()};
    if let Some(entry)=entries.iter_mut().find(|v|v["feature"]==name){*entry=payload;}
    else {entries.push(payload);}
    if entries.len()>2048{return Err("特征档案条目超过上限".into());}
    let tmp=root()?.join("features.json.tmp");
    fs::write(&tmp,serde_json::to_vec_pretty(&entries).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    replace_file_windows(&tmp,&path)?;
    Ok(path.display().to_string())
}
pub fn features()->Result<Vec<(String,String)>,String>{
    let raw=match fs::read_to_string(root()?.join("features.json")){
        Ok(raw)=>raw,
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>"[]".into(),
        Err(e)=>return Err(format!("读取特征数据库失败：{e}")),
    };
    let values:Vec<Value>=serde_json::from_str(&raw).map_err(|e|e.to_string())?;
    Ok(values.into_iter().filter_map(|v|
        Some((v.get("feature")?.as_str()?.to_owned(),v.get("aob")?.as_str()?.to_owned()))
    ).collect())
}

fn parse_kind(raw:&str)->Option<ValueKind>{
    ValueKind::ALL.into_iter().find(|kind|kind.label()==raw)
}
fn decode_watches(raw:&str)->Result<Vec<(usize,ValueKind)>,String>{
    if raw.len()>32*1024{return Err("地址监视数据库超过 32 KiB".into());}
    let source:Vec<Value>=serde_json::from_str(raw).map_err(|e|e.to_string())?;
    let mut entries=Vec::new();
    for item in source.into_iter().take(64) {
        let (Some(address),Some(kind))=(item["address"].as_str(),item["kind"].as_str()) else {continue};
        if let (Ok(address),Some(kind))=(parse_address(address),parse_kind(kind)){
            if address>=0x10000 && !entries.iter().any(|(existing,_)|*existing==address){
                entries.push((address,kind));
            }
        }
    }
    Ok(entries)
}
pub fn load_watches()->Result<Vec<(usize,ValueKind)>,String>{
    let raw=match fs::read_to_string(root()?.join("watches.json")){
        Ok(raw)=>raw,
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(Vec::new()),
        Err(e)=>return Err(e.to_string()),
    };
    decode_watches(&raw)
}
pub fn save_watches(entries:&[(usize,ValueKind)])->Result<String,String>{
    if entries.len()>64{return Err("最多保存 64 项地址监视".into());}
    let json=entries.iter().map(|(address,kind)|json!({
        "address":format!("0x{address:X}"),
        "kind":kind.label()
    })).collect::<Vec<_>>();
    let path=root()?.join("watches.json");
    let tmp=root()?.join("watches.json.tmp");
    fs::write(&tmp,serde_json::to_vec_pretty(&json).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    replace_file_windows(&tmp,&path)?;
    Ok(path.display().to_string())
}

pub fn compare(old:&str,new:&str,aob:&str)->Result<Vec<String>,String>{
    let rule=Pattern::parse(aob).map_err(str::to_owned)?;
    let mut lines=Vec::new();
    for (label,path) in [("旧版本",old),("新版本",new)]{
        let meta=fs::metadata(path).map_err(|e|format!("{label}文件错误: {e}"))?;
        if meta.len()>MAX_FILE as u64{return Err(format!("{label}文件超过离线分析上限 160 MiB；请拆分分析目标模块"));}
        if !meta.is_file(){return Err(format!("{label}不是普通文件"));}
        let data=fs::read(path).map_err(|e|e.to_string())?;
        let mut count=0usize;
        let mut first=Vec::new();
        for (at,win) in data.windows(rule.0.len()).enumerate() {
            if rule.0.iter().zip(win).all(|(expected,actual)|expected.is_none_or(|b|b==*actual)) {
                count+=1;
                if first.len()<12 {first.push(format!("文件偏移 0x{at:X}"));}
                if count>=10000 {break;}
            }
        }
        let sample=first.join("、");
        lines.push(format!("{label}：{} 字节；匹配 {}{} 处；{}",data.len(),count,
            if count>=10000{"+"}else{""},sample));
    }
    lines.push("注意：报告中的地址是文件偏移，不是 RVA；候选需要手动验证函数语义和 ABI。".into());
    Ok(lines)
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn ide_layout_clamps_invalid_widths(){
        let parsed=decode_layout(r#"{"explorer_width":9999,"inspector_width":1,"console_height":-400,"console_visible":false}"#).unwrap();
        assert_eq!(parsed.explorer_width,400.);
        assert_eq!(parsed.inspector_width,165.);
        assert_eq!(parsed.console_height,90.);
        assert!(!parsed.console_visible);
    }
        #[test]fn manifest_rejects_invalid_pattern(){assert!(Pattern::parse("GG").is_err());}
    #[test]fn watch_list_deduplicates_and_skips_bad_entries(){
        let entries=decode_watches(r#"[{"address":"0x20000","kind":"Float"},{"address":"0x20000","kind":"Float"},{"address":"garbage","kind":"Double"}]"#).unwrap();
        assert_eq!(entries.len(),1);
        assert_eq!(entries[0].0,0x20000);
    }
}
