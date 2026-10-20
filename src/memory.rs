//! DevTools-owned, bounded same-process memory inspection.
//! No BLoader API is used here. Every scan is worker-thread-only.
use std::{
    ffi::c_void, mem,
    sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError},
    thread::{self, JoinHandle},
};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
    Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_GUARD, PAGE_NOACCESS,
        PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY},
    Threading::GetCurrentProcess,
};

const MAX_SCAN_BYTES: usize = 128*1024*1024;
const BLOCK:usize = 256*1024;
const MAX_RESULTS:usize=8192;

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum ValueKind { U8, U32, U64, F32, F64 }
impl ValueKind {
    pub const ALL:[Self;5]=[Self::U8,Self::U32,Self::U64,Self::F32,Self::F64];
    pub fn label(self)->&'static str {
        match self {Self::U8=>"Byte",Self::U32=>"4 Bytes",Self::U64=>"8 Bytes",Self::F32=>"Float",Self::F64=>"Double"}
    }
    pub fn size(self)->usize{match self{Self::U8=>1,Self::U32|Self::F32=>4,Self::U64|Self::F64=>8}}
    pub fn encode(self,text:&str)->Result<Vec<u8>,String>{
        macro_rules! number { ($t:ty) => {text.trim().parse::<$t>().map_err(|e|e.to_string())?}; }
        Ok(match self {
            Self::U8=>vec![number!(u8)],
            Self::U32=>number!(u32).to_le_bytes().to_vec(),
            Self::U64=>number!(u64).to_le_bytes().to_vec(),
            Self::F32=>number!(f32).to_le_bytes().to_vec(),
            Self::F64=>number!(f64).to_le_bytes().to_vec(),
        })
    }
    pub fn display(self,bytes:&[u8])->String {
        if bytes.len()<self.size(){return "读取失败".into();}
        match self {
            Self::U8=>bytes[0].to_string(),
            Self::U32=>u32::from_le_bytes(bytes[..4].try_into().unwrap()).to_string(),
            Self::U64=>u64::from_le_bytes(bytes[..8].try_into().unwrap()).to_string(),
            Self::F32=>f32::from_le_bytes(bytes[..4].try_into().unwrap()).to_string(),
            Self::F64=>f64::from_le_bytes(bytes[..8].try_into().unwrap()).to_string(),
        }
    }
    fn numeric(self, bytes:&[u8])->f64 {
        match self {
            Self::U8=>bytes[0] as f64,
            Self::U32=>u32::from_le_bytes(bytes[..4].try_into().unwrap()) as f64,
            Self::U64=>u64::from_le_bytes(bytes[..8].try_into().unwrap()) as f64,
            Self::F32=>f32::from_le_bytes(bytes[..4].try_into().unwrap()) as f64,
            Self::F64=>f64::from_le_bytes(bytes[..8].try_into().unwrap()),
        }
    }
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Filter { Exact, Changed, Unchanged, Increased, Decreased }
impl Filter {
    pub const ALL:[Self;5]=[Self::Exact,Self::Changed,Self::Unchanged,Self::Increased,Self::Decreased];
    pub fn label(self)->&'static str{
        match self{Self::Exact=>"精确",Self::Changed=>"变化",Self::Unchanged=>"未变",Self::Increased=>"增加",Self::Decreased=>"减少"}
    }
}
#[derive(Clone,Debug)]
pub struct Hit {pub address:usize,pub bytes:Vec<u8>}
#[derive(Clone,Debug)]
pub enum Command {
    Scan(ValueKind,String),
    Refine(Filter,String),
    Read(usize,usize),
    Write {address:usize,kind:ValueKind,old:String,new:String},
    Disassemble(usize,usize),
    Aob(String),
    Script(Vec<Command>),
    Modules,
    Compare{old:String,new:String,pattern:String},
    Reset,
}
#[derive(Debug,Clone)]
pub struct Report {
    pub title:String,
    pub lines:Vec<String>,
    pub hits:Vec<Hit>,
    pub kind:ValueKind,
    pub dump:Vec<u8>,
    pub dump_base:usize,
}
impl Report {
    fn new(title:&str,kind:ValueKind)->Self{
        Self{title:title.into(),lines:Vec::new(),hits:Vec::new(),kind,dump:Vec::new(),dump_base:0}
    }
}
pub fn parse_address(raw:&str)->Result<usize,String>{
    let s=raw.trim().replace('_',"");
    let s=s.strip_prefix("0x").or_else(||s.strip_prefix("0X")).unwrap_or(&s);
    usize::from_str_radix(s,16).map_err(|_|"请输入十六进制地址，例如 0x7FF600001000".into())
}
pub fn read(address:usize,size:usize)->Result<Vec<u8>,String>{
    if address<0x10000 || size==0 || size>BLOCK{return Err("地址或读取长度不在允许范围内".into())}
    let mut bytes=vec![0u8;size];
    let mut got=0;
    let ok=unsafe{ReadProcessMemory(GetCurrentProcess(),address as *const c_void,
        bytes.as_mut_ptr() as *mut c_void,size,&mut got)};
    if ok==0 || got!=size {return Err(format!("无法读取 0x{address:X} ({got}/{size})"));}
    Ok(bytes)
}
fn writable(p:u32)->bool {
    p&PAGE_GUARD==0 && [PAGE_READWRITE,PAGE_WRITECOPY,PAGE_EXECUTE_READWRITE,PAGE_EXECUTE_WRITECOPY]
        .contains(&(p&0xff))
}
fn readable(p:u32)->bool {
    p&(PAGE_NOACCESS|PAGE_GUARD)==0 && [PAGE_READONLY,PAGE_READWRITE,PAGE_WRITECOPY,
        PAGE_EXECUTE_READ,PAGE_EXECUTE_READWRITE,PAGE_EXECUTE_WRITECOPY].contains(&(p&0xff))
}
fn write_data(address:usize,old:&[u8],new:&[u8])->Result<(),String>{
    if address<0x10000 || old.len()!=new.len() || old.is_empty() || old.len()>8 {
        return Err("只支持 1–8 字节的受控数据修改".into());
    }
    let mut mbi:MEMORY_BASIC_INFORMATION=unsafe{mem::zeroed()};
    if unsafe{VirtualQuery(address as *const c_void,&mut mbi,mem::size_of::<MEMORY_BASIC_INFORMATION>())}==0
        || mbi.State!=MEM_COMMIT || !writable(mbi.Protect) || mbi.Protect & 0xf0 != 0
        || address.checked_add(old.len()).ok_or("地址溢出")? > (mbi.BaseAddress as usize).saturating_add(mbi.RegionSize) {
        return Err("不是可写数据页；不会修改可执行代码或更改页面保护".into());
    }
    if read(address,old.len())?!=old{return Err("当前值不等于预期旧值；已阻止写入".into());}
    let mut written=0usize;
    let ok=unsafe{WriteProcessMemory(GetCurrentProcess(),address as *mut c_void,
        new.as_ptr() as *const c_void,new.len(),&mut written)};
    if ok==0 || written!=new.len(){return Err("WriteProcessMemory 失败".into());}
    Ok(())
}
#[derive(Clone,Copy)]
struct Region{base:usize,len:usize}
fn enumerate_regions(limit:usize)->Vec<Region>{
    let mut out=Vec::new();
    let (mut address,mut bytes)=(0x10000usize,0usize);
    while address<usize::MAX-0x10000 && bytes<limit && out.len()<12000 {
        let mut mbi:MEMORY_BASIC_INFORMATION=unsafe{mem::zeroed()};
        if unsafe{VirtualQuery(address as *const c_void,&mut mbi,mem::size_of::<MEMORY_BASIC_INFORMATION>())}==0{break}
        let start=mbi.BaseAddress as usize;
        let next=start.saturating_add(mbi.RegionSize);
        if next<=address{break}
        if mbi.State==MEM_COMMIT && readable(mbi.Protect) && mbi.RegionSize>0 {
            let length=mbi.RegionSize.min(limit-bytes);
            out.push(Region{base:start,len:length});
            bytes+=length;
        }
        address=next;
    }
    out
}
pub struct Engine{
    pub busy:bool,
    tx:Option<SyncSender<Command>>,
    rx:Receiver<Report>,
    handle:Option<JoinHandle<()>>,
}
impl Engine {
    pub fn start()->Self{
        let (tx,cmd)=sync_channel::<Command>(1);
        let (result,rx)=sync_channel::<Report>(1);
        let handle=thread::Builder::new().name("bloader-devtools-scan".into()).spawn(move||{
            let mut state=ScanState::default();
            while let Ok(item)=cmd.recv() {
                let report=state.execute(item);
                if result.send(report).is_err(){break;}
            }
        }).ok();
        Self{busy:false,tx:Some(tx),rx,handle}
    }
    pub fn submit(&mut self, cmd:Command)->Result<(),String>{
        if self.busy {return Err("后台任务尚未完成".into());}
        self.tx.as_ref().ok_or("扫描线程无法启动")?.try_send(cmd).map_err(|e|match e {
            TrySendError::Full(_)=>"扫描队列已满".to_owned(),
            TrySendError::Disconnected(_)=>"扫描线程已停止".to_owned()
        })?;
        self.busy=true;Ok(())
    }
    pub fn poll(&mut self)->Option<Report>{
        match self.rx.try_recv(){Ok(report)=>{self.busy=false;Some(report)},Err(_)=>None}
    }
}
impl Drop for Engine {
    fn drop(&mut self){
        self.tx.take();
        if let Some(handle)=self.handle.take(){let _=handle.join();}
    }
}
struct ScanState { hits:Vec<Hit>,kind:ValueKind }
impl Default for ScanState{
    fn default()->Self{Self{hits:Vec::new(),kind:ValueKind::F32}}
}
impl ScanState {
    fn execute(&mut self, cmd:Command)->Report{
        match cmd {
            Command::Modules => {
                let mut r=Report::new("进程模块快照",self.kind);
                r.lines=crate::inspection::modules();
                r
            },
            Command::Compare{old,new,pattern} => {
                let mut r=Report::new("跨版本 AOB 对比",self.kind);
                r.lines=match crate::project::compare(&old,&new,&pattern){
                    Ok(v)=>v,Err(e)=>vec![format!("对比失败: {e}")]
                };
                r
            },
            Command::Script(commands) => {
                let mut combined=Report::new("脚本执行结果",self.kind);
                for (index,command) in commands.into_iter().enumerate() {
                    let report=self.execute(command);
                    combined.lines.push(format!("--- #{:02} {} ---",index+1,report.title));
                    combined.lines.extend(report.lines);
                    combined.hits=report.hits;
                    combined.kind=report.kind;
                    if !report.dump.is_empty(){combined.dump=report.dump;combined.dump_base=report.dump_base;}
                }
                combined
            },
            Command::Reset => {self.hits.clear();Report::new("已重置扫描",self.kind)}
            Command::Read(address,len)=>{
                let mut r=Report::new("十六进制查看",self.kind);
                r.dump_base=address;
                match read(address,len.min(4096)){
                    Ok(data)=>{r.dump=data;r.lines.push(format!("已读取 {} 字节",r.dump.len()))}
                    Err(e)=>r.lines.push(e)
                };r
            }
            Command::Disassemble(address,count)=>{
                let mut r=Report::new("反汇编",self.kind);
                match read(address,(count.clamp(1,128)*15).min(2048)){
                    Ok(bytes)=>{
                        let mut decoder=iced_x86::Decoder::with_ip(64,&bytes,address as u64,iced_x86::DecoderOptions::NONE);
                        let mut fmt=iced_x86::NasmFormatter::new();
                        let mut line=String::new();
                        while decoder.can_decode() && r.lines.len()<count.clamp(1,128) {
                            let instruction=decoder.decode();
                            line.clear();
                            use iced_x86::Formatter;
                            fmt.format(&instruction,&mut line);
                            r.lines.push(format!("{:016X}  {}",instruction.ip(),line));
                        }
                    }
                    Err(e)=>r.lines.push(e)
                };r
            }
            Command::Write{address,kind,old,new}=>{
                let mut r=Report::new("手动数值写入",kind);
                let outcome=kind.encode(&old).and_then(|old|kind.encode(&new)
                    .and_then(|new|write_data(address,&old,&new)));
                r.lines.push(match outcome{Ok(())=>format!("已更新 0x{address:X}；请验证游戏实际效果"),Err(e)=>format!("拒绝写入：{e}")});
                r
            }
            Command::Scan(kind,text)=>{
                self.kind=kind;self.hits.clear();
                let mut r=Report::new("首次精确扫描",kind);
                let needle=match kind.encode(&text){Ok(b)=>b,Err(e)=>{r.lines.push(e);return r}};
                let mut total=0usize;
                'outer: for region in enumerate_regions(MAX_SCAN_BYTES) {
                    let mut offset=0usize;
                    let mut overlap=Vec::new();
                    while offset<region.len {
                        let len=(region.len-offset).min(BLOCK);
                        let at=region.base+offset;
                        if let Ok(buffer)=read(at,len) {
                            let mut joined=overlap.clone();
                            joined.extend_from_slice(&buffer);
                            let base=at-overlap.len();
                            for (i,bytes) in joined.windows(needle.len()).enumerate() {
                                if bytes==needle {
                                    self.hits.push(Hit{address:base+i,bytes:bytes.to_vec()});
                                    if self.hits.len()>=MAX_RESULTS{break 'outer}
                                }
                            }
                            let tail=needle.len().saturating_sub(1);
                            overlap=joined[joined.len().saturating_sub(tail)..].to_vec();
                        }else{overlap.clear()}
                        offset+=len;total+=len;
                    }
                }
                r.lines.push(format!("已扫描约 {} MiB，找到 {} 个候选（上限 {}）；受安全预算限制，仅扫描前 128 MiB 的可读区域",total/1048576,self.hits.len(),MAX_RESULTS));
                r.hits=self.hits.clone();r
            }
            Command::Refine(filter,text)=>{
                let mut r=Report::new("再次扫描",self.kind);
                let target=if filter==Filter::Exact{
                    match self.kind.encode(&text){Ok(v)=>Some(v),Err(e)=>{r.lines.push(e);return r}}
                }else{None};
                let kind=self.kind;
                self.hits.retain_mut(|hit|{
                    let Ok(now)=read(hit.address,kind.size()) else{return false};
                    let keep=match filter {
                        Filter::Exact=>target.as_ref().is_some_and(|bytes|*bytes==now),
                        Filter::Changed=>now!=hit.bytes,
                        Filter::Unchanged=>now==hit.bytes,
                        Filter::Increased=>kind.numeric(&now)>kind.numeric(&hit.bytes),
                        Filter::Decreased=>kind.numeric(&now)<kind.numeric(&hit.bytes),
                    };
                    if keep{hit.bytes=now}keep
                });
                r.hits=self.hits.clone();
                r.lines.push(format!("过滤后剩余 {} 个候选",r.hits.len()));r
            }
            Command::Aob(pattern)=>{
                let mut r=Report::new("游戏内特征扫描",self.kind);
                let pat=match crate::signature::Pattern::parse(&pattern){
                    Ok(p)=>p,Err(e)=>{r.lines.push(e.into());return r}
                };
                let mut total=0usize;
                'outer:for region in enumerate_regions(MAX_SCAN_BYTES) {
                    let mut offset=0usize;
                    let mut overlap=Vec::new();
                    while offset<region.len{
                        let n=(region.len-offset).min(BLOCK);
                        if let Ok(bytes)=read(region.base+offset,n){
                            let mut joined=overlap.clone();
                            joined.extend_from_slice(&bytes);
                            let base=region.base+offset-overlap.len();
                            for i in pat.matches(&joined) {
                                r.hits.push(Hit{address:base+i,bytes:Vec::new()});
                                if r.hits.len()==MAX_RESULTS{break 'outer}
                            }
                            overlap=joined[joined.len().saturating_sub(pat.0.len().saturating_sub(1))..].to_vec();
                        }else {overlap.clear()}
                        offset+=n;total+=n;
                    }
                }
                r.lines.push(format!("AOB 匹配 {} 项；已扫描 {} MiB",r.hits.len(),total/1048576));
                r
            }
        }
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn parse_addresses(){assert_eq!(parse_address("0xAB_CD").unwrap(),0xABCD);}
    #[test]fn values(){assert_eq!(ValueKind::F32.encode("1.5").unwrap(),1.5f32.to_le_bytes());}
}

pub fn hex_bytes(data:&[u8])->String {
    data.iter().map(|byte|format!("{byte:02X}")).collect::<Vec<_>>().join(" ")
}
