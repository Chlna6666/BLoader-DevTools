//! DevTools-owned, bounded same-process memory inspection.
//! No BLoader API is used here. Every scan is worker-thread-only.
use std::{
    ffi::c_void, mem,
    sync::{mpsc::{sync_channel, Receiver, SyncSender, TrySendError}, Arc, atomic::{AtomicBool,Ordering}},
    thread::{self, JoinHandle},
};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
    Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_GUARD, PAGE_NOACCESS,
        PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY},
    Threading::GetCurrentProcess,
};

pub const DEFAULT_SCAN_MIB: usize = 128;
pub const MAX_SCAN_MIB: usize = 1024;
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum ScanScope { Writable, AllReadable, Executable }
impl ScanScope {
    pub const ALL:[Self;3]=[Self::Writable,Self::AllReadable,Self::Executable];
    pub fn label(self)->&'static str {
        match self {
            Self::Writable=>"可写数据（默认）",
            Self::AllReadable=>"全部可读",
            Self::Executable=>"可执行代码",
        }
    }
    fn accepts(self,protect:u32)->bool {
        match self{
            Self::Writable=>writable(protect),
            Self::AllReadable=>readable(protect),
            Self::Executable=>readable(protect) && matches!(protect&0xff,
                PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)
        }
    }
}
#[derive(Debug,Clone,Copy)]
pub struct ScanOptions {
    pub scope:ScanScope,
    pub budget_mib:usize,
    pub start:usize,
    pub end:usize,
}
impl Default for ScanOptions{
    fn default()->Self{Self{scope:ScanScope::Writable,budget_mib:DEFAULT_SCAN_MIB,
        start:0x10000,end:usize::MAX}}
}
impl ScanOptions{
    pub fn validate(self)->Result<Self,String>{
        if self.start<0x10000 || self.end<=self.start{return Err("扫描起止地址无效".into());}
        if !(16..=MAX_SCAN_MIB).contains(&self.budget_mib){
            return Err(format!("扫描预算必须在 16–{MAX_SCAN_MIB} MiB 之间"));
        }
        Ok(self)
    }
    /// Collision inspection may traverse all committed writable pages when
    /// budget_mib == 0; generic numeric scans retain their explicit cap.
    pub fn validate_collision(self)->Result<Self,String>{
        if self.start<0x10000||self.end<=self.start{
            return Err("碰撞箱扫描起止地址无效".into());
        }
        if self.budget_mib!=0 && !(16..=MAX_SCAN_MIB).contains(&self.budget_mib){
            return Err("碰撞箱扫描预算必须为 0 或 16–1024 MiB".into());
        }
        Ok(self)
    }
    fn byte_limit(self)->usize{self.budget_mib*1024*1024}
}
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
    pub fn compare(self,a:&[u8],b:&[u8])->std::cmp::Ordering {
        use std::cmp::Ordering;
        match self {
            Self::U8=>a[0].cmp(&b[0]),
            Self::U32=>u32::from_le_bytes(a[..4].try_into().unwrap())
                .cmp(&u32::from_le_bytes(b[..4].try_into().unwrap())),
            Self::U64=>u64::from_le_bytes(a[..8].try_into().unwrap())
                .cmp(&u64::from_le_bytes(b[..8].try_into().unwrap())),
            _=>{
                let (x,y)=(self.numeric(a),self.numeric(b));
                x.partial_cmp(&y).unwrap_or(Ordering::Equal)
            }
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
    ScanRange(ValueKind,String,ScanOptions),
    Refine(Filter,String),
    Read(usize,usize),
    Write {address:usize,kind:ValueKind,old:String,new:String},
    Disassemble(usize,usize),
    Aob(String),
    AobRange(String,ScanOptions),
    Script(Vec<Command>),
    TrackAabb{addresses:Vec<usize>,samples:usize,interval_ms:u64},
    Modules,
    Compare{old:String,new:String,pattern:String},
    Reset,
    Watch(Vec<(usize,ValueKind)>),
    Assert {address:usize,kind:ValueKind,expected:String},
    Wait(u64),
    ProbeLocalPlayer{
        source:usize,
        kind:crate::local_player::SourceKind,
        access:crate::local_player::PlayerAccess,
    },
    FindClientCodeSignatures,
    ScanPlayerAabb {profile:crate::collision::Profile,options:ScanOptions},
    RefinePlayerAabb {profile:crate::collision::Profile,motion:crate::collision::Motion},
    DiscoverLocalPlayer(crate::discovery::Options),
    RefineDiscoveredPlayer{
        motion:crate::collision::Motion,
        profile:crate::collision::Profile,
    },
    Lifecycle(crate::lifecycle::Action),
    SymbolInventory,
    ResolveSymbol {module:String,symbol:String,local_pdb:bool},
}
#[derive(Debug,Clone)]
pub struct Report {
    pub title:String,
    pub lines:Vec<String>,
    pub hits:Vec<Hit>,
    pub kind:ValueKind,
    pub dump:Vec<u8>,
    pub dump_base:usize,
    pub watch_values:Vec<(usize,ValueKind,String)>,
    pub ok:bool,
    pub player_candidate:Option<crate::local_player::Candidate>,
    pub index_candidate:Option<usize>,
    pub player_hitboxes:Option<Vec<crate::collision::Hit>>,
    pub discovery:Option<crate::discovery::Report>,
}
impl Report {
    fn new(title:&str,kind:ValueKind)->Self{
        Self{title:title.into(),lines:Vec::new(),hits:Vec::new(),kind,dump:Vec::new(),dump_base:0,watch_values:Vec::new(),ok:true,
            player_candidate:None,index_candidate:None,player_hitboxes:None,discovery:None}
    }
}
pub fn parse_address(raw:&str)->Result<usize,String>{
    let s=raw.trim().replace('_',"");
    let s=s.strip_prefix("0x").or_else(||s.strip_prefix("0X")).unwrap_or(&s);
    usize::from_str_radix(s,16).map_err(|_|"请输入十六进制地址，例如 0x7FF600001000".into())
}
pub(crate) fn read_into(address:usize,bytes:&mut [u8])->Result<(),String>{
    if address<0x10000||bytes.is_empty()||bytes.len()>BLOCK||
        address.checked_add(bytes.len()).is_none(){
        return Err("读取地址或长度非法".into());
    }
    let mut got=0usize;
    let ok=unsafe{ReadProcessMemory(GetCurrentProcess(),address as *const c_void,
        bytes.as_mut_ptr().cast::<c_void>(),bytes.len(),&mut got)};
    if ok==0||got!=bytes.len(){
        return Err(format!("读取失败 0x{address:X} ({got}/{})",bytes.len()));
    }
    Ok(())
}
/// Classify an address before interpreting data as x64 instructions.
pub fn page_info(address:usize)->Result<(String,bool),String>{
    let mut info:MEMORY_BASIC_INFORMATION=unsafe{mem::zeroed()};
    if unsafe{VirtualQuery(address as *const c_void,&mut info,
        mem::size_of::<MEMORY_BASIC_INFORMATION>())}==0{
        return Err(format!("VirtualQuery 无法查询 0x{address:X}"));
    }
    let type_name=match info.Type{
        windows_sys::Win32::System::Memory::MEM_PRIVATE=>"MEM_PRIVATE(堆/私有)",
        windows_sys::Win32::System::Memory::MEM_IMAGE=>"MEM_IMAGE(模块映像)",
        windows_sys::Win32::System::Memory::MEM_MAPPED=>"MEM_MAPPED(映射)",
        _=>"其他/未提交",
    };
    let committed=info.State==MEM_COMMIT;
    let executable=committed && info.Protect&(PAGE_GUARD|PAGE_NOACCESS)==0 &&
        matches!(info.Protect&0xff,PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|
            PAGE_EXECUTE_WRITECOPY|0x10);
    Ok((format!(
        "内存页 0x{:X}–0x{:X}；{}；state=0x{:X} protection=0x{:X}；可执行={}",
        info.BaseAddress as usize,
        (info.BaseAddress as usize).saturating_add(info.RegionSize),
        type_name,info.State,info.Protect,executable
    ),executable))
}
pub fn read(address:usize,size:usize)->Result<Vec<u8>,String>{
    if size==0||size>BLOCK{return Err("读取长度非法".into());}
    let mut bytes=vec![0;size];
    read_into(address,&mut bytes)?;
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
fn enumerate_regions(options:ScanOptions)->Vec<Region>{
    let mut out=Vec::new();
    let (mut address,mut bytes)=(options.start,0usize);
    let limit=options.byte_limit();
    while address<options.end && bytes<limit && out.len()<250000 {
        let mut mbi:MEMORY_BASIC_INFORMATION=unsafe{mem::zeroed()};
        if unsafe{VirtualQuery(address as *const c_void,&mut mbi,mem::size_of::<MEMORY_BASIC_INFORMATION>())}==0{break}
        let base=mbi.BaseAddress as usize;
        let next=base.saturating_add(mbi.RegionSize);
        if next<=address{break}
        if mbi.State==MEM_COMMIT && options.scope.accepts(mbi.Protect) && mbi.RegionSize>0 {
            let actual_start=base.max(options.start);
            let actual_end=next.min(options.end);
            if actual_start<actual_end {
                let length=(actual_end-actual_start).min(limit-bytes);
                out.push(Region{base:actual_start,len:length});
                bytes+=length;
            }
        }
        address=next;
    }
    out
}


/// Heap-oriented scanning: enumerate all committed private, writable memory
/// before applying the byte budget. The generic scanner historically spent its
/// entire first 128 MiB on early low-address regions, missing high-address
/// Bedrock world / Actor allocations.
fn collision_regions(options:ScanOptions)->Vec<Region>{
    let mut candidates:Vec<(Region,bool)>=Vec::new();
    let mut address=options.start;
    while address<options.end && candidates.len()<200000 {
        let mut info:MEMORY_BASIC_INFORMATION=unsafe{mem::zeroed()};
        if unsafe{VirtualQuery(address as *const c_void,&mut info,
            mem::size_of::<MEMORY_BASIC_INFORMATION>())}==0{break;}
        let start=(info.BaseAddress as usize).max(options.start);
        let next=(info.BaseAddress as usize).saturating_add(info.RegionSize);
        if next<=address{break;}
        let stop=next.min(options.end);
        if info.State==MEM_COMMIT && options.scope.accepts(info.Protect) &&
            start<stop && stop-start>=crate::collision::AABB_BYTES {
            candidates.push((Region{base:start,len:stop-start},info.Type==MEM_PRIVATE));
        }
        address=next;
    }
    if options.budget_mib==0{
        // Deterministic full traversal includes every committed writable
        // image/mapped/private region in the configured address range.
        let mut all=candidates.into_iter().map(|(region,_)|region)
            .collect::<Vec<_>>();
        all.sort_unstable_by_key(|r|r.base);
        return all;
    }
    // Prefer private heap and larger pages, then round-robin sample ranges.
    // Very large allocations must not monopolize the entire scan budget.
    candidates.sort_unstable_by(|a,b|{
        b.1.cmp(&a.1).then_with(||b.0.len.cmp(&a.0.len))
    });
    let mut list=Vec::new();
    let mut budget=options.byte_limit();
    let mut cursors=vec![0usize;candidates.len()];
    const SLICE:usize=4*1024*1024;
    while budget>=crate::collision::AABB_BYTES {
        let mut progress=false;
        for (i,(region,_)) in candidates.iter().enumerate() {
            let cursor=cursors[i];
            if cursor>=region.len {continue;}
            if budget<crate::collision::AABB_BYTES {break;}
            let len=(region.len-cursor).min(SLICE).min(budget);
            if len<crate::collision::AABB_BYTES {continue;}
            list.push(Region{base:region.base+cursor,len});
            cursors[i]+=len;
            budget-=len;
            progress=true;
        }
        if !progress{break;}
    }
    list
}

pub struct Engine{
    pub busy:bool,
    tx:Option<SyncSender<Command>>,
    rx:Receiver<Report>,
    handle:Option<JoinHandle<()>>,
    cancel:Arc<AtomicBool>,
}
impl Engine {
    pub fn start()->Self{
        let (tx,cmd)=sync_channel::<Command>(1);
        let (result,rx)=sync_channel::<Report>(1);
        let cancel=Arc::new(AtomicBool::new(false));
        let worker_cancel=cancel.clone();
        let handle=thread::Builder::new().name("bloader-devtools-scan".into()).spawn(move||{
            let mut state=ScanState::new(worker_cancel.clone());
            while let Ok(item)=cmd.recv() {
                let report=state.execute(item);
                if result.send(report).is_err(){break;}
            }
        }).ok();
        Self{busy:false,tx:Some(tx),rx,handle,cancel}
    }
    pub fn submit(&mut self, cmd:Command)->Result<(),String>{
        if self.busy {return Err("后台任务尚未完成".into());}
        self.cancel.store(false,Ordering::Release);
        self.tx.as_ref().ok_or("扫描线程无法启动")?.try_send(cmd).map_err(|e|match e {
            TrySendError::Full(_)=>"扫描队列已满".to_owned(),
            TrySendError::Disconnected(_)=>"扫描线程已停止".to_owned()
        })?;
        self.busy=true;Ok(())
    }
    pub fn cancel(&self){self.cancel.store(true,Ordering::Release);}
    pub fn poll(&mut self)->Option<Report>{
        match self.rx.try_recv(){Ok(report)=>{self.busy=false;Some(report)},Err(_)=>None}
    }
}
impl Drop for Engine {
    fn drop(&mut self){
        self.cancel.store(true,Ordering::Release);
        self.tx.take();
        if let Some(handle)=self.handle.take(){let _=handle.join();}
    }
}
struct ScanState {
    hits:Vec<Hit>,kind:ValueKind,cancel:Arc<AtomicBool>,
    player_hitboxes:Vec<crate::collision::Hit>,
    last_discovery:Option<crate::discovery::Report>,
}
impl ScanState{
    fn new(cancel:Arc<AtomicBool>)->Self{
        Self{hits:Vec::new(),kind:ValueKind::F32,cancel,
            player_hitboxes:Vec::new(),last_discovery:None}
    }
}
impl ScanState {
    fn execute(&mut self, cmd:Command)->Report{
        match cmd {
            Command::Lifecycle(action)=>{
                let mut report=Report::new("客户端生命周期观察器",self.kind);
                match crate::lifecycle::execute(action){
                    Ok(text)=>report.lines.push(text),
                    Err(e)=>{report.ok=false;report.lines.push(e);}
                }
                report
            },
            Command::SymbolInventory=>{
                let mut r=Report::new("符号模块清单",self.kind);
                match crate::symbols::inventory(){
                    Ok(lines)=>{
                        r.lines.push("模块清单使用 SHA-256 精确版本标识，profile 是离线符号记录，不允许错版本套用".into());
                        r.lines.extend(lines);
                    }
                    Err(e)=>{r.ok=false;r.lines.push(e);}
                }
                r
            },
            Command::ResolveSymbol{module,symbol,local_pdb}=>{
                let mut r=Report::new("客户端符号解析",self.kind);
                match crate::symbols::resolve(&module,&symbol,local_pdb){
                    Ok(Some(located))=>{
                        r.lines.push(format!(
                            "{}!{} = 0x{:X} (RVA 0x{:X}), source={:?}, SHA-256={}",
                            located.module,located.symbol,located.address,located.rva,
                            located.origin,located.module_sha256));
                        r.lines.push("已完成符号地址映射；还未验证调用约定、游戏线程或 LocalPlayer 返回值".into());
                    }
                    Ok(None)=>r.lines.push("无精确版本离线符号；本地 PDB 未发现或未开启，未采用其他版本的偏移".into()),
                    Err(e)=>{r.ok=false;r.lines.push(e);}
                }
                r
            },
            Command::RefineDiscoveredPlayer{motion,profile}=>{
                let mut report=Report::new("统一定位行为验证",self.kind);
                let Some(previous)=self.last_discovery.as_ref() else {
                    report.ok=false;
                    report.lines.push("请先完成统一定位初始扫描".into());
                    return report;
                };
                match crate::discovery::refine(previous,motion,profile,&self.cancel){
                    Ok(verified)=>{
                        report.ok=!verified.cancelled;
                        report.lines=crate::discovery::summarise(&verified).lines()
                            .map(str::to_owned).collect();
                        if !verified.cancelled{
                            self.last_discovery=Some(verified.clone());
                        }
                        report.discovery=Some(verified);
                    }
                    Err(e)=>{report.ok=false;report.lines.push(e);}
                }
                report
            },
            Command::DiscoverLocalPlayer(options)=>{
                let mut report=Report::new("统一本地玩家分析",self.kind);
                match crate::discovery::run(options,&self.cancel){
                    Ok(evidence)=>{
                        report.ok=!evidence.cancelled;
                        report.lines=crate::discovery::summarise(&evidence).lines()
                            .map(str::to_owned).collect();
                        if !evidence.cancelled {
                            self.last_discovery=Some(evidence.clone());
                        }
                        report.discovery=Some(evidence);
                    },
                    Err(e)=>{report.ok=false;report.lines.push(e);}
                }
                report
            },
            Command::ScanPlayerAabb{profile,options}=>{
                let mut report=Report::new("玩家碰撞箱首次扫描",self.kind);
                let (profile,options)=match (profile.validate(),options.validate_collision()) {
                    (Ok(p),Ok(o))=>(p,o),
                    (Err(e),_)|(_,Err(e))=>{
                        report.ok=false;report.lines.push(e);return report;
                    }
                };
                let mut hits=Vec::new();
                let mut block_hits=Vec::new();
                let mut scratch=vec![0u8;BLOCK];
                let mut combined=Vec::with_capacity(BLOCK+crate::collision::AABB_BYTES-1);
                let mut total_hits=0u64;
                let mut reservoir_state=0x9E3779B97F4A7C15u64;
                let mut bytes_scanned=0usize;
                let mut failed_blocks=0usize;
                let mut cancelled=false;
                const RESULT_LIMIT:usize=8192;
                'regions:for region in collision_regions(options) {
                    let mut offset=0usize;
                    let mut overlap=Vec::new();
                    while offset<region.len {
                        if self.cancel.load(Ordering::Acquire){cancelled=true;break 'regions;}
                        let size=(region.len-offset).min(BLOCK);
                        let addr=region.base+offset;
                        match read_into(addr,&mut scratch[..size]){
                            Ok(())=>{
                                combined.clear();
                                combined.extend_from_slice(&overlap);
                                combined.extend_from_slice(&scratch[..size]);
                                let base=addr-overlap.len();
                                block_hits.clear();
                                crate::collision::scan_bytes(base,&combined,profile,
                                    usize::MAX,&mut block_hits);
                                for hit in block_hits.drain(..){
                                    if hit.address+crate::collision::AABB_BYTES<=addr{continue;}
                                    total_hits=total_hits.saturating_add(1);
                                    if hits.len()<RESULT_LIMIT{hits.push(hit);continue;}
                                    reservoir_state^=reservoir_state<<13;
                                    reservoir_state^=reservoir_state>>7;
                                    reservoir_state^=reservoir_state<<17;
                                    let slot=reservoir_state%total_hits;
                                    if slot<RESULT_LIMIT as u64{hits[slot as usize]=hit;}
                                }
                                let count=(crate::collision::AABB_BYTES-1).min(combined.len());
                                overlap.clear();
                                overlap.extend_from_slice(&combined[combined.len()-count..]);
                                // Prevent overlap across discontiguous slices.
                                // The next region may have unrelated address space.
                            }
                            Err(_)=>{failed_blocks+=1;overlap.clear();}
                        }
                        bytes_scanned+=size;
                        offset+=size;
                        // The retained-result cap never stops full memory traversal.
                    }
                }
                if cancelled {
                    report.ok=false;
                    report.lines.push("扫描已取消；保留原候选状态，未提交部分结果".into());
                    report.player_hitboxes=Some(self.player_hitboxes.clone());
                    return report;
                }
                hits.sort_unstable_by_key(|h|h.address);
                hits.dedup_by_key(|h|h.address);
                self.player_hitboxes=hits;
                report.lines.push(format!(
                    "碰撞箱{}：命中总数={}，保留={}；扫描={:.1} MiB；读取失败块={}；宽={:.3} 高={:.3} 容差={:.3}",
                    if options.budget_mib==0{"完整进程扫描"}else{"分段抽样"},
                    total_hits,self.player_hitboxes.len(),bytes_scanned as f64/1048576.,failed_blocks,
                    profile.width,profile.height,profile.tolerance));
                report.lines.push("本结果仅是空间几何特征；含其他玩家、实体及物理缓存，不能直接作为 LocalPlayer 地址".into());
                report.player_hitboxes=Some(self.player_hitboxes.clone());
                report
            },
            Command::RefinePlayerAabb{profile,motion}=>{
                let mut report=Report::new("玩家碰撞箱动态筛选",self.kind);
                let profile=match profile.validate(){
                    Ok(p)=>p,Err(e)=>{report.ok=false;report.lines.push(e);return report;}
                };
                if self.player_hitboxes.is_empty(){
                    report.ok=false;
                    report.lines.push("尚无候选，请先运行玩家碰撞箱首次扫描".into());
                    return report;
                }
                let mut filtered=Vec::new();
                for hit in &self.player_hitboxes {
                    if self.cancel.load(Ordering::Acquire){
                        report.ok=false;
                        report.lines.push("动态筛选已取消，保留原候选列表".into());
                        report.player_hitboxes=Some(self.player_hitboxes.clone());
                        return report;
                    }
                    let Some(now)=read(hit.address,crate::collision::AABB_BYTES)
                        .ok().and_then(|data|crate::collision::parse_aabb(&data)) else {continue;};
                    if !profile.matches(now)||!motion.accepts(hit.box3,now){continue;}
                    let old=hit.box3.center();
                    let new=now.center();
                    let mut next=hit.clone();
                    next.traveled+=((new.x-old.x).powi(2)+(new.z-old.z).powi(2)).sqrt();
                    next.vertical+=(new.y-old.y).abs();
                    next.box3=now;
                    next.samples=next.samples.saturating_add(1);
                    filtered.push(next);
                }
                self.player_hitboxes=filtered;
                report.lines.push(format!("动作={}，剩余碰撞箱候选 {} 项。重复不同动作筛选，直至足够少。",
                    motion.label(),self.player_hitboxes.len()));
                report.player_hitboxes=Some(self.player_hitboxes.clone());
                report
            },
            Command::ProbeLocalPlayer{source,kind,access}=>{
                let mut r=Report::new("本地玩家候选检查",self.kind);
                match crate::local_player::probe(source,kind,access) {
                    Ok(candidate)=>{
                        r.lines=crate::local_player::format_candidate(&candidate);
                        r.player_candidate=Some(candidate);
                    }
                    Err(e)=>{r.ok=false;r.lines.push(format!("检查失败：{e}"));}
                }
                r
            },
            Command::FindClientCodeSignatures=>{
                let mut r=Report::new("客户端参考代码特征",self.kind);
                let (base,size)=match crate::inspection::main_image_range(){
                    Ok(v)=>v,Err(e)=>{r.ok=false;r.lines.push(e);return r;}
                };
                r.lines.push(format!("主模块 0x{base:X}，大小 {:.1} MiB；仅扫描 PE .text，不扫描游戏堆",size as f64/1048576.));
                match crate::code_signatures::scan(base,size,&self.cancel){
                    Ok(report)=>{
                        r.lines.push(format!("PE .text {:.1} MiB；读取失败块={}；命中上限={}",
                            report.scanned_bytes as f64/1048576.,report.read_failures,report.capped));
                        for (label,addresses) in [
                            ("ClientInstance::update",report.update),
                            ("ClientInstance::getLocalPlayer",report.getter)
                        ]{
                            r.lines.push(format!("{label}: {} 个参考 AOB 候选",addresses.len()));
                            for &addr in addresses.iter().take(12){
                                r.lines.push(format!("  RVA 0x{:X} | 0x{addr:X}（未验证）",addr-base));
                            }
                            if addresses.is_empty(){
                                r.lines.push("  当前游戏构建不符合参考字节特征；禁止猜测 RVA".into());
                            }else if addresses.len()!=1||report.capped{
                                r.lines.push("  命中不唯一或超过上限：禁止自动选取入口".into());
                            }
                        }
                        r.lines.push("这是静态代码特征报告，不进行任何游戏函数调用/Hook/LocalPlayer 身份确认。".into());
                    }
                    Err(e)=>{r.ok=false;r.lines.push(format!("代码特征扫描失败：{e}"));}
                }
                r
            },
            Command::Assert{address,kind,expected}=>{
                let mut r=Report::new("脚本断言",kind);
                let outcome=kind.encode(&expected).and_then(|target|{
                    let actual=read(address,kind.size())?;
                    if target==actual {
                        Ok(format!("PASS 0x{address:X}: {} = {}",kind.label(),expected))
                    }else{
                        Err(format!("FAIL 0x{address:X}: expected={expected}, actual={}",
                            kind.display(&actual)))
                    }
                });
                match outcome{
                    Ok(message)=>r.lines.push(message),
                    Err(message)=>{r.ok=false;r.lines.push(message);}
                }
                r
            },
            Command::Wait(ms)=>{
                let mut r=Report::new("脚本等待",self.kind);
                if ms>2000 {r.ok=false;r.lines.push("单次等待不能超过 2000ms".into());return r;}
                let started=std::time::Instant::now();
                while started.elapsed()<std::time::Duration::from_millis(ms) {
                    if self.cancel.load(Ordering::Acquire){r.ok=false;r.lines.push("等待已取消".into());return r;}
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                r.lines.push(format!("等待 {} ms 完成",ms));r
            },
            Command::Watch(entries)=>{
                let mut r=Report::new("地址监视刷新",self.kind);
                for (address,kind) in entries.into_iter().take(64) {
                    let value=match read(address,kind.size()){
                        Ok(bytes)=>kind.display(&bytes),
                        Err(_)=>"不可读".to_owned(),
                    };
                    r.watch_values.push((address,kind,value));
                }
                r
            },
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
                    if self.cancel.load(Ordering::Acquire){combined.lines.push("脚本已取消".into());break;}
                    let report=self.execute(command);
                    combined.lines.push(format!("--- #{:02} {} ---",index+1,report.title));
                    combined.lines.extend(report.lines);
                    let failed=!report.ok;
                    if failed {
                        combined.ok=false;
                        combined.lines.push("脚本遇到断言或执行错误，已停止后续命令".into());
                        break;
                    }
                    if matches!(report.title.as_str(), "首次精确扫描"|"再次扫描"|"游戏内特征扫描"|"已重置扫描"){
                        combined.hits=report.hits;
                        combined.kind=report.kind;
                    }
                    if !report.dump.is_empty(){combined.dump=report.dump;combined.dump_base=report.dump_base;}
                }
                combined
            },
            Command::Reset => {self.hits.clear();Report::new("已重置扫描",self.kind)}
            Command::TrackAabb{addresses,samples,interval_ms}=>{
                let mut r=Report::new("AABB 六地址动态追踪",self.kind);
                // These are private game pages, not LocalPlayer* or a registry.
                // Enforce the bounds in the evaluator too (not just the DSL).
                if !(2..=12).contains(&addresses.len()) ||
                   !(2..=16).contains(&samples) ||
                   !(100..=2000).contains(&interval_ms) ||
                   ((samples-1) as u64)*interval_ms>30000 ||
                   addresses.iter().any(|a|*a<0x10000||a%4!=0) {
                    r.ok=false;
                    r.lines.push("aabb_track 参数超出安全范围".into());
                    return r;
                }
                let mut frames=Vec::<Vec<Option<crate::collision::Aabb>>>::with_capacity(samples);
                let mut last=vec![None::<crate::collision::Aabb>;addresses.len()];
                let mut distance=vec![(0f32,0f32);addresses.len()];
                let mut failed=0usize;
                r.lines.push(format!(
                    "只读动态实验：{} 个地址，{} 轮，{}ms 间隔，约 {:.1}s；游戏进程内 ReadProcessMemory，不调用任何游戏函数、不写内存。",
                    addresses.len(),samples,interval_ms,(samples-1) as f32*interval_ms as f32/1000.
                ));
                for round in 0..samples{
                    if self.cancel.load(Ordering::Acquire){
                        r.ok=false;r.lines.push("实验已取消；只保留已读取的结果".into());
                        return r;
                    }
                    r.lines.push(format!("--- 第 {} / {} 轮 · t={}ms ---",
                        round+1,samples,round as u64*interval_ms));
                    let mut current=Vec::with_capacity(addresses.len());
                    for (index,&addr) in addresses.iter().enumerate(){
                        let bytes=read(addr,32);
                        let value=bytes.as_ref().ok().and_then(|raw|{
                            crate::collision::parse_aabb(raw)
                        }).filter(|b|{
                            let e=b.extent();
                            b.finite() && e.x>0. && e.y>0. && e.z>0. &&
                            e.x<=10. && e.y<=10. && e.z<=10.
                        });
                        if let Some(box3)=value{
                            let c=box3.center();
                            let e=box3.extent();
                            if let Some(previous)=last[index]{
                                let old=previous.center();
                                let dx=c.x-old.x;let dz=c.z-old.z;
                                distance[index].0+=(dx*dx+dz*dz).sqrt();
                                distance[index].1+=(c.y-old.y).abs();
                            }
                            let metadata=bytes.as_ref().ok().map(|raw|{
                                let width=f32::from_le_bytes(raw[24..28].try_into().unwrap());
                                let height=f32::from_le_bytes(raw[28..32].try_into().unwrap());
                                format!(" w/h={width:.3}/{height:.3}")
                            }).unwrap_or_default();
                            r.lines.push(format!(
                                "#{:02} 0x{:X} center=({:.3},{:.3},{:.3}) extent=({:.3},{:.3},{:.3}){}",
                                index+1,addr,c.x,c.y,c.z,e.x,e.y,e.z,metadata
                            ));
                            last[index]=Some(box3);
                        }else{
                            failed+=1;
                            r.lines.push(format!("#{:02} 0x{:X} 无法读取或不符合正向有限 AABB",index+1,addr));
                            last[index]=None;
                        }
                        current.push(value);
                    }
                    frames.push(current);
                    if round+1<samples{
                        let start=std::time::Instant::now();
                        let interval=std::time::Duration::from_millis(interval_ms);
                        while start.elapsed()<interval{
                            if self.cancel.load(Ordering::Acquire){
                                r.ok=false;
                                r.lines.push("动态采样已取消".into());
                                return r;
                            }
                            std::thread::sleep((interval-start.elapsed())
                                .min(std::time::Duration::from_millis(25)));
                        }
                    }
                }
                r.lines.push(format!("--- 轨迹汇总：{} 轮，无法解析 {} 个地址样本 ---",samples,failed));
                for (i,addr) in addresses.iter().enumerate(){
                    r.lines.push(format!(
                        "#{:02} 0x{:X} 累计水平位移={:.3} 累计垂直变化={:.3}",
                        i+1,addr,distance[i].0,distance[i].1
                    ));
                }
                let mut near_pairs=0;
                for i in 0..addresses.len(){
                    for j in i+1..addresses.len(){
                        let mut comparable=0;
                        let mut same=0;
                        for frame in &frames {
                            if let (Some(a),Some(b))=(frame[i],frame[j]){
                                comparable+=1;
                                let ca=a.center();let cb=b.center();
                                let ea=a.extent();let eb=b.extent();
                                let offset=(ca.x-cb.x).abs().max((ca.y-cb.y).abs())
                                    .max((ca.z-cb.z).abs());
                                let shape=(ea.x-eb.x).abs().max((ea.y-eb.y).abs())
                                    .max((ea.z-eb.z).abs());
                                if offset<=0.02 && shape<=0.02{same+=1;}
                            }
                        }
                        if comparable>=2 && same*5>=comparable*4{
                            near_pairs+=1;
                            r.lines.push(format!(
                                "近似同步 #{:02} ↔ #{:02}：{}/{} 次 AABB 中心/尺寸相近；地址间隔=0x{:X}",
                                i+1,j+1,same,comparable,addresses[j].abs_diff(addresses[i])
                            ));
                        }
                    }
                }
                r.lines.push(if near_pairs>0 {
                    format!(
                        "检测到 {near_pairs} 对近似同步 AABB。可能是同一运动状态的多个缓存/组件副本；不能据此认为存在多个玩家或确定 LocalPlayer 地址。"
                    )
                }else{
                    "未检测到高度相同的 AABB 轨迹；可尝试加长采样，仍不能由 AABB 直接推断 Actor*。".into()
                });
                r
            },
            Command::Read(address,len)=>{
                let mut r=Report::new("十六进制查看",self.kind);
                r.dump_base=address;
                if let Ok((page,_))=page_info(address){r.lines.push(page);}
                match read(address,len.min(4096)){
                    Ok(data)=>{r.dump=data;r.lines.push(format!("已读取 {} 字节",r.dump.len()))}
                    Err(e)=>{r.ok=false;r.lines.push(e);}
                };r
            }
            Command::Disassemble(address,count)=>{
                let mut r=Report::new("反汇编",self.kind);
                match page_info(address){
                    Ok((page,enabled))=>{
                        r.lines.push(page);
                        if !enabled{
                            r.ok=false;
                            r.lines.push("拒绝将非可执行内存当成机器码：此处可能是指针/结构体，请在十六进制视图检查。代码特征只应在主模块 .text 查询。".into());
                            return r;
                        }
                    }
                    Err(e)=>{r.ok=false;r.lines.push(e);return r;}
                }
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
                r.lines.push(match outcome{Ok(())=>format!("已更新 0x{address:X}；请验证游戏实际效果"),
                    Err(e)=>{r.ok=false;format!("拒绝写入：{e}")}});
                r
            }
            Command::Scan(kind,text)=>self.execute(Command::ScanRange(kind,text,ScanOptions::default())),
            Command::ScanRange(kind,text,options)=>{
                let options=match options.validate(){
                    Ok(opts)=>opts,
                    Err(e)=>{let mut r=Report::new("首次精确扫描",kind);r.lines.push(e);return r;}
                };
                self.kind=kind;self.hits.clear();
                let mut r=Report::new("首次精确扫描",kind);
                let needle=match kind.encode(&text){Ok(b)=>b,Err(e)=>{r.lines.push(e);return r}};
                let mut total=0usize;
                'outer: for region in enumerate_regions(options) {
                    if self.cancel.load(Ordering::Acquire){r.lines.push("用户取消扫描".into());break;}
                    let mut offset=0usize;
                    let mut overlap=Vec::new();
                    while offset<region.len {
                        if self.cancel.load(Ordering::Acquire){r.lines.push("用户取消扫描".into());break 'outer;}
                        let len=(region.len-offset).min(BLOCK);
                        let at=region.base+offset;
                        if let Ok(buffer)=read(at,len) {
                            let mut joined=overlap.clone();
                            joined.extend_from_slice(&buffer);
                            let base=at-overlap.len();
                            for (i,bytes) in joined.windows(needle.len()).enumerate() {
                                let hit_addr=base+i;
                                if hit_addr%kind.size()==0 && bytes==needle {
                                    self.hits.push(Hit{address:hit_addr,bytes:bytes.to_vec()});
                                    if self.hits.len()>=MAX_RESULTS{break 'outer}
                                }
                            }
                            let tail=needle.len().saturating_sub(1);
                            overlap=joined[joined.len().saturating_sub(tail)..].to_vec();
                        }else{overlap.clear()}
                        offset+=len;total+=len;
                    }
                }
                r.lines.push(format!("已处理 {} MiB，候选 {} 项，上限 {}；区域={}；预算={} MiB",
                    total/1048576,self.hits.len(),MAX_RESULTS,options.scope.label(),options.budget_mib));
                r.hits=self.hits.clone();r
            }
            Command::Refine(filter,text)=>{
                let mut r=Report::new("再次扫描",self.kind);
                if self.hits.is_empty() || self.hits.iter().any(|hit|hit.bytes.len()!=self.kind.size()) {
                    r.lines.push("没有可用的数值扫描基线；请先执行首次数值扫描。AOB 匹配不能直接用数值变化过滤。".into());
                    r.hits=self.hits.clone();
                    return r;
                }
                let target=if filter==Filter::Exact{
                    match self.kind.encode(&text){Ok(v)=>Some(v),Err(e)=>{r.lines.push(e);return r}}
                }else{None};
                let kind=self.kind;
                let mut filtered=Vec::with_capacity(self.hits.len());
                for hit in &self.hits {
                    if self.cancel.load(Ordering::Acquire){
                        r.lines.push("筛选已取消；保留取消前的原候选，未提交部分结果".into());
                        r.hits=self.hits.clone();
                        return r;
                    }
                    let Ok(now)=read(hit.address,kind.size()) else {continue;};
                    let keep=match filter {
                        Filter::Exact=>target.as_ref().is_some_and(|bytes|*bytes==now),
                        Filter::Changed=>now!=hit.bytes,
                        Filter::Unchanged=>now==hit.bytes,
                        Filter::Increased=>kind.compare(&now,&hit.bytes).is_gt(),
                        Filter::Decreased=>kind.compare(&now,&hit.bytes).is_lt(),
                    };
                    if keep{filtered.push(Hit{address:hit.address,bytes:now});}
                }
                self.hits=filtered;
                r.hits=self.hits.clone();
                r.lines.push(format!("过滤后剩余 {} 个候选",r.hits.len()));r
            }
            Command::Aob(pattern)=>self.execute(Command::AobRange(pattern,ScanOptions{scope:ScanScope::AllReadable,..Default::default()})),
            Command::AobRange(pattern,options)=>{
                let mut r=Report::new("游戏内特征扫描",self.kind);
                let options=match options.validate(){Ok(v)=>v,Err(e)=>{r.lines.push(e);return r;}};
                let pat=match crate::signature::Pattern::parse(&pattern){
                    Ok(p)=>p,Err(e)=>{r.lines.push(e.into());return r}
                };
                let mut total=0usize;
                'outer:for region in enumerate_regions(options) {
                    if self.cancel.load(Ordering::Acquire){r.lines.push("用户取消扫描".into());break;}
                    let mut offset=0usize;
                    let mut overlap=Vec::new();
                    while offset<region.len{
                        if self.cancel.load(Ordering::Acquire){r.lines.push("用户取消扫描".into());break 'outer;}
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
                r.lines.push(format!("AOB 匹配 {} 项；已处理 {} MiB；范围={}，预算={} MiB",
                    r.hits.len(),total/1048576,options.scope.label(),options.budget_mib));
                self.hits=r.hits.clone();
                r
            }
        }
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn parse_addresses(){assert_eq!(parse_address("0xAB_CD").unwrap(),0xABCD);}
    #[test]fn track_aabb_reads_two_bounded_owned_buffers_without_writing(){
        fn box_bytes(x:f32)->[u8;32]{
            let vals=[x,70.0,10.0,x+0.6,71.8,10.6,0.6,1.8];
            let mut out=[0u8;32];
            for (i,n) in vals.iter().enumerate(){out[i*4..i*4+4].copy_from_slice(&n.to_le_bytes());}
            out
        }
        let data=[box_bytes(14.0),box_bytes(14.0)];
        let addresses=data.iter().map(|b|b.as_ptr() as usize).collect::<Vec<_>>();
        let mut engine=ScanState::new(Arc::new(AtomicBool::new(false)));
        let r=engine.execute(Command::TrackAabb{addresses,samples:2,interval_ms:100});
        assert!(r.ok);
        assert!(r.lines.iter().any(|s|s.contains("近似同步")));
        assert!(r.lines.iter().any(|s|s.contains("0.600/1.800")));
    }
    #[test]fn values(){assert_eq!(ValueKind::F32.encode("1.5").unwrap(),1.5f32.to_le_bytes());}
    #[test]fn large_u64_order_is_exact(){
        let lo=(1u64<<60).to_le_bytes();
        let hi=((1u64<<60)+1).to_le_bytes();
        assert!(ValueKind::U64.compare(&hi,&lo).is_gt());
    }
    #[test]fn assert_reads_owned_memory_and_rejects_wrong_value(){
        let value=Box::new(90.0f32);
        let address=(&*value as *const f32) as usize;
        let mut engine=ScanState::new(Arc::new(AtomicBool::new(false)));
        assert!(engine.execute(Command::Assert{
            address,kind:ValueKind::F32,expected:"90".into()
        }).ok);
        let failed=engine.execute(Command::Assert{
            address,kind:ValueKind::F32,expected:"91".into()
        });
        assert!(!failed.ok);
        assert!(*value==90.0);
    }
    #[test]fn failed_assert_stops_script_before_write(){
        let value=Box::new(90.0f32);
        let address=(&*value as *const f32) as usize;
        let mut engine=ScanState::new(Arc::new(AtomicBool::new(false)));
        let report=engine.execute(Command::Script(vec![
            Command::Assert{address,kind:ValueKind::F32,expected:"2".into()},
            Command::Write{address,kind:ValueKind::F32,old:"90".into(),new:"65".into()},
        ]));
        assert!(!report.ok);
        assert_eq!(*value,90.0);
    }
        #[test]fn compare_unsigned_32_is_exact(){
        let a=u32::MAX.to_le_bytes();
        let b=(u32::MAX-1).to_le_bytes();
        assert!(ValueKind::U32.compare(&a,&b).is_gt());
    }
    #[test]fn options_reject_invalid_bounds(){
        assert!(ScanOptions{start:0x20000,end:0x10000,..Default::default()}.validate().is_err());
        assert!(ScanOptions{budget_mib:2048,..Default::default()}.validate().is_err());
    }
}

pub fn hex_bytes(data:&[u8])->String {
    data.iter().map(|byte|format!("{byte:02X}")).collect::<Vec<_>>().join(" ")
}
