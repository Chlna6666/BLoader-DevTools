//! Opt-in Bedrock client lifecycle observer, entirely owned by DevTools.
//!
//! No hook is installed on startup. Installing requires an exact EXE/DLL hash,
//! unmodified entry bytes, a reviewed ABI and an explicit UI/MCP action.
//! The update detour has NO allocations, locks, logging, memory scanning or
//! UI calls. It records ClientInstance and returns through the trampoline.
//!
//! A second *separate* opt-in allows the matched getLocalPlayer function to be
//! invoked on the observed update thread. This is deliberately not automatic:
//! symbol identity and function bytes alone cannot establish C++ ABI safety.
use std::{
    ffi::c_void,fs,mem, sync::{Mutex,atomic::{AtomicBool,AtomicU32,AtomicU64,AtomicUsize,Ordering}},
    time::{Duration,Instant},
};
use serde_json::Value;
use iced_x86::Decoder;
use windows_sys::Win32::System::{Memory::{
    VirtualQuery,MEMORY_BASIC_INFORMATION,MEM_COMMIT,PAGE_EXECUTE,PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE,PAGE_EXECUTE_WRITECOPY,PAGE_GUARD,PAGE_NOACCESS,
},Threading::GetCurrentThreadId};
use crate::{memory,symbols};

const MAX_FILE:u64=16*1024;
const OBSERVATION_TTL_MS:u64=3000;
static CONTROL:Mutex<Control>=Mutex::new(Control{target:0,active:false,getter:0,pinned:false,patch_disabled:false});
static ORIGINAL:AtomicUsize=AtomicUsize::new(0);
static ENABLED:AtomicBool=AtomicBool::new(false);
static GETTER:AtomicUsize=AtomicUsize::new(0);
static IN_FLIGHT:AtomicUsize=AtomicUsize::new(0);
static INSTANCE:AtomicUsize=AtomicUsize::new(0);
static PLAYER:AtomicUsize=AtomicUsize::new(0);
static THREAD_ID:AtomicU32=AtomicU32::new(0);
static CAPTURE_COUNT:AtomicU64=AtomicU64::new(0);
static SNAPSHOT_SEQ:AtomicU64=AtomicU64::new(0);
static SNAPSHOT_WRITER:AtomicBool=AtomicBool::new(false);
static CONCURRENT_SKIPS:AtomicU64=AtomicU64::new(0);
static INSTANCE_CHANGES:AtomicU64=AtomicU64::new(0);
static READY_FLAG_CHANGES:AtomicU64=AtomicU64::new(0);
static LAST_SEEN:AtomicU64=AtomicU64::new(0);
static IS_READY:AtomicBool=AtomicBool::new(false);

#[link(name="kernel32")]
unsafe extern "system" {
    fn GetTickCount64()->u64;
    fn GetModuleHandleExW(flags:u32,address:*const u16,module:*mut *mut c_void)->i32;
}
type UpdateFn=unsafe extern "system" fn(*mut c_void,bool)->bool;
type GetterFn=unsafe extern "system" fn(*mut c_void)->*mut c_void;
struct Control{target:usize,active:bool,getter:usize,pinned:bool,patch_disabled:bool}
#[derive(Clone,Debug)]
struct CodeTarget{
    module:String,sha256:String,rva:usize,entry_bytes:Vec<u8>,address:usize,
}
#[derive(Clone,Debug)]
struct Profile{
    update:CodeTarget,getter:Option<CodeTarget>,
}
fn hex_bytes(src:&str)->Result<Vec<u8>,String>{
    let raw=src.split_whitespace().collect::<Vec<_>>();
    if !(12..=48).contains(&raw.len()){return Err("入口指令指纹必须是 12–48 个完整字节，不允许通配符".into());}
    let mut out=Vec::new();
    for p in raw{
        if p.len()!=2 || !p.as_bytes().iter().all(u8::is_ascii_hexdigit){
            return Err("入口指纹必须由空格分隔的精确十六进制字节组成".into());
        }
        out.push(u8::from_str_radix(p,16).map_err(|e|e.to_string())?);
    }
    Ok(out)
}
fn parse_rva(v:&Value)->Result<usize,String>{
    let Some(s)=v.as_str() else{return Err("RVA 需要 0x... 十六进制字符串".into());};
    let Some(raw)=s.strip_prefix("0x").or_else(||s.strip_prefix("0X")) else {
        return Err("RVA 必须以 0x 开头".into());
    };
    usize::from_str_radix(raw,16).map_err(|_|"RVA 无效".into())
}
fn parse_target(value:&Value,expect_abi:&str)->Result<CodeTarget,String>{
    let module=value["module"].as_str().ok_or("目标缺少 module")?;
    if module.is_empty() || module.len()>256 || module.contains("..") ||
        module.contains('/') || module.contains('\\'){return Err("目标模块名非法".into());}
    let sha256=value["sha256"].as_str().ok_or("目标缺少 sha256")?;
    if sha256.len()!=64 || !sha256.bytes().all(|c|c.is_ascii_hexdigit()){
        return Err("目标必须指定当前模块的 64 字符 SHA-256".into());
    }
    if value["abi"].as_str()!=Some(expect_abi) {
        return Err(format!("当前仅支持经检查的 {expect_abi} 调用约定"));
    }
    let entry_bytes=hex_bytes(value["entry_bytes"].as_str().ok_or("目标缺少 entry_bytes")?)?;
    let rva=parse_rva(&value["rva"])?;
    Ok(CodeTarget{module:module.into(),sha256:sha256.to_ascii_lowercase(),
        rva,entry_bytes,address:0})
}
fn parse(raw:&str)->Result<Profile,String>{
    let v:Value=serde_json::from_str(raw).map_err(|e|e.to_string())?;
    if v["schema"]!=1 {return Err("生命周期配置 schema 必须为 1".into());}
    let update=parse_target(&v["update"],"client_update_this_bool_to_bool")?;
    let getter=if v["getter"].is_null(){None}
        else{Some(parse_target(&v["getter"],"client_get_local_player_this_to_ptr")?)};
    Ok(Profile{update,getter})
}
fn profile_file()->Result<Profile,String>{
    let path=crate::project::root()?.join("client_lifecycle.json");
    let metadata=fs::metadata(&path).map_err(|e|format!("未找到 client_lifecycle.json：{e}"))?;
    if metadata.len()>MAX_FILE{return Err("生命周期配置超过 16 KiB".into());}
    let text=fs::read_to_string(path).map_err(|e|e.to_string())?;
    parse(&text)
}
fn check_code(target:&mut CodeTarget)->Result<(),String>{
    let module=symbols::modules()?.into_iter()
        .find(|m|m.name.eq_ignore_ascii_case(&target.module))
        .ok_or_else(||format!("未加载模块 {}",target.module))?;
    if module.hash()?.to_ascii_lowercase()!=target.sha256{
        return Err(format!("{} 的 SHA-256 不匹配，禁止跨版本安装 Hook",module.name));
    }
    if target.rva.checked_add(target.entry_bytes.len()).is_none_or(|n|n>module.size){
        return Err("入口 RVA 或验证长度超出模块".into());
    }
    let address=module.base.checked_add(target.rva).ok_or("模块地址溢出")?;
    let mut mbi:MEMORY_BASIC_INFORMATION=unsafe{mem::zeroed()};
    if unsafe{VirtualQuery(address as *const c_void,&mut mbi,
        mem::size_of::<MEMORY_BASIC_INFORMATION>())}==0 ||
        mbi.State!=MEM_COMMIT || mbi.Protect&(PAGE_GUARD|PAGE_NOACCESS)!=0 ||
        !matches!(mbi.Protect&0xff,PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY) {
        return Err("入口地址不是可执行且已提交的内存页".into());
    }
    let current=memory::read(address,target.entry_bytes.len())?;
    if current!=target.entry_bytes {
        return Err("函数入口字节与当前游戏不相同；可能版本错误或已被其他 Mod Hook".into());
    }
    // Validate instruction boundaries; MinHook relocates whole instructions,
    // but an operator must still supply a complete unmodified fingerprint.
    let mut decoder=Decoder::with_ip(64,&current,address as u64,iced_x86::DecoderOptions::NONE);
    let mut advanced=0usize;
    while advanced<current.len(){
        let inst=decoder.decode();
        if inst.is_invalid() || inst.len()==0 {return Err("入口包含不可解码的 x64 指令".into());}
        advanced+=inst.len();
        if advanced>current.len(){return Err("指纹结束于指令中间，不能安装".into());}
    }
    if [0xE9,0xEB,0xCC].contains(&current[0]) ||
        (current[0]==0xFF && matches!(current.get(1),Some(0x25)|Some(0x15))) {
        return Err("函数入口存在跳转/调试补丁，拒绝覆盖可能属于其他 Mod 的 Hook".into());
    }
    target.address=address;
    Ok(())
}
pub fn verify_profile()->Result<String,String>{
    let mut profile=profile_file()?;
    check_code(&mut profile.update)?;
    let getter=if let Some(target)=profile.getter.as_mut(){
        check_code(target)?;
        format!("; getter=0x{:X} (ABI 仍需实机验证)",target.address)
    }else{String::new()};
    Ok(format!(
        "验证通过：{}!update RVA=0x{:X} VA=0x{:X}{}；默认不安装 Hook，必须显式启用",
        profile.update.module,profile.update.rva,profile.update.address,getter
    ))
}
// BL Mod v1 on_unload returns void and cannot veto FreeLibrary. Once a hook
// has ever been enabled, retain BOTH the detour DLL and the MinHook trampoline
// until process exit. Disabling only prevents new branches into the detour;
// another thread may already have fetched the old branch instruction.
fn pin_module_for_hook()->Result<(),String>{
    const PIN:u32=0x0000_0001;
    const FROM_ADDRESS:u32=0x0000_0004;
    let mut module:*mut c_void=std::ptr::null_mut();
    let ok=unsafe{GetModuleHandleExW(
        PIN|FROM_ADDRESS,on_update as *const () as *const u16,&mut module
    )};
    if ok==0 || module.is_null(){
        return Err(format!("无法将 Detour 所在 DLL 固定至进程结束：{}",
            std::io::Error::last_os_error()));
    }
    Ok(())
}
#[derive(Clone,Copy)]
struct Captured{
    instance:usize,player:usize,thread:u32,ready:bool,last_seen:u64,
    callbacks:u64,epoch:u64,instance_changes:u64,ready_flag_changes:u64,
}
fn capture_snapshot()->Option<Captured>{
    for _ in 0..8 {
        let epoch=SNAPSHOT_SEQ.load(Ordering::Acquire);
        if epoch&1!=0 {std::hint::spin_loop();continue;}
        let snap=Captured{
            instance:INSTANCE.load(Ordering::Acquire),
            player:PLAYER.load(Ordering::Acquire),
            thread:THREAD_ID.load(Ordering::Acquire),
            ready:IS_READY.load(Ordering::Acquire),
            last_seen:LAST_SEEN.load(Ordering::Acquire),
            callbacks:CAPTURE_COUNT.load(Ordering::Relaxed),
            instance_changes:INSTANCE_CHANGES.load(Ordering::Relaxed),
            ready_flag_changes:READY_FLAG_CHANGES.load(Ordering::Relaxed),
            epoch,
        };
        if SNAPSHOT_SEQ.load(Ordering::Acquire)==epoch{return Some(snap);}
    }
    None
}
unsafe extern "system" fn on_update(instance:*mut c_void,ready:bool)->bool{
    IN_FLIGHT.fetch_add(1,Ordering::AcqRel);
    let original=ORIGINAL.load(Ordering::Acquire);
    if original==0 {
        // This is unreachable while a hook is installed: ORIGINAL and its
        // trampoline are deliberately never retired after first enable.
        IN_FLIGHT.fetch_sub(1,Ordering::AcqRel);
        return false;
    }
    let callback:UpdateFn=unsafe{mem::transmute(original)};
    let result=unsafe{callback(instance,ready)};
    if ENABLED.load(Ordering::Acquire) && !instance.is_null(){
        // Never serialize arbitrary game callbacks on a mutex. Only the first
        // observed update thread may publish a complete snapshot/invoke getter.
        if SNAPSHOT_WRITER.compare_exchange(false,true,Ordering::Acquire,
            Ordering::Relaxed).is_ok(){
            let thread=unsafe{GetCurrentThreadId()};
            let owner=THREAD_ID.load(Ordering::Acquire);
            if owner==0 || owner==thread {
                let address=GETTER.load(Ordering::Acquire);
                let player=if address!=0 && ready &&
                    ENABLED.load(Ordering::Acquire) {
                    let getter:GetterFn=unsafe{mem::transmute(address)};
                    (unsafe{getter(instance)}) as usize
                }else{0};
                SNAPSHOT_SEQ.fetch_add(1,Ordering::AcqRel); // odd: writer
                if INSTANCE.load(Ordering::Acquire)!=instance as usize{
                    INSTANCE_CHANGES.fetch_add(1,Ordering::Relaxed);
                }
                if CAPTURE_COUNT.load(Ordering::Relaxed)>0 &&
                    IS_READY.load(Ordering::Acquire)!=ready{
                    READY_FLAG_CHANGES.fetch_add(1,Ordering::Relaxed);
                }
                INSTANCE.store(instance as usize,Ordering::Release);
                PLAYER.store(player,Ordering::Release);
                THREAD_ID.store(thread,Ordering::Release);
                IS_READY.store(ready,Ordering::Release);
                LAST_SEEN.store(unsafe{GetTickCount64()},Ordering::Release);
                CAPTURE_COUNT.fetch_add(1,Ordering::Relaxed);
                SNAPSHOT_SEQ.fetch_add(1,Ordering::Release); // even: publish
            }else{
                CONCURRENT_SKIPS.fetch_add(1,Ordering::Relaxed);
            }
            SNAPSHOT_WRITER.store(false,Ordering::Release);
        }else{
            CONCURRENT_SKIPS.fetch_add(1,Ordering::Relaxed);
        }
    }
    IN_FLIGHT.fetch_sub(1,Ordering::AcqRel);
    result
}
fn clear_snapshot(){
    ENABLED.store(false,Ordering::Release);
    GETTER.store(0,Ordering::Release);
    // Called with the control mutex held, before enabling or after draining.
    SNAPSHOT_SEQ.fetch_add(1,Ordering::AcqRel);
    INSTANCE.store(0,Ordering::Release);
    PLAYER.store(0,Ordering::Release);
    THREAD_ID.store(0,Ordering::Release);
    IS_READY.store(false,Ordering::Release);
    LAST_SEEN.store(0,Ordering::Release);
    SNAPSHOT_SEQ.fetch_add(1,Ordering::Release);
}
pub fn install_observer()->Result<String,String>{
    let mut control=CONTROL.lock().map_err(|_|"观察器控制锁中毒")?;
    if control.active{return Err("生命周期观察器仍然处于活动或退休等待状态".into());}
    if IN_FLIGHT.load(Ordering::Acquire)!=0 {
        return Err("旧版回调仍未排空，不能重新启用观察器".into());
    }
    let mut profile=profile_file()?;
    check_code(&mut profile.update)?;
    let target=profile.update.address as *mut c_void;
    if control.target!=0 && control.target!=target as usize {
        return Err("进程内保留了另一目标的 trampoline；禁止更换 Hook 目标，请重启游戏".into());
    }
    if control.target==0 {
        min_hook_rs::initialize().map_err(|e|format!("初始化 Hook 失败：{e:?}"))?;
        let trampoline=match min_hook_rs::create_hook(target,on_update as *mut c_void){
            Ok(p)=>p,
            Err(e)=>{
                let _=min_hook_rs::uninitialize();
                return Err(format!("创建 Hook 失败：{e:?}"));
            }
        };
        ORIGINAL.store(trampoline as usize,Ordering::Release);
        if let Err(err)=pin_module_for_hook(){
            // The hook has not yet been enabled, so it is safe to clean up.
            let _=min_hook_rs::remove_hook(target);
            ORIGINAL.store(0,Ordering::Release);
            let _=min_hook_rs::uninitialize();
            return Err(err);
        }
        // The PIN is irreversible. Keep the trampoline allocated forever,
        // including after stop(), to protect delayed in-flight detours.
        control.target=target as usize;
        control.pinned=true;
        control.patch_disabled=true;
    }
    clear_snapshot();
    // A failed patch attempt is treated as potentially installed until stop()
    // successfully disables it; BL v1 provides no unload veto.
    control.active=true;
    control.patch_disabled=false;
    if let Err(e)=min_hook_rs::enable_hook(target){
        // Do not release the trampoline even if the patch API reports failure.
        // On another thread the patch may already have become visible.
        return Err(format!("启用 Hook 失败：{e:?}；DLL 已固定，trampoline 不会被释放"));
    }
    ENABLED.store(true,Ordering::Release);
    Ok(format!("已启用只读 ClientInstance::update 观察器；{} RVA 0x{:X}；Hook DLL/trampoline 将保留到游戏进程退出；getter 未授权",
        profile.update.module,profile.update.rva))
}
pub fn enable_verified_getter()->Result<String,String>{
    let mut control=CONTROL.lock().map_err(|_|"观察器控制锁中毒")?;
    if !control.active{return Err("请先启用生命周期观察器".into());}
    let mut profile=profile_file()?;
    // Ensure profile and update entry still refer to same active target.
    // MinHook has patched update's prologue, so do not compare its bytes again.
    let loaded=symbols::modules()?;
    let module=loaded.iter().find(|m|m.name.eq_ignore_ascii_case(&profile.update.module))
        .ok_or("update 模块已卸载")?;
    if module.hash()?.to_ascii_lowercase()!=profile.update.sha256 ||
        module.base.checked_add(profile.update.rva)!=Some(control.target){
        return Err("生命周期版本身份已变更；拒绝启用 getter".into());
    }
    let target=profile.getter.as_mut().ok_or("配置缺少已审核的 getter 函数")?;
    check_code(target)?;
    if target.address==control.target {
        return Err("getter 与 update 指向同一个入口，拒绝递归调用".into());
    }
    // Explicit enable only; caller accepts ABI responsibility for this build.
    control.getter=target.address;
    GETTER.store(target.address,Ordering::Release);
    Ok(format!("getter 已单独授权；仅在 update 游戏线程、ready=true 后调用 0x{:X}。实际返回值仍需生命周期验证",target.address))
}
pub fn stop()->Result<String,String>{
    let mut control=CONTROL.lock().map_err(|_|"观察器控制锁中毒")?;
    if !control.active {
        clear_snapshot();
        return Ok(if control.pinned {
            "观察器已停止；Detour DLL 与 trampoline 仍安全保留至进程退出".into()
        }else{"观察器未安装".into()});
    }
    let target=control.target as *mut c_void;
    // A getter already loaded by an in-flight callback is protected by
    // IN_FLIGHT; neither it nor the retained trampoline may be reclaimed.
    GETTER.store(0,Ordering::Release);
    ENABLED.store(false,Ordering::Release);
    if !control.patch_disabled {
        min_hook_rs::disable_hook(target).map_err(|e|
            format!("无法禁用观察器 Hook：{e:?}；DLL 已固定，不能安全热卸载"))?;
        control.patch_disabled=true;
    }
    let deadline=Instant::now()+Duration::from_secs(3);
    while IN_FLIGHT.load(Ordering::Acquire)!=0 {
        if Instant::now()>deadline {
            return Err("回调未在 3 秒内排空；Hook DLL/trampoline 保留，禁止热替换".into());
        }
        std::thread::yield_now();
    }
    // Do not call remove_hook()/uninitialize() after a hook was enabled:
    // even when IN_FLIGHT == 0, a paused thread may have already fetched the
    // detour branch but not entered the Rust callback yet.
    control.active=false;
    control.getter=0;
    clear_snapshot();
    Ok("观察器已禁用且已排空可见回调；DLL 与 trampoline 固定至进程退出，未进行不安全卸载".into())
}
/// Check the captured getter result against the exact game EXE's ECS
/// profile, on the DevTools worker (never in the hot game update detour).
/// Passive inspection of a captured ClientInstance candidate. Never call any
/// game function, infer ECS layout, or dereference a raw pointer directly.
pub fn inspect_captured_instance()->Result<String,String>{
    let active=CONTROL.lock().map_err(|_|"观察器控制锁中毒")?.active;
    if !active{
        return Err("观察器未启动；需在本地 UI 用精确版本/ABI 配置授权 update Hook".into());
    }
    let modules=symbols::modules()?;
    let snapshot=capture_snapshot().ok_or("快照正在更新，请重试")?;
    let age=unsafe{GetTickCount64()}.saturating_sub(snapshot.last_seen);
    if snapshot.last_seen==0 || age>OBSERVATION_TTL_MS{
        return Err("最近 3 秒内没有可靠的游戏 update 回调，拒绝过期指针".into());
    }
    let this=snapshot.instance;
    if this<0x10000 || this&7!=0{
        return Err("ClientInstance this 候选不符合最低地址/对齐要求".into());
    }
    // A first-word vtable is a C++ polymorphic-object heuristic only.
    // ReadProcessMemory handles inaccessible pages but not object lifetimes.
    let vtable=usize::from_le_bytes(memory::read(this,8)?
        .try_into().map_err(|_|"对象首指针长度无效")?);
    if vtable<0x10000 || vtable&7!=0{
        return Err("候选对象首指针无法解释为有效虚表地址".into());
    }
    let slot0=usize::from_le_bytes(memory::read(vtable,8)?
        .try_into().map_err(|_|"虚表条目长度无效")?);
    let vtable_owner=modules.iter().find(|m|m.contains(vtable))
        .map(|m|m.name.as_str()).unwrap_or("未知模块");
    let method_owner=modules.iter().find(|m|m.contains(slot0))
        .map(|m|m.name.as_str()).unwrap_or("未知模块");
    let (page,executable)=memory::page_info(slot0)?;
    if capture_snapshot().is_none_or(|after|after.epoch!=snapshot.epoch){
        return Err("检查过程中游戏快照代次变化，结果作废".into());
    }
    Ok(format!(
        "ClientInstance this 候选=0x{this:X}；vtable=0x{vtable:X} ({vtable_owner})；slot[0]=0x{slot0:X} ({method_owner})；可执行={executable}；{page}；update线程={}；ready参数={}；距回调={}ms；代次={}；this变化={}次；ready参数变化={}次。仅证明可读和模块归属，不能确认真实类型/Actor/LocalPlayer，绝不执行虚函数。",
        snapshot.thread,snapshot.ready,age,snapshot.epoch,
        snapshot.instance_changes,snapshot.ready_flag_changes
    ))
}
pub fn validate_captured_player()->Result<String,String>{
    let (active,getter)=CONTROL.lock()
        .map(|c|(c.active,c.getter!=0))
        .map_err(|_|"观察器控制锁已损坏")?;
    if !active || !getter {
        return Err("需要先启用观察器，并由用户单独批准 getter ABI".into());
    }
    // Hashing the executable and loading the profile can be expensive. Do it
    // before obtaining the live snapshot so that validation only spans reads.
    let build=crate::local_player::executable_build_id()?;
    let layout=crate::ecs_layout::load_for_build(&build)?
        .ok_or("没有与当前客户端 EXE SHA-256 完全匹配的 ecs_layouts.json 配置，拒绝使用旧版偏移")?;
    let snapshot=capture_snapshot().ok_or("采集快照正在更新，请重试")?;
    let now=unsafe{GetTickCount64()};
    if snapshot.last_seen==0 || now.saturating_sub(snapshot.last_seen)>OBSERVATION_TTL_MS {
        return Err("最近 3 秒没有新鲜的游戏 update 回调；请进入世界重试".into());
    }
    if !snapshot.ready {
        return Err("最近一次 update 的 ready 标志尚未就绪".into());
    }
    let player=snapshot.player;
    let instance=snapshot.instance;
    if player<0x10000 || player&7!=0 || instance<0x10000 {
        return Err("getter 当前返回 nullptr、非法地址，或 ClientInstance 尚未确认".into());
    }
    let evidence=crate::ecs_layout::inspect_known_actor(player,&layout)
        .ok_or("getter 候选未通过 ActorOwner / Player / Shape 三组件及双向引用验证；不输出已确认对象")?;
    // A -> B -> A pointer reuse must also be rejected, not just address
    // changes. A monotonic seqlock generation identifies ANY intervening
    // callback, even when the same address is recycled.
    if capture_snapshot().is_none_or(|current|current.epoch!=snapshot.epoch) {
        return Err("检查期间游戏快照代次发生变化，拒绝跨代次 ECS 结构结果".into());
    }
    Ok(format!(
        "结构验证通过（仅限快照代次 {}）：ClientInstance=0x{instance:X}, getter对象=0x{player:X}, ActorOwner=0x{:X}, PlayerComponent=0x{:X}, Shape=0x{:X}。尚需跨世界/退出/分屏生命周期实机验证；不得作为永久指针",
        snapshot.epoch,evidence.owner_component,evidence.player_component,evidence.shape_component))
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Action {Verify, Start, EnableGetter, Stop, Status, InspectInstance, ValidatePlayer}
impl Action {
    pub fn from_str(value:&str)->Result<Self,String>{
        match value{
            "verify"=>Ok(Self::Verify),
            "start"=>Ok(Self::Start),
            "enable_getter"=>Ok(Self::EnableGetter),
            "stop"=>Ok(Self::Stop),
            "status"=>Ok(Self::Status),
            "inspect_instance"=>Ok(Self::InspectInstance),
            "validate_player"=>Ok(Self::ValidatePlayer),
            _=>Err("支持 verify/start/enable_getter/stop/status/inspect_instance/validate_player".into()),
        }
    }
}
pub fn execute(action:Action)->Result<String,String>{
    match action {
        Action::Verify=>verify_profile(),
        Action::Start=>install_observer(),
        Action::EnableGetter=>enable_verified_getter(),
        Action::Stop=>stop(),
        Action::Status=>Ok(status()),
        Action::InspectInstance=>inspect_captured_instance(),
        Action::ValidatePlayer=>validate_captured_player(),
    }
}
pub fn status()->String{
    let (active,getter,pinned,patch_disabled)=CONTROL.lock()
        .map(|c|(c.active,c.getter!=0,c.pinned,c.patch_disabled))
        .unwrap_or((false,false,false,false));
    let now=unsafe{GetTickCount64()};
    let snapshot=capture_snapshot();
    let fresh=snapshot.is_some_and(|s|s.last_seen!=0 &&
        now.saturating_sub(s.last_seen)<=OBSERVATION_TTL_MS);
    let instance=if fresh{snapshot.map_or(0,|s|s.instance)}else{0};
    let player=if fresh && getter{snapshot.map_or(0,|s|s.player)}else{0};
    let last_seen=snapshot.map_or(0,|s|if s.last_seen==0 {0}
        else{now.saturating_sub(s.last_seen)});
    format!("observer={} getter_enabled={} module_pinned={} patch_disabled={} in_flight={} concurrent_skips={} callbacks={} snapshot_epoch={} callback_thread={} ready={} this_changes={} ready_flag_changes={} last_seen_ms={} fresh={} ClientInstance_candidate=0x{:X} LocalPlayer_candidate=0x{:X}; candidate-only, world unload invalidates pointers",
        active,getter,pinned,patch_disabled,IN_FLIGHT.load(Ordering::Acquire),
        CONCURRENT_SKIPS.load(Ordering::Relaxed),
        snapshot.map_or(0,|s|s.callbacks),
        snapshot.map_or(0,|s|s.epoch),
        snapshot.map_or(0,|s|s.thread),
        snapshot.is_some_and(|s|s.ready),
        snapshot.map_or(0,|s|s.instance_changes),
        snapshot.map_or(0,|s|s.ready_flag_changes),
        last_seen,fresh,instance,player)
}
#[cfg(test)]
mod tests{
    use super::*;
    unsafe extern "system" fn synthetic_update(this:*mut c_void,ready:bool)->bool{
        !this.is_null() && ready
    }
    unsafe extern "system" fn synthetic_getter(this:*mut c_void)->*mut c_void{
        this
    }
    #[test]fn observed_this_and_getter_are_separately_gated(){
        let mut client=[1234usize,5678usize];
        let this=client.as_mut_ptr().cast::<c_void>();
        ORIGINAL.store(synthetic_update as usize,Ordering::Release);
        ENABLED.store(true,Ordering::Release);
        GETTER.store(0,Ordering::Release);
        PLAYER.store(0,Ordering::Release);
        assert!(unsafe{on_update(this,true)});
        assert_eq!(INSTANCE.load(Ordering::Acquire),this as usize);
        assert_eq!(PLAYER.load(Ordering::Acquire),0);
        assert_ne!(THREAD_ID.load(Ordering::Acquire),0);
        GETTER.store(synthetic_getter as usize,Ordering::Release);
        assert!(!unsafe{on_update(this,false)});
        assert_eq!(PLAYER.load(Ordering::Acquire),0);
        assert!(unsafe{on_update(this,true)});
        assert_eq!(PLAYER.load(Ordering::Acquire),this as usize);
        assert_eq!(IN_FLIGHT.load(Ordering::Acquire),0);
        let before=capture_snapshot().unwrap();
        assert!(before.instance_changes>=1);
        assert!(before.ready_flag_changes>=2);
        let ptr=this as usize;
        // A non-owner thread must never invoke the version-pinned getter.
        let other=std::thread::spawn(move||unsafe{on_update(ptr as *mut c_void,true)});
        assert!(other.join().unwrap());
        let after=capture_snapshot().unwrap();
        assert_eq!(before.thread,after.thread);
        assert_eq!(before.epoch,after.epoch);
        assert!(CONCURRENT_SKIPS.load(Ordering::Acquire)>=1);
        // Disabled capture must still forward the original callback.
        ENABLED.store(false,Ordering::Release);
        GETTER.store(synthetic_getter as usize,Ordering::Release);
        PLAYER.store(0,Ordering::Release);
        assert!(unsafe{on_update(this,true)});
        assert_eq!(PLAYER.load(Ordering::Acquire),0);
        clear_snapshot();
        ORIGINAL.store(0,Ordering::Release);
    }
    #[test]fn rejects_wrong_build_and_abi(){
        let hash="b".repeat(64);
        let raw=serde_json::json!({"schema":1,"update":{
            "module":"Minecraft.Windows.exe","sha256":hash,"rva":"0x1234",
            "abi":"not-the-right-one","entry_bytes":"48 8B 44 24 08 48 89 5C 24 10 57 48 83 EC 20"
        }});
        assert!(parse(&raw.to_string()).is_err());
        let raw=raw.to_string().replace("not-the-right-one","client_update_this_bool_to_bool");
        assert!(parse(&raw).is_ok());
        assert!(parse(&raw.replace(&"b".repeat(64),"bad")).is_err());
    }
    #[test]fn fingerprint_never_accepts_wildcards(){
        assert!(hex_bytes("48 8B ?? 48 89 5C 24 10 57 48 83 EC").is_err());
        assert!(hex_bytes("48 8B 44 24 08 48 89 5C 24 10 57 48").is_ok());
    }
}
