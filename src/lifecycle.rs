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
static CONTROL:Mutex<Control>=Mutex::new(Control{target:0,active:false,getter:0});
static ORIGINAL:AtomicUsize=AtomicUsize::new(0);
static ENABLED:AtomicBool=AtomicBool::new(false);
static GETTER:AtomicUsize=AtomicUsize::new(0);
static IN_FLIGHT:AtomicUsize=AtomicUsize::new(0);
static INSTANCE:AtomicUsize=AtomicUsize::new(0);
static PLAYER:AtomicUsize=AtomicUsize::new(0);
static THREAD_ID:AtomicU32=AtomicU32::new(0);
static CAPTURE_COUNT:AtomicU64=AtomicU64::new(0);
static LAST_SEEN:AtomicU64=AtomicU64::new(0);
static IS_READY:AtomicBool=AtomicBool::new(false);

#[link(name="kernel32")]
unsafe extern "system" {
    fn GetTickCount64()->u64;
}
type UpdateFn=unsafe extern "system" fn(*mut c_void,bool)->bool;
type GetterFn=unsafe extern "system" fn(*mut c_void)->*mut c_void;
struct Control{target:usize,active:bool,getter:usize}
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
unsafe extern "system" fn on_update(instance:*mut c_void,ready:bool)->bool{
    IN_FLIGHT.fetch_add(1,Ordering::AcqRel);
    let original=ORIGINAL.load(Ordering::Acquire);
    // ORIGINAL is published before the Hook is ever enabled.
    // A null original would mean a broken lifecycle and must fail closed.
    if original==0 {
        IN_FLIGHT.fetch_sub(1,Ordering::AcqRel);
        return false;
    }
    let callback:UpdateFn=unsafe{mem::transmute(original)};
    if ENABLED.load(Ordering::Acquire) && !instance.is_null() {
        INSTANCE.store(instance as usize,Ordering::Release);
        THREAD_ID.store(unsafe{GetCurrentThreadId()},Ordering::Release);
        IS_READY.store(ready,Ordering::Release);
        LAST_SEEN.store(unsafe{GetTickCount64()},Ordering::Release);
        CAPTURE_COUNT.fetch_add(1,Ordering::Relaxed);
    }
    let result=unsafe{callback(instance,ready)};
    if ENABLED.load(Ordering::Acquire) && !instance.is_null(){
        let address=GETTER.load(Ordering::Acquire);
        if address!=0 && ready {
            // An explicitly approved, version-pinned getter is invoked ONLY
            // on the real game update thread, following original update.
            let getter:GetterFn=unsafe{mem::transmute(address)};
            let player=unsafe{getter(instance)};
            PLAYER.store(player as usize,Ordering::Release);
        }else{
            PLAYER.store(0,Ordering::Release);
        }
    }
    IN_FLIGHT.fetch_sub(1,Ordering::AcqRel);
    result
}
fn clear_snapshot(){
    ENABLED.store(false,Ordering::Release);
    GETTER.store(0,Ordering::Release);
    INSTANCE.store(0,Ordering::Release);
    PLAYER.store(0,Ordering::Release);
    THREAD_ID.store(0,Ordering::Release);
    IS_READY.store(false,Ordering::Release);
    LAST_SEEN.store(0,Ordering::Release);
}
pub fn install_observer()->Result<String,String>{
    let mut control=CONTROL.lock().map_err(|_|"观察器控制锁中毒")?;
    if control.active{return Err("已经启用了 ClientInstance 生命周期观察器".into());}
    let mut profile=profile_file()?;
    check_code(&mut profile.update)?;
    let target=profile.update.address as *mut c_void;
    min_hook_rs::initialize().map_err(|e|format!("初始化 Hook 失败：{e:?}"))?;
    let trampoline=match min_hook_rs::create_hook(target,on_update as *mut c_void){
        Ok(p)=>p,
        Err(e)=>{let _=min_hook_rs::uninitialize();return Err(format!("创建 Hook 失败：{e:?}"));}
    };
    ORIGINAL.store(trampoline as usize,Ordering::Release);
    clear_snapshot();
    ENABLED.store(true,Ordering::Release);
    if let Err(e)=min_hook_rs::enable_hook(target){
        ENABLED.store(false,Ordering::Release);
        let _=min_hook_rs::remove_hook(target);
        ORIGINAL.store(0,Ordering::Release);
        let _=min_hook_rs::uninitialize();
        return Err(format!("启用 Hook 失败：{e:?}"));
    }
    control.target=target as usize;
    control.active=true;
    Ok(format!("已启用只读 ClientInstance::update 观察器；模块 {} RVA 0x{:X}，不调用 getter",
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
    if !control.active{
        clear_snapshot();
        return Ok("观察器未安装".into());
    }
    let target=control.target as *mut c_void;
    // Prevent future getter calls before making a thread-invasive patch.
    GETTER.store(0,Ordering::Release);
    ENABLED.store(false,Ordering::Release);
    min_hook_rs::disable_hook(target).map_err(|e|
        format!("无法禁用观察器 Hook：{e:?}；不要热卸载 DLL"))?;
    let deadline=Instant::now()+Duration::from_secs(3);
    while IN_FLIGHT.load(Ordering::Acquire)!=0 {
        if Instant::now()>deadline {
            return Err("回调尚未退出；为避免悬空 trampoline，请不要热卸载 DevTools".into());
        }
        std::thread::yield_now();
    }
    min_hook_rs::remove_hook(target).map_err(|e|format!("卸除 Hook 失败：{e:?}"))?;
    let _=min_hook_rs::uninitialize();
    control.target=0;
    control.active=false;
    control.getter=0;
    ORIGINAL.store(0,Ordering::Release);
    clear_snapshot();
    Ok("观察器已关闭、原函数 trampoline 已退休、采集指针已清除".into())
}
/// Check the captured getter result against the exact game EXE's ECS
/// profile, on the DevTools worker (never in the hot game update detour).
pub fn validate_captured_player()->Result<String,String>{
    let (active,getter)=CONTROL.lock()
        .map(|c|(c.active,c.getter!=0))
        .map_err(|_|"观察器控制锁已损坏")?;
    if !active || !getter {
        return Err("需要先启用观察器，并由用户单独批准 getter ABI".into());
    }
    let now=unsafe{GetTickCount64()};
    let last=LAST_SEEN.load(Ordering::Acquire);
    if last==0 || now.saturating_sub(last)>OBSERVATION_TTL_MS {
        return Err("最近 3 秒没有新鲜的游戏 update 回调；请进入世界重试".into());
    }
    if !IS_READY.load(Ordering::Acquire){
        return Err("最近一次 update 的 ready 标志尚未就绪".into());
    }
    let player=PLAYER.load(Ordering::Acquire);
    let instance=INSTANCE.load(Ordering::Acquire);
    if player<0x10000 || player&7!=0 || instance<0x10000 {
        return Err("getter 当前返回 nullptr、非法地址，或 ClientInstance 尚未确认".into());
    }
    let build=crate::local_player::executable_build_id()?;
    let layout=crate::ecs_layout::load_for_build(&build)?
        .ok_or("没有与当前客户端 EXE SHA-256 完全匹配的 ecs_layouts.json 配置，拒绝使用旧版偏移")?;
    let evidence=crate::ecs_layout::inspect_known_actor(player,&layout)
        .ok_or("getter 候选未通过 ActorOwner / Player / Shape 三组件及双向引用验证；不输出已确认对象")?;
    if LAST_SEEN.load(Ordering::Acquire)!=last ||
        PLAYER.load(Ordering::Acquire)!=player {
        return Err("检查过程中游戏对象已更新，拒绝提交跨代次的结构结果".into());
    }
    Ok(format!(
        "结构验证通过（仅限当前快照）：ClientInstance=0x{instance:X}, getter对象=0x{player:X}, ActorOwner=0x{:X}, PlayerComponent=0x{:X}, Shape=0x{:X}。尚需跨世界/退出/分屏生命周期实机验证；不得作为永久指针",
        evidence.owner_component,evidence.player_component,evidence.shape_component))
}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Action {Verify, Start, EnableGetter, Stop, Status, ValidatePlayer}
impl Action {
    pub fn from_str(value:&str)->Result<Self,String>{
        match value{
            "verify"=>Ok(Self::Verify),
            "start"=>Ok(Self::Start),
            "enable_getter"=>Ok(Self::EnableGetter),
            "stop"=>Ok(Self::Stop),
            "status"=>Ok(Self::Status),
            "validate_player"=>Ok(Self::ValidatePlayer),
            _=>Err("支持 verify/start/enable_getter/stop/status/validate_player".into()),
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
        Action::ValidatePlayer=>validate_captured_player(),
    }
}
pub fn status()->String{
    let (active,getter)=CONTROL.lock().map(|c|(c.active,c.getter!=0)).unwrap_or((false,false));
    let now=unsafe{GetTickCount64()};
    let last=LAST_SEEN.load(Ordering::Acquire);
    let fresh=last!=0 && now.saturating_sub(last)<=OBSERVATION_TTL_MS;
    let instance=if fresh{INSTANCE.load(Ordering::Acquire)}else{0};
    let player=if fresh && getter{PLAYER.load(Ordering::Acquire)}else{0};
    format!("observer={} getter_enabled={} callbacks={} callback_thread={} ready={} last_seen_ms={} fresh={} ClientInstance_candidate=0x{:X} LocalPlayer_candidate=0x{:X}; candidate-only, world unload invalidates pointers",
        active,getter,CAPTURE_COUNT.load(Ordering::Relaxed),
        THREAD_ID.load(Ordering::Acquire),IS_READY.load(Ordering::Acquire),
        if last==0{0}else{now.saturating_sub(last)},fresh,instance,player)
}
#[cfg(test)]
mod tests{
    use super::*;
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
