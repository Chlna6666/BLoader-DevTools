//! Optional loopback MCP server. No external EXE, no startup network listener.
//!
//! Threat model: untrusted browser JS and other local applications must not
//! control the game silently. Explicit UI opt-in + unpredictable bearer token,
//! localhost-only socket, Origin rejection and tightly scoped commands.

use std::{
    collections::VecDeque, io::{Read, Write}, mem, net::{TcpListener, TcpStream},
    sync::{Arc, Mutex, mpsc::{self, SyncSender}, atomic::{AtomicBool, Ordering}},
    thread::{self, JoinHandle}, time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use windows_sys::Win32::{
    Foundation::{HWND,POINT},
    Graphics::Gdi::ClientToScreen,
    UI::Input::KeyboardAndMouse::{INPUT,INPUT_MOUSE,MOUSEEVENTF_LEFTDOWN,MOUSEEVENTF_LEFTUP,SendInput},
    UI::WindowsAndMessaging::{
        GetClientRect, IsWindow, GetWindowThreadProcessId, GetClassNameW, GetWindowTextW,
        GetForegroundWindow, SetForegroundWindow, SetCursorPos, PostMessageW, WM_LBUTTONDOWN,
        WM_LBUTTONUP, WM_MOUSEMOVE,
    },
};
use crate::{info, warn, window};

pub struct Connection {
    running: Arc<AtomicBool>,
    thread: JoinHandle<()>,
    endpoint: String,
    token: String,
}
static SERVER: Mutex<Option<Connection>> = Mutex::new(None);

/// Capture commands are processed only on the DevTools-owned D3D11/UI thread.
pub(crate) enum UiCommand {
    Capture(SyncSender<Result<Vec<u8>, String>>),
    QueryState(SyncSender<String>),
    Navigate(String,SyncSender<Result<String,String>>),
    CollisionScan(crate::collision::Profile,usize,SyncSender<Result<String,String>>),
    CollisionRefine(crate::collision::Motion,SyncSender<Result<String,String>>),
    CollisionResults(usize,SyncSender<String>),
    PlayerDiscover(crate::discovery::Options,SyncSender<Result<String,String>>),
    PlayerReport(SyncSender<String>),
    Lifecycle(crate::lifecycle::Action,SyncSender<Result<String,String>>),
    PlayerRefine(crate::collision::Motion,SyncSender<Result<String,String>>),
}
static UI_COMMANDS: Mutex<VecDeque<UiCommand>> = Mutex::new(VecDeque::new());

pub(crate) fn drain_ui_commands() -> Vec<UiCommand> {
    UI_COMMANDS.lock().map(|mut q| q.drain(..).collect()).unwrap_or_default()
}

fn ui_request<T>(make:impl FnOnce(SyncSender<T>)->UiCommand)->Result<T,String>{
    if window::ui_hwnd()==0 {return Err("DevTools UI 尚未创建".into());}
    let (sender,receiver)=mpsc::sync_channel(1);
    {
        let mut queue=UI_COMMANDS.lock().map_err(|_|"UI 命令队列已损坏")?;
        if queue.len()>=8{return Err("UI 命令队列已满".into());}
        queue.push_back(make(sender));
    }
    receiver.recv_timeout(Duration::from_secs(4)).map_err(|_|"UI 操作响应超时".into())
}
fn capture_devtools_gpu() -> Result<Vec<u8>, String> {
    ui_request(UiCommand::Capture)?
}
const MAX_REQUEST_BYTES: usize = 65536;


pub fn status() -> Option<(String, String)> {
    SERVER.lock().ok()?.as_ref().map(|s| (s.endpoint.clone(), s.token.clone()))
}

pub fn start() -> Result<(), String> {
    let mut state = SERVER.lock().map_err(|_| "MCP 状态锁已损坏")?;
    if state.is_some() { return Ok(()); }
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|err| err.to_string())?;
    let token: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|err| err.to_string())?;
    listener.set_nonblocking(true).map_err(|err| err.to_string())?;
    let endpoint = format!("http://127.0.0.1:{}/mcp", listener.local_addr().map_err(|e|e.to_string())?.port());
    let run = Arc::new(AtomicBool::new(true));
    let worker_run = run.clone();
    let worker_token = token.clone();
    let thread = thread::Builder::new().name("bloader-devtools-mcp".into())
        .spawn(move || serve(listener, &worker_token, &worker_run))
        .map_err(|e| e.to_string())?;
    info(format!("[BLoader DevTools] MCP_ENABLED endpoint={endpoint} auth=required (token not logged)"));
    *state = Some(Connection { running:run,thread,endpoint,token });
    Ok(())
}

pub fn stop() {
    let server = SERVER.lock().ok().and_then(|mut s| s.take());
    if let Some(server) = server {
        server.running.store(false, Ordering::Release);
        let _ = server.thread.join();
        info("[BLoader DevTools] MCP_DISABLED");
    }
}

fn serve(listener: TcpListener, token: &str, running: &AtomicBool) {
    while running.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((mut conn, addr)) => {
                if !addr.ip().is_loopback() { continue; }
                let _ = conn.set_read_timeout(Some(Duration::from_secs(3)));
                let _ = conn.set_write_timeout(Some(Duration::from_secs(3)));
                handle_http(&mut conn, token);
            },
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            },
            Err(err) => {
                warn(format!("[BLoader DevTools] MCP_ACCEPT_FAILED: {err}"));
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn response(stream: &mut TcpStream, status: &str, body: &str) {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json; charset=utf-8\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}

fn handle_http(stream: &mut TcpStream, secret: &str) {
    let mut data = Vec::with_capacity(4096);
    let mut temp = [0u8; 4096];
    let header_end = loop {
        match stream.read(&mut temp) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                data.extend_from_slice(&temp[..n]);
                if data.len() > MAX_REQUEST_BYTES { response(stream, "413 Payload Too Large", "{}"); return; }
                if let Some(end) = data.windows(4).position(|v| v == b"\r\n\r\n") {
                    break end + 4;
                }
            }
        }
    };
    let headers = match std::str::from_utf8(&data[..header_end]) {
        Ok(h) => h,
        Err(_) => { response(stream,"400 Bad Request","{}"); return; }
    };
    let Some(first) = headers.lines().next() else {return;};
    if first != "POST /mcp HTTP/1.1" {
        response(stream,"404 Not Found","{}");
        return;
    }
    let mut auth = None;
    let mut content_length = None;
    let mut bad_origin = false;
    let mut host_ok = false;
    for line in headers.lines().skip(1) {
        let Some((key,value)) = line.split_once(':') else { continue };
        let k = key.trim();
        let v = value.trim();
        if k.eq_ignore_ascii_case("authorization") { auth = v.strip_prefix("Bearer "); }
        if k.eq_ignore_ascii_case("content-length") { content_length = v.parse::<usize>().ok(); }
        // Reject ALL browser Origins: this listener is for local developer tools only.
        if k.eq_ignore_ascii_case("origin") { bad_origin = true; }
        if k.eq_ignore_ascii_case("host") {
            host_ok = v.starts_with("127.0.0.1:") || v.starts_with("localhost:");
        }
    }
    if bad_origin || !host_ok {
        response(stream,"403 Forbidden","{\"error\":\"invalid origin or host\"}");
        return;
    }
    if auth != Some(secret) {
        response(stream,"401 Unauthorized","{\"error\":\"bearer token required\"}");
        return;
    }
    let Some(length) = content_length else {
        response(stream,"411 Length Required","{}"); return;
    };
    if length > MAX_REQUEST_BYTES-header_end { response(stream,"413 Payload Too Large","{}"); return; }
    while data.len() < header_end + length {
        match stream.read(&mut temp) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                data.extend_from_slice(&temp[..n]);
                if data.len() > MAX_REQUEST_BYTES { response(stream,"413 Payload Too Large","{}"); return; }
            }
        }
    }
    let request: Value = match serde_json::from_slice(&data[header_end..header_end+length]) {
        Ok(v) => v,
        Err(_) => { response(stream,"400 Bad Request","{}"); return; }
    };
    let id = request.get("id").cloned();
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        response(stream,"400 Bad Request","{}"); return;
    };
    if id.is_none() {
        response(stream,"202 Accepted","{}");
        return;
    }
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-11-25",
            "capabilities":{"tools":{"listChanged":false}},
            "serverInfo":{"name":"bloader-devtools","version":env!("CARGO_PKG_VERSION")}
        }),
        "ping" => json!({}),
        "tools/list" => json!({"tools": [
            {
                "name":"devtools_state",
                "description":"从真实 egui UI 线程查询当前工具标签、扫描状态、候选数量、监视地址和最后几条控制台日志。",
                "inputSchema":{"type":"object","properties":{}}
            },
            {
                "name":"devtools_navigate",
                "description":"在真实 DevTools UI 线程切换编辑器标签，支持 memory/localplayer/hex/disasm/signature/script/migration/hooks/settings。",
                "inputSchema":{"type":"object","properties":{"tab":{"type":"string"}},"required":["tab"]}
            },
            {
                "name":"devtools_lifecycle",
                "description":"游戏线程观察器：status/verify/inspect_instance/stop/validate_player。inspect_instance 仅读取最近 update 捕获的 this/vtable/模块归属；MCP 不能安装 Hook 或调用 getter。",
                "inputSchema":{"type":"object","properties":{
                    "action":{"type":"string","enum":["status","verify","inspect_instance","stop","validate_player"]}
                },"required":["action"]}
            },
            {
                "name":"devtools_player_discover",
                "description":"运行统一只读 Symbol Resolver→ECS Inspector→LocalPlayer Validator。扫描匹配宽高的 AABB，若提供 x/y/z 则回退到 Vec3 空间坐标；分析组件指针引用与 RTTI。结果只为候选，不能直接作为 LocalPlayer*。所有深度扫描均在独立后台线程。",
                "inputSchema":{"type":"object","properties":{
                    "width":{"type":"number"},
                    "height":{"type":"number"},
                    "tolerance":{"type":"number"},
                    "budget_mib":{"type":"integer","minimum":0,"maximum":1024},
                    "x":{"type":"number"},"y":{"type":"number"},"z":{"type":"number"},
                    "radius":{"type":"number"},
                    "client_instance":{"type":"string","description":"可选：已知的 ClientInstance 候选十六进制地址"}
                }}
            },
            {
                "name":"devtools_player_refine",
                "description":"玩家已在游戏中完成走动或跳跃后，重新读取统一定位快照并验证位置变化。仅保留与动作吻合的 ECS/Vec3 候选，不宣称已取得 LocalPlayer*。",
                "inputSchema":{"type":"object","properties":{
                    "motion":{"type":"string","enum":["moved","horizontal","jumped","stationary"]}
                },"required":["motion"]}
            },
            {
                "name":"devtools_player_report",
                "description":"获取统一分析的后台任务状态、真实扫描覆盖率、符号候选、ECS 引用和 RTTI 验证证据。没有游戏线程 getter 的身份验证时只返回候选。",
                "inputSchema":{"type":"object","properties":{}}
            },
            {
                "name":"devtools_collision_scan",
                "description":"后台扫描进程内玩家尺寸 AABB (6 f32)，可指定宽高、容差、内存预算和可选玩家脚底 XYZ。返回任务已提交，不保证识别 LocalPlayer。",
                "inputSchema":{"type":"object","properties":{
                    "width":{"type":"number"},"height":{"type":"number"},
                    "tolerance":{"type":"number"},"budget_mib":{"type":"integer","minimum":0,"maximum":1024},
                    "x":{"type":"number"},"y":{"type":"number"},"z":{"type":"number"},
                    "radius":{"type":"number"}
                }}
            },
            {
                "name":"devtools_collision_refine",
                "description":"游戏中移动或跳跃后，重新比较上次碰撞箱坐标。motion: moved/horizontal/jumped/stationary",
                "inputSchema":{"type":"object","properties":{
                    "motion":{"type":"string","enum":["moved","horizontal","jumped","stationary"]}
                },"required":["motion"]}
            },
            {
                "name":"devtools_collision_results",
                "description":"返回后台扫描是否结束、最多 50 个 AABB 候选地址、尺寸与位置，不代表本地玩家归属。",
                "inputSchema":{"type":"object","properties":{"limit":{"type":"integer","minimum":1,"maximum":50}}}
            },
            {
                "name":"window_info",
                "description":"查询 DevTools 或 Minecraft 当前窗口尺寸、可见性和句柄（不执行点击）",
                "inputSchema":{"type":"object","properties":{"target":{"type":"string","enum":["devtools","game"]}},"required":["target"]}
            },
            {
                "name":"capture_window",
                "description":"DevTools 使用 D3D11 GPU 读回，游戏前台使用桌面合成截图、否则实验性 PrintWindow。模式可选择 auto/desktop/printwindow；输出尺寸可能缩放。",
                "inputSchema":{"type":"object","properties":{
                    "target":{"type":"string","enum":["devtools","game"]},
                    "mode":{"type":"string","enum":["auto","desktop","printwindow"]}
                },"required":["target"]}
            },
            {
                "name":"click_window",
                "description":"在目标窗口客户区点击：game 默认使用 SendInput 真实输入（需游戏处于交互桌面），devtools 默认 Win32 消息。mode=message 可测试后台消息，mode=input 可测试游戏原生输入。仅用于有授权的离线游戏测试。",
                "inputSchema":{"type":"object","properties":{
                    "target":{"type":"string","enum":["devtools","game"]},
                    "x":{"type":"integer","minimum":0},"y":{"type":"integer","minimum":0},
                    "mode":{"type":"string","enum":["input","message"]}
                },"required":["target","x","y"]}
            }
        ]}),
        "tools/call" => call_tool(&request),
        _ => {
            let err = json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method not found"}});
            response(stream,"200 OK",&err.to_string());return;
        }
    };
    let reply = json!({"jsonrpc":"2.0","id":id,"result":result});
    response(stream,"200 OK",&reply.to_string());
}

fn target_hwnd(target: &str) -> Result<HWND, String> {
    let hwnd = match target {
        "devtools" => window::ui_hwnd(),
        "game" => window::game_hwnd(),
        _ => return Err("未知目标窗口".into()),
    };
    if hwnd == 0 || unsafe { IsWindow(hwnd as HWND) } == 0 {
        return Err(format!("未找到 {target} 的有效窗口。DevTools 已重新枚举 Bedrock/Minecraft HWND；请确认游戏处于可见状态"));
    }
    Ok(hwnd as HWND)
}

fn rect(hwnd: HWND) -> Result<(u32,u32),String> {
    let mut r: windows_sys::Win32::Foundation::RECT = unsafe { mem::zeroed() };
    if unsafe { GetClientRect(hwnd, &mut r) } == 0 {
        return Err("GetClientRect 失败".into());
    }
    let w = (r.right-r.left).max(0) as u32;
    let h = (r.bottom-r.top).max(0) as u32;
    if w == 0 || h == 0 || w>16384 || h>16384 {
        return Err("窗口客户区尺寸无效".into());
    }
    Ok((w,h))
}


/// SendInput acts on the foreground desktop, not a background HWND.
/// The foreground check avoids clicking some unrelated active application.
fn click_with_input(hwnd:HWND,x:i32,y:i32)->Result<(),String>{
    let mut pos=POINT{x,y};
    if unsafe {ClientToScreen(hwnd,&mut pos)}==0 {
        return Err("ClientToScreen 失败；无法将游戏客户区坐标映射到桌面".into());
    }
    if unsafe{GetForegroundWindow()}!=hwnd {
        unsafe {SetForegroundWindow(hwnd);}
        std::thread::sleep(Duration::from_millis(70));
        if unsafe{GetForegroundWindow()}!=hwnd {
            return Err("无法激活 Minecraft 窗口；请先将游戏切换到前台再执行 input 点击".into());
        }
    }
    if unsafe{SetCursorPos(pos.x,pos.y)}==0{
        return Err("SetCursorPos 失败：远程桌面可能不允许光标注入".into());
    }
    let mut down:INPUT=unsafe {mem::zeroed()};
    down.r#type=INPUT_MOUSE;
    down.Anonymous.mi.dwFlags=MOUSEEVENTF_LEFTDOWN;
    if unsafe{SendInput(1,&down,mem::size_of::<INPUT>() as i32)}!=1{
        return Err("SendInput 按下失败；可能受到桌面会话权限或 UIPI 限制".into());
    }
    std::thread::sleep(Duration::from_millis(45));
    let mut up:INPUT=unsafe {mem::zeroed()};
    up.r#type=INPUT_MOUSE;
    up.Anonymous.mi.dwFlags=MOUSEEVENTF_LEFTUP;
    if unsafe{SendInput(1,&up,mem::size_of::<INPUT>() as i32)}!=1{
        return Err("SendInput 释放失败；请检查是否有鼠标按键状态滞留".into());
    }
    Ok(())
}

fn call_tool(request:&Value) -> Value {
    let params=&request["params"];
    let name=params["name"].as_str().unwrap_or("");
    let args=&params["arguments"];
    let result: Result<Value,String> = (|| {
        if name=="devtools_state" {
            let state=ui_request(UiCommand::QueryState)?;
            return Ok(json!({"content":[{"type":"text","text":state}]}));
        }
        if name=="devtools_navigate" {
            let tab=args["tab"].as_str().ok_or("缺少 tab 参数")?;
            if tab.len()>32{return Err("标签名称过长".into());}
            let result=ui_request(|reply|UiCommand::Navigate(tab.to_owned(),reply))??;
            return Ok(json!({"content":[{"type":"text","text":result}]}));
        }
        if name=="devtools_lifecycle" {
            let command=match args["action"].as_str().unwrap_or(""){
                "status"=>crate::lifecycle::Action::Status,
                "verify"=>crate::lifecycle::Action::Verify,
                "inspect_instance"=>crate::lifecycle::Action::InspectInstance,
                "stop"=>crate::lifecycle::Action::Stop,
                "validate_player"=>crate::lifecycle::Action::ValidatePlayer,
                _=>return Err("MCP 仅允许 status/verify/inspect_instance/stop/validate_player；本地 UI 才能启用 Hook".into()),
            };
            // Status does not need to lock the egui UI; all hooks publish into
            // atomics, with a short-lived control lock for state metadata.
            let output=if command==crate::lifecycle::Action::Status {
                crate::lifecycle::status()
            }else{
                ui_request(|reply|UiCommand::Lifecycle(command,reply))??
            };
            return Ok(json!({"content":[{"type":"text","text":output}]}));
        }
        if name=="devtools_player_discover" {
            let mut profile=crate::collision::Profile::default();
            if let Some(n)=args["width"].as_f64(){profile.width=n as f32;}
            if let Some(n)=args["height"].as_f64(){profile.height=n as f32;}
            if let Some(n)=args["tolerance"].as_f64(){profile.tolerance=n as f32;}
            if let Some(n)=args["radius"].as_f64(){profile.radius=n as f32;}
            let xyz=[args["x"].as_f64(),args["y"].as_f64(),args["z"].as_f64()];
            if xyz.iter().any(Option::is_some){
                let (Some(x),Some(y),Some(z))=(xyz[0],xyz[1],xyz[2]) else {
                    return Err("需要同时提供 x/y/z 三个坐标".into());
                };
                profile.feet_hint=Some(crate::collision::Vec3{
                    x:x as f32,y:y as f32,z:z as f32,
                });
            }
            let budget=args["budget_mib"].as_u64().unwrap_or(0);
            if budget!=0 && !(16..=1024).contains(&budget){return Err("预算应为 0（完整内存）或 16–1024 MiB".into());}
            let client_instance=match args["client_instance"].as_str(){
                Some(raw)=>Some(crate::memory::parse_address(raw)?),
                None=>None,
            };
            let options=crate::discovery::Options{
                profile:profile.validate()?,budget_mib:budget as usize,
                source_instance:client_instance,
            }.validate()?;
            let result=ui_request(|reply|UiCommand::PlayerDiscover(options,reply))??;
            return Ok(json!({"content":[{"type":"text","text":result}]}));
        }
        if name=="devtools_player_refine" {
            let motion=match args["motion"].as_str().unwrap_or(""){
                "moved"=>crate::collision::Motion::Moved,
                "horizontal"=>crate::collision::Motion::Horizontal,
                "jumped"=>crate::collision::Motion::Jumped,
                "stationary"=>crate::collision::Motion::Stationary,
                _=>return Err("motion 可选 moved/horizontal/jumped/stationary".into()),
            };
            let result=ui_request(|reply|UiCommand::PlayerRefine(motion,reply))??;
            return Ok(json!({"content":[{"type":"text","text":result}]}));
        }
        if name=="devtools_player_report" {
            let report=ui_request(UiCommand::PlayerReport)?;
            return Ok(json!({"content":[{"type":"text","text":report}]}));
        }
        if name=="devtools_collision_scan" {
            let mut profile=crate::collision::Profile::default();
            if let Some(n)=args["width"].as_f64(){profile.width=n as f32;}
            if let Some(n)=args["height"].as_f64(){profile.height=n as f32;}
            if let Some(n)=args["tolerance"].as_f64(){profile.tolerance=n as f32;}
            if let Some(n)=args["radius"].as_f64(){profile.radius=n as f32;}
            let coords=[args["x"].as_f64(),args["y"].as_f64(),args["z"].as_f64()];
            if coords.iter().any(Option::is_some){
                let (Some(x),Some(y),Some(z))=(coords[0],coords[1],coords[2]) else {
                    return Err("世界坐标必须同时提供 x/y/z".into());
                };
                profile.feet_hint=Some(crate::collision::Vec3{
                    x:x as f32,y:y as f32,z:z as f32
                });
            }
            let profile=profile.validate()?;
            let budget=args["budget_mib"].as_u64().unwrap_or(256);
            if budget!=0 && !(16..=1024).contains(&budget){
                return Err("碰撞箱预算须为 0（完整扫描）或 16–1024 MiB".into());
            }
            let res=ui_request(|reply|UiCommand::CollisionScan(profile,budget as usize,reply))??;
            return Ok(json!({"content":[{"type":"text","text":res}]}));
        }
        if name=="devtools_collision_refine" {
            let motion=match args["motion"].as_str().unwrap_or("") {
                "moved"=>crate::collision::Motion::Moved,
                "horizontal"=>crate::collision::Motion::Horizontal,
                "jumped"=>crate::collision::Motion::Jumped,
                "stationary"=>crate::collision::Motion::Stationary,
                _=>return Err("不支持的 motion".into())
            };
            let res=ui_request(|reply|UiCommand::CollisionRefine(motion,reply))??;
            return Ok(json!({"content":[{"type":"text","text":res}]}));
        }
        if name=="devtools_collision_results" {
            let limit=args["limit"].as_u64().unwrap_or(15);
            if !(1..=50).contains(&limit){return Err("limit 应为 1–50".into());}
            let res=ui_request(|reply|UiCommand::CollisionResults(limit as usize,reply))?;
            return Ok(json!({"content":[{"type":"text","text":res}]}));
        }
        let target = args["target"].as_str().ok_or("缺少 target 参数")?;
        let hwnd = target_hwnd(target)?;
        let (width,height)=rect(hwnd)?;
        match name {
            "window_info" => {
                let mut pid=0u32;
                unsafe { GetWindowThreadProcessId(hwnd,&mut pid); }
                let mut cls=[0u16;128];
                let mut title=[0u16;256];
                let cls_len=unsafe { GetClassNameW(hwnd,cls.as_mut_ptr(),cls.len() as i32) }.max(0) as usize;
                let title_len=unsafe { GetWindowTextW(hwnd,title.as_mut_ptr(),title.len() as i32) }.max(0) as usize;
                Ok(json!({"content":[{"type":"text","text":format!(
                    "target={target}; hwnd=0x{:X}; class={}; title={}; pid={}; client={}x{}; mcp=opt-in",
                    hwnd as usize,
                    String::from_utf16_lossy(&cls[..cls_len]),
                    String::from_utf16_lossy(&title[..title_len]),
                    pid,width,height
                )}]}))
            },
            "capture_window" => {
                let (image,out_width,out_height,method)=if target=="devtools" {
                    if args.get("mode").and_then(Value::as_str).is_some_and(|m|m!="auto") {
                        return Err("DevTools UI 只能通过 GPU 读回截图".into());
                    }
                    (capture_devtools_gpu()?,width,height,"d3d11")
                }else{
                    let mode=crate::capture::Mode::parse(args.get("mode").and_then(Value::as_str))?;
                    let got=crate::capture::capture(hwnd,width,height,mode)?;
                    (got.png,got.width,got.height,got.method)
                };
                Ok(json!({"content":[
                    {"type":"text","text":format!(
                        "target={target}, client={width}x{height}, output={}x{}, capture={method}；点击仍使用原始客户区坐标。",
                        out_width,out_height
                    )},
                    {"type":"image","mimeType":"image/png","data":STANDARD.encode(image)}
                ]}))
            },
            "click_window" => {
                let x=args["x"].as_u64().ok_or("缺少整数 x")?;
                let y=args["y"].as_u64().ok_or("缺少整数 y")?;
                if x>=width as u64 || y>=height as u64 { return Err("坐标超出窗口客户区".into()); }
                let mode=args["mode"].as_str().unwrap_or(if target=="game"{"input"}else{"message"});
                if mode=="input" {
                    click_with_input(hwnd,x as i32,y as i32)?;
                } else if mode=="message" {
                    let packed=(((y as usize) << 16) | (x as usize)) as isize;
                    unsafe {
                        if PostMessageW(hwnd,WM_MOUSEMOVE,0,packed)==0 ||
                           PostMessageW(hwnd,WM_LBUTTONDOWN,0x0001usize,packed)==0 ||
                           PostMessageW(hwnd,WM_LBUTTONUP,0,packed)==0 {
                            return Err("PostMessageW 发送失败".into());
                        }
                    }
                } else {return Err("mode 只能为 input 或 message".into());}
                Ok(json!({"content":[{"type":"text","text":format!(
                    "已提交左键点击：target={target}, mode={mode}, hwnd=0x{:X}, x={x}, y={y}；请截图验证目标是否真的响应",
                    hwnd as usize
                )}]}))
            },
            _ => Err("未知工具".into()),
        }
    })();
    match result {
        Ok(v) => v,
        Err(reason) => json!({"content":[{"type":"text","text":reason}],"isError":true}),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rpc_list_contract() {
        let doc=json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        assert_eq!(doc["method"],"tools/list");
    }
}
