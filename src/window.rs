//! Native Win32 child window + egui + independent D3D11 device.
//! We deliberately do NOT use winit here: its process-wide Raw Input
//! registration can conflict with Minecraft's input devices.

use std::{
    cell::RefCell, ffi::c_void, iter, mem, ptr,
    sync::{Arc, Mutex, atomic::{AtomicBool, AtomicIsize, Ordering}},
    thread::{self, JoinHandle}, time::{Duration, Instant},
};

use egui::{Context, Event, Key, Modifiers, MouseWheelUnit, PointerButton, Pos2, RawInput, TouchPhase, Vec2};
use windows::Win32::{
    Foundation::{HMODULE, HWND as ComHwnd},
    Graphics::{
        Direct3D::{D3D_DRIVER_TYPE_UNKNOWN, D3D_DRIVER_TYPE_WARP, D3D_FEATURE_LEVEL_11_0},
        Direct3D11::*,
        Dxgi::{Common::*, *},
    },
};
use windows_sys::Win32::{
    Foundation::*,
    System::{
        DataExchange::{CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData},
        LibraryLoader::GetModuleHandleW,
        Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock},
        Threading::GetCurrentProcessId,
    },
    UI::{
        Input::KeyboardAndMouse::{GetAsyncKeyState, GetKeyState},
        WindowsAndMessaging::*,
    },
};

use crate::{ui::Workbench, info, warn, error};
use windows_sys::Win32::Graphics::Gdi::ValidateRect;
#[link(name="user32")]
unsafe extern "system" {
    fn SetCapture(hwnd:HWND)->HWND;
    fn ReleaseCapture()->i32;
}


fn missing_resource() -> windows::core::Error {
    windows::core::Error::from(windows::core::HRESULT(0x80004005_u32 as i32))
}

const CF_UNICODETEXT: u32 = 13;

const WINDOW_CLASS: &[u16] = &[
    66, 76, 111, 97, 100, 101, 114, 68, 101, 118, 84, 111, 111, 108, 115, 67, 104, 105, 108, 100, 0,
];
const WINDOW_TITLE: &[u16] = &[
    66, 76, 111, 97, 100, 101, 114, 32, 68, 101, 118, 84, 111, 111, 108, 115, 0,
];

struct Worker {
    running: Arc<AtomicBool>,
    hwnd: Arc<AtomicIsize>,
    thread: JoinHandle<()>,
}
static WORKER: Mutex<Option<Worker>> = Mutex::new(None);
static UI_HWND: AtomicIsize = AtomicIsize::new(0);
static GAME_HWND: AtomicIsize = AtomicIsize::new(0);
pub(crate) fn ui_hwnd() -> isize { UI_HWND.load(Ordering::Acquire) }
pub(crate) fn game_hwnd() -> isize { resolve_game_hwnd() }

#[derive(Default)]
struct InputQueue {
    events: Vec<Event>,
    mouse: Pos2,
    dirty: bool,
    visible: bool,
}

thread_local! {
    static INPUT: RefCell<InputQueue> = RefCell::new(InputQueue {
        visible: true, dirty: true, ..Default::default()
    });
}

fn mark_dirty(event: Option<Event>) {
    INPUT.with(|cell| {
        let mut input = cell.borrow_mut();
        if let Some(event) = event { input.events.push(event); }
        input.dirty = true;
    });
}

fn modifiers() -> Modifiers {
    let pressed = |vk| unsafe { (GetKeyState(vk) as u16 & 0x8000) != 0 };
    Modifiers {
        alt: pressed(0x12),
        ctrl: pressed(0x11),
        shift: pressed(0x10),
        mac_cmd: false,
        command: pressed(0x11),
    }
}

fn pointer(lparam: LPARAM) -> Pos2 {
    Pos2::new(
        (lparam as u16 as i16) as f32,
        ((lparam >> 16) as u16 as i16) as f32,
    )
}

fn translate_key(vkey: u32) -> Option<Key> {
    let name = match vkey {
        0x08 => "Backspace", 0x09 => "Tab", 0x0D => "Enter",
        0x1B => "Escape", 0x20 => "Space", 0x21 => "PageUp", 0x22 => "PageDown",
        0x23 => "End", 0x24 => "Home", 0x25 => "ArrowLeft", 0x26 => "ArrowUp",
        0x27 => "ArrowRight", 0x28 => "ArrowDown", 0x2D => "Insert", 0x2E => "Delete",
        _ => "",
    };
    if !name.is_empty() { return Key::from_name(name); }
    if (0x30..=0x39).contains(&vkey) || (0x41..=0x5A).contains(&vkey) {
        return char::from_u32(vkey).and_then(|ch| Key::from_name(&ch.to_string()));
    }
    None
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_ERASEBKGND => return 1,
        WM_PAINT => {
            unsafe { ValidateRect(hwnd, ptr::null()); }
            mark_dirty(None);
            return 0;
        }
        WM_CLOSE => {
            unsafe { ShowWindow(hwnd, SW_HIDE); }
            INPUT.with(|cell| cell.borrow_mut().visible = false);
            return 0;
        }
        WM_DESTROY => {
            // Destroy/recreate a HWND during fallback without quitting the UI thread.
            return 0;
        }
        WM_SETFOCUS => mark_dirty(Some(Event::WindowFocused(true))),
        WM_KILLFOCUS => mark_dirty(Some(Event::WindowFocused(false))),
        WM_SIZE => mark_dirty(None),
        WM_CAPTURECHANGED => {
            // OS revoked mouse capture while a selection was in progress.
            // Do not retain a stale egui dragging pointer.
            mark_dirty(Some(Event::PointerGone));
        }
        WM_MOUSEMOVE => {
            let pos = pointer(lp);
            INPUT.with(|cell| cell.borrow_mut().mouse = pos);
            mark_dirty(Some(Event::PointerMoved(pos)));
        }
        WM_MOUSEWHEEL => {
            let clicks = ((wp >> 16) as u16 as i16) as f32 / 120.0;
            mark_dirty(Some(Event::MouseWheel {
                unit: MouseWheelUnit::Line,
                delta: Vec2::new(0.0, clicks * 3.0),
                phase: TouchPhase::Move,
                modifiers: modifiers(),
            }));
        }
        WM_LBUTTONDOWN | WM_LBUTTONUP | WM_RBUTTONDOWN | WM_RBUTTONUP => {
            let pressed = msg == WM_LBUTTONDOWN || msg == WM_RBUTTONDOWN;
            if msg==WM_LBUTTONDOWN {
                // Capture only mouse drag in this DevTools window. Without it,
                // Win32 stops dispatching WM_MOUSEMOVE past the client edge and
                // egui cannot extend selection/auto-scroll the console.
                unsafe{SetCapture(hwnd);}
            }
            let pos = pointer(lp);
            mark_dirty(Some(Event::PointerButton {
                pos,
                button: if msg == WM_LBUTTONDOWN || msg == WM_LBUTTONUP {
                    PointerButton::Primary
                } else { PointerButton::Secondary },
                pressed,
                modifiers: modifiers(),
            }));
            if msg==WM_LBUTTONUP {
                unsafe{ReleaseCapture();}
            }
        }
        WM_KEYDOWN | WM_SYSKEYDOWN | WM_KEYUP | WM_SYSKEYUP => {
            let pressed = msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN;
            let key_mods = modifiers();
            let key = wp as u32;
            if pressed && key_mods.ctrl {
                match key {
                    0x43 => mark_dirty(Some(Event::Copy)),
                    0x58 => mark_dirty(Some(Event::Cut)),
                    0x56 => {
                        if let Some(value) = clipboard_read() {
                            mark_dirty(Some(Event::Paste(value)));
                        }
                    }
                    _ => {}
                }
            }
            if let Some(key) = translate_key(key) {
                mark_dirty(Some(Event::Key {
                    key, physical_key: None, pressed,
                    repeat: ((lp >> 30) & 1) != 0,
                    modifiers: key_mods,
                }));
            }
        }
        WM_CHAR => {
            if let Some(ch) = char::from_u32(wp as u32) {
                if !ch.is_control() {
                    mark_dirty(Some(Event::Text(ch.to_string())));
                }
            }
        }
        _ => {}
    }
    unsafe { DefWindowProcW(hwnd, msg, wp, lp) }
}

fn clipboard_write(owner: isize, value: &str) {
    let wide: Vec<u16> = value.encode_utf16().chain(iter::once(0)).collect();
    unsafe {
        if OpenClipboard(owner as HWND) == 0 { return; }
        if EmptyClipboard() != 0 {
            let handle = GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2);
            if !handle.is_null() {
                let dest = GlobalLock(handle);
                if !dest.is_null() {
                    ptr::copy_nonoverlapping(wide.as_ptr(), dest as *mut u16, wide.len());
                    GlobalUnlock(handle);
                    if SetClipboardData(CF_UNICODETEXT, handle).is_null() {
                        GlobalFree(handle);
                    }
                } else { GlobalFree(handle); }
            }
        }
        CloseClipboard();
    }
}

fn clipboard_read() -> Option<String> {
    unsafe {
        if OpenClipboard(ptr::null_mut()) == 0 { return None; }
        let mut result = None;
        let handle = GetClipboardData(CF_UNICODETEXT);
        if !handle.is_null() {
            let data = GlobalLock(handle);
            if !data.is_null() {
                let capacity = GlobalSize(handle) / 2;
                let units = std::slice::from_raw_parts(data as *const u16, capacity);
                let length = units.iter().position(|unit| *unit == 0).unwrap_or(capacity);
                result = Some(String::from_utf16_lossy(&units[..length]));
                GlobalUnlock(handle);
            }
        }
        CloseClipboard();
        result
    }
}

#[derive(Default)]
struct WindowSearch {
    own_pid: u32,
    hwnd: isize,
    selected_pid: u32,
    score: u32,
    area: i64,
}
fn win_text(hwnd: HWND, class: bool) -> String {
    let mut text = [0u16; 260];
    let count = if class {
        unsafe { GetClassNameW(hwnd, text.as_mut_ptr(), text.len() as i32) }
    } else {
        unsafe { GetWindowTextW(hwnd, text.as_mut_ptr(), text.len() as i32) }
    };
    String::from_utf16_lossy(&text[..count.max(0) as usize])
}
unsafe extern "system" fn enum_window(hwnd: HWND, user: LPARAM) -> i32 {
    let state = unsafe { &mut *(user as *mut WindowSearch) };
    if unsafe { IsWindowVisible(hwnd) } == 0 { return 1; }
    let cls = win_text(hwnd, true);
    let title = win_text(hwnd, false);
    let lower_title = title.to_ascii_lowercase();
    // Never resolve our own UI or another arbitrary top-level window as "game".
    // Bedrock HWNDs can belong to a different PID in UWP/window-host scenarios.
    let is_bedrock = cls.eq_ignore_ascii_case("Bedrock");
    let is_uwp_host = cls.eq_ignore_ascii_case("ApplicationFrameWindow");
    if !lower_title.contains("minecraft") || !(is_bedrock || is_uwp_host) {
        return 1;
    }
    let mut pid = 0;
    unsafe { GetWindowThreadProcessId(hwnd, &mut pid); }
    let mut rect: RECT = unsafe { mem::zeroed() };
    if unsafe { GetClientRect(hwnd, &mut rect) } == 0 { return 1; }
    let w = (rect.right - rect.left) as i64;
    let h = (rect.bottom - rect.top) as i64;
    if w <= 0 || h <= 0 { return 1; }
    let area = w.saturating_mul(h);
    let score = (if is_bedrock { 100 } else { 50 }) +
        (if pid == state.own_pid { 20 } else { 0 });
    if score > state.score || (score == state.score && area > state.area) {
        state.hwnd = hwnd as isize;
        state.selected_pid = pid;
        state.score = score;
        state.area = area;
    }
    1
}
fn find_game_window() -> Option<(isize, u32)> {
    let mut info = WindowSearch {
        own_pid: unsafe { GetCurrentProcessId() },
        ..WindowSearch::default()
    };
    unsafe { EnumWindows(Some(enum_window), &mut info as *mut WindowSearch as isize); }
    (info.hwnd != 0).then_some((info.hwnd, info.selected_pid))
}

/// MCP clients request this on-demand. Win32 HWND lifetime is independent
/// from the DevTools DLL, so a one-time startup cache is never authoritative.
pub(crate) fn resolve_game_hwnd() -> isize {
    let result = find_game_window();
    let hwnd = result.map_or(0, |item| item.0);
    let previous = GAME_HWND.swap(hwnd, Ordering::AcqRel);
    if hwnd != previous {
        if let Some((handle,pid)) = result {
            info(format!("[BLoader DevTools] GAME_HWND_RESOLVED hwnd=0x{handle:X} pid={pid} class=Bedrock/ApplicationFrameWindow"));
        } else if previous != 0 {
            warn("[BLoader DevTools] GAME_HWND_INVALIDATED; waiting for game window to reappear");
        }
    }
    hwnd
}

pub fn start() -> Result<(), ()> {
    let mut worker = WORKER.lock().map_err(|_| ())?;
    if worker.is_some() { return Ok(()); }
    let running = Arc::new(AtomicBool::new(true));
    let hwnd = Arc::new(AtomicIsize::new(0));
    let thread_running = Arc::clone(&running);
    let thread_hwnd = Arc::clone(&hwnd);
    let handle = thread::Builder::new().name("bloader-devtools-ui".into())
        .spawn(move || {
            if let Err(err) = run(thread_running, thread_hwnd) {
                error(format!("[BLoader DevTools] UI_THREAD_FAILED: {err}"));
            } else {
                info("[BLoader DevTools] UI thread finished");
            }
        }).map_err(|_| ())?;
    *worker = Some(Worker { running, hwnd, thread: handle });
    Ok(())
}
pub fn stop() {
    let worker = WORKER.lock().ok().and_then(|mut slot| slot.take());
    if let Some(worker) = worker {
        worker.running.store(false, Ordering::Release);
        let hwnd = worker.hwnd.load(Ordering::Acquire);
        if hwnd != 0 {
            unsafe { PostMessageW(hwnd as HWND, WM_NULL, 0, 0); }
        }
        let _ = worker.thread.join();
    }
}

struct Graphics {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    chain: IDXGISwapChain,
    target: Option<ID3D11RenderTargetView>,
    renderer: egui_directx11::Renderer,
    size: (u32, u32),
}
impl Graphics {
    fn new(hwnd: isize, width: u32, height: u32) -> windows::core::Result<Self> {
        let factory: IDXGIFactory = unsafe { CreateDXGIFactory() }?;
        let adapter: IDXGIAdapter = unsafe { factory.EnumAdapters(0) }?;
        let mut device = None;
        let mut context = None;
        let device_result = unsafe {
            D3D11CreateDevice(
                &adapter, D3D_DRIVER_TYPE_UNKNOWN, HMODULE(ptr::null_mut()),
                D3D11_CREATE_DEVICE_FLAG(0), Some(&[D3D_FEATURE_LEVEL_11_0]),
                D3D11_SDK_VERSION, Some(&mut device), None, Some(&mut context)
            )
        };
        if let Err(err) = device_result {
            warn(format!("[BLoader DevTools] D3D11 hardware adapter initialization failed: {err}; trying WARP software device"));
            device = None;
            context = None;
            unsafe {
                D3D11CreateDevice(
                    None::<&IDXGIAdapter>, D3D_DRIVER_TYPE_WARP, HMODULE(ptr::null_mut()),
                    D3D11_CREATE_DEVICE_FLAG(0), Some(&[D3D_FEATURE_LEVEL_11_0]),
                    D3D11_SDK_VERSION, Some(&mut device), None, Some(&mut context)
                )
            }?;
            warn("[BLoader DevTools] D3D11_WARP_FALLBACK enabled (remote GPU/device may be unavailable)");
        }
        let device = device.ok_or_else(missing_resource)?;
        let context = context.ok_or_else(missing_resource)?;
        let desc = DXGI_SWAP_CHAIN_DESC {
            BufferDesc: DXGI_MODE_DESC {
                Width: width.max(1), Height: height.max(1),
                Format: DXGI_FORMAT_R8G8B8A8_UNORM, ..Default::default()
            },
            SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
            BufferCount: 2,
            OutputWindow: ComHwnd(hwnd as *mut c_void),
            Windowed: true.into(),
            SwapEffect: DXGI_SWAP_EFFECT_DISCARD,
            Flags: 0,
        };
        let mut chain = None;
        unsafe { factory.CreateSwapChain(&device, &desc, &mut chain) }.ok()?;
        let chain = chain.ok_or_else(missing_resource)?;
        let target = Some(Self::create_target(&device, &chain)?);
        let renderer = egui_directx11::Renderer::new(&device)?;
        Ok(Self { device, context, chain, target, renderer, size: (width, height) })
    }
    fn create_target(
        device: &ID3D11Device, chain: &IDXGISwapChain,
    ) -> windows::core::Result<ID3D11RenderTargetView> {
        let buffer = unsafe { chain.GetBuffer::<ID3D11Texture2D>(0) }?;
        let mut view = None;
        unsafe { device.CreateRenderTargetView(&buffer, None, Some(&mut view)) }?;
        view.ok_or_else(missing_resource)
    }
    fn resize(&mut self, width: u32, height: u32) -> windows::core::Result<()> {
        if width == 0 || height == 0 || self.size == (width, height) { return Ok(()); }
        self.target = None;
        unsafe { self.context.ClearState(); }
        unsafe {
            self.chain.ResizeBuffers(
                2, width, height, DXGI_FORMAT_R8G8B8A8_UNORM, DXGI_SWAP_CHAIN_FLAG(0)
            )
        }?;
        self.target = Some(Self::create_target(&self.device, &self.chain)?);
        self.size = (width, height);
        Ok(())
    }
    fn capture_png(&mut self) -> Result<Vec<u8>, String> {
        // Capture ONLY on explicit MCP request, before Present; no idle GPU readback.
        let source = unsafe { self.chain.GetBuffer::<ID3D11Texture2D>(0) }
            .map_err(|err| err.to_string())?;
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { source.GetDesc(&mut desc); }
        if desc.Width == 0 || desc.Height == 0 ||
            (desc.Width as u64) * (desc.Height as u64) > 1920*1080 {
            return Err("UI backbuffer 超出截图尺寸上限".into());
        }
        desc.Usage = D3D11_USAGE_STAGING;
        desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
        desc.BindFlags = 0;
        desc.MiscFlags = 0;
        let mut staging = None;
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut staging)) }
            .map_err(|err| err.to_string())?;
        let staging = staging.ok_or("CreateTexture2D staging 失败")?;
        unsafe { self.context.CopyResource(&staging, &source); }
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        unsafe { self.context.Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped)) }
            .map_err(|err| err.to_string())?;
        let mut rgba=vec![0u8; (desc.Width as usize)*(desc.Height as usize)*4];
        unsafe {
            let ptr = mapped.pData as *const u8;
            for row in 0..desc.Height as usize {
                std::ptr::copy_nonoverlapping(
                    ptr.add(row * mapped.RowPitch as usize),
                    rgba.as_mut_ptr().add(row * desc.Width as usize * 4),
                    desc.Width as usize * 4,
                );
            }
            self.context.Unmap(&staging, 0);
        }
        let mut png_bytes=Vec::new();
        {
            let mut encoder=png::Encoder::new(&mut png_bytes, desc.Width, desc.Height);
            encoder.set_color(png::ColorType::Rgba);
            encoder.set_depth(png::BitDepth::Eight);
            let mut writer=encoder.write_header().map_err(|err|err.to_string())?;
            writer.write_image_data(&rgba).map_err(|err|err.to_string())?;
        }
        Ok(png_bytes)
    }

    fn render(
        &mut self, ctx: &Context, output: egui_directx11::RendererOutput,
        screenshot: bool,
    ) -> windows::core::Result<Option<Result<Vec<u8>,String>>> {
        let Some(view) = self.target.as_ref() else { return Ok(None); };
        unsafe { self.context.ClearRenderTargetView(view, &[0.075,0.083,0.105,1.0]); }
        self.renderer.render(&self.context, view, ctx, output)?;
        let capture = screenshot.then(|| self.capture_png());
        unsafe { self.chain.Present(1, DXGI_PRESENT(0)) }.ok()?;
        Ok(capture)
    }
}

fn run(running: Arc<AtomicBool>, window_slot: Arc<AtomicIsize>) -> Result<(), String> {
    info("[BLoader DevTools] UI_THREAD_STARTED; searching for Minecraft top-level HWND");
    let _ = resolve_game_hwnd();
    // Always create an independent top-level HWND. Parenting a D3D11 swapchain
    // window to Minecraft's RenderDragon/Bedrock HWND obscures the game client
    // and may deadlock on cross-thread Win32 window messages/focus changes.
    // The UI is still in this DLL/process; no external executable is used.
    let remote_session = unsafe { GetSystemMetrics(SM_REMOTESESSION) != 0 };
    let game_hint = find_game_window();
    if let Some((game,pid))=game_hint {
        info(format!("[BLoader DevTools] GAME_HWND_FOUND hwnd=0x{game:X} pid={pid} (placement hint only; never a parent)"));
    }
    if remote_session {
        info("[BLoader DevTools] REMOTE_SESSION_DETECTED; independent top-level UI is retained");
    }
    let instance = unsafe { GetModuleHandleW(ptr::null()) };
    let class = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(wndproc),
        hInstance: instance,
        lpszClassName: WINDOW_CLASS.as_ptr(),
        ..unsafe { mem::zeroed() }
    };
    if unsafe { RegisterClassW(&class) } == 0 {
        return Err(format!("RegisterClassW failed: win32_error={}",unsafe { GetLastError() }));
    }
    info("[BLoader DevTools] Win32 class registered");
    const PANEL_W:i32=1040;
    const PANEL_H:i32=720;
    // Prefer unused desktop space beside the game. A normal framed window
    // remains movable/minimizable and does not swallow game input underneath.
    let desktop_w=unsafe { GetSystemMetrics(SM_CXSCREEN) };
    let desktop_h=unsafe { GetSystemMetrics(SM_CYSCREEN) };
    let mut position=(CW_USEDEFAULT,CW_USEDEFAULT);
    if let Some((game,_))=game_hint {
        let mut rect:RECT=unsafe{mem::zeroed()};
        if unsafe{GetWindowRect(game as HWND,&mut rect)}!=0 {
            let right=rect.right.saturating_add(16);
            let left=rect.left.saturating_sub(PANEL_W+16);
            if right>=0 && right.saturating_add(PANEL_W)<=desktop_w {
                position=(right,rect.top.max(0));
            } else if left>=0 {
                position=(left,rect.top.max(0));
            } else {
                position=(32,(desktop_h-PANEL_H-72).max(32));
            }
        }
    }
    info(format!(
        "[BLoader DevTools] WINDOW_CREATING mode=standalone-top-level parent=none size={PANEL_W}x{PANEL_H} pos={},{}",
        position.0,position.1
    ));
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_APPWINDOW,WINDOW_CLASS.as_ptr(),WINDOW_TITLE.as_ptr(),
            WS_OVERLAPPEDWINDOW,position.0,position.1,PANEL_W,PANEL_H,
            ptr::null_mut(),ptr::null_mut(),instance,ptr::null()
        )
    };
    if hwnd.is_null() {
        unsafe { UnregisterClassW(WINDOW_CLASS.as_ptr(),instance); }
        return Err(format!("CreateWindowExW top-level failed: win32_error={}",unsafe { GetLastError() }));
    }
    window_slot.store(hwnd as isize,Ordering::Release);
    UI_HWND.store(hwnd as isize,Ordering::Release);
    info(format!("[BLoader DevTools] UI_WINDOW_CREATED mode=standalone-top-level hwnd=0x{:X}",hwnd as usize));
    // Showing without activation leaves Minecraft in control until the user
    // explicitly clicks the independent DevTools window.
    unsafe { ShowWindow(hwnd,SW_SHOWNOACTIVATE); }
    let visible=unsafe{IsWindowVisible(hwnd)}!=0;
    info(format!("[BLoader DevTools] UI_WINDOW_SHOW_REQUEST visible={visible} activation=none; can be moved/minimized independently"));
    let mut gfx = match Graphics::new(hwnd as isize,PANEL_W as u32,PANEL_H as u32){
        Ok(gfx)=>gfx,
        Err(err)=>{
            unsafe{DestroyWindow(hwnd);UnregisterClassW(WINDOW_CLASS.as_ptr(),instance);}
            window_slot.store(0,Ordering::Release);
            UI_HWND.store(0,Ordering::Release);
            return Err(format!("D3D11 initialization failed: {err}"));
        }
    };
    info("[BLoader DevTools] UI_MODE_READY mode=standalone-top-level");
    info("[BLoader DevTools] D3D11_DEVICE_READY; initializing egui frame");
    let ctx = Context::default();
    crate::ui::configure_appearance(&ctx, true);
    match crate::ui::install_system_fonts(&ctx) {
        Ok(path) => info(format!("[BLoader DevTools] SYSTEM_CJK_FONT_LOADED: {path}")),
        Err(err) => warn(format!("[BLoader DevTools] CHINESE_FONT_UNAVAILABLE: {err}")),
    }
    let mut first_frame_logged = false;
    let mut workbench = Workbench::default();
    let mut was_f8_down = false;
    let mut keep_running = true;
    while keep_running && running.load(Ordering::Acquire) &&
        unsafe { IsWindow(hwnd) != 0 } &&
        {
        let mut msg: MSG = unsafe { mem::zeroed() };
        while unsafe { PeekMessageW(&mut msg, ptr::null_mut(), 0, 0, PM_REMOVE) } != 0 {
            if msg.message == WM_QUIT {
                keep_running = false;
                break;
            }
            unsafe { TranslateMessage(&msg); DispatchMessageW(&msg); }
        }
        if !keep_running { break; }

        let f8_down = (unsafe { GetAsyncKeyState(0x77) } as u16 & 0x8000) != 0;
        let foreground = unsafe { GetForegroundWindow() };
        if f8_down && !was_f8_down &&
            (foreground == hwnd || game_hint.is_some_and(|(game,_)|foreground==game as HWND)) {
            let visible = INPUT.with(|cell| {
                let mut input = cell.borrow_mut();
                input.visible = !input.visible;
                input.dirty = input.visible;
                input.visible
            });
            unsafe { ShowWindow(hwnd, if visible { SW_SHOW } else { SW_HIDE }); }
        }
        was_f8_down = f8_down;

        let mut pending_captures = Vec::new();
        for command in crate::mcp::drain_ui_commands() {
            match command {
                crate::mcp::UiCommand::Capture(reply) => {
                    pending_captures.push(reply);
                    mark_dirty(None);
                }
                crate::mcp::UiCommand::QueryState(reply)=>{
                    let _=reply.send(workbench.status_summary());
                }
                crate::mcp::UiCommand::Navigate(tool,reply)=>{
                    let result=workbench.navigate(&tool);
                    let _=reply.send(result);
                    mark_dirty(None);
                }
                crate::mcp::UiCommand::CollisionScan(profile,budget,reply)=>{
                    let result=workbench.scan_collision_for_ai(profile,budget);
                    let _=reply.send(result);
                    mark_dirty(None);
                }
                crate::mcp::UiCommand::CollisionRefine(motion,reply)=>{
                    let result=workbench.refine_collision_for_ai(motion);
                    let _=reply.send(result);
                    mark_dirty(None);
                }
                crate::mcp::UiCommand::CollisionResults(limit,reply)=>{
                    let result=workbench.collision_results_for_ai(limit);
                    let _=reply.send(result);
                }
                crate::mcp::UiCommand::PlayerDiscover(options,reply)=>{
                    let result=workbench.discover_player_for_ai(
                        options.profile,options.budget_mib,options.source_instance);
                    let _=reply.send(result);
                    mark_dirty(None);
                }
                crate::mcp::UiCommand::PlayerReport(reply)=>{
                    let result=workbench.discovery_status_for_ai();
                    let _=reply.send(result);
                }
                crate::mcp::UiCommand::Lifecycle(action,reply)=>{
                    // Mutating actions run through Engine worker, not this UI
                    // thread. Direct read-only status is handled in MCP.
                    let result=match action{
                        crate::lifecycle::Action::Verify|
                        crate::lifecycle::Action::InspectInstance|
                        crate::lifecycle::Action::ValidatePlayer|
                        crate::lifecycle::Action::Stop=>{
                            workbench.submit_lifecycle_for_ai(action)
                        },
                        _=>Err("MCP 不能通过 UI 队列启用 Hook".into()),
                    };
                    let _=reply.send(result);
                    mark_dirty(None);
                }
                crate::mcp::UiCommand::PlayerRefine(motion,reply)=>{
                    let result=workbench.refine_discovered_for_ai(motion);
                    let _=reply.send(result);
                    mark_dirty(None);
                }
            }
        }

        if workbench.needs_poll() { mark_dirty(None); }
        let (visible, dirty, events) = INPUT.with(|cell| {
            let mut state = cell.borrow_mut();
            let dirty = mem::take(&mut state.dirty);
            (state.visible, dirty, mem::take(&mut state.events))
        });
        if visible && dirty {
            let mut rect: RECT = unsafe { mem::zeroed() };
            if unsafe { GetClientRect(hwnd, &mut rect) } != 0 {
                let width = (rect.right - rect.left).max(0) as u32;
                let height = (rect.bottom - rect.top).max(0) as u32;
                if width > 0 && height > 0 {
                    if gfx.resize(width, height).is_ok() {
                        let input = RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(
                                Pos2::ZERO, egui::vec2(width as f32, height as f32)
                            )),
                            events,
                            ..Default::default()
                        };
                        let output = ctx.run_ui(input, |ui| workbench.ui(ui));
                        let (draw, platform, _) = egui_directx11::split_output(output);
                        for command in platform.commands {
                            if let egui::OutputCommand::CopyText(value) = command {
                                clipboard_write(hwnd as isize, &value);
                            }
                        }
                        match gfx.render(&ctx, draw, !pending_captures.is_empty()) {
                            Ok(captured) => {
                                if !first_frame_logged {
                                    first_frame_logged = true;
                                    info("[BLoader DevTools] UI_PRESENT_READY: first D3D11 Present succeeded; standalone window visibility still requires OS compositor verification");
                                }
                                if let Some(result) = captured {
                                    for responder in pending_captures.drain(..) {
                                        let _ = responder.send(result.clone());
                                    }
                                }
                            }
                            Err(err) => {
                                error(format!("[BLoader DevTools] D3D11_PRESENT_FAILED: {err}"));
                                for responder in pending_captures.drain(..) {
                                    let _ = responder.send(Err(format!("D3D11 Present 失败: {err}")));
                                }
                                keep_running = false;
                            }
                        }
                        if workbench.hide_requested {
                            workbench.hide_requested = false;
                            INPUT.with(|cell| cell.borrow_mut().visible = false);
                            unsafe { ShowWindow(hwnd, SW_HIDE); }
                        }
                    }
                }
            }
        }
        for responder in pending_captures.drain(..) {
            let _ = responder.send(Err("UI 没有生成有效截图帧".into()));
        }
        let active_input=INPUT.with(|cell|cell.borrow().visible) && workbench.needs_poll();
        unsafe {
            MsgWaitForMultipleObjectsEx(
                0,ptr::null(),if active_input{16}else{80},QS_ALLINPUT,MWMO_INPUTAVAILABLE
            );
        }
    }
    info("[BLoader DevTools] UI_SHUTDOWN: releasing D3D11 resources");
    // Drop D3D resources before destroying the child HWND and unregistering its class.
    drop(gfx);
    window_slot.store(0, Ordering::Release);
    UI_HWND.store(0, Ordering::Release);
    GAME_HWND.store(0, Ordering::Release);
    unsafe {
        if IsWindow(hwnd) != 0 { DestroyWindow(hwnd); }
        UnregisterClassW(WINDOW_CLASS.as_ptr(), instance);
    }
    Ok(())
}
