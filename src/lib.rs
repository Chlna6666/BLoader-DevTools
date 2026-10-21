#![cfg(windows)]
//! BLoader BL Mod v1 entrypoint. No work is performed in DllMain.
//! The BL host ABI prefix and BL mod descriptor mirror BLoader/bl-sdk at v0.2.77.

mod signature;
mod memory;
mod script;
mod project;
mod inspection;
mod local_player;
mod collision;
mod mcp;
mod capture;
mod ui;
mod window;

use std::ffi::{c_char, c_void};
use std::sync::OnceLock;

#[repr(C)]
#[derive(Clone, Copy)]
struct BlStringView {
    ptr: *const c_char,
    len: usize,
}
unsafe impl Sync for BlStringView {}
unsafe impl Send for BlStringView {}

#[repr(C)]
struct BlHostPrefix {
    api_version: u32,
    reserved: u32,
    log: Option<unsafe extern "system" fn(u32, BlStringView)>,
}

#[repr(C)]
struct BlModApiV1 {
    api_version: u32,
    mod_id: BlStringView,
    mod_name: BlStringView,
    on_load: Option<unsafe extern "system" fn(*const BlHostPrefix) -> i32>,
    on_unload: Option<unsafe extern "system" fn()>,
}
unsafe impl Sync for BlModApiV1 {}
unsafe impl Send for BlModApiV1 {}

static ID: &[u8] = b"bloader.devtools";
static NAME: &[u8] = b"BLoader DevTools";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = "Chlna6666";
const SOURCE_URL: &str = "https://github.com/Chlna6666/BLoader-DevTools";
const LICENSE: &str = "GPL-3.0-only";
type HostLogger = unsafe extern "system" fn(u32, BlStringView);
static HOST_LOGGER: OnceLock<HostLogger> = OnceLock::new();

pub(crate) fn log(level: u32, message: &str) {
    if let Some(logger) = HOST_LOGGER.get().copied() {
        let payload = BlStringView { ptr: message.as_ptr().cast(), len: message.len() };
        unsafe { logger(level, payload) };
    }
}

pub(crate) fn info(message: impl AsRef<str>) { log(1, message.as_ref()); }
pub(crate) fn warn(message: impl AsRef<str>) { log(2, message.as_ref()); }
pub(crate) fn error(message: impl AsRef<str>) { log(3, message.as_ref()); }


fn view(value: &'static [u8]) -> BlStringView {
    BlStringView { ptr: value.as_ptr().cast(), len: value.len() }
}

unsafe extern "system" fn on_load(host: *const BlHostPrefix) -> i32 {
    std::panic::catch_unwind(|| {
        let Some(host) = (unsafe { host.as_ref() }) else { return -1; };
        if host.api_version != 1 { return -2; }
        if let Some(logger) = host.log {
            let _ = HOST_LOGGER.set(logger);
        }
        info("==================================================");
        info(format!("[BLoader DevTools] v{VERSION} | Windows x64"));
        info(format!("[BLoader DevTools] Author: {AUTHORS}"));
        info(format!("[BLoader DevTools] License: {LICENSE} (open source)"));
        info(format!("[BLoader DevTools] Source: {SOURCE_URL}"));
        info("[BLoader DevTools] UI: in-process Win32 child + egui + D3D11");
        info("[BLoader DevTools] Hotkey: F8; no external executable");
        info("[BLoader DevTools] Load sequence: BL entry => UI worker => game HWND => D3D11 => first frame");
        info("==================================================");
        match window::start() {
            Ok(()) => {
                info("[BLoader DevTools] UI worker started; UI_READY will be logged after the first Present");
                0
            }
            Err(()) => {
                error("[BLoader DevTools] UI worker thread failed to start");
                -3
            }
        }
    }).unwrap_or_else(|_| {
        error("[BLoader DevTools] Panic in on_load");
        -4
    })
}

unsafe extern "system" fn on_unload() {
    info("[BLoader DevTools] Unloading: stopping MCP and UI worker...");
    mcp::stop();
    let _ = std::panic::catch_unwind(window::stop);
    info("[BLoader DevTools] UI worker stopped");
}

#[unsafe(no_mangle)]
pub extern "system" fn bl_mod_main_v1(_host: *const BlHostPrefix) -> *const c_void {
    // A stable C-compatible BL v1 descriptor; it is owned by this DLL.
    static API: std::sync::OnceLock<BlModApiV1> = std::sync::OnceLock::new();
    API.get_or_init(|| BlModApiV1 {
        api_version: 1,
        mod_id: view(ID),
        mod_name: view(NAME),
        on_load: Some(on_load),
        on_unload: Some(on_unload),
    }) as *const _ as *const c_void
}
