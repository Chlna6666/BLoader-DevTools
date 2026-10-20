#![cfg(windows)]
//! BLoader BL Mod v1 entrypoint. No work is performed in DllMain.
//! The BL host ABI prefix and BL mod descriptor mirror BLoader/bl-sdk at v0.2.77.

mod signature;
mod ui;
mod window;

use std::ffi::{c_char, c_void};

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

fn view(value: &'static [u8]) -> BlStringView {
    BlStringView { ptr: value.as_ptr().cast(), len: value.len() }
}

unsafe extern "system" fn on_load(host: *const BlHostPrefix) -> i32 {
    std::panic::catch_unwind(|| {
        let Some(host) = (unsafe { host.as_ref() }) else { return -1 };
        if host.api_version != 1 { return -2; }
        match window::start() {
            Ok(()) => {
                if let Some(log) = host.log {
                    let msg = b"DevTools loaded; press F8 to toggle in-game panel";
                    unsafe {
                        log(1, BlStringView { ptr: msg.as_ptr().cast(), len: msg.len() });
                    }
                }
                0
            }
            Err(()) => -3,
        }
    }).unwrap_or(-4)
}

unsafe extern "system" fn on_unload() {
    // Joining is necessary: DLL must not be unloaded while its UI thread executes code.
    let _ = std::panic::catch_unwind(window::stop);
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
