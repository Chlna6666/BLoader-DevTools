//! Best-effort game window capture: visible desktop compositing first and
//! PrintWindow fallback. This is not a RenderDragon GPU frame capture API.
//! The desktop path only runs when the selected game HWND is foreground,
//! preventing a screenshot of some unrelated application's pixels.
use std::{ffi::c_void,mem,ptr};
use windows_sys::Win32::{
    Foundation::{HWND,POINT},
    Graphics::Gdi::{
        BI_RGB,BITMAPINFO,BITMAPINFOHEADER,ClientToScreen,CreateCompatibleDC,
        CreateDIBSection,DeleteDC,DeleteObject,SelectObject,GetDC,ReleaseDC,
        BitBlt,StretchBlt,SRCCOPY,DIB_RGB_COLORS,
    },
    UI::WindowsAndMessaging::{GetForegroundWindow,IsIconic,IsWindowVisible},
};

#[link(name="user32")]
unsafe extern "system" {
    fn PrintWindow(hwnd:HWND, dc:*mut c_void, flags:u32)->i32;
}

/// Limit PNG transfer bandwidth and memory, without limiting window_info or click_window.
const MAX_CAPTURE_PIXELS:usize=2560*1440;
const MAX_CAPTURE_EDGE:u32=2560;

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Mode { Auto, Desktop, PrintWindow }
impl Mode {
    pub fn parse(s:Option<&str>)->Result<Self,String>{
        match s.unwrap_or("auto") {
            "auto"=>Ok(Self::Auto),"desktop"=>Ok(Self::Desktop),
            "printwindow"=>Ok(Self::PrintWindow),
            _=>Err("capture mode 仅支持 auto、desktop、printwindow".into())
        }
    }
}
pub struct Captured {
    pub png:Vec<u8>,
    pub width:u32,
    pub height:u32,
    pub method:&'static str,
}
pub fn constrained_size(width:u32,height:u32)->Result<(u32,u32),String>{
    if width==0 || height==0 || width>16384 || height>16384{
        return Err("目标窗口尺寸不可用".into());
    }
    let scale=((width as f64/MAX_CAPTURE_EDGE as f64)
        .max(height as f64/MAX_CAPTURE_EDGE as f64)
        .max(((width as f64*height as f64)/MAX_CAPTURE_PIXELS as f64).sqrt()))
        .max(1.0);
    let out_w=((width as f64/scale).floor() as u32).max(1);
    let out_h=((height as f64/scale).floor() as u32).max(1);
    Ok((out_w,out_h))
}
fn png_encode(mut bgra:Vec<u8>,w:u32,h:u32,mode:&'static str)->Result<Captured,String>{
    // Readbacks can be all-black if the game bypasses GDI. Report rather than
    // fabricate a successful RenderDragon screenshot.
    let nonblack=bgra.chunks_exact(4).any(|p|p[0]!=0||p[1]!=0||p[2]!=0);
    if !nonblack{return Err(format!("{mode} 画面全黑；可能正在加载或未能捕获 GPU 合成画面"));}
    for p in bgra.chunks_exact_mut(4){p.swap(0,2);p[3]=255;}
    let mut png=Vec::new();
    {
        let mut encoder=png::Encoder::new(&mut png,w,h);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer=encoder.write_header().map_err(|e|e.to_string())?;
        writer.write_image_data(&bgra).map_err(|e|e.to_string())?;
    }
    Ok(Captured{png,width:w,height:h,method:mode})
}
/// Owns a compatible memory DC and a 32-bit top-down bitmap. All GDI allocations
/// are cleaned up on success or failure.
fn capture_bitmap(hwnd:HWND,w:u32,h:u32,out_w:u32,out_h:u32,desktop:bool)->Result<Captured,String>{
    unsafe {
        let mem_dc=CreateCompatibleDC(ptr::null_mut());
        if mem_dc.is_null(){return Err("CreateCompatibleDC 失败".into());}
        let mut info:BITMAPINFO=mem::zeroed();
        info.bmiHeader.biSize=mem::size_of::<BITMAPINFOHEADER>() as u32;
        info.bmiHeader.biWidth=out_w as i32;
        info.bmiHeader.biHeight=-(out_h as i32);
        info.bmiHeader.biPlanes=1;
        info.bmiHeader.biBitCount=32;
        info.bmiHeader.biCompression=BI_RGB;
        let mut bits:*mut c_void=ptr::null_mut();
        let bitmap=CreateDIBSection(mem_dc,&info,DIB_RGB_COLORS,&mut bits,ptr::null_mut(),0);
        if bitmap.is_null(){
            DeleteDC(mem_dc);
            return Err("CreateDIBSection 失败".into());
        }
        let old=SelectObject(mem_dc,bitmap);
        let (ok,method)=if desktop{
            let mut origin=POINT{x:0,y:0};
            let converted=ClientToScreen(hwnd,&mut origin)!=0;
            let screen=GetDC(ptr::null_mut());
            let ok=if converted && !screen.is_null(){
                // Crops to the selected visible client's screen rect.
                // StretchBlt handles HiDPI / >2.5k windows without extra
                // full-resolution intermediate allocations.
                if out_w==w && out_h==h {
                    BitBlt(mem_dc,0,0,out_w as i32,out_h as i32,screen,
                        origin.x,origin.y,SRCCOPY)!=0
                }else{
                    StretchBlt(mem_dc,0,0,out_w as i32,out_h as i32,screen,
                        origin.x,origin.y,w as i32,h as i32,SRCCOPY)!=0
                }
            }else{false};
            if !screen.is_null(){ReleaseDC(ptr::null_mut(),screen);}
            (ok,"desktop")
        }else{
            (PrintWindow(hwnd,mem_dc,2)!=0,"printwindow")
        };
        let pixels=if ok && !bits.is_null(){
            std::slice::from_raw_parts(bits as *const u8,(out_w as usize)*(out_h as usize)*4).to_vec()
        }else{Vec::new()};
        SelectObject(mem_dc,old);
        DeleteObject(bitmap);
        DeleteDC(mem_dc);
        if pixels.is_empty(){return Err(format!("{method} 未能捕获窗口"));}
        png_encode(pixels,out_w,out_h,method)
    }
}
pub fn capture(hwnd:HWND,width:u32,height:u32,mode:Mode)->Result<Captured,String>{
    let (w,h)=constrained_size(width,height)?;
    let foreground=unsafe{GetForegroundWindow()==hwnd};
    let visible=unsafe{IsWindowVisible(hwnd)!=0 && IsIconic(hwnd)==0};
    if matches!(mode,Mode::Desktop) && (!foreground || !visible) {
        return Err("桌面截图模式需要 Minecraft 位于前台并且未最小化；防止误截取其他应用".into());
    }
    if matches!(mode,Mode::Auto|Mode::Desktop) && foreground && visible {
        match capture_bitmap(hwnd,width,height,w,h,true) {
            Ok(captured)=>return Ok(captured),
            Err(e) if mode==Mode::Desktop=>return Err(e),
            Err(_)=>{},
        }
    }
    if mode==Mode::Desktop{return Err("当前无法使用桌面截图模式".into());}
    if w!=width || h!=height {
        return Err("游戏窗口超过 PrintWindow 原生截图预算；请激活游戏后使用 desktop 模式进行自动缩放截图".into());
    }
    capture_bitmap(hwnd,width,height,w,h,false)
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn capture_scales_4k_without_restricting_window_info(){
        let (w,h)=constrained_size(3840,2160).unwrap();
        assert!(w<h*2 && w*h<=MAX_CAPTURE_PIXELS as u32);
        assert!(w<3840 && h<2160);
    }
    #[test]fn capture_mode_validation(){
        assert_eq!(Mode::parse(None).unwrap(),Mode::Auto);
        assert_eq!(Mode::parse(Some("desktop")).unwrap(),Mode::Desktop);
        assert!(Mode::parse(Some("evil")).is_err());
    }
}
