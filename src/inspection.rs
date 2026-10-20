//! Read-only module and code inspection. It does not depend on BLoader's SDK.
use std::mem;
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Module32FirstW, Module32NextW,
            MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32},
        Threading::GetCurrentProcessId,
    }
};
/// Return the image range of the game process main executable. The first
/// ToolHelp module entry is the process executable on Windows; do not guess
/// an ASLR base or search unrelated shared DLLs for a game-only reference.
pub fn main_image_range()->Result<(usize,usize),String>{
    let snap=unsafe {CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,GetCurrentProcessId())};
    if snap==INVALID_HANDLE_VALUE{return Err("主 EXE 模块枚举失败".into());}
    let mut entry:MODULEENTRY32W=unsafe{mem::zeroed()};
    entry.dwSize=mem::size_of::<MODULEENTRY32W>() as u32;
    let ok=unsafe{Module32FirstW(snap,&mut entry)};
    unsafe{CloseHandle(snap);}
    if ok==0 || entry.modBaseAddr.is_null() || entry.modBaseSize==0{
        return Err("无法确定 Minecraft EXE 映像范围".into());
    }
    let base=entry.modBaseAddr as usize;
    let size=entry.modBaseSize as usize;
    if base.checked_add(size).is_none(){return Err("游戏模块地址溢出".into());}
    Ok((base,size))
}
pub fn modules()->Vec<String>{
    let snap=unsafe{CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,
        GetCurrentProcessId())};
    if snap==INVALID_HANDLE_VALUE {return vec!["模块快照失败".into()];}
    let mut entry:MODULEENTRY32W=unsafe{mem::zeroed()};
    entry.dwSize=mem::size_of::<MODULEENTRY32W>() as u32;
    let mut lines=Vec::new();
    if unsafe{Module32FirstW(snap,&mut entry)}!=0 {
        loop {
            let len=entry.szModule.iter().position(|c|*c==0).unwrap_or(entry.szModule.len());
            let name=String::from_utf16_lossy(&entry.szModule[..len]);
            lines.push(format!("{:016X}  {:>7} KiB  {}",
                entry.modBaseAddr as usize,entry.modBaseSize/1024,name));
            if lines.len()>=512 || unsafe{Module32NextW(snap,&mut entry)}==0 {break;}
        }
    }
    unsafe{CloseHandle(snap);}
    lines
}
/// Classification is explicitly heuristic: many legitimate game functions
/// begin with jump thunks. No owner attribution is possible from a jump alone.
pub fn entry_hint(bytes:&[u8])->&'static str {
    if bytes.len()>=5 && bytes[0]==0xE9 {"相对 JMP 跳转；可能是编译器跳板或 Inline Hook"}
    else if bytes.len()>=6 && bytes[0]==0xFF && bytes[1]==0x25 {"间接 JMP；可能是导入跳板或 Hook"}
    else if bytes.len()>=1 && bytes[0]==0xCC {"INT3；可能是断点或填充字节"}
    else {"未发现常见入口跳转特征（不能证明没有 Hook）"}
}
#[cfg(test)]
mod tests{
 use super::*;
 #[test]fn detects_heuristics(){assert!(entry_hint(&[0xE9,0,0,0,0]).contains("JMP"));}
}
