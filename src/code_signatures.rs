//! PE .text-only experimental signatures. Reference: b01dev/MCBE_DX12_ModBase,
//! src/minecraft/bedrock_memory.h (MIT, Copyright 2026 Binary01).
//! Candidates are NOT verified code addresses or calling conventions.
use std::{ffi::c_void,mem,sync::atomic::{AtomicBool,Ordering}};
use windows_sys::Win32::System::Memory::{
    VirtualQuery,MEMORY_BASIC_INFORMATION,MEM_COMMIT,PAGE_GUARD,PAGE_NOACCESS,
    PAGE_EXECUTE,PAGE_EXECUTE_READ,PAGE_EXECUTE_READWRITE,PAGE_EXECUTE_WRITECOPY,
};
use crate::{memory,signature::Pattern};
const BLOCK:usize=64*1024;
const MAX_MATCHES:usize=32;
const UPDATE_AOB:&str=concat!(
    "55 41 57 41 56 41 55 41 54 56 57 53 48 81 EC ?? ?? ?? ?? ",
    "48 8D AC 24 ?? ?? ?? ?? 48 C7 85 ?? ?? ?? ?? FE FF FF FF ",
    "89 D3 48 89 CE 48 8B 01 48 8B 80 ?? ?? ?? ?? ",
    "48 8D 95 ?? ?? ?? ?? FF 15 ?? ?? ?? ??"
);
const GETTER_AOB:&str=concat!(
    "48 83 EC 48 48 8B 05 ?? ?? ?? ?? 48 31 E0 48 89 44 24 40 ",
    "48 8D 91 ?? ?? ?? ?? 48 8D 4C 24 20 E8 ?? ?? ?? ?? 80 7C 24 38 01"
);
#[derive(Debug,Clone,Default)]
pub struct Report{
    pub update:Vec<usize>,
    pub getter:Vec<usize>,
    pub scanned_bytes:usize,
    pub read_failures:usize,
    pub capped:bool,
}
fn section_text(image:&[u8],size:usize)->Result<(usize,usize),String>{
    if image.len()<0x40 || &image[..2]!=b"MZ"{return Err("主模块 DOS MZ 头无效".into());}
    let pe=u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
    if pe.checked_add(24).is_none_or(|e|e>image.len()) ||
        &image[pe..pe+4]!=b"PE\0\0"{
        return Err("PE/COFF 头不合法".into());
    }
    let sections=u16::from_le_bytes(image[pe+6..pe+8].try_into().unwrap()) as usize;
    let optional=u16::from_le_bytes(image[pe+20..pe+22].try_into().unwrap()) as usize;
    if !(1..=96).contains(&sections){return Err("PE 节表数量无效".into());}
    let table=pe.checked_add(24).and_then(|x|x.checked_add(optional)).ok_or("PE 节表溢出")?;
    if table.checked_add(sections*40).is_none_or(|e|e>image.len()){
        return Err("PE 节表超出读取范围".into());
    }
    for n in 0..sections{
        let i=table+n*40;
        if &image[i..i+8]==b".text\0\0\0"{
            let virtual_size=u32::from_le_bytes(image[i+8..i+12].try_into().unwrap()) as usize;
            let rva=u32::from_le_bytes(image[i+12..i+16].try_into().unwrap()) as usize;
            let raw_size=u32::from_le_bytes(image[i+16..i+20].try_into().unwrap()) as usize;
            let bytes=virtual_size.max(raw_size);
            if bytes==0 || rva>=size || bytes>size-rva{
                return Err(".text RVA/大小超出模块映像".into());
            }
            return Ok((rva,bytes));
        }
    }
    Err("找不到主模块 .text 节".into())
}
struct Compiled{
    pattern:Pattern,
    anchor_start:usize,
    anchor:Vec<u8>,
}
impl Compiled{
    fn parse(src:&str)->Result<Self,String>{
        let pattern=Pattern::parse(src).map_err(str::to_owned)?;
        let mut best=(0usize,0usize);
        let mut i=0;
        while i<pattern.0.len(){
            if pattern.0[i].is_none(){i+=1;continue;}
            let mut j=i+1;
            while j<pattern.0.len() && pattern.0[j].is_some(){j+=1;}
            if j-i>best.1{best=(i,j-i);}
            i=j;
        }
        if best.1<6{return Err("固定指令锚点不足 6 字节".into());}
        let anchor=pattern.0[best.0..best.0+best.1]
            .iter().map(|b|b.unwrap()).collect();
        Ok(Self{pattern,anchor_start:best.0,anchor})
    }
    fn scan(&self,base:usize,bytes:&[u8],out:&mut Vec<usize>)->bool{
        let plen=self.pattern.0.len();
        if bytes.len()<plen{return false;}
        let mut offset=0;
        while offset+plen<=bytes.len(){
            let Some(pos)=bytes[offset+self.anchor_start..]
                .iter().position(|b|*b==self.anchor[0])else{break;};
            let at=offset+pos;
            if at+plen>bytes.len(){break;}
            if bytes[at+self.anchor_start..at+self.anchor_start+self.anchor.len()]
                ==*self.anchor &&
                self.pattern.0.iter().zip(&bytes[at..at+plen])
                .all(|(want,b)|want.is_none_or(|x|x==*b)){
                let address=base+at;
                if !out.contains(&address){
                    if out.len()==MAX_MATCHES{return true;}
                    out.push(address);
                }
            }
            offset=at+1;
        }
        false
    }
}
pub fn scan(base:usize,image_size:usize,cancel:&AtomicBool)->Result<Report,String>{
    let header=memory::read(base,4096)?;
    let (rva,size)=section_text(&header,image_size)?;
    let lo=base.checked_add(rva).ok_or("PE .text 起点溢出")?;
    let end=lo.checked_add(size).ok_or("PE .text 终点溢出")?;
    let update=Compiled::parse(UPDATE_AOB)?;
    let getter=Compiled::parse(GETTER_AOB)?;
    let overlap=update.pattern.0.len().max(getter.pattern.0.len())-1;
    let mut result=Report::default();
    let mut block=vec![0u8;BLOCK];
    let mut joined=Vec::with_capacity(BLOCK+overlap);
    let mut tail=Vec::with_capacity(overlap);
    let mut previous=0usize;
    let mut at=lo;
    while at<end{
        if cancel.load(Ordering::Acquire){return Err("用户取消特征扫描".into());}
        let mut info:MEMORY_BASIC_INFORMATION=unsafe{mem::zeroed()};
        if unsafe{VirtualQuery(at as *const c_void,&mut info,
                mem::size_of::<MEMORY_BASIC_INFORMATION>())}==0{break;}
        let next=(info.BaseAddress as usize).saturating_add(info.RegionSize).min(end);
        if next<=at{break;}
        let executable=info.State==MEM_COMMIT &&
            info.Protect&(PAGE_GUARD|PAGE_NOACCESS)==0 &&
            matches!(info.Protect&0xff,PAGE_EXECUTE|PAGE_EXECUTE_READ|
                PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY);
        if !executable{tail.clear();previous=0;at=next;continue;}
        while at<next{
            if cancel.load(Ordering::Acquire){return Err("用户取消特征扫描".into());}
            let len=(next-at).min(BLOCK);
            if memory::read_into(at,&mut block[..len]).is_ok(){
                if previous!=at{tail.clear();}
                joined.clear();
                joined.extend_from_slice(&tail);
                joined.extend_from_slice(&block[..len]);
                let first=at-tail.len();
                result.capped|=update.scan(first,&joined,&mut result.update);
                result.capped|=getter.scan(first,&joined,&mut result.getter);
                let n=overlap.min(joined.len());
                tail.clear();tail.extend_from_slice(&joined[joined.len()-n..]);
                previous=at+len;
            }else{result.read_failures+=1;tail.clear();previous=0;}
            result.scanned_bytes+=len;
            at+=len;
        }
    }
    Ok(result)
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn parses_only_valid_pe_text(){
        let mut img=vec![0u8;4096];
        img[..2].copy_from_slice(b"MZ");
        img[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        img[0x80..0x84].copy_from_slice(b"PE\0\0");
        img[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        img[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        let s=0x80+24+0xF0;
        img[s..s+8].copy_from_slice(b".text\0\0\0");
        img[s+8..s+12].copy_from_slice(&0x6000u32.to_le_bytes());
        img[s+12..s+16].copy_from_slice(&0x1000u32.to_le_bytes());
        assert_eq!(section_text(&img,0x10000).unwrap(),(0x1000,0x6000));
        assert!(section_text(&img,0x2000).is_err());
    }
    #[test]fn anchor_and_wildcards_are_verified(){
        let compiled=Compiled::parse(GETTER_AOB).unwrap();
        let mut bytes=vec![0xCC;128];
        for (n,v) in compiled.pattern.0.iter().enumerate(){
            bytes[10+n]=v.unwrap_or(0x23);
        }
        let mut matches=Vec::new();
        compiled.scan(0x140000000,&bytes,&mut matches);
        assert_eq!(matches,vec![0x14000000A]);
        bytes[10+7]=0x31;
        matches.clear();compiled.scan(0x140000000,&bytes,&mut matches);
        assert_eq!(matches.len(),1);
        bytes[10]=0;
        matches.clear();compiled.scan(0x140000000,&bytes,&mut matches);
        assert!(matches.is_empty());
    }
}
