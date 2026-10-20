//! Client-only LocalPlayer discovery assistant.
//! The game-facing object layout is NOT stable. This module never calls an
//! unverified virtual function and never treats a plausible pointer as proof
//! that an object is a LocalPlayer. Results are version-scoped candidates.
use std::{fs::File,io::{BufReader,Read},path::PathBuf,sync::OnceLock};
use sha2::{Digest,Sha256};
use crate::memory::{parse_address,read};

pub const INDEX_REFERENCE_AOB:&str =
    "49 8B 00 49 8B C8 48 8B 80 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 48 85 C0 0F 84 ?? ?? ?? ?? 48 8B C8";

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum SourceKind { DirectInstance, PointerSlot }
impl SourceKind {
    pub fn label(self)->&'static str {
        match self{Self::DirectInstance=>"ClientInstance 直接地址",
            Self::PointerSlot=>"保存 ClientInstance* 的指针槽"}
    }
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub enum PlayerAccess { MemberOffset(usize), VtableIndex(usize) }
#[derive(Clone,Debug)]
pub struct Candidate {
    pub instance:usize,
    pub source:usize,
    pub source_kind:SourceKind,
    pub access:PlayerAccess,
    pub player:Option<usize>,
    pub vtable:usize,
    pub getter_entry:Option<usize>,
    pub notes:Vec<String>,
    pub build_id:String,
}
fn pointer_at(addr:usize)->Result<usize,String>{
    let bytes=read(addr,8)?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()) as usize)
}
fn checked_at(base:usize,offset:usize)->Result<usize,String>{
    base.checked_add(offset).ok_or("内存地址加法溢出".into())
}
fn aligned_pointer(value:usize)->bool {
    value>=0x10000 && (value&7)==0
}
fn plausible_object(ptr:usize)->Result<usize,String>{
    if !aligned_pointer(ptr){return Err(format!("候选 0x{ptr:X} 不是有效的 8 字节对齐用户对象地址"));}
    // A C++ polymorphic object normally starts with a vptr. This is
    // only a coarse memory safety check, NOT an identity proof.
    let vtable=pointer_at(ptr)?;
    if !aligned_pointer(vtable) {return Err(format!("对象 0x{ptr:X} 的 vptr 不可用"));}
    let method=pointer_at(vtable)?;
    if method<0x10000 || read(method,1).is_err() {
        return Err(format!("对象 0x{ptr:X} 的虚表首项不是可读代码地址"));
    }
    Ok(vtable)
}
pub fn probe(source:usize,kind:SourceKind,access:PlayerAccess)->Result<Candidate,String>{
    if !aligned_pointer(source){return Err("来源地址必须是已验证的 8 字节对齐地址".into());}
    let instance=match kind {
        SourceKind::DirectInstance=>source,
        SourceKind::PointerSlot=>pointer_at(source)?,
    };
    let vtable=plausible_object(instance)?;
    let mut notes=vec![
        format!("ClientInstance 候选=0x{instance:016X}, vtable=0x{vtable:016X}"),
        "虚表/指针可读只说明内存结构合理，不能证明这是 ClientInstance 或 LocalPlayer。".into(),
    ];
    let (player,getter_entry)=match access {
        PlayerAccess::MemberOffset(offset)=>{
            if offset>0x10000 || offset%8!=0 {
                return Err("成员偏移必须是 0–0x10000 范围内的 8 字节对齐整数；虚函数版本请改为虚表索引模式".into());
            }
            let slot=checked_at(instance,offset)?;
            let addr=pointer_at(slot)?;
            if addr==0 {
                notes.push("成员槽当前为 nullptr：可能未进入世界，也可能偏移不适用。".into());
                (None,None)
            }else{
                let player_vtable=plausible_object(addr)?;
                notes.push(format!("LocalPlayer 候选=0x{addr:016X}, vtable=0x{player_vtable:016X}"));
                notes.push("请先在世界内外分别验证非空/空值变化，再确认具体玩家类型；不要直接把该指针提供给其他 Mod。".into());
                (Some(addr),None)
            }
        }
        PlayerAccess::VtableIndex(index)=>{
            if index>1023 {return Err("虚表索引超过 1023，拒绝读取".into());}
            let entry=pointer_at(checked_at(vtable,index*8)?)?;
            if entry<0x10000 || read(entry,1).is_err() {
                return Err("虚表方法地址不可读；索引或 ClientInstance 候选可能不正确".into());
            }
            notes.push(format!("getLocalPlayer 虚表候选：index={index}，entry=0x{entry:016X}"));
            notes.push("此处只定位虚函数入口，没有执行。需在游戏线程经 ABI 验证后才能调用，故尚未取得 LocalPlayer 指针。".into());
            (None,Some(entry))
        }
    };
    Ok(Candidate{instance,source,source_kind:kind,access,player,vtable,getter_entry,
        notes,build_id:executable_build_id()?})
}
/// Reference signature describes an x64 MOV rax,[rax+disp32] at match+6,
/// with vtable slot displacement at match+9. This is version-sensitive.
pub fn decode_index_reference(bytes:&[u8])->Result<usize,String>{
    if bytes.len()<13 || bytes[..9]!=[0x49,0x8B,0x00,0x49,0x8B,0xC8,0x48,0x8B,0x80] {
        return Err("不是预期的 getLocalPlayerIndex 指令序列，不能提取虚表索引".into());
    }
    let displacement=i32::from_le_bytes(bytes[9..13].try_into().unwrap());
    if displacement<0 || displacement%8!=0{return Err("虚表位移不是非负且 8 字节对齐".into());}
    let index=displacement as usize/8;
    if index>1023{return Err("提取的虚表索引超出验证上限".into());}
    Ok(index)
}
pub fn get_index_at(match_address:usize)->Result<usize,String>{
    decode_index_reference(&read(match_address,13)?)
}
static BUILD_ID:OnceLock<Result<String,String>>=OnceLock::new();
pub fn executable_build_id()->Result<String,String>{
    BUILD_ID.get_or_init(|| {
        let path=std::env::current_exe().map_err(|e|e.to_string())?;
        hash_executable(path)
    }).clone()
}
fn hash_executable(path:PathBuf)->Result<String,String>{
    let source=File::open(&path).map_err(|e|format!("读取游戏主 EXE 失败：{e}"))?;
    let mut reader=BufReader::with_capacity(256*1024,source);
    let mut hasher=Sha256::new();
    let mut buffer=[0u8;65536];
    loop{
        let read_count=reader.read(&mut buffer).map_err(|e|e.to_string())?;
        if read_count==0 {break}
        hasher.update(&buffer[..read_count]);
    }
    Ok(format!("exe-sha256:{}",hex_digest(&hasher.finalize())))
}
fn hex_digest(bytes:&[u8])->String{
    bytes.iter().map(|b|format!("{b:02x}")).collect()
}
pub fn parse_offset(value:&str)->Result<usize,String>{
    let raw=value.trim();
    if raw.is_empty(){return Err("请输入成员偏移或虚表索引".into());}
    if raw.starts_with("0x") || raw.starts_with("0X"){
        parse_address(raw)
    }else{
        raw.parse::<usize>().map_err(|_|"请输入十进制整数或 0x 十六进制整数".into())
    }
}
pub fn format_candidate(candidate:&Candidate)->Vec<String>{
    let mut result=vec![
        format!("构建：{}",candidate.build_id),
        format!("来源：0x{:016X}，模式：{}",candidate.source,candidate.source_kind.label()),
    ];
    result.extend(candidate.notes.iter().cloned());
    result
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn decode_reference_index(){
        let sample=[0x49,0x8B,0x00,0x49,0x8B,0xC8,0x48,0x8B,0x80,0xC0,0x01,0x00,0x00];
        assert_eq!(decode_index_reference(&sample).unwrap(),56);
        let mut wrong=sample;
        wrong[9]=0xC1;
        assert!(decode_index_reference(&wrong).is_err());
    }
    #[test]fn offset_and_alignment(){
        assert_eq!(parse_offset("0x28").unwrap(),40);
        assert_eq!(parse_offset("56").unwrap(),56);
        assert!(!aligned_pointer(0x10003));
    }
    #[test]fn source_probe_with_owned_in_process_test_object(){
        let fake_code=source_probe_with_owned_in_process_test_object as usize;
        let vtable=Box::new([fake_code,fake_code]);
        let obj=Box::new([vtable.as_ptr() as usize,0usize]);
        let instance=obj.as_ptr() as usize;
        let result=probe(instance,SourceKind::DirectInstance,PlayerAccess::VtableIndex(1)).unwrap();
        assert_eq!(result.getter_entry,Some(fake_code));
        assert!(result.player.is_none());
    }
}
