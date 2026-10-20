//! DevTools script DSL. Non-Turing-complete by design: no arbitrary Rust/OS code.
//! The interpreter shares the memory worker; never runs on the game/render thread.
use crate::memory::{Command, Filter, ValueKind, parse_address};

fn kind(s:&str)->Result<ValueKind,String> {
    match s.to_ascii_lowercase().as_str() {
        "u8"|"byte"=>Ok(ValueKind::U8),
        "u32"|"i32"=>Ok(ValueKind::U32),
        "u64"|"i64"=>Ok(ValueKind::U64),
        "f32"|"float"=>Ok(ValueKind::F32),
        "f64"|"double"=>Ok(ValueKind::F64),
        _=>Err(format!("未知数据类型：{s}"))
    }
}
fn filter(s:&str)->Result<Filter,String>{
    match s.to_ascii_lowercase().as_str(){
        "exact"=>Ok(Filter::Exact),"changed"=>Ok(Filter::Changed),
        "same"|"unchanged"=>Ok(Filter::Unchanged),
        "up"|"increased"=>Ok(Filter::Increased),
        "down"|"decreased"=>Ok(Filter::Decreased),
        _=>Err(format!("未知筛选条件：{s}"))
    }
}
/// At most 40 simple commands, no loops, no file IO and no arbitrary calls.
/// Write syntax always includes a compare-before-write expected old value.
pub fn parse(source:&str,allow_writes:bool)->Result<Vec<Command>,String>{
    let mut commands=Vec::new();
    for (line_index,line) in source.lines().enumerate(){
        let line=line.trim();
        if line.is_empty()||line.starts_with('#')||line.starts_with("//"){continue;}
        if commands.len()>=40{return Err("脚本最多允许 40 条命令".into());}
        let parts:Vec<&str>=line.split_ascii_whitespace().collect();
        let cmd=match parts.as_slice(){
            ["scan",t,value]=>Command::Scan(kind(t)?,(*value).to_owned()),
            ["next",f]=>Command::Refine(filter(f)?,"".into()),
            ["next","exact",value]=>Command::Refine(Filter::Exact,(*value).to_owned()),
            ["read",address,len]=>Command::Read(parse_address(address)?,len.parse().map_err(|_|"read 长度必须为整数")?),
            ["disasm",address,count]=>Command::Disassemble(parse_address(address)?,count.parse().map_err(|_|"disasm 条数必须为整数")?),
            ["aob",bytes @ ..] if !bytes.is_empty()=>Command::Aob(bytes.join(" ")),
            ["write",address,t,old,new]=>{
                if !allow_writes{return Err(format!("第 {} 行包含 write，但未显式允许脚本写入",line_index+1));}
                Command::Write{address:parse_address(address)?,kind:kind(t)?,old:(*old).into(),new:(*new).into()}
            }
            ["reset"]=>Command::Reset,
            _=>return Err(format!("第 {} 行无法识别命令：{line}",line_index+1)),
        };
        commands.push(cmd);
    }
    if commands.is_empty(){return Err("脚本为空".into());}
    Ok(commands)
}
pub const EXAMPLE:&str=r#"# BLoader DevTools 脚本示例
# 仅用于本机游戏内存开发测试
scan f32 90
next changed
# disasm 0x7FF600001000 24
# aob 48 8B ?? ?? 89
# write 0x7FF600001000 f32 90 65
"#;
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn script_rejects_writes_by_default(){
        assert!(parse("write 0x100000 f32 90 70",false).is_err());
        assert!(parse("write 0x100000 f32 90 70",true).is_ok());
    }
    #[test]fn script_parses(){assert_eq!(parse(EXAMPLE,false).unwrap().len(),2);}
}
