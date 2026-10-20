//! Self-contained offline feature manifests and cross-build AOB validation.
use serde_json::{json,Value};
use std::{fs,path::PathBuf};
use crate::signature::Pattern;
const MAX_FILE:usize=160*1024*1024;
fn root()->Result<PathBuf,String>{
    let base=std::env::var_os("LOCALAPPDATA").ok_or("无法找到 LOCALAPPDATA")?;
    let folder=PathBuf::from(base).join("BLoader-DevTools");
    fs::create_dir_all(&folder).map_err(|e|e.to_string())?;
    Ok(folder)
}
pub fn save_script(source:&str)->Result<String,String>{
    if source.len()>64*1024{return Err("脚本超过 64 KiB 上限".into());}
    let target=root()?.join("workspace.bldscript");
    fs::write(&target,source).map_err(|e|e.to_string())?;
    Ok(target.display().to_string())
}
pub fn load_script()->Result<String,String>{
    fs::read_to_string(root()?.join("workspace.bldscript")).map_err(|e|e.to_string())
}
pub fn save_feature(name:&str,pattern:&str)->Result<String,String>{
    let rule=Pattern::parse(pattern).map_err(str::to_owned)?;
    if name.trim().len()>120||name.trim().is_empty(){return Err("请填写不超过 120 字的特征名称".into());}
    let payload=json!({
        "schema":1,
        "feature":name,
        "origin":"BLoader-DevTools",
        "aob":rule.canonical(),
        "validation":"unverified",
        "note":"静态候选，未包含 ABI/运行时兼容验证"
    });
    let path=root()?.join("features.json");
    let mut entries=if let Ok(raw)=fs::read_to_string(&path){
        serde_json::from_str::<Vec<Value>>(&raw).map_err(|e|format!("存量档案格式错误: {e}"))?
    }else{Vec::new()};
    if let Some(entry)=entries.iter_mut().find(|v|v["feature"]==name){*entry=payload;}
    else {entries.push(payload);}
    if entries.len()>2048{return Err("特征档案条目超过上限".into());}
    let tmp=root()?.join("features.json.tmp");
    fs::write(&tmp,serde_json::to_vec_pretty(&entries).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    fs::rename(&tmp,&path).map_err(|e|e.to_string())?;
    Ok(path.display().to_string())
}
pub fn features()->Result<Vec<(String,String)>,String>{
    let raw=fs::read_to_string(root()?.join("features.json")).unwrap_or_else(|_|"[]".into());
    let values:Vec<Value>=serde_json::from_str(&raw).map_err(|e|e.to_string())?;
    Ok(values.into_iter().filter_map(|v|
        Some((v.get("feature")?.as_str()?.to_owned(),v.get("aob")?.as_str()?.to_owned()))
    ).collect())
}
pub fn compare(old:&str,new:&str,aob:&str)->Result<Vec<String>,String>{
    let rule=Pattern::parse(aob).map_err(str::to_owned)?;
    let mut lines=Vec::new();
    for (label,path) in [("旧版本",old),("新版本",new)]{
        let meta=fs::metadata(path).map_err(|e|format!("{label}文件错误: {e}"))?;
        if meta.len()>MAX_FILE as u64{return Err(format!("{label}文件超过离线分析上限 160 MiB；请拆分分析目标模块"));}
        if !meta.is_file(){return Err(format!("{label}不是普通文件"));}
        let data=fs::read(path).map_err(|e|e.to_string())?;
        let mut count=0usize;
        let mut first=Vec::new();
        for (at,win) in data.windows(rule.0.len()).enumerate() {
            if rule.0.iter().zip(win).all(|(expected,actual)|expected.is_none_or(|b|b==*actual)) {
                count+=1;
                if first.len()<12 {first.push(format!("文件偏移 0x{at:X}"));}
                if count>=10000 {break;}
            }
        }
        let sample=first.join("、");
        lines.push(format!("{label}：{} 字节；匹配 {}{} 处；{}",data.len(),count,
            if count>=10000{"+"}else{""},sample));
    }
    lines.push("注意：报告中的地址是文件偏移，不是 RVA；候选需要手动验证函数语义和 ABI。".into());
    Ok(lines)
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn manifest_rejects_invalid_pattern(){assert!(Pattern::parse("GG").is_err());}
}
