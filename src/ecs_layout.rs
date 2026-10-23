//! Version-bound, read-only ECS relationship inspection.
//!
//! An arbitrary AABB pointer/RTTI name is not an Actor. A layout profile must
//! match the EXACT Minecraft EXE SHA-256 and the relationships must agree.
//! Even a passing structural proof is not proof of client control (LocalPlayer).
use std::fs;
use serde_json::Value;
use crate::memory;
const MAX_BYTES:u64=256*1024;
const MAX_OFFSET:usize=16*1024;
#[derive(Debug,Clone)]
pub struct Layout {
    pub module_sha256:String,
    pub actor_owner_ptr:usize,
    pub player_component_ptr:usize,
    pub aabb_component_ptr:usize,
    pub owner_backref:usize,
    pub player_backref:usize,
    pub aabb_offset:usize,
}
fn checked_offset(v:&Value,key:&str)->Result<usize,String>{
    let raw=v[key].as_u64().ok_or_else(||format!("{key} 必须为整数"))?;
    let value=usize::try_from(raw).map_err(|_|format!("{key} 超限"))?;
    if value>MAX_OFFSET || value%8!=0{return Err(format!("{key} 必须 8 字节对齐并小于 16 KiB"));}
    Ok(value)
}
pub fn decode(raw:&str)->Result<Vec<Layout>,String>{
    let document:Value=serde_json::from_str(raw).map_err(|e|e.to_string())?;
    if document["schema"]!=1{return Err("ECS 布局 schema 必须为 1".into());}
    let list=document["layouts"].as_array().ok_or("缺少 layouts 数组")?;
    if list.len()>32{return Err("ECS 布局上限 32 个版本".into());}
    let mut profiles=Vec::new();
    for v in list {
        let hash=v["module_sha256"].as_str().ok_or("缺少 module_sha256")?;
        if hash.len()!=64 || !hash.bytes().all(|b|b.is_ascii_hexdigit()){
            return Err("module_sha256 必须为 64 个十六进制字符".into());
        }
        let offsets=[
            checked_offset(v,"actor_owner_ptr")?,
            checked_offset(v,"player_component_ptr")?,
            checked_offset(v,"aabb_component_ptr")?,
        ];
        if offsets[0]==offsets[1]||offsets[0]==offsets[2]||offsets[1]==offsets[2]{
            return Err("组件指针字段必须位于不同偏移".into());
        }
        profiles.push(Layout{
            module_sha256:hash.to_lowercase(),
            actor_owner_ptr:offsets[0],player_component_ptr:offsets[1],
            aabb_component_ptr:offsets[2],
            owner_backref:checked_offset(v,"owner_backref")?,
            player_backref:checked_offset(v,"player_backref")?,
            aabb_offset:{
                let n=v["aabb_offset"].as_u64().ok_or("aabb_offset 必须为整数")?;
                let off=usize::try_from(n).map_err(|_|"aabb_offset 超限")?;
                if off>MAX_OFFSET || off%4!=0{
                    return Err("aabb_offset 必须 4 字节对齐且不超过 16 KiB".into());
                }
                off
            },
        });
    }
    Ok(profiles)
}
pub fn load_for_build(build_id:&str)->Result<Option<Layout>,String>{
    let hash=build_id.strip_prefix("exe-sha256:").unwrap_or(build_id);
    let folder=crate::project::root()?;
    let path=folder.join("ecs_layouts.json");
    let metadata=match fs::metadata(&path) {
        Ok(m)=>m,
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>return Ok(None),
        Err(e)=>return Err(e.to_string()),
    };
    if metadata.len()>MAX_BYTES{return Err("ECS 布局文件超过 256 KiB".into());}
    let text=fs::read_to_string(path).map_err(|e|e.to_string())?;
    Ok(decode(&text)?.into_iter().find(|l|l.module_sha256.eq_ignore_ascii_case(hash)))
}
fn exact_relation(actor:usize,layout:&Layout,read:impl Fn(usize)->Option<usize>)
    ->Option<(usize,usize,usize)>{
    let owner=read(actor.checked_add(layout.actor_owner_ptr)?)?;
    let player=read(actor.checked_add(layout.player_component_ptr)?)?;
    let shape=read(actor.checked_add(layout.aabb_component_ptr)?)?;
    if owner==player||owner==shape||player==shape||owner<0x10000 ||
       player<0x10000||shape<0x10000{return None;}
    if read(owner.checked_add(layout.owner_backref)?)?!=actor ||
       read(player.checked_add(layout.player_backref)?)?!=actor{return None;}
    Some((owner,player,shape))
}
#[derive(Debug,Clone)]
pub struct Evidence {
    pub actor:usize,pub owner_component:usize,
    pub player_component:usize,pub shape_component:usize,
    pub shape_value_address:usize,
    pub status:&'static str,
}
/// Inspect a captured Actor/Player candidate without first requiring a
/// geometry seed. Only a version-exact profile can authorize these offsets.
/// All reads use ReadProcessMemory and may fail during world unload.
pub fn inspect_known_actor(actor:usize,layout:&Layout)->Option<Evidence>{
    if actor<0x10000||actor%8!=0{return None;}
    let (owner,player,shape)=exact_relation(actor,layout,|at|{
        let raw=memory::read(at,8).ok()?;
        Some(u64::from_le_bytes(raw.try_into().ok()?) as usize)
    })?;
    let data=shape.checked_add(layout.aabb_offset)?;
    if memory::read(data,24).is_err(){return None;}
    Some(Evidence{
        actor,owner_component:owner,player_component:player,
        shape_component:shape,shape_value_address:data,
        status:"版本匹配的三组件双向引用成立；仍未验证 LocalPlayer 控制归属",
    })
}
pub fn inspect(actor:usize,seed:usize,layout:&Layout)->Option<Evidence>{
    let evidence=inspect_known_actor(actor,layout)?;
    // A geometry seed may be within the embedded bounds payload.
    if seed<evidence.shape_value_address || seed-evidence.shape_value_address>24 {
        return None;
    }
    Some(evidence)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample()->String{
        format!(r#"{{"schema":1,"layouts":[{{
          "module_sha256":"{}",
          "actor_owner_ptr":8,"player_component_ptr":16,
          "aabb_component_ptr":24,"owner_backref":0,
          "player_backref":0,"aabb_offset":32
        }}]}}"#,"a".repeat(64))
    }
    #[test]fn requires_exact_version_and_offsets(){
        let layouts=decode(&sample()).unwrap();
        assert_eq!(layouts.len(),1);
        assert!(decode(r#"{"schema":1,"layouts":[{"module_sha256":"wrong"}]}"#).is_err());
    }
    #[test]fn reads_three_backlinked_components_from_owned_buffers(){
        let layout=decode(&sample()).unwrap().remove(0);
        let mut actor=Box::new([0usize;8]);
        let mut owner=Box::new([0usize;8]);
        let mut player=Box::new([0usize;8]);
        let shape=Box::new([0u64;16]);
        let actor_addr=actor.as_mut_ptr() as usize;
        let owner_addr=owner.as_mut_ptr() as usize;
        let player_addr=player.as_mut_ptr() as usize;
        let shape_addr=shape.as_ptr() as usize;
        actor[1]=owner_addr;
        actor[2]=player_addr;
        actor[3]=shape_addr;
        owner[0]=actor_addr;
        player[0]=actor_addr;
        let report=inspect_known_actor(actor_addr,&layout).unwrap();
        assert_eq!(report.actor,actor_addr);
        assert_eq!(report.player_component,player_addr);
        player[0]=0;
        assert!(inspect_known_actor(actor_addr,&layout).is_none());
    }
        #[test]fn two_sided_relations_reject_wrong_ownership(){
        let layout=decode(&sample()).unwrap().remove(0);
        let actor=0x100000usize;
        let owner=0x200000usize;
        let player=0x300000usize;
        let shape=0x400000usize;
        let mut mem=std::collections::HashMap::from([
            (actor+8,owner),(actor+16,player),(actor+24,shape),
            (owner,actor),(player,actor)
        ]);
        assert_eq!(exact_relation(actor,&layout,|at|mem.get(&at).copied()),
            Some((owner,player,shape)));
        mem.insert(player,actor+8);
        assert!(exact_relation(actor,&layout,|at|mem.get(&at).copied()).is_none());
    }
}
