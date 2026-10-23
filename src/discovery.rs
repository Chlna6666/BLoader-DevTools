//! Experimental, read-only Bedrock client discovery pipeline.
//!
//! Symbol Resolver -> ECS reference inspection -> LocalPlayer Validator.
//! This tool produces evidence, never fabricates an Actor*/LocalPlayer*.
//! All process memory reads run on DevTools' background worker.
use std::{cmp::Ordering as Cmp,collections::HashMap,ffi::c_void,mem,sync::atomic::{AtomicBool,Ordering}};
use windows_sys::Win32::System::Memory::{
    VirtualQuery,MEMORY_BASIC_INFORMATION,MEM_COMMIT,MEM_PRIVATE,
    PAGE_GUARD,PAGE_NOACCESS,PAGE_READWRITE,PAGE_WRITECOPY,
    PAGE_EXECUTE_READWRITE,PAGE_EXECUTE_WRITECOPY,PAGE_READONLY,
    PAGE_EXECUTE_READ,
};
use crate::{collision::{self,Profile,Vec3},inspection,local_player,memory,signature::Pattern};

const BLOCK:usize=64*1024;
const MAX_GEOMETRY:usize=1536;
const MAX_LINKS:usize=80;
const MAX_SYMBOL_MATCHES:usize=32;

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum SeedKind { Aabb, Vec3Position }
impl SeedKind {
    pub fn label(self)->&'static str {match self{Self::Aabb=>"AABB",Self::Vec3Position=>"Vec3"}}
}
#[derive(Debug,Clone)]
pub struct Seed {
    pub address:usize,
    pub kind:SeedKind,
    pub position:Vec3,
    pub distance:f32,
}
#[derive(Debug,Clone)]
pub struct SymbolEvidence {
    pub base:usize,
    pub image_size:usize,
    pub matches:Vec<usize>,
    pub index:Option<usize>,
    pub status:String,
}
#[derive(Debug,Clone)]
pub struct EcsLink {
    pub pointer_slot:usize,
    pub points_to:usize,
    pub offset_before_seed:usize,
    pub actor_candidate:Option<usize>,
    pub type_hint:Option<String>,
}
#[derive(Debug,Clone)]
pub struct Validated {
    pub seed:Seed,
    pub links:Vec<EcsLink>,
    pub status:String,
    pub score:u32,
    pub confidence:&'static str,
}
#[derive(Debug,Clone)]
pub struct Report {
    pub build_id:Option<String>,
    pub symbol:SymbolEvidence,
    pub seeds:Vec<Seed>,
    pub inspected:Vec<Validated>,
    pub scanned_bytes:usize,
    pub eligible_bytes:usize,
    pub failed_reads:usize,
    pub cancelled:bool,
    pub messages:Vec<String>,
}
#[derive(Debug,Clone,Copy)]
pub struct Options {
    pub profile:Profile,
    pub budget_mib:usize,
    pub source_instance:Option<usize>,
}
impl Options {
    pub fn validate(self)->Result<Self,String>{
        self.profile.validate()?;
        if !(16..=1024).contains(&self.budget_mib){return Err("分析预算应在 16–1024 MiB 之间".into());}
        Ok(self)
    }
}
fn is_data(protection:u32)->bool{
    protection&(PAGE_GUARD|PAGE_NOACCESS)==0 &&
    matches!(protection&0xff,PAGE_READWRITE|PAGE_WRITECOPY|
        PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY)
}
fn is_code(protection:u32)->bool{
    protection&(PAGE_GUARD|PAGE_NOACCESS)==0 &&
    matches!(protection&0xff,PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|
        PAGE_EXECUTE_WRITECOPY)
}
#[derive(Debug,Clone,Copy)]
struct Region{base:usize,len:usize}
fn regions(only_private:bool, executable:bool, start:usize,end:usize)->Vec<Region>{
    let mut result=Vec::new();
    let mut address=start.max(0x10000);
    while address<end && result.len()<200000 {
        let mut info:MEMORY_BASIC_INFORMATION=unsafe{mem::zeroed()};
        if unsafe{VirtualQuery(address as *const c_void,&mut info,
                mem::size_of::<MEMORY_BASIC_INFORMATION>())}==0 {break;}
        let base=info.BaseAddress as usize;
        let next=base.saturating_add(info.RegionSize);
        if next<=address{break;}
        let lo=base.max(address);
        let hi=next.min(end);
        if info.State==MEM_COMMIT &&
           (!only_private || info.Type==MEM_PRIVATE) &&
           (if executable{is_code(info.Protect)}else{is_data(info.Protect)}) &&
           hi.saturating_sub(lo)>=24 {
            result.push(Region{base:lo,len:hi-lo});
        }
        address=next;
    }
    result
}
/// Find an x86 instruction reference with an exact 9-byte anchor first,
/// then verify the entire signature including wildcards. This avoids the
/// O(image_size * signature_length) generic AOB matcher for every byte.
fn find_reference_matches(base:usize,bytes:&[u8],pattern:&Pattern,out:&mut Vec<usize>){
    const PREFIX:[u8;9]=[0x49,0x8B,0x00,0x49,0x8B,0xC8,0x48,0x8B,0x80];
    if bytes.len()<pattern.0.len(){return;}
    let mut offset=0usize;
    while offset+pattern.0.len()<=bytes.len() && out.len()<MAX_SYMBOL_MATCHES {
        let Some(hit)=bytes[offset..].iter().position(|b|*b==PREFIX[0]) else{break;};
        let at=offset+hit;
        if at+pattern.0.len()>bytes.len(){break;}
        if bytes[at..at+PREFIX.len()]==PREFIX &&
            pattern.0.iter().zip(&bytes[at..at+pattern.0.len()])
                .all(|(expect,got)|expect.is_none_or(|e|e==*got)) {
            let address=base+at;
            if !out.contains(&address){out.push(address);}
        }
        offset=at+1;
    }
}

fn scan_symbol(cancel:&AtomicBool)->SymbolEvidence{
    let mut evidence=SymbolEvidence{
        base:0,image_size:0,matches:Vec::new(),index:None,status:String::new(),
    };
    let (start,size)=match inspection::main_image_range(){
        Ok(range)=>range,
        Err(e)=>{evidence.status=format!("主模块枚举失败：{e}");return evidence;}
    };
    evidence.base=start;
    evidence.image_size=size;
    let signature=match Pattern::parse(local_player::INDEX_REFERENCE_AOB){
        Ok(p)=>p,Err(e)=>{evidence.status=e.into();return evidence;}
    };
    // Do not stop after the first AOB hit. Ambiguity must be reported.
    let mut overlap=Vec::new();
    let mut prev_end=0usize;
    let mut processed=0usize;
    for r in regions(false,true,start,start.saturating_add(size)){
        if cancel.load(Ordering::Acquire){evidence.status="符号扫描已取消".into();return evidence;}
        let mut offset=0usize;
        while offset<r.len && processed<512*1024*1024 {
            if cancel.load(Ordering::Acquire){evidence.status="符号扫描已取消".into();return evidence;}
            let n=(r.len-offset).min(BLOCK);
            let address=r.base+offset;
            match memory::read(address,n){
                Ok(bytes)=>{
                    if prev_end!=address{overlap.clear();}
                    let mut combined=overlap.clone();
                    combined.extend_from_slice(&bytes);
                    let base=address-overlap.len();
                    find_reference_matches(base,&combined,&signature,&mut evidence.matches);
                    let copy=(signature.0.len()-1).min(combined.len());
                    overlap=combined[combined.len()-copy..].to_vec();
                    prev_end=address+n;
                }
                Err(_)=>{overlap.clear();prev_end=0;}
            }
            processed+=n;
            offset+=n;
            if evidence.matches.len()>=MAX_SYMBOL_MATCHES{break;}
        }
        if evidence.matches.len()>=MAX_SYMBOL_MATCHES||processed>=512*1024*1024{break;}
    }
    if evidence.matches.len()==1 {
        evidence.index=local_player::get_index_at(evidence.matches[0]).ok();
    }
    evidence.status=match (evidence.matches.len(),evidence.index){
        (0,_)=>"参考符号未匹配：当前客户端可能重构，不能从旧 AOB 推断 getter".into(),
        (1,Some(n))=>format!("参考指令唯一匹配；候选虚表索引={n}，还需要确认 ClientInstance 和 ABI"),
        (1,None)=>"字节特征命中，但指令解码失败；未确认符号".into(),
        _=>format!("参考特征命中 {} 项，存在歧义；拒绝自动选择",evidence.matches.len()),
    };
    evidence
}
fn vec3_at(bytes:&[u8])->Option<Vec3>{
    if bytes.len()<12{return None;}
    let get=|offset|f32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap());
    let v=Vec3{x:get(0),y:get(4),z:get(8)};
    (v.x.is_finite()&&v.y.is_finite()&&v.z.is_finite()).then_some(v)
}
fn point_distance(a:Vec3,b:Vec3)->f32{
    ((a.x-b.x).powi(2)+(a.y-b.y).powi(2)+(a.z-b.z).powi(2)).sqrt()
}
fn push_geometry(base:usize,data:&[u8],profile:Profile,results:&mut Vec<Seed>){
    if data.len()<12{return;}
    let first=(4-base%4)%4;
    for i in (first..data.len()-11).step_by(4){
        // Validate complete AABB first, but fall back to a location vector
        // when the client stores shape bounds in a different ECS component.
        if data.len()-i>=24 {
            if let Some(box3)=collision::parse_aabb(&data[i..i+24]){
                if profile.matches(box3){
                    let pos=box3.center();
                    let dist=profile.feet_hint.map_or(0.,|p|point_distance(pos,p));
                    results.push(Seed{address:base+i,kind:SeedKind::Aabb,position:pos,distance:dist});
                    continue;
                }
            }
        }
        if let (Some(p),Some(hint))=(vec3_at(&data[i..i+12]),profile.feet_hint){
            let d=point_distance(p,hint);
            // 3D coordinates can represent a location instead of hitbox
            // bounds. Do not infer a player type from this alone.
            if d<=profile.radius {
                results.push(Seed{address:base+i,kind:SeedKind::Vec3Position,position:p,distance:d});
            }
        }
    }
}
fn geometry_regions(regions:&[Region],byte_budget:usize)->Vec<Region>{
    let mut selected=Vec::new();
    if regions.is_empty()||byte_budget<4096{return selected;}
    // First choose regions uniformly across the entire address space, not
    // only the first low addresses. Each pass samples at most one small slice
    // from each region, so a single huge heap cannot consume the budget.
    let slots=regions.len().min(byte_budget/4096).max(1);
    let indexes=(0..slots).map(|n|n*regions.len()/slots).collect::<Vec<_>>();
    let mut next_pass=vec![0usize;slots];
    let chunk=(byte_budget/slots).clamp(4096,512*1024);
    let mut budget=byte_budget;
    loop{
        let mut progress=false;
        for (slot,&index) in indexes.iter().enumerate(){
            let region=regions[index];
            if budget<24{break;}
            let total_passes=region.len.div_ceil(chunk);
            let pass=next_pass[slot];
            if pass>=total_passes{continue;}
            // Alternating the low and high edge of each region reaches
            // spatially distant allocations before filling intervening bytes.
            let page=if pass%2==0{pass/2}else{total_passes-1-pass/2};
            let start_offset=page*chunk;
            let take=(region.len-start_offset).min(chunk).min(budget);
            if take<24{continue;}
            selected.push(Region{base:region.base+start_offset,len:take});
            next_pass[slot]+=1;
            budget-=take;
            progress=true;
        }
        if !progress{break;}
    }
    selected
}

fn collect_geometry(profile:Profile,budget:usize,cancel:&AtomicBool)
    ->(Vec<Seed>,usize,usize,usize){
    let valid_regions=regions(true,false,0x10000,usize::MAX);
    let eligible=valid_regions.iter().map(|r|r.len as u64).sum::<u64>()
        .min(usize::MAX as u64) as usize;
    let mut seeds=Vec::new();
    let mut scanned=0usize;
    let mut failed=0usize;
    let mut previous_end=0usize;
    let mut leftover=Vec::new();
    for segment in geometry_regions(&valid_regions,budget) {
        if cancel.load(Ordering::Acquire){break;}
        let mut offset=0usize;
        while offset<segment.len {
            if cancel.load(Ordering::Acquire){break;}
            let address=segment.base+offset;
            let len=(segment.len-offset).min(BLOCK);
            if let Ok(bytes)=memory::read(address,len){
                if previous_end!=address{leftover.clear();}
                let mut buffer=leftover.clone();
                buffer.extend_from_slice(&bytes);
                push_geometry(address-leftover.len(),&buffer,profile,&mut seeds);
                let n=23.min(buffer.len());
                leftover=buffer[buffer.len()-n..].to_vec();
                previous_end=address+len;
            }else{failed+=1;leftover.clear();previous_end=0;}
            scanned+=len;
            offset+=len;
            if seeds.len()>MAX_GEOMETRY*16{break;}
        }
        if seeds.len()>MAX_GEOMETRY*16{break;}
    }
    // Known coordinates are strong *spatial* filters, not type evidence.
    seeds.sort_by(|a,b|a.distance.partial_cmp(&b.distance).unwrap_or(Cmp::Equal)
        .then_with(||match (a.kind,b.kind){
            (SeedKind::Aabb,SeedKind::Vec3Position)=>Cmp::Less,
            (SeedKind::Vec3Position,SeedKind::Aabb)=>Cmp::Greater,
            _=>Cmp::Equal,
        }));
    seeds.dedup_by_key(|seed|seed.address);
    seeds.truncate(MAX_GEOMETRY);
    (seeds,scanned,eligible,failed)
}
fn read_ptr(address:usize)->Option<usize>{
    let data=memory::read(address,8).ok()?;
    Some(u64::from_le_bytes(data.try_into().ok()?) as usize)
}
fn pointer_targets(seed:usize)->HashMap<usize,usize>{
    let mut wanted=HashMap::new();
    for offset in (0..=128).step_by(8){
        if let Some(addr)=seed.checked_sub(offset){
            wanted.insert(addr,offset);
        }
    }
    wanted
}
fn collect_links(seed:&Seed,limit:usize,cancel:&AtomicBool)->Vec<EcsLink>{
    let targets=pointer_targets(seed.address);
    let mut links=Vec::new();
    let mut total=0usize;
    let mut overlap=Vec::new();
    let mut previous_end=0usize;
    let eligible=regions(true,false,0x10000,usize::MAX);
    for region in geometry_regions(&eligible,limit){
        let mut offset=0usize;
        while offset<region.len && total<limit && links.len()<MAX_LINKS {
            if cancel.load(Ordering::Acquire){return links;}
            let at=region.base+offset;
            let count=(region.len-offset).min(BLOCK).min(limit-total);
            if count<8{break;}
            if let Ok(data)=memory::read(at,count){
                if previous_end!=at{overlap.clear();}
                let mut block=overlap.clone();
                block.extend_from_slice(&data);
                let base=at-overlap.len();
                let first=(8-base%8)%8;
                for i in (first..block.len().saturating_sub(7)).step_by(8) {
                    let p=u64::from_le_bytes(block[i..i+8].try_into().unwrap()) as usize;
                    if let Some(delta)=targets.get(&p){
                        let slot=base+i;
                        links.push(EcsLink{pointer_slot:slot,points_to:p,offset_before_seed:*delta,
                            actor_candidate:None,type_hint:None});
                        if links.len()>=MAX_LINKS{break;}
                    }
                }
                let carry=7.min(block.len());
                overlap=block[block.len()-carry..].to_vec();
                previous_end=at+count;
            }else{overlap.clear();previous_end=0;}
            total+=count;
            offset+=count;
        }
        if total>=limit||links.len()>=MAX_LINKS{break;}
    }
    links
}
fn printable_type_name(name:&str)->bool{
    name.len()>=5 && name.len()<192 &&
    name.bytes().all(|c|c.is_ascii_alphanumeric()||b"_?@.$".contains(&c))
}
/// MSVC x64 RTTI may store a CompleteObjectLocator pointer immediately before
/// the vtable. The type-descriptor RVA is at COL+12. This is optional evidence.
fn rtti_name(object:usize,module_base:usize,module_size:usize)->Option<String>{
    let vt=read_ptr(object)?;
    if vt<0x10008{return None;}
    let col=read_ptr(vt.checked_sub(8)?)?;
    let loc=memory::read(col,24).ok()?;
    let signature=u32::from_le_bytes(loc[..4].try_into().ok()?);
    if signature!=1{return None;}
    let rva=u32::from_le_bytes(loc[12..16].try_into().ok()?) as usize;
    if rva>=module_size{return None;}
    let typed=module_base.checked_add(rva+16)?;
    let bytes=memory::read(typed,160).ok()?;
    let n=bytes.iter().position(|c|*c==0)?;
    let name=std::str::from_utf8(&bytes[..n]).ok()?;
    printable_type_name(name).then_some(name.into())
}
fn maybe_owner(slot:usize,module_base:usize,module_size:usize)->Option<(usize,String)>{
    // The reference slot may reside in Actor::BuiltInActorComponents. Search
    // bounded preceding pointer-aligned object starts with MSVC RTTI.
    for before in (0..=512).step_by(8){
        let Some(start)=slot.checked_sub(before) else {continue;};
        if let Some(class)=rtti_name(start,module_base,module_size){
            if class.contains("Actor")||class.contains("Player") {
                return Some((start,class));
            }
        }
    }
    None
}
fn validate(seed:Seed,mut links:Vec<EcsLink>,symbol:&SymbolEvidence)->Validated{
    let mut strong=false;
    let mut owner=false;
    for link in &mut links {
        if let Some((address,name))=maybe_owner(link.pointer_slot,symbol.base,symbol.image_size){
            link.actor_candidate=Some(address);
            link.type_hint=Some(name.clone());
            if name.contains("Player"){strong=true;}
            if name.contains("Actor"){owner=true;}
        }
    }
    let score=(seed.kind==SeedKind::Aabb) as u32*20+
        (seed.distance<2.) as u32*15+
        (!links.is_empty()) as u32*15+
        owner as u32*15+strong as u32*25;
    let confidence=if strong{"类型候选（未确认受本机控制）"}
        else if owner{"Actor 所有者候选"}
        else if !links.is_empty(){"组件引用候选"}
        else{"仅几何/位置候选"};
    Validated{
        seed,links,
        status:if strong {
            "RTTI 与 Player 相关，但未证明是当前客户端控制的 LocalPlayer".into()
        }else{
            "没有游戏线程 getter / ECS PlayerComponent / ClientInstance 一致性证明".into()
        },
        score,confidence,
    }
}
pub fn run(options:Options,cancel:&AtomicBool)->Result<Report,String>{
    let options=options.validate()?;
    let mut messages=Vec::new();
    let build_id=local_player::executable_build_id().ok();
    let symbol=scan_symbol(cancel);
    messages.push(format!("Symbol Resolver：{}",symbol.status));
    if let Some(source)=options.source_instance {
        if let Some(index)=symbol.index {
            match local_player::probe(source,local_player::SourceKind::DirectInstance,
                local_player::PlayerAccess::VtableIndex(index)){
                Ok(candidate)=>messages.push(format!(
                    "ClientInstance(候选 0x{source:X}) 的 getter 入口=0x{:X}；未调用游戏函数",
                    candidate.getter_entry.unwrap_or(0))),
                Err(e)=>messages.push(format!("ClientInstance 只读验证失败：{e}")),
            }
        }
    }
    if cancel.load(Ordering::Acquire){
        return Ok(Report{build_id,symbol,seeds:Vec::new(),inspected:Vec::new(),
            scanned_bytes:0,eligible_bytes:0,failed_reads:0,cancelled:true,messages});
    }
    let budget=options.budget_mib*1024*1024;
    let (seeds,scanned,eligible,failed)=collect_geometry(options.profile,budget,cancel);
    messages.push(format!(
        "ECS 初筛：扫描 {:.1} MiB / 可写私有内存 {:.1} MiB（覆盖 {:.2}%），读取失败={failed}，几何/Vec3 候选={}",
        scanned as f64/1048576.,eligible as f64/1048576.,
        if eligible>0{100.*scanned as f64/eligible as f64}else{0.},seeds.len()
    ));
    if options.profile.feet_hint.is_none(){
        messages.push("未提供玩家世界坐标：无 Vec3 模式，仍依赖 AABB 结构；建议输入 HUD XYZ 后重试".into());
    }
    if seeds.is_empty(){
        messages.push("零候选原因可能是 ECS 布局、对象姿态、内存采样不覆盖目标；不会把零结果当作玩家不存在".into());
    }
    let mut inspected=Vec::new();
    // Reverse references only for the most promising spatial candidates;
    // never run an N * whole-process memory scan on thousands of seeds.
    for (i,seed) in seeds.iter().take(5).enumerate(){
        if cancel.load(Ordering::Acquire){break;}
        let links=collect_links(seed,options.budget_mib*1024*1024/2,cancel);
        messages.push(format!("ECS 指针引用 {}：0x{:X} 找到 {} 个可能的组件基址引用",
            i+1,seed.address,links.len()));
        inspected.push(validate(seed.clone(),links,&symbol));
    }
    inspected.sort_by(|a,b|b.score.cmp(&a.score));
    messages.push("LocalPlayer Validator：尚未安全获取当前游戏线程的 getLocalPlayer 返回值，所有结果均为候选，禁止自动导出 Actor*。".into());
    Ok(Report{build_id,symbol,seeds,inspected,scanned_bytes:scanned,
        eligible_bytes:eligible,failed_reads:failed,
        cancelled:cancel.load(Ordering::Acquire),messages})
}
pub fn summarise(report:&Report)->String{
    let mut lines=report.messages.clone();
    if report.cancelled{lines.push("操作被取消，结果不应视为完整扫描".into());}
    if let Some(build)=&report.build_id{lines.push(format!("游戏 EXE 身份：{build}"));}
    for (index,item) in report.inspected.iter().enumerate(){
        lines.push(format!("{}: {} 0x{:X} 距离={:.2} 评分={} {:?} 引用={}；{}",
            index+1,item.seed.kind.label(),item.seed.address,item.seed.distance,
            item.score,item.confidence,item.links.len(),item.status));
        for link in item.links.iter().take(3) {
            lines.push(format!("  引用槽=0x{:X} → 0x{:X} 偏移=0x{:X} actor={:?} RTTI={}",
                link.pointer_slot,link.points_to,link.offset_before_seed,
                link.actor_candidate,link.type_hint.as_deref().unwrap_or("无")));
        }
    }
    lines.join("\n")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]fn unambiguous_vec3_coordinates(){
        let profile=Profile{
            feet_hint:Some(Vec3{x:100.,y:64.,z:200.}),radius:3.,..Default::default()
        };
        let mut data=vec![0u8;128];
        for (i,value) in [100.3f32,64.1,200.2].into_iter().enumerate(){
            data[16+i*4..20+i*4].copy_from_slice(&value.to_le_bytes());
        }
        let mut result=Vec::new();
        push_geometry(0x10000,&data,profile,&mut result);
        assert!(result.iter().any(|p|p.address==0x10010 && p.kind==SeedKind::Vec3Position));
    }
    #[test]fn anchored_symbol_disambiguates_and_checks_wildcards(){
        let pattern=Pattern::parse(local_player::INDEX_REFERENCE_AOB).unwrap();
        let mut bytes=vec![0xCC;120];
        for (i,item) in pattern.0.iter().enumerate(){
            bytes[16+i]=item.unwrap_or(0x55);
        }
        let mut result=Vec::new();
        find_reference_matches(0x400000,&bytes,&pattern,&mut result);
        assert_eq!(result,vec![0x400010]);
        bytes[16+10]=0x66; // a wildcard displacement byte: still matches
        result.clear();
        find_reference_matches(0x400000,&bytes,&pattern,&mut result);
        assert_eq!(result.len(),1);
        bytes[16]=0x48; // break exact anchor
        result.clear();
        find_reference_matches(0x400000,&bytes,&pattern,&mut result);
        assert!(result.is_empty());
    }
        #[test]fn sample_budget_spreads_across_regions(){
        let regs=vec![
            Region{base:0x10000,len:128*1024*1024},
            Region{base:0x20000000,len:128*1024*1024},
            Region{base:0x40000000,len:128*1024*1024},
        ];
        let chosen=geometry_regions(&regs,12*1024*1024);
        assert!(chosen.iter().any(|r|r.base>=regs[0].base && r.base<regs[0].base+regs[0].len));
        assert!(chosen.iter().any(|r|r.base>=regs[1].base && r.base<regs[1].base+regs[1].len));
        assert!(chosen.iter().any(|r|r.base>=regs[2].base && r.base<regs[2].base+regs[2].len));
        assert!(chosen.iter().map(|r|r.len).sum::<usize>()<=12*1024*1024);
    }
        #[test]fn reverse_reference_targets(){
        let targets=pointer_targets(0x20080);
        assert_eq!(targets.get(&0x20000),Some(&128));
        assert_eq!(targets.get(&0x20080),Some(&0));
    }
    #[test]fn blocks_false_localplayer_confirmation(){
        let seed=Seed{address:0x20000,kind:SeedKind::Vec3Position,
            position:Vec3{x:1.,y:2.,z:3.},distance:0.};
        let symbol=SymbolEvidence{base:0,image_size:0,matches:Vec::new(),index:None,
            status:"missing".into()};
        let result=validate(seed,Vec::new(),&symbol);
        assert_eq!(result.confidence,"仅几何/位置候选");
        assert!(result.status.contains("没有游戏线程 getter"));
    }
    #[test]fn validates_budget() {
        let options=Options{profile:Profile::default(),budget_mib:8,source_instance:None};
        assert!(options.validate().is_err());
    }
}
