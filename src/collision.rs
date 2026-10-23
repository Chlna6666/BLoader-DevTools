//! Read-only AABB geometry matcher for locating player-shaped dynamic data.
//! Memory layout hypothesis: 6 little-endian f32 [minX,minY,minZ,maxX,maxY,maxZ].
//! A hitbox is NOT an Actor, LocalPlayer, or pointer to either one.
#[derive(Debug,Clone,Copy,PartialEq)]
pub struct Vec3 {pub x:f32,pub y:f32,pub z:f32}
impl Vec3 {
    fn finite(self)->bool{self.x.is_finite() && self.y.is_finite() && self.z.is_finite()}
    pub fn distance(self,other:Self)->f32{
        ((self.x-other.x).powi(2)+(self.y-other.y).powi(2)+(self.z-other.z).powi(2)).sqrt()
    }
}
#[derive(Debug,Clone,Copy,PartialEq)]
pub struct Aabb {pub min:Vec3,pub max:Vec3}
impl Aabb {
    pub fn center(self)->Vec3 {Vec3{
        x:(self.min.x+self.max.x)*0.5,
        y:(self.min.y+self.max.y)*0.5,
        z:(self.min.z+self.max.z)*0.5,
    }}
    pub fn extent(self)->Vec3 {Vec3{
        x:self.max.x-self.min.x,
        y:self.max.y-self.min.y,
        z:self.max.z-self.min.z,
    }}
    pub fn finite(self)->bool {self.min.finite()&&self.max.finite()}
}
pub const AABB_BYTES:usize=24;
#[derive(Debug,Clone,Copy,PartialEq)]
pub struct Profile {pub width:f32,pub height:f32,pub tolerance:f32,
    /// Optional known player feet position (e.g. coordinates shown in game).
    pub feet_hint:Option<Vec3>,pub radius:f32}
impl Default for Profile{
    fn default()->Self{Self{width:0.6,height:1.8,tolerance:0.035,feet_hint:None,radius:4.}}
}
impl Profile {
    pub fn validate(self)->Result<Self,String>{
        if !self.width.is_finite()|| !self.height.is_finite() ||
            !self.tolerance.is_finite() || !self.radius.is_finite() ||
            !(0.25..=5000.).contains(&self.radius) ||
            self.feet_hint.is_some_and(|pos| !pos.finite()) ||
            !(0.1..=5.).contains(&self.width) ||
            !(0.2..=5.).contains(&self.height) ||
            !(0.001..=0.25).contains(&self.tolerance) {
            return Err("碰撞箱宽度应在 0.1–5、高度 0.2–5、容差 0.001–0.25 范围内".into());
        }
        Ok(self)
    }
    pub fn matches(self,b:Aabb)->bool{
        if !b.finite(){return false;}
        let e=b.extent();
        // Reject reversed / obviously out-of-world boxes. Do not filter by
        // absolute coordinates to allow deep underground and large worlds.
        e.x>0. && e.y>0. && e.z>0. &&
        (e.x-self.width).abs()<=self.tolerance &&
        (e.z-self.width).abs()<=self.tolerance &&
        (e.y-self.height).abs()<=self.tolerance &&
        self.feet_hint.is_none_or(|p|{
            let dx=(b.min.x+b.max.x)*0.5-p.x;
            let dz=(b.min.z+b.max.z)*0.5-p.z;
            let dy=b.min.y-p.y;
            dx.abs()<=self.radius && dz.abs()<=self.radius &&
                dy.abs()<=self.radius && (dx*dx+dz*dz+dy*dy).sqrt()<=self.radius
        })
    }
}
pub fn parse_aabb(raw:&[u8])->Option<Aabb>{
    if raw.len()<AABB_BYTES{return None;}
    let mut v=[0f32;6];
    for (i,x) in v.iter_mut().enumerate(){
        *x=f32::from_le_bytes(raw[i*4..i*4+4].try_into().ok()?);
    }
    Some(Aabb{
        min:Vec3{x:v[0],y:v[1],z:v[2]},
        max:Vec3{x:v[3],y:v[4],z:v[5]},
    })
}
#[derive(Debug,Clone)]
pub struct Hit{pub address:usize,pub box3:Aabb,pub baseline:Aabb,pub traveled:f32,pub vertical:f32,pub samples:u32}
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Motion { Moved, Horizontal, Jumped, Stationary }
impl Motion{
    pub const ALL:[Self;4]=[Self::Moved,Self::Horizontal,Self::Jumped,Self::Stationary];
    pub fn label(self)->&'static str {
        match self{
            Self::Moved=>"任意移动",Self::Horizontal=>"水平走动",
            Self::Jumped=>"跳跃/垂直移动",Self::Stationary=>"站立不动",
        }
    }
    pub fn accepts(self,old:Aabb,new:Aabb)->bool{
        let a=old.center();
        let b=new.center();
        let dx=b.x-a.x;let dz=b.z-a.z;let dy=b.y-a.y;
        let horizontal=(dx*dx+dz*dz).sqrt();
        match self {
            Self::Moved=>horizontal>0.10 || dy.abs()>0.12,
            Self::Horizontal=>horizontal>0.15 && dy.abs()<1.5,
            Self::Jumped=>dy.abs()>0.20 && horizontal<2.5,
            Self::Stationary=>horizontal<0.04 && dy.abs()<0.04,
        }
    }
}
pub fn scan_bytes(base:usize,bytes:&[u8],profile:Profile,limit:usize,out:&mut Vec<Hit>){
    if bytes.len()<AABB_BYTES || out.len()>=limit{return;}
    // Most native glm/Vec3 payloads are naturally 4-byte aligned. AABB
    // starts can be at 4-byte offsets even when object headers are 8-byte aligned.
    let first=(4-base%4)%4;
    for offset in (first..=bytes.len()-AABB_BYTES).step_by(4){
        let x0=f32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap());
        let x1=f32::from_le_bytes(bytes[offset+12..offset+16].try_into().unwrap());
        if (x1-x0-profile.width).abs()>profile.tolerance{continue;}
        let Some(aabb)=parse_aabb(&bytes[offset..offset+AABB_BYTES]) else {continue;};
        if profile.matches(aabb){
            out.push(Hit{
                address:base+offset,box3:aabb,baseline:aabb,
                traveled:0.,vertical:0.,samples:1,
            });
            if out.len()>=limit{break;}
        }
    }
}
pub fn refine_hits(
    hits:&[Hit], motion:Motion, min_profile:Profile,
    mut read_at:impl FnMut(usize)->Option<Aabb>,
)->Vec<Hit>{
    let mut out=Vec::new();
    for hit in hits{
        let Some(now)=read_at(hit.address) else {continue;};
        if !min_profile.matches(now)||!motion.accepts(hit.box3,now){continue;}
        let old=hit.box3.center();
        let new=now.center();
        let mut match_hit=hit.clone();
        match_hit.traveled+=((new.x-old.x).powi(2)+(new.z-old.z).powi(2)).sqrt();
        match_hit.vertical+=(new.y-old.y).abs();
        match_hit.box3=now;
        match_hit.samples=hit.samples.saturating_add(1);
        out.push(match_hit);
    }
    out
}
pub fn describe(hit:&Hit)->String {
    let c=hit.box3.center();
    let e=hit.box3.extent();
    format!("0x{:016X} | ({:.2},{:.2},{:.2}) | {:.2}×{:.2}×{:.2} | 水平累计 {:.2} | {} 样本",
        hit.address,c.x,c.y,c.z,e.x,e.y,e.z,hit.traveled,hit.samples)
}
#[cfg(test)]
mod tests{
    use super::*;
    fn bytes(min:[f32;3],max:[f32;3])->Vec<u8>{
        min.into_iter().chain(max).flat_map(f32::to_le_bytes).collect()
    }
    #[test]fn standing_player_aabb(){
        let b=bytes([9.7,64.,19.7],[10.3,65.8,20.3]);
        let a=parse_aabb(&b).unwrap();
        assert!(Profile::default().matches(a));
        assert!(!Profile{height:0.6,..Profile::default()}.matches(a));
    }
    #[test]fn scan_with_padding_and_alignment(){
        let mut data=vec![0xff;128];
        let a=bytes([1.7,-10.,2.7],[2.3,-8.2,3.3]);
        data[20..44].copy_from_slice(&a);
        let mut hits=Vec::new();
        scan_bytes(0x10000,&data,Profile::default(),12,&mut hits);
        assert_eq!(hits.len(),1);
        assert_eq!(hits[0].address,0x10014);
    }
    #[test]fn movement_refines_only_expected_box(){
        let mut found=Vec::new();
        let old=bytes([9.7,64.,19.7],[10.3,65.8,20.3]);
        scan_bytes(0x10000,&old,Profile::default(),8,&mut found);
        let mut now=bytes([12.7,64.,20.7],[13.3,65.8,21.3]);
        let moving=refine_hits(&found,Motion::Horizontal,Profile::default(),
            |_|parse_aabb(&now));
        assert_eq!(moving.len(),1);
        assert!(moving[0].traveled>3.0);
        assert!(refine_hits(&found,Motion::Stationary,Profile::default(),
            |_|parse_aabb(&now)).is_empty());
        now=vec![0;24];
        assert!(refine_hits(&found,Motion::Moved,Profile::default(),
            |_|parse_aabb(&now)).is_empty());
    }
    #[test]fn optional_world_coordinates_filter(){
        let raw=bytes([9.7,64.,19.7],[10.3,65.8,20.3]);
        let aabb=parse_aabb(&raw).unwrap();
        let nearby=Profile{feet_hint:Some(Vec3{x:10.,y:64.,z:20.}),radius:0.5,..Profile::default()};
        assert!(nearby.matches(aabb));
        let far=Profile{feet_hint:Some(Vec3{x:500.,y:64.,z:20.}),radius:2.,..Profile::default()};
        assert!(!far.matches(aabb));
    }
    #[test]fn rejects_nan_and_reversed_bounds(){
        assert!(!Profile::default().matches(parse_aabb(&bytes(
            [f32::NAN,1.,1.],[3.,2.8,3.])).unwrap()));
        assert!(!Profile::default().matches(parse_aabb(&bytes(
            [2.,2.,2.],[1.,4.,3.])).unwrap()));
    }
}
