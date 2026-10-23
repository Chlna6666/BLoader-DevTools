//! IDEA-inspired in-process debugging workspace.
//! All memory access, disassembly and script execution live inside DevTools,
//! never in BLoader and never on the game/render thread.
use crate::{
    memory::{self,Command,Engine,Filter,Hit,ValueKind,ScanScope,ScanOptions},
    local_player::{self,Candidate,PlayerAccess,SourceKind},
    collision::{self,Motion},
    discovery::{self,Options as DiscoveryOptions},
    signature::{Pattern,decode_hex},
};
use egui::{Align,Color32,FontFamily,FontId,Frame,Layout,RichText,ScrollArea,Stroke,TextEdit,Ui,Vec2};
use std::{collections::VecDeque,time::{Duration,Instant}};
use crate::project::LayoutSettings;
#[derive(Clone)]
struct Watch { address:usize,kind:ValueKind,value:String }

const ACCENT:Color32=Color32::from_rgb(99,153,250);
const GREEN:Color32=Color32::from_rgb(79,204,162);
const BG:Color32=Color32::from_rgb(22,25,33);
const PANEL:Color32=Color32::from_rgb(31,36,47);
const LINE:Color32=Color32::from_rgb(51,60,75);
const MUTED:Color32=Color32::from_rgb(155,168,190);
const REPO:&str="https://github.com/Chlna6666/BLoader-DevTools";

#[derive(Clone,Copy,PartialEq,Eq)]
enum Tab{Memory,LocalPlayer,Hex,Disasm,Signature,Script,Migration,Hooks,Settings}
impl Tab {
    const ALL:[Self;9]=[Self::Memory,Self::LocalPlayer,Self::Hex,Self::Disasm,Self::Signature,
        Self::Script,Self::Migration,Self::Hooks,Self::Settings];
    fn name(self)->&'static str { match self{
        Self::Memory=>"内存扫描",Self::LocalPlayer=>"本地玩家定位",Self::Hex=>"十六进制",
        Self::Disasm=>"反汇编",Self::Signature=>"AOB 特征",
        Self::Script=>"脚本实验室",Self::Migration=>"版本迁移",
        Self::Hooks=>"模块 / Hook",Self::Settings=>"设置",
    }}
}
pub fn configure_appearance(ctx:&egui::Context,dark:bool){
    let theme=if dark{egui::Theme::Dark}else{egui::Theme::Light};
    let mut style=(*ctx.style_of(theme)).clone();
    let mut visuals=if dark{egui::Visuals::dark()}else{egui::Visuals::light()};
    if dark {
        visuals.panel_fill=BG;
        visuals.window_fill=BG;
        visuals.extreme_bg_color=Color32::from_rgb(17,21,29);
        visuals.faint_bg_color=PANEL;
        visuals.widgets.inactive.bg_fill=PANEL;
        visuals.widgets.inactive.weak_bg_fill=PANEL;
        visuals.widgets.hovered.bg_fill=Color32::from_rgb(49,62,85);
        visuals.widgets.active.bg_fill=Color32::from_rgb(56,80,117);
        visuals.widgets.noninteractive.bg_stroke=Stroke::new(1.,LINE);
    }else{
        visuals.panel_fill=Color32::from_rgb(246,248,252);
        visuals.window_fill=Color32::WHITE;
    }
    visuals.selection.bg_fill=ACCENT;
    visuals.selection.stroke=Stroke::new(1.,Color32::WHITE);
    style.visuals=visuals;
    style.spacing.item_spacing=Vec2::new(7.,7.);
    style.spacing.button_padding=Vec2::new(9.,6.);
    style.spacing.interact_size.y=28.;
    style.text_styles.insert(egui::TextStyle::Body,FontId::new(14.,FontFamily::Proportional));
    style.text_styles.insert(egui::TextStyle::Button,FontId::new(13.,FontFamily::Proportional));
    style.text_styles.insert(egui::TextStyle::Monospace,FontId::new(13.,FontFamily::Monospace));
    style.text_styles.insert(egui::TextStyle::Small,FontId::new(12.,FontFamily::Proportional));
    style.text_styles.insert(egui::TextStyle::Heading,FontId::new(20.,FontFamily::Proportional));
    ctx.set_style_of(theme,style);
    ctx.set_theme(theme);
}
pub fn install_system_fonts(ctx:&egui::Context)->Result<String,String>{
    let folder=std::path::PathBuf::from(std::env::var_os("WINDIR").unwrap_or_else(||"C:\\Windows".into())).join("Fonts");
    for font in ["msyh.ttc","msyhbd.ttc","simhei.ttf","Deng.ttf","simsun.ttc"] {
        let path=folder.join(font);
        if let Ok(bytes)=std::fs::read(&path){
            let mut fonts=egui::FontDefinitions::default();
            fonts.font_data.insert("bloader_system_cjk".into(),egui::FontData::from_owned(bytes).into());
            for family in [FontFamily::Proportional,FontFamily::Monospace]{
                fonts.families.entry(family).or_default().insert(0,"bloader_system_cjk".into());
            }
            ctx.set_fonts(fonts);
            return Ok(path.display().to_string());
        }
    }
    Err("找不到已安装的中文 Windows 系统字体".into())
}

/// Resize panes by dragging visible splitter grips. Pointer delta is frame-local,
/// preventing accumulated overshoot when drag events span multiple frames.
fn drag_splitter(ui:&mut Ui,id:egui::Id,height:f32,positive:bool,value:&mut f32)->bool{
    let (rect,response)=ui.allocate_exact_size(
        Vec2::new(8.,height.max(8.)),egui::Sense::drag()
    );
    let _=id;
    let active=response.dragged() || response.hovered();
    ui.painter().rect_filled(rect.shrink2(Vec2::new(2.,8.)),3.,
        if active{ACCENT}else{LINE});
    if active {ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);}
    if response.dragged() {
        let dx=ui.input(|input|input.pointer.delta().x);
        if dx!=0. {
            *value=(*value+if positive{dx}else{-dx})
                .clamp(if positive{130.}else{165.},if positive{400.}else{430.});
            return true;
        }
    }
    false
}
fn drag_console_split(ui:&mut Ui,width:f32,height:&mut f32)->bool{
    let (rect,response)=ui.allocate_exact_size(Vec2::new(width.max(1.),8.),egui::Sense::drag());
    let active=response.hovered()||response.dragged();
    ui.painter().rect_filled(rect.shrink2(Vec2::new(12.,2.)),3.,
        if active{ACCENT}else{LINE});
    if active{ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeVertical);}
    if response.dragged() {
        let dy=ui.input(|input|input.pointer.delta().y);
        if dy!=0. {
            *height=(*height-dy).clamp(90.,340.);
            return true;
        }
    }
    false
}


/// Isometric wireframe preview of the measured bounding volume, not a
/// Minecraft RenderDragon model or verified Actor geometry.
fn draw_hitbox(ui:&mut Ui,box3:collision::Aabb){
    let (rect,_)=ui.allocate_exact_size(Vec2::new(235.,166.),egui::Sense::hover());
    let d=box3.extent();
    let center=rect.center();
    let scale=52.0/d.x.max(d.y).max(d.z).max(1.);
    let points=(0..8).map(|i|{
        let x=if i&1==0{-d.x/2.}else{d.x/2.};
        let y=if i&2==0{-d.y/2.}else{d.y/2.};
        let z=if i&4==0{-d.z/2.}else{d.z/2.};
        egui::pos2(center.x+(x-z)*0.85*scale,
            center.y+((x+z)*0.36-y)*scale)
    }).collect::<Vec<_>>();
    for i in 0..8 {
        for bit in [1usize,2,4] {
            if i&bit==0 {
                ui.painter().line_segment([points[i],points[i|bit]],Stroke::new(1.8,ACCENT));
            }
        }
    }
}

pub struct Workbench {
    tab:Tab,
    pub hide_requested:bool,
    engine:Engine,
    console:VecDeque<String>,
    hits:Vec<Hit>,
    module_lines:Vec<String>,
    result_lines:Vec<String>,
    dump:Vec<u8>,
    dump_base:usize,
    value_kind:ValueKind,
    scan_value:String,
    filter:Filter,
    address:String,
    read_size:String,
    write_old:String,
    write_new:String,
    write_armed:bool,
    aob:String,
    aob_test:String,
    feature_name:String,
    features:Vec<(String,String)>,
    script:String,
    script_writes:bool,
    old_file:String,
    new_file:String,
    dark:bool,
    left_width:f32,
    right_width:f32,
    bottom_height:f32,
    selected_hit:Option<usize>,
    hit_page:usize,
    scan_scope:ScanScope,
    scan_budget:usize,
    start_addr:String,
    end_addr:String,
    watches:Vec<Watch>,
    watch_due:Instant,
    show_explorer:bool,
    show_inspector:bool,
    show_console:bool,
    layout_dirty:bool,
    player_source:String,
    player_source_kind:SourceKind,
    player_access_vtable:bool,
    player_offset:String,
    player_candidate:Option<Candidate>,
    player_lines:Vec<String>,
    player_index_hit:Option<usize>,
    player_profiles:Vec<String>,
    collision_hits:Vec<collision::Hit>,
    collision_width:f32,
    collision_height:f32,
    collision_tolerance:f32,
    collision_use_coords:bool,
    collision_coords:[String;3],
    collision_radius:f32,
    collision_motion:Motion,
    collision_selected:Option<usize>,
    collision_page:usize,
    discovery_report:Option<discovery::Report>,
    discovery_budget:usize,
    symbol_module:String,
    symbol_name:String,
    symbol_use_pdb:bool,
    symbol_status:Vec<String>,
}
impl Default for Workbench{
    fn default()->Self{
        let layout=crate::project::load_layout().unwrap_or_default();
        Self {
            tab:Tab::Memory,hide_requested:false,engine:Engine::start(),
            console:VecDeque::from(["DevTools 工作区已就绪；扫描、解析和脚本在专用后台线程运行。".into()]),
            hits:Vec::new(),module_lines:Vec::new(),result_lines:Vec::new(),
            dump:Vec::new(),dump_base:0,value_kind:ValueKind::F32,
            scan_value:"90".into(),filter:Filter::Exact,address:"0x0".into(),
            read_size:"256".into(),write_old:"90".into(),write_new:"65".into(),
            write_armed:false,aob:"48 8B 05 ?? ?? ?? ?? 48 85 C0".into(),
            aob_test:"90 48 8B 05 01 02 03 04 48 85 C0 C3".into(),
            feature_name:"camera.fov".into(),
            features:crate::project::features().unwrap_or_default(),
            script:crate::project::load_script().unwrap_or_else(|_|crate::script::EXAMPLE.into()),
            script_writes:false,old_file:String::new(),new_file:String::new(),
            dark:true,left_width:layout.explorer_width,
            right_width:layout.inspector_width,bottom_height:layout.console_height,
            selected_hit:None,hit_page:0,scan_scope:ScanScope::Writable,
            scan_budget:128,start_addr:"0x10000".into(),end_addr:"最大地址".into(),
            watches:crate::project::load_watches().unwrap_or_default().into_iter()
                .map(|(address,kind)|Watch{address,kind,value:"等待刷新".into()})
                .collect(),
            watch_due:Instant::now(),
            show_explorer:layout.explorer_visible,
            show_inspector:layout.inspector_visible,
            show_console:layout.console_visible,layout_dirty:false,
            player_source:"0x0".into(),
            player_source_kind:SourceKind::DirectInstance,
            player_access_vtable:true,
            player_offset:"0".into(),
            player_candidate:None,
            player_lines:Vec::new(),
            player_index_hit:None,
            player_profiles:crate::project::local_player_recipes().unwrap_or_default(),
            collision_hits:Vec::new(),
            collision_width:0.6,
            collision_height:1.8,
            collision_tolerance:0.035,
            collision_use_coords:false,
            collision_coords:["0".into(),"64".into(),"0".into()],
            collision_radius:4.0,
            collision_motion:Motion::Horizontal,
            collision_selected:None,
            collision_page:0,
            discovery_report:None,
            discovery_budget:256,
            symbol_module:"Minecraft.Windows.exe".into(),
            symbol_name:"ClientInstance::getLocalPlayer".into(),
            symbol_use_pdb:false,
            symbol_status:Vec::new(),
        }
    }
}
impl Workbench{
    pub fn navigate(&mut self,name:&str)->Result<String,String>{
        self.tab=match name.trim().to_ascii_lowercase().as_str(){
            "memory"|"scan"|"内存扫描"=>Tab::Memory,
            "localplayer"|"player"|"本地玩家"|"本地玩家定位"=>Tab::LocalPlayer,
            "hex"|"十六进制"=>Tab::Hex,
            "disasm"|"反汇编"=>Tab::Disasm,
            "signature"|"aob"|"特征"=>Tab::Signature,
            "script"|"脚本"=>Tab::Script,
            "migration"|"迁移"=>Tab::Migration,
            "hooks"|"modules"|"模块"=>Tab::Hooks,
            "settings"|"设置"=>Tab::Settings,
            _=>return Err(format!("未知工作台工具标签：{name}")),
        };
        Ok(format!("已在 UI 线程切换到：{}",self.tab.name()))
    }
    pub fn status_summary(&self)->String{
        let recent=self.console.iter().rev().take(5).cloned().collect::<Vec<_>>();
        format!("tool={} busy={} candidates={} watches={} explorer={} inspector={} console={} recent_logs={:?}",
            self.tab.name(),self.engine.busy,self.hits.len(),self.watches.len(),
            self.show_explorer,self.show_inspector,self.show_console,recent)
    }
    fn collision_profile(&self)->Result<collision::Profile,String>{
        let feet_hint=if self.collision_use_coords{
            let v=self.collision_coords.iter().map(|text|
                text.trim().parse::<f32>().map_err(|_|"坐标必须是数字".to_owned())
            ).collect::<Result<Vec<_>,_>>()?;
            Some(collision::Vec3{x:v[0],y:v[1],z:v[2]})
        }else{None};
        collision::Profile{
            width:self.collision_width,height:self.collision_height,
            tolerance:self.collision_tolerance,
            feet_hint,radius:self.collision_radius,
        }.validate()
    }
    /// Used by explicitly enabled localhost MCP, dispatched on DevTools UI
    /// thread; the actual memory scan still runs on Engine's worker thread.
    pub fn scan_collision_for_ai(&mut self,profile:collision::Profile,budget:usize)
        ->Result<String,String>{
        let profile=profile.validate()?;
        let mut options=self.scan_options()?;
        options.scope=ScanScope::Writable;
        options.budget_mib=budget;
        let options=options.validate()?;
        self.engine.submit(Command::ScanPlayerAabb{profile,options})?;
        self.collision_width=profile.width;
        self.collision_height=profile.height;
        self.collision_tolerance=profile.tolerance;
        self.collision_use_coords=profile.feet_hint.is_some();
        if let Some(p)=profile.feet_hint{
            self.collision_coords=[p.x.to_string(),p.y.to_string(),p.z.to_string()];
        }
        self.collision_radius=profile.radius;
        self.scan_budget=budget;
        self.tab=Tab::LocalPlayer;
        self.log("AI 已提交碰撞箱后台扫描；使用碰撞箱结果工具轮询完成状态");
        Ok("任务已提交，请轮询 devtools_collision_results 等待 busy=false".into())
    }
    pub fn refine_collision_for_ai(&mut self,motion:Motion)->Result<String,String>{
        if self.collision_hits.is_empty(){
            return Err("还没有碰撞箱候选，请先扫描并等待完成".into());
        }
        let mut profile=self.collision_profile()?;
        profile.feet_hint=None;
        self.engine.submit(Command::RefinePlayerAabb{profile,motion})?;
        self.collision_motion=motion;
        self.tab=Tab::LocalPlayer;
        Ok(format!("已提交碰撞箱{}筛选；等待完成后读取结果",motion.label()))
    }
    pub fn discover_player_for_ai(&mut self,profile:collision::Profile,budget:usize,
        instance:Option<usize>)->Result<String,String>{
        let options=DiscoveryOptions{profile,budget_mib:budget,source_instance:instance}.validate()?;
        self.engine.submit(Command::DiscoverLocalPlayer(options))?;
        self.tab=Tab::LocalPlayer;
        self.discovery_report=None;
        self.discovery_budget=budget;
        self.collision_width=profile.width;
        self.collision_height=profile.height;
        self.collision_tolerance=profile.tolerance;
        self.collision_use_coords=profile.feet_hint.is_some();
        if let Some(coords)=profile.feet_hint {
            self.collision_coords=[coords.x.to_string(),coords.y.to_string(),coords.z.to_string()];
        }
        self.collision_radius=profile.radius;
        Ok("已提交 Symbol Resolver → ECS Inspector → LocalPlayer Validator；用 devtools_player_report 轮询（任何结果只作为候选）。".into())
    }
    pub fn refine_discovered_for_ai(&mut self,motion:Motion)->Result<String,String>{
        if self.discovery_report.is_none(){return Err("尚无统一发现候选，请先完成统一分析".into());}
        let mut profile=self.collision_profile()?;
        profile.feet_hint=None;
        self.engine.submit(Command::RefineDiscoveredPlayer{motion,profile})?;
        self.collision_motion=motion;
        Ok(format!("已提交行为验证（{}）；请稍后读取 devtools_player_report",motion.label()))
    }
    pub fn discovery_status_for_ai(&mut self)->String{
        self.poll();
        match &self.discovery_report{
            Some(r)=>format!("busy={}\n{}",self.engine.busy,discovery::summarise(r)),
            None=>format!("busy={}；尚无统一定位报告或任务尚未完成",self.engine.busy),
        }
    }
    pub fn collision_results_for_ai(&mut self,count:usize)->String {
        // poll now, as the user might query from MCP without an active
        // continuous repaint trigger.
        self.poll();
        let mut text=format!("busy={} candidates={}; AABB 地址不是 Actor*/LocalPlayer*\\n",
            self.engine.busy,self.collision_hits.len());
        for hit in self.collision_hits.iter().take(count.clamp(1,50)){
            text.push_str(&collision::describe(hit));
            text.push('\n');
        }
        text
    }
    pub fn needs_poll(&self)->bool{self.engine.busy || (!self.watches.is_empty() && self.watch_due.elapsed()>=Duration::from_millis(700))}
    fn line(&self)->Color32{if self.dark{LINE}else{Color32::from_rgb(213,223,233)}}
    fn panel(&self)->Color32{if self.dark{PANEL}else{Color32::WHITE}}
    fn muted(&self)->Color32{if self.dark{MUTED}else{Color32::from_rgb(83,96,113)}}
    fn persist_layout(&mut self) {
        if !self.layout_dirty{return;}
        let layout=LayoutSettings{
            explorer_width:self.left_width,inspector_width:self.right_width,
            console_height:self.bottom_height,
            explorer_visible:self.show_explorer,inspector_visible:self.show_inspector,
            console_visible:self.show_console,
        };
        match crate::project::save_layout(&layout){
            Ok(_)=>self.layout_dirty=false,
            Err(e)=>{self.layout_dirty=false;self.log(format!("保存界面布局失败：{e}"));}
        }
    }
    fn log(&mut self,message:impl Into<String>){
        self.console.push_back(message.into());
        while self.console.len()>280{self.console.pop_front();}
    }
    fn job(&mut self,command:Command){
        match self.engine.submit(command){
            Ok(())=>self.log("后台任务已提交"),
            Err(err)=>self.log(format!("无法提交任务：{err}"))
        }
    }
    fn scan_options(&self)->Result<ScanOptions,String>{
        let start=memory::parse_address(&self.start_addr)?;
        let end=if self.end_addr.trim()=="最大地址" || self.end_addr.trim().is_empty(){
            usize::MAX
        }else{memory::parse_address(&self.end_addr)?};
        ScanOptions{start,end,scope:self.scan_scope,budget_mib:self.scan_budget}.validate()
    }
    fn save_watch_list(&mut self){
        let entries=self.watches.iter().map(|w|(w.address,w.kind)).collect::<Vec<_>>();
        if let Err(e)=crate::project::save_watches(&entries){
            self.log(format!("监视表保存失败：{e}"));
        }
    }
    fn add_watch(&mut self,address:usize){
        if self.watches.iter().any(|x|x.address==address){self.log("地址已在监视列表");return;}
        if self.watches.len()>=64{self.log("最多监视 64 个地址");return;}
        self.watches.push(Watch{address,kind:self.value_kind,value:"等待刷新".into()});
        self.save_watch_list();
        self.watch_due=Instant::now()-Duration::from_secs(1);
    }
    fn poll(&mut self){
        if let Some(report)=self.engine.poll(){
            if report.title=="地址监视刷新" {
                for (address,kind,value) in report.watch_values {
                    if let Some(w)=self.watches.iter_mut().find(|w|w.address==address && w.kind==kind){
                        w.value=value;
                    }
                }
            } else {
                self.log(format!("{} · {}",report.title,report.lines.len()));
                for line in &report.lines {self.log(line.clone());}
            }
            match report.title.as_str(){
                "符号模块清单"|"客户端符号解析"=>{
                    self.symbol_status=report.lines.clone();
                },
                "统一本地玩家分析"|"统一定位行为验证"=>{
                    self.discovery_report=report.discovery;
                },
                "玩家碰撞箱首次扫描"|"玩家碰撞箱动态筛选"=>{
                    if let Some(items)=report.player_hitboxes {
                        self.collision_hits=items;
                        self.collision_selected=None;
                        self.collision_page=0;
                    }
                },
                "本地玩家候选检查"=>{
                    self.player_lines=report.lines.clone();
                    self.player_candidate=report.player_candidate.clone();
                },
                "本地玩家虚表索引特征"=>{
                    self.player_lines=report.lines.clone();
                    self.player_index_hit=report.index_candidate;
                    if let Some(index)=report.index_candidate{
                        self.player_access_vtable=true;
                        self.player_offset=index.to_string();
                    }
                },
                "首次精确扫描"|"再次扫描"|"游戏内特征扫描"|"脚本执行结果"=>{
                    self.hits=report.hits;
                    self.selected_hit=None;
                    self.hit_page=0;
                    if !self.hits.first().is_some_and(|h|h.bytes.is_empty()) {
                        self.value_kind=report.kind;
                    }
                },
                "十六进制查看"=>{self.dump=report.dump;self.dump_base=report.dump_base;},
                "反汇编"|"跨版本 AOB 对比"=>{self.result_lines=report.lines;},
                "进程模块快照"=>{self.module_lines=report.lines;},
                _=>{}
            }
        }
        if !self.engine.busy && !self.watches.is_empty() && self.watch_due.elapsed()>=Duration::from_millis(700) {
            let values=self.watches.iter().map(|w|(w.address,w.kind)).collect();
            if self.engine.submit(Command::Watch(values)).is_ok(){
                self.watch_due=Instant::now();
            }
        }
    }
    pub fn ui(&mut self,ui:&mut Ui){
        self.poll();
        // IDE keyboard navigation. The game receives no extra global hotkeys.
        let shortcuts=[
            (egui::Key::Num1,"memory"),(egui::Key::Num2,"hex"),
            (egui::Key::Num3,"disasm"),(egui::Key::Num4,"signature"),
            (egui::Key::Num5,"script"),(egui::Key::Num6,"migration"),
            (egui::Key::Num7,"hooks"),(egui::Key::Num8,"settings"),
            (egui::Key::Num9,"localplayer"),
        ];
        for (key,tool) in shortcuts {
            if ui.input(|input|input.modifiers.ctrl && input.key_pressed(key)){
                let _=self.navigate(tool);
            }
        }
        let viewport=ui.available_size();
        let width=viewport.x.max(320.);
        let height=viewport.y.max(320.);
        let left=if self.show_explorer && width>630. {
            self.left_width.clamp(130.,(width-300.).max(130.))
        }else{0.};
        let right=if self.show_inspector && width>950. {
            self.right_width.clamp(165.,(width-left-360.).max(165.))
        }else{0.};
        let bottom=if self.show_console {
            self.bottom_height.clamp(90.,(height-190.).max(90.))
        }else{0.};
        // Primary toolbar / breadcrumb.
        ui.allocate_ui_with_layout(Vec2::new(width,43.),Layout::left_to_right(Align::Center),|ui|{
            ui.add_space(12.);
            ui.label(RichText::new("B").color(Color32::WHITE).strong().background_color(ACCENT).size(21.));
            ui.label(RichText::new("BLoader DevTools").strong().size(17.));
            ui.separator();
            ui.label(RichText::new("Minecraft Bedrock").color(self.muted()));
            ui.label(RichText::new(" / ").color(self.muted()));
            ui.label(self.tab.name());
            ui.label(RichText::new("Ctrl+1…9").small().color(self.muted()));
            ui.menu_button("视图",|ui|{
                if ui.checkbox(&mut self.show_explorer,"项目导航").changed(){self.layout_dirty=true;}
                if ui.checkbox(&mut self.show_inspector,"地址检查器").changed(){self.layout_dirty=true;}
                if ui.checkbox(&mut self.show_console,"底部控制台").changed(){self.layout_dirty=true;}
                ui.separator();
                if ui.button("恢复默认布局").clicked(){
                    let defaults=LayoutSettings::default();
                    self.left_width=defaults.explorer_width;
                    self.right_width=defaults.inspector_width;
                    self.bottom_height=defaults.console_height;
                    self.show_explorer=true;
                    self.show_inspector=true;
                    self.show_console=true;
                    self.layout_dirty=true;
                    ui.close();
                }
            });
            ui.with_layout(Layout::right_to_left(Align::Center),|ui|{
                if ui.button("设置").clicked(){self.tab=Tab::Settings;}
                if self.engine.busy {ui.spinner();ui.label("后台任务中");if ui.button("取消任务").clicked(){self.engine.cancel();}}
                else {ui.label(RichText::new("BL Mod  ·  就绪").color(GREEN));}
            });
        });
        ui.separator();
        let main_height=(height-bottom-97.).max(120.);
        ui.allocate_ui_with_layout(Vec2::new(width,main_height),Layout::left_to_right(Align::Min),|ui|{
            if left>0.{
                ui.allocate_ui_with_layout(Vec2::new(left,main_height),Layout::top_down(Align::Min),|ui|{
                    self.left_panel(ui);
                });
                if drag_splitter(ui,egui::Id::new("explorer_split"),main_height,true,&mut self.left_width){
                    self.layout_dirty=true;
                }
            }
            let mid=(ui.available_width()-right-(if right>0.{8.}else{0.})).max(180.);
            ui.allocate_ui_with_layout(Vec2::new(mid,main_height),Layout::top_down(Align::Min),|ui|{
                self.editor(ui);
            });
            if right>0. {
                if drag_splitter(ui,egui::Id::new("inspector_split"),main_height,false,&mut self.right_width){
                    self.layout_dirty=true;
                }
                ui.allocate_ui_with_layout(Vec2::new(right,main_height),Layout::top_down(Align::Min),|ui|{
                    self.inspector(ui);
                });
            }
        });
        if bottom>0.{
            if drag_console_split(ui,width,&mut self.bottom_height){self.layout_dirty=true;}
            ui.allocate_ui_with_layout(Vec2::new(width,bottom),Layout::top_down(Align::Min),|ui|{
                self.bottom_panel(ui);
            });
        }
        // On narrow game windows keep the address inspector accessible.
        if self.show_inspector && width<=850. {
            let mut open=true;
            let ctx=ui.ctx().clone();
            egui::Window::new("地址检查器")
                .id(egui::Id::new("compact_inspector"))
                .open(&mut open).resizable(true).default_width(275.)
                .show(&ctx,|ui|self.inspector(ui));
            if !open {
                self.show_inspector=false;
                self.layout_dirty=true;
            }
        }
        ui.separator();
        if self.layout_dirty && ui.input(|input|!input.pointer.any_down()){
            self.persist_layout();
        }
        ui.horizontal(|ui|{
            ui.add_space(10.);
            ui.label(RichText::new(format!("BLoader DevTools v{}  ·  GPL-3.0-only",env!("CARGO_PKG_VERSION"))).color(self.muted()).small());
            ui.separator();
            ui.label(RichText::new(format!("候选：{}  ·  后台线程：{}",self.hits.len(),if self.engine.busy{"忙碌"}else{"空闲"})).color(self.muted()).small());
            ui.with_layout(Layout::right_to_left(Align::Center),|ui|{
                ui.label(RichText::new("F8 可选 · 自动显示").color(self.muted()).small());
            });
        });
    }
    fn left_panel(&mut self,ui:&mut Ui){
        ui.add_space(9.);
        ui.horizontal(|ui|{
            ui.label(RichText::new("  项目").strong());
            if ui.small_button("↻").clicked(){
                self.features=crate::project::features().unwrap_or_default();
            }
        });
        ui.separator();
        ScrollArea::vertical().id_salt("explorer").show(ui,|ui|{
            for tab in Tab::ALL{
                if ui.add(egui::Button::new(tab.name()).selected(self.tab==tab)
                    .min_size(Vec2::new(ui.available_width().max(100.),29.))).clicked(){
                    self.tab=tab;
                }
            }
            ui.add_space(10.);
            ui.label(RichText::new("  已保存特征").color(self.muted()).small());
            let features=self.features.clone();
            for (name,aob) in features{
                if ui.small_button(format!("◇ {name}")).clicked(){
                    self.aob=aob;
                    self.feature_name=name;
                    self.tab=Tab::Signature;
                }
            }
        });
        ui.separator();
        ui.collapsing("面板布局",|ui|{
            ui.label("左栏宽度");
            if ui.add(egui::Slider::new(&mut self.left_width,130. ..= 400.)).changed(){self.layout_dirty=true;}
            ui.label("检查器宽度");
            if ui.add(egui::Slider::new(&mut self.right_width,165. ..= 430.)).changed(){self.layout_dirty=true;}
        });
    }
    fn editor(&mut self,ui:&mut Ui){
        ui.horizontal_wrapped(|ui|{
            for tab in Tab::ALL{
                if ui.selectable_label(self.tab==tab,tab.name()).clicked(){self.tab=tab;}
            }
        });
        ui.separator();
        ScrollArea::vertical().id_salt("editor").auto_shrink([false,false]).show(ui,|ui|{
            ui.add_space(8.);
            match self.tab{
                Tab::Memory=>self.memory_editor(ui),
                Tab::LocalPlayer=>self.localplayer_editor(ui),
                Tab::Hex=>self.hex_editor(ui),
                Tab::Disasm=>self.disasm_editor(ui),
                Tab::Signature=>self.signature_editor(ui),
                Tab::Script=>self.script_editor(ui),
                Tab::Migration=>self.migration_editor(ui),
                Tab::Hooks=>self.hooks_editor(ui),
                Tab::Settings=>self.settings_editor(ui),
            }
        });
    }

    fn localplayer_editor(&mut self,ui:&mut Ui){
        ui.heading("本地玩家 / LocalPlayer 定位向导");
        ui.label(RichText::new("开发常用路径：ClientInstance → getLocalPlayer() → LocalPlayer。此页只读，不调用未验证的游戏虚函数。")
            .color(self.muted()).small());
        ui.add_space(8.);
        Frame::new().fill(self.panel()).inner_margin(12.).show(ui,|ui|{
            ui.strong("模块符号 / Local PDB · 符号库按 SHA-256 精确匹配");
            ui.horizontal_wrapped(|ui|{
                ui.label("模块");
                ui.add(TextEdit::singleline(&mut self.symbol_module).desired_width(190.));
                ui.label("符号");
                ui.add(TextEdit::singleline(&mut self.symbol_name).desired_width(210.));
            });
            ui.horizontal_wrapped(|ui|{
                ui.checkbox(&mut self.symbol_use_pdb,"允许本地 DbgHelp/PDB（不联网）");
                if ui.add_enabled(!self.engine.busy,egui::Button::new("刷新模块")).clicked(){
                    self.job(Command::SymbolInventory);
                }
                if ui.add_enabled(!self.engine.busy,egui::Button::new("解析符号")).clicked(){
                    self.job(Command::ResolveSymbol{
                        module:self.symbol_module.clone(),
                        symbol:self.symbol_name.clone(),
                        local_pdb:self.symbol_use_pdb,
                    });
                }
            });
            ui.label(RichText::new(
                "版本库：%LOCALAPPDATA%/BLoader-DevTools/symbol_profiles.json · ECS：ecs_layouts.json。没有同一模块 SHA-256 的记录时不套用偏移。")
                .small().color(self.muted()));
            for line in self.symbol_status.iter().take(12){
                ui.label(RichText::new(line).monospace().small());
            }
        });
        ui.add_space(8.);
        Frame::new().fill(self.panel()).inner_margin(12.).show(ui,|ui|{
            ui.heading("一键分析 · Symbol Resolver → ECS Inspector → LocalPlayer Validator");
            ui.label(RichText::new("按游戏模块参考符号定位，再检查 ECS 碰撞箱/位置向量和内存引用；最后尝试 MSVC RTTI 对象类型校验。全程后台只读。")
                .color(self.muted()).small());
            ui.horizontal_wrapped(|ui|{
                ui.label("扫描预算（MiB）");
                ui.add(egui::DragValue::new(&mut self.discovery_budget).range(16..=1024).speed(16));
                if ui.add_enabled(!self.engine.busy,egui::Button::new("开始统一分析")).clicked(){
                    match self.collision_profile(){
                        Ok(profile)=>{
                            let instance=memory::parse_address(&self.player_source).ok()
                                .filter(|addr|*addr>=0x10000);
                            let opts=DiscoveryOptions{
                                profile,budget_mib:self.discovery_budget,source_instance:instance,
                            };
                            if let Err(e)=opts.validate(){
                                self.log(format!("分析参数错误：{e}"));
                            }else{
                                self.discovery_report=None;
                                self.job(Command::DiscoverLocalPlayer(opts));
                            }
                        }
                        Err(e)=>self.log(format!("分析参数错误：{e}")),
                    }
                }
            });
            ui.horizontal_wrapped(|ui|{
                egui::ComboBox::from_id_salt("discovery-motion")
                    .selected_text(self.collision_motion.label()).show_ui(ui,|ui|{
                        for kind in Motion::ALL {
                            ui.selectable_value(&mut self.collision_motion,kind,kind.label());
                        }
                    });
                if ui.add_enabled(!self.engine.busy &&
                        self.discovery_report.as_ref().is_some_and(|r|!r.seeds.is_empty()),
                        egui::Button::new("动作完成后进行行为验证")).clicked(){
                    match self.collision_profile(){
                        Ok(mut profile)=>{
                            profile.feet_hint=None;
                            self.job(Command::RefineDiscoveredPlayer{
                                motion:self.collision_motion,profile,
                            });
                        }
                        Err(e)=>self.log(format!("行为验证参数错误：{e}")),
                    }
                }
                if let Some(report)=&self.discovery_report {
                    ui.label(format!("已验证 {} 轮",report.validation_rounds));
                }
            });
            if self.collision_use_coords {
                ui.label(RichText::new("已启用 HUD 坐标：额外检索 Vec3 位置结构，即使 AABB 布局改变仍可给出空间候选。")
                    .small().color(GREEN));
            } else {
                ui.label(RichText::new("建议勾选下方「利用已知世界坐标」并输入玩家的 X/Y/Z。没有坐标时，仍可能因组件布局变化出现零候选。")
                    .small().color(self.muted()));
            }
            ui.label(RichText::new("无论是否命中：仅凭 RTTI、引用链或空间位置都不能证明本地玩家身份，未取得游戏线程 getter 结果前不会导出 Actor*。")
                .small().color(self.muted()));
            let candidate_symbol=self.discovery_report.as_ref().and_then(|report|{
                (report.symbol.matches.len()==1).then(||
                    (report.symbol.matches[0],report.symbol.base)
                )
            });
            if let Some((address,base))=candidate_symbol {
                ui.horizontal(|ui|{
                    if ui.small_button("反汇编候选符号").clicked(){
                        self.address=format!("0x{address:X}");
                        self.tab=Tab::Disasm;
                        self.job(Command::Disassemble(address,32));
                    }
                    if ui.small_button("复制候选 RVA（未验证）").clicked(){
                        ui.ctx().copy_text(format!("0x{:X}",address.saturating_sub(base)));
                    }
                });
            }
            if let Some(report)=&self.discovery_report {
                if ui.small_button("复制完整分析报告").clicked(){
                    ui.ctx().copy_text(discovery::summarise(report));
                }
            }
            if let Some(report)=&self.discovery_report{
                ui.separator();
                ui.strong(format!("符号定位：{}",report.symbol.status));
                ui.label(format!(
                    "ECS 私有堆覆盖 {:.2}%（读 {:.1} / {:.1} MiB） · 读取失败 {} · 候选 {}",
                    if report.eligible_bytes>0 {100.*report.scanned_bytes as f64/report.eligible_bytes as f64}else{0.},
                    report.scanned_bytes as f64/1048576.,
                    report.eligible_bytes as f64/1048576.,
                    report.failed_reads,report.seeds.len()
                ));
                if report.cancelled{
                    ui.colored_label(Color32::YELLOW,"已取消；结果非完整扫描");
                }
                for item in report.inspected.iter().take(5){
                    ui.horizontal_wrapped(|ui|{
                        ui.monospace(format!("0x{:X}",item.seed.address));
                        ui.label(format!("{} · {} · 得分 {} · 引用 {}",
                            item.seed.kind.label(),item.confidence,item.score,item.links.len()));
                        if ui.small_button("复制地址").clicked(){
                            ui.ctx().copy_text(format!("0x{:X}",item.seed.address));
                        }
                    });
                    for link in item.links.iter().take(3) {
                        ui.label(RichText::new(format!(
                            "    ECS 引用 0x{:X} → 0x{:X}，候选 Actor: {}",
                            link.pointer_slot,link.points_to,
                            link.type_hint.as_deref().unwrap_or("RTTI 未识别")
                        )).monospace().small().color(self.muted()));
                    }
                }
                ui.label(RichText::new("完整阶段报告已输出到底部任务控制台，也可通过 MCP 的 devtools_player_report 获取。")
                    .small().color(self.muted()));
            }
        });
        ui.add_space(8.);
        Frame::new().fill(self.panel()).inner_margin(12.).show(ui,|ui|{
            ui.heading("快速查找 · 玩家 3D 碰撞箱");
            ui.label(RichText::new("默认按站立玩家 0.6 × 1.8 × 0.6 的 AABB 几何结构搜索；如潜行、游泳、版本变更，可调整宽高。")
                .small().color(self.muted()));
            ui.horizontal_wrapped(|ui|{
                ui.label("宽度");
                ui.add(egui::DragValue::new(&mut self.collision_width).speed(0.01).range(0.1..=5.));
                ui.label("高度");
                ui.add(egui::DragValue::new(&mut self.collision_height).speed(0.01).range(0.2..=5.));
                ui.label("容差");
                ui.add(egui::DragValue::new(&mut self.collision_tolerance).speed(0.002).range(0.001..=0.25));
            });
            ui.horizontal_wrapped(|ui|{
                ui.checkbox(&mut self.collision_use_coords,"利用已知世界坐标（脚底位置）加速筛选");
                if self.collision_use_coords {
                    for (i,name) in ["X","Y","Z"].iter().enumerate(){
                        ui.label(*name);
                        ui.add(TextEdit::singleline(&mut self.collision_coords[i]).desired_width(75.));
                    }
                    ui.label("半径");
                    ui.add(egui::DragValue::new(&mut self.collision_radius).speed(0.5).range(0.25..=5000.));
                }
            });
            ui.horizontal_wrapped(|ui|{
                if ui.add_enabled(!self.engine.busy,egui::Button::new("开始碰撞箱快速扫描")).clicked(){
                    match (self.collision_profile(),self.scan_options()){
                        (Ok(profile),Ok(mut options))=>{
                            options.scope=ScanScope::Writable;
                            self.job(Command::ScanPlayerAabb{profile,options});
                        }
                        (Err(e),_)|(_,Err(e))=>self.log(format!("扫描参数无效：{e}")),
                    }
                }
                egui::ComboBox::from_id_salt("collision-motion")
                    .selected_text(self.collision_motion.label()).show_ui(ui,|ui|{
                    for kind in Motion::ALL{
                        ui.selectable_value(&mut self.collision_motion,kind,kind.label());
                    }
                });
                if ui.add_enabled(!self.engine.busy && !self.collision_hits.is_empty(),
                    egui::Button::new("动作后筛选")).clicked(){
                    match self.collision_profile(){
                        Ok(mut profile)=>{
                            // During movement, coordinates differ from the initial hint.
                            // Refine on shape & motion, not on stale absolute XYZ.
                            profile.feet_hint=None;
                            self.job(Command::RefinePlayerAabb{
                                profile,motion:self.collision_motion
                            });
                        }
                        Err(e)=>self.log(format!("碰撞参数错误：{e}"))
                    }
                }
            });
            ui.label(RichText::new("建议流程：入世界静止时首次扫描 → 走几步后水平筛选 → 再跳跃筛选。动态筛选应在动作完成后点击，不能在同一帧循环扫描。")
                .small().color(self.muted()));
            ui.label(RichText::new(format!("候选数：{}；扫描预算由「内存扫描」的 MiB 和起止地址控制。",self.collision_hits.len()))
                .strong());
            if !self.collision_hits.is_empty(){
                let max_pages=self.collision_hits.len().div_ceil(30).max(1);
                self.collision_page=self.collision_page.min(max_pages-1);
                ui.horizontal(|ui|{
                    if ui.add_enabled(self.collision_page>0,egui::Button::new("上一页")).clicked(){self.collision_page-=1;}
                    ui.label(format!("{}/{}",self.collision_page+1,max_pages));
                    if ui.add_enabled(self.collision_page+1<max_pages,egui::Button::new("下一页")).clicked(){self.collision_page+=1;}
                });
                let start=self.collision_page*30;
                egui::Grid::new("collision-candidates").striped(true).show(ui,|ui|{
                    ui.strong("AABB 内存地址");ui.strong("中心坐标");ui.strong("采样");ui.end_row();
                    for i in start..(start+30).min(self.collision_hits.len()){
                        let item=&self.collision_hits[i];
                        let center=item.box3.center();
                        if ui.selectable_label(self.collision_selected==Some(i),
                            format!("0x{:X}",item.address)).clicked(){
                            self.collision_selected=Some(i);
                        }
                        ui.monospace(format!("{:.1}, {:.1}, {:.1}",center.x,center.y,center.z));
                        ui.label(item.samples.to_string());
                        ui.end_row();
                    }
                });
                if let Some(index)=self.collision_selected {
                    if let Some(item)=self.collision_hits.get(index){
                        ui.separator();
                        ui.strong("候选碰撞箱 3D 线框（示意投影）");
                        draw_hitbox(ui,item.box3);
                        ui.label(collision::describe(item));
                        let address=item.address;
                        ui.horizontal(|ui|{
                            if ui.button("复制 AABB 地址").clicked(){
                                ui.ctx().copy_text(format!("0x{address:X}"));
                            }
                            if ui.button("转到十六进制").clicked(){
                                self.address=format!("0x{address:X}");
                                self.tab=Tab::Hex;
                                self.job(Command::Read(address,128));
                            }
                        });
                    }
                }
            }
            ui.label(RichText::new("重要：AABB 数据地址 ≠ Actor* ≠ LocalPlayer*。同尺寸实体、玩家影子对象和缓存都可能命中；需进一步验证实例归属及生命周期。")
                .color(self.muted()).small());
        });
        ui.add_space(8.);
        Frame::new().fill(self.panel()).inner_margin(12.).show(ui,|ui|{
            ui.strong("第 1 步 · 定位 getLocalPlayer 虚表索引");
            ui.label("参考已有客户端的已知特征，在当前游戏 EXE 可执行内存中寻找唯一匹配。");
            if ui.add_enabled(!self.engine.busy,egui::Button::new("扫描参考特征（游戏主 EXE）")).clicked(){
                self.job(Command::FindLocalPlayerIndex);
            }
            if ui.button("把参考特征复制到 AOB 工作区").clicked(){
                self.aob=local_player::INDEX_REFERENCE_AOB.into();
                self.tab=Tab::Signature;
            }
            if let Some(index)=self.player_index_hit{
                ui.label(RichText::new(format!("候选虚表索引：{index}（尚未验证）"))
                    .color(GREEN).strong());
            }
            ui.label(RichText::new("找不到匹配或匹配多项时，不猜测索引。其他游戏版本需重新验证。").small().color(self.muted()));
        });
        ui.add_space(12.);
        Frame::new().fill(self.panel()).inner_margin(12.).show(ui,|ui|{
            ui.strong("第 2 步 · 输入 ClientInstance 来源");
            ui.horizontal_wrapped(|ui|{
                ui.label("地址");
                ui.add(TextEdit::singleline(&mut self.player_source).desired_width(220.));
                egui::ComboBox::from_id_salt("player-source-mode")
                    .selected_text(self.player_source_kind.label()).show_ui(ui,|ui|{
                    for kind in [SourceKind::DirectInstance,SourceKind::PointerSlot]{
                        ui.selectable_value(&mut self.player_source_kind,kind,kind.label());
                    }
                });
            });
            ui.label(RichText::new("来源应先通过客户端初始化调用点/已确认的 ClientInstance 指针获取；不能凭虚表索引推断对象地址。").small().color(self.muted()));
            ui.horizontal_wrapped(|ui|{
                ui.selectable_value(&mut self.player_access_vtable,true,"虚表函数索引（新版推荐）");
                ui.selectable_value(&mut self.player_access_vtable,false,"成员指针偏移（仅明确版本）");
            });
            ui.horizontal_wrapped(|ui|{
                ui.label(if self.player_access_vtable{"索引（十进制或 0x）"}else{"成员偏移（十进制或 0x）"});
                ui.add(TextEdit::singleline(&mut self.player_offset).desired_width(120.));
                if ui.add_enabled(!self.engine.busy,egui::Button::new("只读检查候选")).clicked(){
                    let params=memory::parse_address(&self.player_source)
                        .and_then(|source|local_player::parse_offset(&self.player_offset).map(|offset|(source,offset)));
                    match params{
                        Ok((source,offset))=>{
                            self.player_candidate=None;
                            let access=if self.player_access_vtable {
                                PlayerAccess::VtableIndex(offset)
                            }else{PlayerAccess::MemberOffset(offset)};
                            self.job(Command::ProbeLocalPlayer{
                                source,kind:self.player_source_kind,access,
                            });
                        }
                        Err(e)=>self.log(format!("输入无效：{e}"))
                    }
                }
            });
        });
        ui.add_space(12.);
        Frame::new().fill(self.panel()).inner_margin(12.).show(ui,|ui|{
            ui.strong("第 3 步 · 验证、保存并导出版本定位规则");
            if self.player_lines.is_empty(){
                ui.label("等待候选检查。进入世界后再次检查；退出世界时验证空指针与生命周期变化。");
            }
            for line in &self.player_lines {ui.label(line);}
            if let Some(candidate)=self.player_candidate.clone(){
                ui.add_space(6.);
                if ui.button("保存该版本的候选定位规则").clicked(){
                    match crate::project::save_local_player_recipe(&candidate){
                        Ok(path)=>{
                            self.log(format!("本地玩家候选规则已保存：{path}"));
                            self.player_profiles=crate::project::local_player_recipes().unwrap_or_default();
                        }
                        Err(e)=>self.log(format!("保存失败：{e}"))
                    }
                }
                ui.label(RichText::new("规则标识为 candidate-only；不包含运行时绝对指针，不等于已确认 LocalPlayer 类型和稳定 ABI。").small().color(self.muted()));
            }
            ui.separator();
            ui.strong(format!("已保存版本规则（{}）",self.player_profiles.len()));
            for line in self.player_profiles.iter().rev().take(6) {
                ui.label(RichText::new(line).monospace().small());
            }
        });
    }

    fn memory_editor(&mut self,ui:&mut Ui){
        ui.heading("内存扫描");
        ui.label(RichText::new("按指定权限扫描本游戏进程，工作线程运行；可限制地址区间与读取预算").color(self.muted()).small());
        ui.horizontal_wrapped(|ui|{
            egui::ComboBox::from_id_salt("scan_scope")
                .selected_text(self.scan_scope.label()).show_ui(ui,|ui|{
                    for scope in ScanScope::ALL {ui.selectable_value(&mut self.scan_scope,scope,scope.label());}
                });
            ui.label("预算 MiB");
            ui.add(egui::DragValue::new(&mut self.scan_budget).range(16..=1024).speed(8));
        });
        ui.horizontal_wrapped(|ui|{
            ui.label("起始");
            ui.add(TextEdit::singleline(&mut self.start_addr).desired_width(160.));
            ui.label("结束");
            ui.add(TextEdit::singleline(&mut self.end_addr).desired_width(165.));
        });
        ui.add_space(6.);
        ui.horizontal_wrapped(|ui|{
            ui.label("数据类型");
            egui::ComboBox::from_id_salt("kind").selected_text(self.value_kind.label()).show_ui(ui,|ui|{
                for value in ValueKind::ALL{ui.selectable_value(&mut self.value_kind,value,value.label());}
            });
            ui.label("数值");
            ui.add(TextEdit::singleline(&mut self.scan_value).desired_width(125.));
        });
        ui.horizontal_wrapped(|ui|{
            if ui.add_enabled(!self.engine.busy,egui::Button::new("首次扫描")).clicked(){
                match self.scan_options(){
                    Ok(opt)=>self.job(Command::ScanRange(self.value_kind,self.scan_value.clone(),opt)),
                    Err(e)=>self.log(format!("扫描范围错误：{e}")),
                }
            }
            egui::ComboBox::from_id_salt("filter").selected_text(self.filter.label()).show_ui(ui,|ui|{
                for f in Filter::ALL{ui.selectable_value(&mut self.filter,f,f.label());}
            });
            if ui.add_enabled(!self.engine.busy,egui::Button::new("再次筛选")).clicked(){
                self.job(Command::Refine(self.filter,self.scan_value.clone()));
            }
            if ui.add_enabled(!self.engine.busy,egui::Button::new("重置")).clicked(){
                self.job(Command::Reset);self.hits.clear();
            }
        });
        ui.separator();
        ui.horizontal(|ui|{
            ui.label(format!("已发现候选：{}",self.hits.len()));
            if ui.button("复制所选地址").clicked(){
                if let Some(i)=self.selected_hit{
                    if let Some(hit)=self.hits.get(i){ui.ctx().copy_text(format!("0x{:X}",hit.address));}
                }
            }
        });
        let pages=self.hits.len().div_ceil(100).max(1);
        self.hit_page=self.hit_page.min(pages-1);
        ui.horizontal(|ui|{
            if ui.add_enabled(self.hit_page>0,egui::Button::new("上一页")).clicked(){self.hit_page-=1;}
            ui.label(format!("第 {} / {} 页（每页 100 条）",self.hit_page+1,pages));
            if ui.add_enabled(self.hit_page+1<pages,egui::Button::new("下一页")).clicked(){self.hit_page+=1;}
        });
        egui::Grid::new("hits_table").striped(true).num_columns(3).show(ui,|ui|{
            ui.strong("地址");ui.strong("上次值");ui.strong("操作");ui.end_row();
            let start=self.hit_page*100;
            for i in start..(start+100).min(self.hits.len()) {
                let hit=&self.hits[i];
                let address=hit.address;
                let value=if hit.bytes.is_empty(){"AOB 匹配".into()}else{self.value_kind.display(&hit.bytes)};
                if ui.selectable_label(self.selected_hit==Some(i),format!("0x{address:016X}")).clicked(){
                    self.selected_hit=Some(i);self.address=format!("0x{address:X}");
                }
                ui.monospace(value);
                if ui.small_button("查看").clicked(){
                    self.address=format!("0x{address:X}");self.tab=Tab::Hex;
                    self.job(Command::Read(address,256));
                }
                ui.end_row();
            }
        });
        if self.hits.len()>=8192{ui.label(RichText::new("达到 8192 条结果上限，建议缩小范围或再次筛选。").color(self.muted()).small());}
    }
    fn hex_editor(&mut self,ui:&mut Ui){
        ui.heading("十六进制查看器");
        ui.horizontal_wrapped(|ui|{
            ui.label("地址");ui.add(TextEdit::singleline(&mut self.address).desired_width(200.));
            ui.label("字节");ui.add(TextEdit::singleline(&mut self.read_size).desired_width(65.));
            if ui.add_enabled(!self.engine.busy,egui::Button::new("读取")).clicked(){
                match (memory::parse_address(&self.address),self.read_size.parse::<usize>()){
                    (Ok(addr),Ok(n))=>self.job(Command::Read(addr,n.clamp(1,4096))),
                    _=>self.log("请输入有效十六进制地址和读取长度")
                }
            }
        });
        Frame::new().fill(self.panel()).inner_margin(11.).show(ui,|ui|{
            for (i,row) in self.dump.chunks(16).take(256).enumerate(){
                let ascii=row.iter().map(|b|if b.is_ascii_graphic(){*b as char}else{'.'}).collect::<String>();
                ui.monospace(format!("{:016X}  {:<48}  {}",
                    self.dump_base+i*16,memory::hex_bytes(row),ascii));
            }
            if self.dump.is_empty(){ui.label("尚未读取任何地址");}
        });
    }
    fn disasm_editor(&mut self,ui:&mut Ui){
        ui.heading("反汇编 · iced-x86");
        ui.label(RichText::new("仅解码游戏进程中的可读字节，不修改指令或附加外部调试器。").color(self.muted()).small());
        ui.horizontal(|ui|{
            ui.label("目标地址");ui.add(TextEdit::singleline(&mut self.address).desired_width(220.));
            if ui.add_enabled(!self.engine.busy,egui::Button::new("解码 32 条指令")).clicked(){
                match memory::parse_address(&self.address){
                    Ok(addr)=>self.job(Command::Disassemble(addr,32)),
                    Err(err)=>self.log(err)
                }
            }
        });
        Frame::new().fill(self.panel()).inner_margin(11.).show(ui,|ui|{
            if self.result_lines.is_empty(){ui.label("输入地址后点击解码，结果显示在此。");}
            for line in self.result_lines.iter().take(160){ui.monospace(line);}
        });
    }
    fn signature_editor(&mut self,ui:&mut Ui){
        ui.heading("AOB / 特征规则");
        ui.label(RichText::new("支持通配符、样本验证、实时进程内查找和特征档案持久化。").color(self.muted()).small());
        ui.label("特征码");ui.add(TextEdit::multiline(&mut self.aob).code_editor().desired_rows(2).desired_width(f32::INFINITY));
        ui.label("离线样本字节");ui.add(TextEdit::multiline(&mut self.aob_test).code_editor().desired_rows(2).desired_width(f32::INFINITY));
        ui.horizontal_wrapped(|ui|{
            if ui.button("验证样本").clicked(){
                match (Pattern::parse(&self.aob),decode_hex(&self.aob_test)){
                    (Ok(p),Ok(bytes))=>self.log(format!("AOB 样本匹配：{:?}",p.matches(&bytes))),
                    (Err(e),_)|(_,Err(e))=>self.log(format!("输入错误：{e}"))
                }
            }
            if ui.add_enabled(!self.engine.busy,egui::Button::new("扫描游戏内存")).clicked(){
                match self.scan_options(){
                    Ok(opt)=>self.job(Command::AobRange(self.aob.clone(),opt)),
                    Err(e)=>self.log(format!("AOB 扫描范围错误：{e}")),
                }
            }
            if ui.button("复制标准特征").clicked(){
                match Pattern::parse(&self.aob){Ok(p)=>ui.ctx().copy_text(p.canonical()),
                    Err(e)=>self.log(e)}
            }
        });
        ui.separator();
        ui.label("特征名称");ui.add(TextEdit::singleline(&mut self.feature_name).desired_width(260.));
        if ui.button("保存到本机特征数据库").clicked(){
            match crate::project::save_feature(&self.feature_name,&self.aob){
                Ok(path)=>{self.log(format!("已写入 {path}"));self.features=crate::project::features().unwrap_or_default();},
                Err(e)=>self.log(e)
            }
        }
        ui.label(RichText::new("已保存特征仅代表候选地址；尚未验证游戏语义和 ABI。").color(self.muted()).small());
    }
    fn script_editor(&mut self,ui:&mut Ui){
        ui.heading("脚本实验室");
        ui.label(RichText::new("CE 风格研究脚本（安全 DSL）。支持 scan / next / read / disasm / aob / assert / wait / write / reset；assert 失败会中止后续操作。").color(self.muted()).small());
        ui.add(TextEdit::multiline(&mut self.script).code_editor().desired_rows(12).desired_width(f32::INFINITY));
        ui.horizontal(|ui|{
            if ui.button("检查脚本语法").clicked(){
                match crate::script::parse(&self.script,self.script_writes){
                    Ok(commands)=>self.log(format!("语法检查通过：{} 条可执行命令",commands.len())),
                    Err(error)=>self.log(format!("语法检查失败：{error}")),
                }
            }
            ui.label(RichText::new("脚本不会调用任意系统命令；修改数据需显式授权。").small().color(self.muted()));
        });
        ui.checkbox(&mut self.script_writes,"此轮运行允许 write 写入（必须提供预期旧值）");
        ui.horizontal_wrapped(|ui|{
            if ui.add_enabled(!self.engine.busy,egui::Button::new("运行脚本")).clicked(){
                match crate::script::parse(&self.script,self.script_writes){
                    Ok(commands)=>self.job(Command::Script(commands)),
                    Err(err)=>self.log(format!("脚本校验失败：{err}"))
                }
                self.script_writes=false;
            }
            if ui.button("保存脚本").clicked(){
                match crate::project::save_script(&self.script){Ok(path)=>self.log(format!("脚本已保存：{path}")),Err(e)=>self.log(e)}
            }
            if ui.button("读取脚本").clicked(){
                match crate::project::load_script(){Ok(s)=>self.script=s,Err(e)=>self.log(e)}
            }
            if ui.button("恢复示例").clicked(){self.script=crate::script::EXAMPLE.into();}
        });
        ui.label(RichText::new("仅用于有授权的离线游戏测试；写入不修改可执行页权限，不保证游戏状态一致性。").color(self.muted()).small());
    }
    fn migration_editor(&mut self,ui:&mut Ui){
        ui.heading("跨版本静态匹配");
        ui.label(RichText::new("使用当前 AOB 比较两个本地游戏模块文件，查找文件偏移。此阶段不是 CFG/ABI 自动恢复。").color(self.muted()).small());
        ui.label("旧构建文件路径");
        ui.add(TextEdit::singleline(&mut self.old_file).desired_width(f32::INFINITY));
        ui.label("新构建文件路径");
        ui.add(TextEdit::singleline(&mut self.new_file).desired_width(f32::INFINITY));
        ui.label("AOB 特征");
        ui.add(TextEdit::multiline(&mut self.aob).code_editor().desired_rows(2).desired_width(f32::INFINITY));
        if ui.add_enabled(!self.engine.busy,egui::Button::new("对比两个版本")).clicked(){
            self.job(Command::Compare{old:self.old_file.clone(),new:self.new_file.clone(),pattern:self.aob.clone()});
        }
        for line in self.result_lines.iter().take(100){ui.monospace(line);}
    }
    fn hooks_editor(&mut self,ui:&mut Ui){
        ui.heading("模块 / Hook 线索");
        ui.label(RichText::new("独立枚举当前进程 DLL；支持查看入口机器码跳转线索，不能归因其他 Mod 私有 Hook。").color(self.muted()).small());
        ui.horizontal_wrapped(|ui|{
            if ui.add_enabled(!self.engine.busy,egui::Button::new("刷新模块列表")).clicked(){self.job(Command::Modules);}
            ui.label("检查地址");
            ui.add(TextEdit::singleline(&mut self.address).desired_width(200.));
            if ui.button("检查入口").clicked(){
                match memory::parse_address(&self.address).and_then(|addr|memory::read(addr,16)){
                    Ok(bytes)=>self.log(format!("Hook 线索：{} · {}",memory::hex_bytes(&bytes),crate::inspection::entry_hint(&bytes))),
                    Err(e)=>self.log(e)
                }
            }
        });
        for line in self.module_lines.iter().take(512){ui.monospace(line);}
    }
    fn settings_editor(&mut self,ui:&mut Ui){
        ui.heading("设置 / 关于");
        ui.horizontal(|ui|{
            ui.label("界面主题");
            if ui.selectable_label(self.dark,"深色").clicked()&&!self.dark{
                self.dark=true;configure_appearance(ui.ctx(),true);
            }
            if ui.selectable_label(!self.dark,"浅色").clicked()&&self.dark{
                self.dark=false;configure_appearance(ui.ctx(),false);
            }
        });
        ui.label("底部控制台高度");if ui.add(egui::Slider::new(&mut self.bottom_height,90. ..= 340.)).changed(){self.layout_dirty=true;}
        ui.label("核心：Rust + egui + DX11 · 所有调试功能在 DevTools DLL 内");
        ui.label("快捷键：Ctrl+1…9 切换工作台标签");
        ui.label("监视表：保存于 %LOCALAPPDATA%/BLoader-DevTools/watches.json");
        ui.label("BLoader 只负责加载、生命周期以及宿主日志；不提供扫描、脚本和 Hook 解析。");
        ui.label("作者：Chlna6666 · GPL-3.0-only");
        ui.hyperlink_to(REPO,REPO);
        if ui.button("复制仓库地址").clicked(){ui.ctx().copy_text(REPO.into());}
        ui.separator();
        ui.heading("AI 自动化 · MCP");
        ui.label(RichText::new("默认禁用，仅监听 127.0.0.1 并强制 Bearer token。").color(self.muted()).small());
        if let Some((endpoint,token))=crate::mcp::status(){
            ui.label(RichText::new("MCP 已启动").color(GREEN));
            ui.monospace(&endpoint);
            ui.horizontal_wrapped(|ui|{
                if ui.button("复制地址").clicked(){ui.ctx().copy_text(endpoint);}
                if ui.button("复制令牌").clicked(){ui.ctx().copy_text(token);}
                if ui.button("停止 MCP").clicked(){crate::mcp::stop();}
            });
        }else if ui.button("开启本机 MCP").clicked(){
            if let Err(e)=crate::mcp::start(){self.log(format!("MCP 启动失败：{e}"));}
        }
        ui.label(RichText::new("DevTools 截图使用 D3D11 GPU 读回；Minecraft 画面当前 PrintWindow 可能无法捕获。").color(self.muted()).small());
    }
    fn inspector(&mut self,ui:&mut Ui){
        ui.add_space(9.);
        ui.strong("检查器  /  地址监视");
        ui.separator();
        ScrollArea::vertical().id_salt("inspector").show(ui,|ui|{
            ui.label("当前地址 (hex)");
            ui.add(TextEdit::singleline(&mut self.address).desired_width(f32::INFINITY));
            if ui.add_enabled(!self.engine.busy,egui::Button::new("查看内存")).clicked(){
                match memory::parse_address(&self.address){
                    Ok(addr)=>{self.tab=Tab::Hex;self.job(Command::Read(addr,256));},
                    Err(e)=>self.log(e)
                }
            }
            ui.label("数据类型");
            egui::ComboBox::from_id_salt("inspector_kind").selected_text(self.value_kind.label()).show_ui(ui,|ui|{
                for kind in ValueKind::ALL{ui.selectable_value(&mut self.value_kind,kind,kind.label());}
            });
            if ui.button("将地址加入监视").clicked(){
                match memory::parse_address(&self.address){
                    Ok(address)=>self.add_watch(address),
                    Err(e)=>self.log(e)
                }
            }
            ui.separator();
            ui.label("预期旧值");
            ui.add(TextEdit::singleline(&mut self.write_old).desired_width(f32::INFINITY));
            ui.label("新值");
            ui.add(TextEdit::singleline(&mut self.write_new).desired_width(f32::INFINITY));
            ui.checkbox(&mut self.write_armed,"允许本次数据写入");
            if ui.add_enabled(self.write_armed&&!self.engine.busy,egui::Button::new("比较并写入")).clicked(){
                match memory::parse_address(&self.address){
                    Ok(address)=>self.job(Command::Write{
                        address,kind:self.value_kind,old:self.write_old.clone(),new:self.write_new.clone()
                    }),
                    Err(e)=>self.log(e)
                }
                self.write_armed=false;
            }
            ui.separator();
            ui.strong(format!("实时地址监视（{} / 64）",self.watches.len()));
            let mut remove=None;
            for (i,w) in self.watches.iter().enumerate(){
                ui.horizontal(|ui|{
                    ui.monospace(format!("0x{:X}",w.address));
                    ui.label(&w.value);
                    if ui.small_button("×").clicked(){remove=Some(i);}
                });
            }
            if let Some(i)=remove{
                self.watches.remove(i);
                self.save_watch_list();
            }
            ui.separator();
            ui.label(RichText::new("地址监视每 700ms 后台刷新并自动保存。").small().color(self.muted()));
            ui.label(RichText::new("只改写已可写的数据页；若旧值变化将拒绝写入。").small().color(self.muted()));
            if let Some(i)=self.selected_hit {
                if let Some(hit)=self.hits.get(i){
                    ui.label(format!("选中：0x{:X}",hit.address));
                    ui.label(if hit.bytes.is_empty(){"AOB 匹配".to_owned()}else{self.value_kind.display(&hit.bytes)});
                }
            }
        });
    }
    fn bottom_panel(&mut self,ui:&mut Ui){
        ui.horizontal(|ui|{
            ui.add_space(7.);
            ui.strong("工具窗口  /  控制台");
            ui.label(RichText::new(format!("{} 条记录",self.console.len())).color(self.muted()).small());
            if ui.small_button("清空").clicked(){self.console.clear();}
            ui.with_layout(Layout::right_to_left(Align::Center),|ui|{
                ui.label(RichText::new("异步任务 · 调试日志 · 错误").color(self.muted()).small());
            });
        });
        ui.separator();
        ScrollArea::vertical().id_salt("console").auto_shrink([false,false])
            .stick_to_bottom(true).show(ui,|ui|{
                for line in &self.console{
                    ui.label(RichText::new(line).monospace().size(12.));
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ide_navigation_resolves_real_tabs(){
        let mut ui=Workbench::default();
        for (input,label) in [
            ("memory","内存扫描"),("hex","十六进制"),("disasm","反汇编"),
            ("signature","AOB 特征"),("script","脚本实验室"),
            ("migration","版本迁移"),("hooks","模块 / Hook"),("settings","设置"),("localplayer","本地玩家定位"),
        ] {
            ui.navigate(input).unwrap();
            assert_eq!(ui.tab.name(),label);
        }
        assert!(ui.navigate("missing").is_err());
    }
    #[test]
    fn scan_options_validate_ui_bounds(){
        let mut ui=Workbench::default();
        ui.start_addr="0x20000".into();
        ui.end_addr="0x10000".into();
        assert!(ui.scan_options().is_err());
        ui.end_addr="0x30000".into();
        assert!(ui.scan_options().is_ok());
    }
}
