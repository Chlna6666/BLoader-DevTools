use crate::signature::{Pattern, decode_hex};
use egui::{Align, Color32, FontFamily, FontId, Frame, Layout, RichText, ScrollArea, Stroke, TextEdit, Ui, Vec2};

const BLUE: Color32 = Color32::from_rgb(92, 148, 245);
const GREEN: Color32 = Color32::from_rgb(87, 207, 165);
const MUTED: Color32 = Color32::from_rgb(156, 168, 187);
const BACKGROUND: Color32 = Color32::from_rgb(17, 22, 31);
const SURFACE: Color32 = Color32::from_rgb(25, 32, 43);
const BORDER: Color32 = Color32::from_rgb(51, 62, 78);
const REPOSITORY: &str = "https://github.com/Chlna6666/BLoader-DevTools";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page { Overview, Memory, Disasm, Pattern, Migration, Hooks, Settings }
impl Page {
    const ALL: [Self; 7] = [
        Self::Overview, Self::Memory, Self::Disasm, Self::Pattern,
        Self::Migration, Self::Hooks, Self::Settings
    ];
    fn label(self) -> &'static str {
        match self {
            Self::Overview => "概览", Self::Memory => "内存扫描", Self::Disasm => "反汇编",
            Self::Pattern => "特征码工具", Self::Migration => "版本迁移",
            Self::Hooks => "Hook 监控", Self::Settings => "设置与关于",
        }
    }
    fn tagline(self) -> &'static str {
        match self {
            Self::Overview => "开发者工作台 / 快速入门",
            Self::Memory => "定位数值、地址与读写来源",
            Self::Disasm => "反汇编、寄存器和调用关系",
            Self::Pattern => "编辑 AOB、测试匹配结果并复制特征",
            Self::Migration => "追踪游戏版本更新后的函数与地址",
            Self::Hooks => "查看物理 Hook 与 Mod 订阅者",
            Self::Settings => "界面主题、窗口模式和项目资料",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Theme { Dark, Light }

pub struct Workbench {
    page: Page,
    theme: Theme,
    pub hide_requested: bool,
    pattern: String,
    buffer: String,
    matches: Vec<usize>,
    result: String,
}
impl Default for Workbench {
    fn default() -> Self {
        Self {
            page: Page::Overview,
            theme: Theme::Dark,
            hide_requested: false,
            pattern: "48 8B 05 ?? ?? ?? ?? 48 85 C0".into(),
            buffer: "90 48 8B 05 01 02 03 04 48 85 C0 C3".into(),
            matches: Vec::new(),
            result: "输入 AOB 与测试字节，然后执行匹配验证。".into(),
        }
    }
}

pub fn configure_appearance(ctx: &egui::Context, dark: bool) {
    let theme = if dark { egui::Theme::Dark } else { egui::Theme::Light };
    let mut style = (*ctx.style_of(theme)).clone();
    let mut visuals = if dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    if dark {
        visuals.panel_fill = BACKGROUND;
        visuals.window_fill = BACKGROUND;
        visuals.extreme_bg_color = Color32::from_rgb(13, 18, 26);
        visuals.faint_bg_color = SURFACE;
        visuals.widgets.inactive.bg_fill = SURFACE;
        visuals.widgets.inactive.weak_bg_fill = SURFACE;
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(42, 56, 77);
        visuals.widgets.active.bg_fill = Color32::from_rgb(53, 79, 116);
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    } else {
        visuals.panel_fill = Color32::from_rgb(248, 250, 253);
        visuals.window_fill = Color32::WHITE;
    }
    visuals.selection.bg_fill = BLUE;
    visuals.selection.stroke = Stroke::new(1.0, Color32::WHITE);
    style.visuals = visuals;
    style.spacing.item_spacing = Vec2::new(9.0, 9.0);
    style.spacing.button_padding = Vec2::new(12.0, 7.0);
    style.spacing.interact_size.y = 30.0;
    style.text_styles.insert(egui::TextStyle::Body, FontId::new(15.0, FontFamily::Proportional));
    style.text_styles.insert(egui::TextStyle::Button, FontId::new(14.0, FontFamily::Proportional));
    style.text_styles.insert(egui::TextStyle::Small, FontId::new(12.0, FontFamily::Proportional));
    style.text_styles.insert(egui::TextStyle::Heading, FontId::new(23.0, FontFamily::Proportional));
    style.spacing.indent = 18.0;
    ctx.set_style_of(theme, style);
    ctx.set_theme(theme);
}

/// Load installed Windows CJK fonts; never bundle or export system font files.
pub fn install_system_fonts(ctx: &egui::Context) -> Result<String, String> {
    let windir = std::env::var_os("WINDIR").unwrap_or_else(|| "C:\\Windows".into());
    let folder = std::path::PathBuf::from(windir).join("Fonts");
    for name in ["msyh.ttc", "msyhbd.ttc", "simhei.ttf", "Deng.ttf", "simsun.ttc"] {
        let path = folder.join(name);
        if let Ok(bytes) = std::fs::read(&path) {
            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert(
                "bloader_system_cjk".into(),
                egui::FontData::from_owned(bytes).into()
            );
            for family in [FontFamily::Proportional, FontFamily::Monospace] {
                fonts.families.entry(family).or_default().insert(0, "bloader_system_cjk".into());
            }
            ctx.set_fonts(fonts);
            return Ok(path.display().to_string());
        }
    }
    Err(format!("未发现可用的系统中文字体：{}", folder.display()))
}

impl Workbench {
    fn is_dark(&self) -> bool { self.theme == Theme::Dark }
    fn text(&self) -> Color32 {
        if self.is_dark() { Color32::from_rgb(232, 237, 247) } else { Color32::from_rgb(31, 42, 57) }
    }
    fn secondary(&self) -> Color32 { if self.is_dark() { MUTED } else { Color32::from_rgb(92, 107, 126) } }
    fn surface(&self) -> Color32 { if self.is_dark() { SURFACE } else { Color32::WHITE } }
    fn line(&self) -> Color32 { if self.is_dark() { BORDER } else { Color32::from_rgb(221, 228, 236) } }

    fn card(&self, ui: &mut Ui, content: impl FnOnce(&mut Ui)) {
        Frame::new().fill(self.surface()).stroke(Stroke::new(1.0, self.line()))
            .corner_radius(10.0).inner_margin(16.0).show(ui, content);
    }

    pub fn ui(&mut self, ui: &mut Ui) {
        let width = ui.available_width();
        let height = ui.available_height();
        ui.allocate_ui_with_layout(
            Vec2::new(width, 62.0),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.add_space(18.0);
                ui.label(RichText::new("B").color(Color32::WHITE).size(22.0).strong()
                    .background_color(BLUE));
                ui.add_space(6.0);
                ui.label(RichText::new("BLoader DevTools").size(19.0).strong().color(self.text()));
                ui.add_space(14.0);
                ui.label(RichText::new("原生模组开发工具").color(self.secondary()));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add_space(18.0);
                    if ui.button("设置").clicked() { self.page = Page::Settings; }
                    ui.label(RichText::new("D3D11  ·  本进程").color(GREEN).size(12.0));
                });
            },
        );
        ui.separator();
        let body_height = (height - 107.0).max(180.0);
        ui.horizontal(|ui| {
            ui.allocate_ui_with_layout(
                Vec2::new(210.0, body_height),
                Layout::top_down(Align::Min),
                |ui| {
                    ui.set_min_width(198.0);
                    ui.add_space(17.0);
                    ui.label(RichText::new("  工作区").color(self.secondary()).size(12.0));
                    ui.add_space(8.0);
                    for page in Page::ALL {
                        let button = egui::Button::new(RichText::new(page.label()).size(15.0))
                            .selected(self.page == page).min_size(Vec2::new(187.0, 39.0));
                        if ui.add(button).clicked() { self.page = page; }
                        ui.add_space(3.0);
                    }
                    ui.add_space(15.0);
                    ui.separator();
                    ui.label(RichText::new("  运行环境").color(self.secondary()).size(12.0));
                    ui.label(RichText::new("  BL Mod ABI v1").size(13.0));
                    ui.label(RichText::new("  egui · DirectX 11").color(self.secondary()).size(12.0));
                }
            );
            ui.separator();
            let right = ui.available_size();
            ui.allocate_ui_with_layout(
                Vec2::new(right.x.max(200.0), body_height),
                Layout::top_down(Align::Min),
                |ui| {
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        ui.add_space(14.0);
                        ui.vertical(|ui| {
                            ui.heading(RichText::new(self.page.label()).size(25.0).color(self.text()));
                            ui.label(RichText::new(self.page.tagline()).size(13.0).color(self.secondary()));
                        });
                    });
                    ui.add_space(13.0);
                    ScrollArea::vertical()
                        .id_salt("bloader_page_scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.add_space(14.0);
                                ui.vertical(|ui| {
                                    ui.set_width((ui.available_width()-25.0).max(180.0));
                                    match self.page {
                                        Page::Overview => self.home(ui),
                                        Page::Memory => self.unavailable(ui, "内存扫描", "用于追踪游戏内数值和地址变化。未来支持浮点/整数/指针、筛选和地址监控。"),
                                        Page::Disasm => self.unavailable(ui, "反汇编", "未来提供指令解码、寄存器快照和函数引用分析。当前不会写入游戏指令。"),
                                        Page::Pattern => self.pattern_panel(ui),
                                        Page::Migration => self.unavailable(ui, "跨版本迁移", "未来从已保存函数特征中查找新版候选并验证 ABI。"),
                                        Page::Hooks => self.unavailable(ui, "Hook 监控", "未来查询 BLoader 的共享 Hook 注册表与冲突关系。"),
                                        Page::Settings => self.settings(ui),
                                    }
                                });
                            });
                        });
                }
            );
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.add_space(16.0);
            ui.label(RichText::new(format!("BLoader DevTools v{}", env!("CARGO_PKG_VERSION"))).size(12.0).color(self.secondary()));
            ui.separator();
            ui.label(RichText::new("GPL-3.0-only  ·  Chlna6666").size(12.0).color(self.secondary()));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(14.0);
                ui.label(RichText::new("启动自动显示 · F8 可切换").size(12.0).color(self.secondary()));
            });
        });
    }

    fn home(&mut self, ui: &mut Ui) {
        let primary = self.text();
        let secondary = self.secondary();
        self.card(ui, |ui| {
            ui.label(RichText::new("欢迎使用 BLoader DevTools").size(20.0).strong().color(primary));
            ui.label(RichText::new("构建轻量、开放的 Minecraft Bedrock 原生 Mod 调试工作流。").color(secondary));
            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("当前已实现").color(GREEN).strong());
                ui.label("AOB 解析 · 通配符匹配 · 本地样本验证 · 一键复制");
            });
        });
        ui.add_space(15.0);
        ui.columns(2, |cols| {
            self.card(&mut cols[0], |ui| {
                ui.label(RichText::new("特征码工作台").size(17.0).strong().color(primary));
                ui.label(RichText::new("将采集的字节转换为可复用的 AOB 匹配规则。").color(secondary));
            });
            self.card(&mut cols[1], |ui| {
                ui.label(RichText::new("后续开发").size(17.0).strong().color(primary));
                ui.label(RichText::new("内存扫描、调试断点、跨版本自动迁移。").color(secondary));
            });
        });
        ui.add_space(11.0);
        if ui.button("打开特征码工作台  →").clicked() { self.page = Page::Pattern; }
        ui.add_space(18.0);
        ui.label(RichText::new("开发流程").size(18.0).strong().color(primary));
        ui.add_space(8.0);
        self.card(ui, |ui| {
            for (index, (name, detail)) in [
                ("定位目标", "扫描与分析游戏内存，确定目标变量或函数。"),
                ("生成识别规则", "保存指令特征、调用关系和匹配上下文。"),
                ("跨版本验证", "对新版二进制重新匹配并进行实际行为校验。"),
            ].iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("  {:02}  ", index+1)).strong().color(BLUE));
                    ui.label(RichText::new(*name).strong());
                    ui.label(RichText::new(*detail).color(secondary));
                });
                if index != 2 { ui.add_space(8.0); }
            }
            ui.add_space(8.0);
            ui.label(RichText::new("注意：以上为工具链规划，当前仅特征码样本验证可用。").color(secondary).size(12.0));
        });
        ui.add_space(14.0);
        self.card(ui, |ui| {
            ui.label(RichText::new("开源项目").size(16.0).strong());
            ui.label(RichText::new(REPOSITORY).color(secondary));
            if ui.button("复制仓库地址").clicked() { ui.ctx().copy_text(REPOSITORY.into()); }
        });
    }

    fn unavailable(&mut self, ui: &mut Ui, name: &str, detail: &str) {
        let secondary = self.secondary();
        self.card(ui, |ui| {
            ui.label(RichText::new("正在规划").color(BLUE).strong());
            ui.add_space(8.0);
            ui.label(RichText::new(name).size(20.0).strong());
            ui.label(detail);
            ui.add_space(8.0);
            ui.label(RichText::new("当前版本尚未接入该功能，避免展示无效的伪调试数据。").color(secondary));
        });
    }

    fn pattern_panel(&mut self, ui: &mut Ui) {
        let primary = self.text();
        let secondary = self.secondary();
        // Inline frame (not self.card) so the editable fields borrow self safely.
        Frame::new().fill(self.surface()).stroke(Stroke::new(1.0, self.line()))
            .corner_radius(10.0).inner_margin(16.0).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(RichText::new("AOB 特征码").size(17.0).strong().color(primary));
                ui.label(RichText::new("以空格分隔的十六进制字节，?? 为通配符。").color(secondary));
                ui.add(TextEdit::multiline(&mut self.pattern)
                    .desired_rows(2).desired_width(f32::INFINITY).code_editor());
                ui.add_space(11.0);
                ui.label(RichText::new("测试字节缓冲区").size(17.0).strong().color(primary));
                ui.label(RichText::new("当前只测试你输入的样本数据，不扫描游戏进程。").color(secondary));
                ui.add(TextEdit::multiline(&mut self.buffer)
                    .desired_rows(4).desired_width(f32::INFINITY).code_editor());
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.button("验证特征").clicked() {
                        self.matches.clear();
                        match (Pattern::parse(&self.pattern), decode_hex(&self.buffer)) {
                            (Ok(pattern), Ok(bytes)) => {
                                self.matches = pattern.matches(&bytes);
                                self.result = format!("匹配 {} 处  ·  缓冲区 {} 字节  ·  特征长度 {} 字节",
                                    self.matches.len(), bytes.len(), pattern.0.len());
                                self.pattern = pattern.canonical();
                            },
                            (Err(err), _) | (_, Err(err)) => self.result = format!("格式错误：{err}"),
                        }
                    }
                    if ui.button("复制标准 AOB").clicked() {
                        match Pattern::parse(&self.pattern) {
                            Ok(pattern) => {
                                ui.ctx().copy_text(pattern.canonical());
                                self.result = "已复制标准 AOB 至剪贴板".into();
                            },
                            Err(err) => self.result = format!("格式错误：{err}"),
                        }
                    }
                    if ui.button("清除结果").clicked() { self.matches.clear(); self.result.clear(); }
                });
            });
        ui.add_space(13.0);
        Frame::new().fill(self.surface()).stroke(Stroke::new(1.0, self.line()))
            .corner_radius(10.0).inner_margin(16.0).show(ui, |ui| {
                ui.label(RichText::new("验证结果").size(17.0).strong().color(primary));
                ui.label(&self.result);
                ui.add_space(6.0);
                for offset in self.matches.iter().take(128) {
                    ui.monospace(format!("样本偏移 + 0x{offset:X}"));
                }
                if self.matches.len() > 128 { ui.label("仅显示前 128 处匹配"); }
                ui.add_space(7.0);
                ui.label(RichText::new("单版本唯一匹配不等于跨版本稳定，也不能直接证明游戏 ABI 正确。")
                    .color(secondary).size(12.0));
            });
    }

    fn settings(&mut self, ui: &mut Ui) {
        let primary = self.text();
        let secondary = self.secondary();
        Frame::new().fill(self.surface()).stroke(Stroke::new(1.0, self.line()))
            .corner_radius(10.0).inner_margin(16.0).show(ui, |ui| {
                ui.label(RichText::new("外观设置").size(17.0).strong().color(primary));
                ui.horizontal(|ui| {
                    ui.label("界面主题");
                    let dark = self.theme == Theme::Dark;
                    if ui.selectable_label(dark, "深色").clicked() && !dark {
                        self.theme = Theme::Dark;
                        configure_appearance(ui.ctx(), true);
                    }
                    if ui.selectable_label(!dark, "浅色").clicked() && dark {
                        self.theme = Theme::Light;
                        configure_appearance(ui.ctx(), false);
                    }
                });
                ui.label(RichText::new("使用 Windows 已安装的中文系统字体，不在 DLL 中分发字体文件。")
                    .size(12.0).color(secondary));
            });
        ui.add_space(14.0);
        self.card(ui, |ui| {
            ui.label(RichText::new("运行方式").size(17.0).strong().color(primary));
            ui.label("单 DLL · BL Mod ABI v1 · 同进程 Win32 窗口");
            ui.label("独立 D3D11 渲染设备 · 事件驱动刷新");
            ui.label("启动后自动显示 · F8 为可选热键");
            ui.label("RDP / UWP 窗口识别失败时使用同进程顶层窗口");
        });
        ui.add_space(14.0);
        Frame::new().fill(self.surface()).stroke(Stroke::new(1.0, self.line()))
            .corner_radius(10.0).inner_margin(16.0).show(ui, |ui| {
                ui.label(RichText::new("AI 测试 / 本机 MCP").size(17.0).strong().color(primary));
                ui.label("单 DLL 内置 MCP HTTP 端点 · 不启动额外 EXE");
                ui.label(RichText::new("出于安全考虑默认关闭，仅绑定 127.0.0.1，必须使用临时令牌。")
                    .color(secondary).size(12.0));
                if let Some((endpoint,token)) = crate::mcp::status() {
                    ui.label(RichText::new("已开启 · 允许已授权的本机 AI 客户端调用").color(GREEN));
                    ui.horizontal_wrapped(|ui| {
                        ui.monospace(&endpoint);
                        if ui.button("复制 MCP 地址").clicked() {
                            ui.ctx().copy_text(endpoint.clone());
                        }
                        if ui.button("复制连接令牌").clicked() {
                            ui.ctx().copy_text(token);
                        }
                        if ui.button("关闭 MCP").clicked() { crate::mcp::stop(); }
                    });
                    ui.label(RichText::new("请求头 Authorization: Bearer <复制的连接令牌>")
                        .color(secondary).size(12.0));
                } else {
                    if ui.button("开启本机 MCP 测试服务").clicked() {
                        if let Err(err) = crate::mcp::start() {
                            crate::error(format!("[BLoader DevTools] MCP_START_FAILED: {err}"));
                        }
                    }
                }
                ui.add_space(4.0);
                ui.label(RichText::new("当前提供窗口信息、Win32 点击和实验性截图。游戏 GPU 画面可能无法通过 PrintWindow 获取；后续需接入 DXGI / Windows Graphics Capture。")
                    .color(secondary).size(12.0));
            });
        ui.add_space(14.0);
        self.card(ui, |ui| {
            ui.label(RichText::new("版本与许可").size(17.0).strong().color(primary));
            ui.label(format!("版本：{}", env!("CARGO_PKG_VERSION")));
            ui.label("作者：Chlna6666");
            ui.label("开源协议：GPL-3.0-only");
            ui.label(format!("源码：{REPOSITORY}"));
            if ui.button("复制项目地址").clicked() { ui.ctx().copy_text(REPOSITORY.into()); }
        });
    }
}
