use crate::signature::{Pattern, decode_hex};
use egui::{Color32, RichText, ScrollArea, TextEdit, Ui};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page { Home, Memory, Disasm, Pattern, Migration, Hooks, Settings }
impl Page {
    const ALL: [Self; 7] = [
        Self::Home, Self::Memory, Self::Disasm, Self::Pattern,
        Self::Migration, Self::Hooks, Self::Settings,
    ];
    fn label(self) -> &'static str {
        match self {
            Self::Home => "Workspace", Self::Memory => "Memory scanner",
            Self::Disasm => "Disassembly", Self::Pattern => "AOB patterns",
            Self::Migration => "Version migration", Self::Hooks => "Hook inspector",
            Self::Settings => "Settings",
        }
    }
}

pub struct Workbench {
    page: Page,
    pub hide_requested: bool,
    pattern: String,
    buffer: String,
    matches: Vec<usize>,
    result: String,
}
impl Default for Workbench {
    fn default() -> Self {
        Self {
            page: Page::Home,
            hide_requested: false,
            pattern: "48 8B 05 ?? ?? ?? ?? 48 85 C0".to_owned(),
            buffer: "90 48 8B 05 01 02 03 04 48 85 C0 C3".to_owned(),
            matches: Vec::new(),
            result: "Paste a byte buffer and AOB pattern to run an offline validation.".into(),
        }
    }
}
impl Workbench {
    pub fn ui(&mut self, ui: &mut Ui) {
        ui.ctx().set_visuals(egui::Visuals::dark());
        ui.horizontal(|ui| {
            ui.heading(RichText::new("BLoader DevTools").strong());
            ui.separator();
            ui.label(RichText::new("IN-PROCESS / D3D11").color(Color32::LIGHT_GREEN));
            if ui.button("Hide (F8)").clicked() { self.hide_requested = true; }
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_width(172.0);
                ui.label(RichText::new("DEVELOPER TOOLS").small().weak());
                for page in Page::ALL {
                    if ui.selectable_label(self.page == page, page.label()).clicked() {
                        self.page = page;
                    }
                }
                ui.separator();
                ui.small("Game-owned child window");
                ui.small("No external EXE");
            });
            ui.separator();
            ui.vertical(|ui| {
                ui.set_width(ui.available_width());
                ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    ui.add_space(10.0);
                    match self.page {
                        Page::Home => self.home(ui),
                        Page::Memory => Self::unavailable(ui, "Memory scanner", "Read-only scanning is not connected in this initial UI build."),
                        Page::Disasm => Self::unavailable(ui, "Disassembly", "Decoder and register snapshots are planned. No game code is patched."),
                        Page::Pattern => self.pattern_panel(ui),
                        Page::Migration => Self::unavailable(ui, "Version migration", "Cross-build function matching and feature manifests are not yet implemented."),
                        Page::Hooks => Self::unavailable(ui, "Hook inspector", "BLoader hook registry integration is planned; this mod installs no hooks."),
                        Page::Settings => self.settings(ui),
                    }
                });
            });
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.small(format!("BLoader DevTools v{}", env!("CARGO_PKG_VERSION")));
            ui.separator();
            ui.small("Offline AOB validation available · F8 toggle");
        });
    }
    fn home(&mut self, ui: &mut egui::Ui) {
        ui.heading("Native Mod Development");
        ui.label("Tools for inspecting, validating and migrating Bedrock native mod interfaces.");
        ui.label(format!("Version {} | Author: Chlna6666 | License: GPL-3.0-only", env!("CARGO_PKG_VERSION")));
        ui.horizontal(|ui| {
            ui.label("Source: https://github.com/Chlna6666/BLoader-DevTools");
            if ui.button("Copy repository URL").clicked() {
                ui.ctx().copy_text("https://github.com/Chlna6666/BLoader-DevTools".into());
            }
        });
        ui.add_space(16.0);
        ui.group(|ui| {
            ui.heading("Available now");
            ui.label("AOB parser, wildcard matching, canonical copy/export and unit tests.");
            if ui.button("Open pattern workspace  >").clicked() { self.page = Page::Pattern; }
        });
        ui.add_space(12.0);
        ui.group(|ui| {
            ui.heading("Safety and performance");
            ui.label("The UI owns a separate D3D11 device and message loop.");
            ui.label("No game Present hook, no memory writes and no breakpoint patching.");
            ui.label("Future scans will run on cancellable worker threads.");
        });
    }
    fn unavailable(ui: &mut egui::Ui, title: &str, desc: &str) {
        ui.heading(title);
        ui.add_space(8.0);
        ui.label(RichText::new("Not implemented in v0.1.1").color(Color32::YELLOW));
        ui.label(desc);
        ui.add_space(14.0);
        ui.group(|ui| {
            ui.label("Design boundary");
            ui.small("BLoader owns mod lifecycle. DevTools owns developer features. Game-facing APIs are optional mods.");
        });
    }
    fn pattern_panel(&mut self, ui: &mut egui::Ui) {
        ui.heading("AOB pattern workspace");
        ui.label("Offline byte-buffer test. This tool does not scan live game memory yet.");
        ui.add_space(8.0);
        ui.label("Signature (hex bytes; ?? for relocation/wildcard)");
        ui.add(TextEdit::multiline(&mut self.pattern).desired_rows(2).desired_width(f32::INFINITY).code_editor());
        ui.add_space(8.0);
        ui.label("Input bytes (sample buffer)");
        ui.add(TextEdit::multiline(&mut self.buffer).desired_rows(3).desired_width(f32::INFINITY).code_editor());
        ui.horizontal(|ui| {
            if ui.button("Validate pattern").clicked() {
                self.matches.clear();
                match (Pattern::parse(&self.pattern), decode_hex(&self.buffer)) {
                    (Ok(pattern), Ok(bytes)) => {
                        self.matches = pattern.matches(&bytes);
                        self.result = format!(
                            "{} match(es) in {} bytes; {} pattern bytes",
                            self.matches.len(), bytes.len(), pattern.0.len()
                        );
                        self.pattern = pattern.canonical();
                    }
                    (Err(err), _) | (_, Err(err)) => self.result = err.to_owned(),
                }
            }
            if ui.button("Copy canonical AOB").clicked() {
                match Pattern::parse(&self.pattern) {
                    Ok(pattern) => ctx_copy(ui, pattern.canonical()),
                    Err(err) => self.result = err.to_owned(),
                }
            }
            if ui.button("Clear results").clicked() {
                self.matches.clear();
                self.result.clear();
            }
        });
        ui.separator();
        ui.label(&self.result);
        for offset in self.matches.iter().take(128) {
            ui.monospace(format!("match @ buffer + 0x{offset:X}"));
        }
        if self.matches.len() > 128 { ui.small("Only the first 128 results are shown."); }
        ui.add_space(12.0);
        ui.small("A unique match is not evidence of ABI or gameplay compatibility.");
    }
    fn settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Runtime settings");
        ui.label(format!("BLoader DevTools v{}", env!("CARGO_PKG_VERSION")));
        ui.label("Author: Chlna6666");
        ui.label("Open-source license: GPL-3.0-only");
        ui.label("Repository: https://github.com/Chlna6666/BLoader-DevTools");
        ui.label("Window: owned Win32 child of Minecraft's top-level HWND.");
        ui.label("Renderer: dedicated Direct3D 11 device and swap chain.");
        ui.label("Frame scheduling: input-driven; no 240 Hz idle redraw loop.");
        ui.label("UI hotkey: F8 (edge-triggered, focused game only).");
        ui.label("Unload: request event-loop exit, then join the worker thread.");
        ui.label("Game Hook API: disabled until verified host integration.");
    }
}
fn ctx_copy(ui: &egui::Ui, content: String) {
    ui.ctx().copy_text(content);
}
