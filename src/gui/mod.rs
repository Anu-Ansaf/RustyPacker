use eframe::egui::{self, Margin, RichText};

pub mod state;
pub mod theme;
pub mod widgets;
pub mod tab_configure;
pub mod tab_flowcase;
pub mod tab_console;

use state::{AppState, Tab};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use widgets::AppStatus;

pub struct App {
    state: AppState,
    build_handle: Option<JoinHandle<()>>,
    build_log: Arc<Mutex<String>>,
    build_running: Arc<std::sync::atomic::AtomicBool>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            state: AppState::default(),
            build_handle: None,
            build_log: Arc::new(Mutex::new(String::new())),
            build_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

impl App {
    pub fn from_storage(cc: &eframe::CreationContext<'_>) -> Self {
        let state: AppState = cc
            .storage
            .and_then(|s| eframe::get_value::<AppState>(s, "app_state"))
            .unwrap_or_default();
        theme::install(&cc.egui_ctx, state.active_theme);
        let mut app = Self::default();
        app.state = state;
        app
    }

    fn start_build(&mut self, ctx: &egui::Context) {
        if self.build_running.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        if let Err(msg) = validate_state(&self.state) {
            self.build_log
                .lock()
                .unwrap()
                .push_str(&format!("[-] {msg}\n"));
            return;
        }
        let order = match self.state.to_order() {
            Some(o) => o,
            None => {
                self.build_log
                    .lock()
                    .unwrap()
                    .push_str("[-] Pick a shellcode file first.\n");
                return;
            }
        };
        self.build_log.lock().unwrap().clear();
        self.build_running
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let log = self.build_log.clone();
        let running = self.build_running.clone();
        let ctx = ctx.clone();

        self.build_handle = Some(std::thread::spawn(move || {
            crate::build_log::set_sink(log.clone());
            crate::build_log::write("[*] Starting build...");
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let folder = crate::puzzle::assemble(order.clone());
                crate::blog!("[*] Compiled output folder: {}", folder.display());
                crate::compiler::compile(&folder);
                let copy_result = crate::tools::process_output(&order, &folder);
                let _ = crate::tools::rename_source_binary(&order, &folder);
                if order.output.is_some() && copy_result.is_ok() {
                    crate::compiler::clean(&folder);
                }
            }));
            let msg = match result {
                Ok(()) => "[+] Build complete.",
                Err(_) => "[-] Build panicked. See output folder for partial artifacts.",
            };
            crate::build_log::write(msg);
            crate::build_log::clear_sink();
            running.store(false, std::sync::atomic::Ordering::SeqCst);
            ctx.request_repaint();
        }));
    }
}

pub fn validate_state(state: &AppState) -> Result<(), String> {
    use crate::gui::state::Format;
    use crate::techniques::{self, Format as TFormat, Requirement};

    let Some(_) = &state.shellcode_path else {
        return Err("Pick a shellcode file.".into());
    };

    let inj = techniques::find(&state.injection_id)
        .ok_or_else(|| format!("Unknown injection: {}", state.injection_id))?;
    if techniques::find(&state.encryption_id).is_none() {
        return Err(format!("Unknown encryption: {}", state.encryption_id));
    }
    for ev_id in &state.enabled_evasions {
        if techniques::find(ev_id).is_none() {
            return Err(format!("Unknown evasion: {}", ev_id));
        }
    }
    for id in &state.enabled_anti_debug {
        if techniques::find(id).is_none() {
            return Err(format!("Unknown anti-debug check: {}", id));
        }
    }
    for req in inj.meta().requires {
        match req {
            Requirement::TargetProcess => {
                let key = format!("{}.target_process", inj.meta().id);
                if state
                    .params
                    .get(&key)
                    .map(String::as_str)
                    .unwrap_or("")
                    .is_empty()
                {
                    return Err(format!(
                        "{} requires a target process.",
                        inj.meta().display_name
                    ));
                }
            }
            Requirement::Format(TFormat::Exe) if state.format == Format::Dll => {
                return Err(format!(
                    "{} requires EXE format.",
                    inj.meta().display_name
                ));
            }
            Requirement::Format(TFormat::Dll) if state.format == Format::Exe => {
                return Err(format!(
                    "{} requires DLL format.",
                    inj.meta().display_name
                ));
            }
            _ => {}
        }
    }

    if state.format == Format::DllSideload {
        if !inj.meta().tags.contains(&"self_injection") {
            return Err(format!(
                "DLL Sideload requires a self-injection technique. {} is remote.",
                inj.meta().display_name
            ));
        }
        if state.sideload.target_dll.is_none() {
            return Err("DLL Sideload: pick a target DLL.".into());
        }
        if state.sideload.hijack_export.trim().is_empty() {
            return Err("DLL Sideload: enter the hijack export name.".into());
        }
        if matches!(state.sideload.mode, crate::gui::state::SideloadMode::Proxy)
            && !state.sideload.use_absolute_path
            && state.sideload.renamed.trim().is_empty()
        {
            return Err(
                "DLL Sideload (Proxy, relative mode): set the renamed-original DLL name."
                    .into(),
            );
        }
    }
    Ok(())
}

impl eframe::App for App {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "app_state", &self.state);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let running = self
            .build_running
            .load(std::sync::atomic::Ordering::SeqCst);
        let count = crate::techniques::all().len();
        let status = if running {
            AppStatus::Building
        } else {
            AppStatus::Ready { count }
        };

        // --- Title bar (with theme picker)
        let mut theme_changed = false;
        egui::TopBottomPanel::top("titlebar")
            .frame(
                egui::Frame::none()
                    .fill(theme::palette::bg_chrome())
                    .inner_margin(Margin::ZERO),
            )
            .show_separator_line(false)
            .show(ctx, |ui| {
                theme_changed = widgets::title_bar(
                    ui,
                    env!("CARGO_PKG_VERSION"),
                    &status,
                    &mut self.state.active_theme,
                );
            });

        if theme_changed {
            theme::install(ctx, self.state.active_theme);
            ctx.request_repaint();
        }

        // --- Tab strip
        egui::TopBottomPanel::top("tabs")
            .frame(
                egui::Frame::none()
                    .fill(theme::palette::bg_chrome())
                    .inner_margin(Margin::ZERO),
            )
            .show_separator_line(false)
            .show(ctx, |ui| {
                widgets::tab_strip(
                    ui,
                    &mut self.state.current_tab,
                    &[
                        (Tab::Configure, "Configure"),
                        (Tab::FlowCase, "FlowCase"),
                        (Tab::Console, "Console"),
                    ],
                );
            });

        // --- Bottom action bar
        egui::TopBottomPanel::bottom("actions")
            .frame(
                egui::Frame::none()
                    .fill(theme::palette::bg_chrome())
                    .inner_margin(Margin {
                        left: theme::space::LG,
                        right: theme::space::LG,
                        top: theme::space::SM + 2.0,
                        bottom: theme::space::SM + 2.0,
                    }),
            )
            .show_separator_line(false)
            .show(ctx, |ui| {
                let r = ui.max_rect();
                ui.painter().hline(
                    r.x_range(),
                    r.top(),
                    egui::Stroke::new(1.0, theme::palette::border_strong()),
                );

                ui.horizontal(|ui| {
                    let status_text = if running {
                        format!("● Building…  ·  see Console for output")
                    } else {
                        format!("Ready  ·  {count} techniques discovered")
                    };
                    let color = if running {
                        theme::palette::accent()
                    } else {
                        theme::palette::text_label()
                    };
                    ui.label(
                        RichText::new(status_text)
                            .font(theme::font_sans(11.0))
                            .color(color),
                    );

                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            let clicked = if running {
                                let _ = widgets::primary_button_disabled(ui, "▶ BUILDING…");
                                false
                            } else {
                                widgets::primary_button(ui, "▶ BUILD PAYLOAD").clicked()
                            };
                            if clicked {
                                self.state.current_tab = Tab::Console;
                                self.start_build(ctx);
                            }
                        },
                    );
                });
            });

        // --- Central body
        let central = egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(theme::palette::bg_base())
                    .inner_margin(Margin {
                        left: theme::space::XXL,
                        right: theme::space::XXL,
                        top: theme::space::LG,
                        bottom: theme::space::LG,
                    }),
            )
            .show(ctx, |ui| match self.state.current_tab {
                Tab::Configure => tab_configure::draw(ui, &mut self.state),
                Tab::FlowCase => tab_flowcase::draw(ui, &mut self.state),
                Tab::Console => tab_console::draw(ui, &mut self.state, &self.build_log),
            });

        // Cyberpunk overlay: subtle CRT scanlines over the central panel.
        if self.state.active_theme.scanlines() {
            widgets::paint_scanlines(ctx, central.response.rect);
        }

        // Animate the building status pip
        if running {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }
    }
}
