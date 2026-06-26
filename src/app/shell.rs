use super::state::{Tab, UiState};
use super::widgets::{
    primary_button, primary_button_disabled, tab_strip, title_bar, AppStatus,
};
use super::{console, flow, form, theme};
use crate::logbus;
use eframe::egui::{self, Frame, Layout, Margin, RichText, Stroke};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Idle,
    Building,
    Cleaning,
}

pub struct Shell {
    state: UiState,
    log_buf: Arc<Mutex<String>>,
    job_handle: Option<JoinHandle<()>>,
    op: Arc<Mutex<Op>>,
}

impl Shell {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut state: UiState = cc
            .storage
            .and_then(|s| eframe::get_value(s, "ui_state"))
            .unwrap_or_default();
        if state.target_exe.is_empty() {
            state.target_exe = "Notepad.exe".into();
        }
        theme::install(&cc.egui_ctx, state.theme);
        Self {
            state,
            log_buf: Arc::new(Mutex::new(String::new())),
            job_handle: None,
            op: Arc::new(Mutex::new(Op::Idle)),
        }
    }

    fn try_claim(&self, want: Op) -> bool {
        let mut op = self.op.lock().unwrap();
        if *op != Op::Idle {
            return false;
        }
        *op = want;
        true
    }

    fn start_build(&mut self, ctx: &egui::Context) {
        if !self.try_claim(Op::Building) {
            return;
        }
        let recipe = match self.state.to_spec() {
            Ok(r) => r,
            Err(e) => {
                *self.op.lock().unwrap() = Op::Idle;
                self.log_buf
                    .lock()
                    .unwrap()
                    .push_str(&format!("[-] {e}\n"));
                return;
            }
        };
        self.log_buf.lock().unwrap().clear();
        let buf = self.log_buf.clone();
        let op = self.op.clone();
        let ctx_clone = ctx.clone();
        self.job_handle = Some(std::thread::spawn(move || {
            let sink = logbus::Sink::new(buf);
            sink.write("[*] build started");
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::compose::run(&recipe, &sink)
            }));
            match outcome {
                Ok(Ok(path)) => sink.write(&format!("[+] artifact: {}", path.display())),
                Ok(Err(e))   => sink.write(&format!("[-] {e}")),
                Err(_)       => sink.write("[-] build panicked"),
            }
            *op.lock().unwrap() = Op::Idle;
            ctx_clone.request_repaint();
        }));
    }

    fn start_clean(&mut self, ctx: &egui::Context) {
        if !self.try_claim(Op::Cleaning) {
            return;
        }
        self.log_buf.lock().unwrap().clear();
        let buf = self.log_buf.clone();
        let op = self.op.clone();
        let ctx_clone = ctx.clone();
        self.job_handle = Some(std::thread::spawn(move || {
            let sink = logbus::Sink::new(buf);
            let before = crate::compose::workdir_size();
            sink.write(&format!(
                "[*] cleaning workdir ({} on disk)",
                human_size(before)
            ));
            match crate::compose::clean_workdir() {
                Ok(freed) => sink.write(&format!(
                    "[+] cleaned, freed {} ({} bytes)",
                    human_size(freed),
                    freed
                )),
                Err(e) => sink.write(&format!("[-] clean failed: {e}")),
            }
            *op.lock().unwrap() = Op::Idle;
            ctx_clone.request_repaint();
        }));
    }
}

fn human_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

impl eframe::App for Shell {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "ui_state", &self.state);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let op = *self.op.lock().unwrap();
        let is_idle = op == Op::Idle;

        let status = match op {
            Op::Idle => AppStatus::Ready {
                hint: "ready · 5 self-inject · 3 remote".into(),
            },
            Op::Building => AppStatus::Building,
            Op::Cleaning => AppStatus::Cleaning,
        };

        let mut theme_changed = false;
        egui::TopBottomPanel::top("rp_titlebar")
            .frame(
                Frame::none()
                    .fill(theme::palette::bg_chrome())
                    .inner_margin(Margin::ZERO),
            )
            .show_separator_line(false)
            .show(ctx, |ui| {
                theme_changed = title_bar(
                    ui,
                    env!("CARGO_PKG_VERSION"),
                    &status,
                    &mut self.state.theme,
                );
            });
        if theme_changed {
            theme::install(ctx, self.state.theme);
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("rp_tabs")
            .frame(
                Frame::none()
                    .fill(theme::palette::bg_chrome())
                    .inner_margin(Margin::ZERO),
            )
            .show_separator_line(false)
            .show(ctx, |ui| {
                tab_strip(
                    ui,
                    &mut self.state.tab,
                    &[
                        (Tab::Build,   "Configure"),
                        (Tab::Flow,    "FlowCase"),
                        (Tab::Console, "Console"),
                    ],
                );
            });

        egui::TopBottomPanel::bottom("rp_actions")
            .frame(
                Frame::none()
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
                    Stroke::new(1.0, theme::palette::border_strong()),
                );
                ui.horizontal(|ui| {
                    let (txt, col) = match op {
                        Op::Idle => (
                            "ready  ·  5 self-inject  ·  3 remote  ·  6 ciphers".to_string(),
                            theme::palette::text_label(),
                        ),
                        Op::Building => (
                            "● Building…  ·  see Console for output".to_string(),
                            theme::palette::accent(),
                        ),
                        Op::Cleaning => (
                            "● Cleaning workdir…".to_string(),
                            theme::palette::warn(),
                        ),
                    };
                    ui.label(
                        RichText::new(txt)
                            .font(theme::font_sans(11.0))
                            .color(col),
                    );
                    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                        if is_idle {
                            if primary_button(ui, "▶ BUILD").clicked() {
                                self.state.tab = Tab::Console;
                                self.start_build(ctx);
                            }
                            ui.add_space(theme::space::SM);
                            if super::widgets::ghost_button(ui, "🧹 CLEAN").clicked() {
                                self.state.tab = Tab::Console;
                                self.start_clean(ctx);
                            }
                        } else {
                            let label = match op {
                                Op::Building => "▶ BUILDING…",
                                Op::Cleaning => "🧹 CLEANING…",
                                _ => "",
                            };
                            let _ = primary_button_disabled(ui, label);
                        }
                    });
                });
            });

        let central = egui::CentralPanel::default()
            .frame(
                Frame::none()
                    .fill(theme::palette::bg_base())
                    .inner_margin(Margin {
                        left: theme::space::XXL,
                        right: theme::space::XXL,
                        top: theme::space::LG,
                        bottom: theme::space::LG,
                    }),
            )
            .show(ctx, |ui| match self.state.tab {
                Tab::Build   => form::draw(ui, &mut self.state),
                Tab::Flow    => flow::draw(ui, &self.state),
                Tab::Console => console::draw(ui, &self.log_buf),
            });

        if self.state.theme.scanlines() {
            super::widgets::paint_scanlines(ctx, central.response.rect);
        }

        if !is_idle {
            ctx.request_repaint_after(std::time::Duration::from_millis(150));
        }
    }
}
