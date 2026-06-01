use crate::gui::state::AppState;
use crate::gui::theme::{self, palette, space};
use crate::gui::widgets::{ghost_button, phase_progress, terminal_view, TerminalOpts};
use eframe::egui::{self, RichText};
use std::sync::{Arc, Mutex};

pub fn draw(ui: &mut egui::Ui, _state: &mut AppState, log: &Arc<Mutex<String>>) {
    let text = log.lock().unwrap().clone();
    let (phase, total, phase_label) = detect_phase(&text);

    ui.label(
        RichText::new("Build output")
            .font(theme::font_sans(16.0))
            .color(palette::text())
            .strong(),
    );
    ui.add_space(2.0);
    ui.label(
        RichText::new("Live build log from the puzzle assembler + cargo compile pipeline.")
            .font(theme::font_sans(11.0))
            .color(palette::text_dim()),
    );
    ui.add_space(space::MD);

    if phase > 0 || total > 0 {
        phase_progress(ui, phase, total, phase_label);
        ui.add_space(space::SM);
    }

    terminal_view(ui, &text, TerminalOpts::default());

    ui.add_space(space::SM);
    ui.horizontal(|ui| {
        if ghost_button(ui, "Copy log").clicked() {
            ui.output_mut(|o| o.copied_text = text.clone());
        }
        ui.add_space(4.0);
        if ghost_button(ui, "Clear").clicked() {
            log.lock().unwrap().clear();
        }
        ui.with_layout(
            egui::Layout::right_to_left(egui::Align::Center),
            |ui| {
                let lines = text.lines().count();
                ui.label(
                    RichText::new(format!("{lines} lines  ·  auto-scroll on"))
                        .font(theme::font_mono(10.5))
                        .color(palette::text_muted()),
                );
            },
        );
    });
}

fn detect_phase(log: &str) -> (u32, u32, &'static str) {
    let markers: &[(&str, &str)] = &[
        ("Starting build",          "preparing template"),
        ("Compiled output folder",  "compiling loader"),
        ("Build complete",          "done"),
    ];
    let total = markers.len() as u32;
    let mut current = 0u32;
    let mut label: &'static str = "";
    for (needle, lbl) in markers {
        if log.contains(needle) {
            current += 1;
            label = lbl;
        }
    }
    if log.contains("Build panicked") {
        return (current.max(1), total, "build panicked");
    }
    (current, total, label)
}
