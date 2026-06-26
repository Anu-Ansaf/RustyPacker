use super::theme::{self, palette, space};
use super::widgets::{ghost_button, terminal_view, TerminalOpts};
use eframe::egui::{self, RichText};
use std::sync::{Arc, Mutex};

pub fn draw(ui: &mut egui::Ui, log: &Arc<Mutex<String>>) {
    let text = log.lock().unwrap().clone();

    ui.label(
        RichText::new("Build output")
            .font(theme::font_sans(16.0))
            .color(palette::text())
            .strong(),
    );
    ui.add_space(2.0);
    ui.label(
        RichText::new("Live log from the emit pipeline + cargo compile.")
            .font(theme::font_sans(11.0))
            .color(palette::text_dim()),
    );
    ui.add_space(space::MD);

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
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let lines = text.lines().count();
            ui.label(
                RichText::new(format!("{lines} lines  ·  auto-scroll on"))
                    .font(theme::font_mono(10.5))
                    .color(palette::text_muted()),
            );
        });
    });
}
