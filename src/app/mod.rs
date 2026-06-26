mod console;
mod flow;
mod form;
mod shell;
pub mod state;
mod theme;
mod widgets;

pub fn run() -> eframe::Result<()> {
    let opts = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 720.0])
            .with_min_inner_size([880.0, 560.0])
            .with_title("rustypacker"),
        persist_window: true,
        ..Default::default()
    };
    eframe::run_native(
        "rustypacker",
        opts,
        Box::new(|cc| Box::new(shell::Shell::new(cc))),
    )
}
