#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::egui;

fn main() -> eframe::Result<()> {
    // The build pipeline resolves `shared/` and `templates/` as relative paths
    // from the CWD. When the GUI is launched directly (e.g. by double-clicking
    // the .exe), the CWD is `target/release/` and those folders don't exist.
    // Anchor to the project root that was current at compile time.
    let project_root = env!("CARGO_MANIFEST_DIR");
    if let Err(e) = std::env::set_current_dir(project_root) {
        eprintln!("Warning: could not set working directory to {project_root}: {e}");
    }

    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 720.0])
            .with_min_inner_size([720.0, 560.0])
            .with_title("RustyPacker"),
        persist_window: true,
        ..Default::default()
    };
    eframe::run_native(
        "RustyPacker",
        opts,
        Box::new(|cc| Box::new(rustpacker::gui::App::from_storage(cc))),
    )
}
