#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use rustypacker::app;

fn main() -> eframe::Result<()> {
    let root = env!("CARGO_MANIFEST_DIR");
    if let Err(e) = std::env::set_current_dir(root) {
        eprintln!("warn: could not anchor cwd to {root}: {e}");
    }
    app::run()
}
