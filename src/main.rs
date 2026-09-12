#![windows_subsystem = "windows"]

mod app;
mod archive;
mod crypto;
mod registry;
mod secure_delete;
mod worker;

use std::path::PathBuf;

fn main() -> eframe::Result<()> {
    let target: Option<PathBuf> = std::env::args_os().nth(1).map(PathBuf::from);

    // Raw RGBA pixels for the generated padlock icon, baked in at compile
    // time (see assets/icon.ico for the exe resource, embedded via build.rs).
    const ICON_RGBA: &[u8] = include_bytes!("../assets/icon_256.rgba");

    let window_size = [460.0, 400.0];
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size(window_size)
            .with_min_inner_size(window_size)
            .with_max_inner_size(window_size)
            .with_resizable(false)
            .with_maximize_button(false)
            .with_drag_and_drop(true)
            .with_icon(eframe::egui::IconData {
                rgba: ICON_RGBA.to_vec(),
                width: 256,
                height: 256,
            }),
        ..Default::default()
    };

    eframe::run_native(
        "AegisCrypt",
        options,
        Box::new(|_cc| Ok(Box::new(app::AegisApp::new(target)))),
    )
}
