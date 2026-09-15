//! broccoli library root — all modules live here; `src/main.rs` is a thin wrapper
//! so integration tests can link against the crate.

pub mod app;
pub mod diag;
pub mod r#gen;
pub mod i18n;
mod icon;
pub mod links;
pub mod metrics;
pub mod model;
pub mod probe_verdict;
pub mod quic_probe;
pub mod rt;
pub mod sys;
pub mod ui;

fn viewport_icon() -> Option<std::sync::Arc<egui::IconData>> {
    let img = image::load_from_memory(include_bytes!(
        "../assets/icons/png/256/broccoli-stopped.png"
    ))
    .ok()?;
    let rgba = img.to_rgba8();
    let (w, h) = rgba.dimensions();
    Some(std::sync::Arc::new(egui::IconData {
        rgba: rgba.into_raw(),
        width: w,
        height: h,
    }))
}

/// GUI entry point.
pub fn run() -> eframe::Result<()> {
    // reqwest 0.12's `-no-provider` TLS backend panics at Client::new() unless
    // a rustls crypto provider is installed first.
    rt::ensure_tls_provider();

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1100.0, 720.0])
        .with_min_inner_size([900.0, 600.0]);
    if let Some(icon) = viewport_icon() {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        persist_window: true,
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "broccoli",
        options,
        Box::new(|cc| Ok(Box::new(app::BroccoliApp::new(cc)))),
    )
}
