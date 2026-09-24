//! broccoli library root — all modules live here; `src/main.rs` is a thin wrapper
//! so integration tests can link against the crate.

pub mod app;
pub mod diag;
pub mod r#gen;
pub mod i18n;
mod icon;
pub mod links;
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

/// Backends the window's wgpu instance may enable.
///
/// `WGPU_BACKEND` (wgpu's own override) wins when set. Otherwise the platform
/// primary set is used — on Windows Vulkan and D3D12 together, so a D3D12
/// adapter stays available for a surface Vulkan cannot present (the adapter
/// wgpu selects is unchanged: Vulkan) — and only the GL backend is withheld
/// unless neither of them offers a hardware adapter. Enabling GL is the
/// expensive half: it loads the legacy OpenGL driver stack and creates a
/// context just to enumerate its adapters, ~80 MB of private commit on an AMD
/// iGPU, against ~5 MB for keeping D3D12 in the set. `primary_adapter_available`
/// runs only when no override is set.
fn select_backends(
    from_env: Option<eframe::wgpu::Backends>,
    primary_adapter_available: impl FnOnce() -> bool,
) -> eframe::wgpu::Backends {
    if let Some(requested) = from_env {
        return requested;
    }
    if primary_adapter_available() {
        eframe::wgpu::Backends::PRIMARY
    } else {
        eframe::wgpu::Backends::PRIMARY | eframe::wgpu::Backends::GL
    }
}

/// Whether Vulkan or D3D12 offers at least one hardware adapter.
///
/// Only an instance is created and dropped here — no adapter is opened, so no
/// device (and none of the GPU memory a device maps into the process) exists
/// before eframe creates the real one. Software rasterizers do not count: the
/// D3D12 WARP adapter is `DeviceType::Cpu`, and on a machine whose GPU only
/// speaks OpenGL the GL backend drives the hardware WARP would replace.
fn primary_adapter_available() -> bool {
    let backends = eframe::wgpu::Backends::PRIMARY;
    let instance = eframe::wgpu::Instance::new(eframe::wgpu::InstanceDescriptor {
        backends,
        ..eframe::wgpu::InstanceDescriptor::new_without_display_handle()
    });
    // Adapter enumeration is async; a throwaway current-thread runtime drives it.
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    runtime
        .block_on(instance.enumerate_adapters(backends))
        .iter()
        .any(|adapter| adapter.get_info().device_type != eframe::wgpu::DeviceType::Cpu)
}

/// wgpu configuration for the app window, with the backend set chosen by
/// [`select_backends`].
fn wgpu_options() -> eframe::WgpuConfiguration {
    let mut options = eframe::WgpuConfiguration::default();
    if let eframe::egui_wgpu::WgpuSetup::CreateNew(setup) = &mut options.wgpu_setup {
        setup.instance_descriptor.backends = select_backends(
            eframe::wgpu::Backends::from_env(),
            primary_adapter_available,
        );
    }
    options
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
        wgpu_options: wgpu_options(),
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

#[cfg(test)]
mod tests {
    use super::select_backends;
    use eframe::wgpu::Backends;

    #[test]
    fn backends_skip_gl_when_a_primary_adapter_exists() {
        // The GL backend is the one whose driver stack is instantiated just to
        // be enumerated, so it must not be part of the default set.
        let backends = select_backends(None, || true);
        assert!(backends.contains(Backends::VULKAN), "{backends:?}");
        assert!(backends.contains(Backends::DX12), "{backends:?}");
        assert!(!backends.contains(Backends::GL), "{backends:?}");
    }

    #[test]
    fn backends_keep_gl_for_machines_without_vulkan_or_d3d12() {
        let backends = select_backends(None, || false);
        assert!(backends.contains(Backends::GL), "{backends:?}");
    }

    #[test]
    fn backends_honour_the_wgpu_backend_override() {
        let requested = Backends::GL | Backends::VULKAN;
        // A pinned set must not second-guess itself with the adapter probe.
        let never_probes = || panic!("the override must skip the adapter probe");
        assert_eq!(select_backends(Some(requested), never_probes), requested);
    }
}
