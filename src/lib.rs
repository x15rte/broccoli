//! broccoli library root — all modules live here; `src/main.rs` is a thin wrapper
//! so integration tests can link against the crate.

pub mod app;
pub mod diag;
/// The crate's diagnostic-text bound, published for tests that assert a
/// bound they cannot compute from the rendered text alone.
pub mod excerpt {
    pub use crate::links::excerpt;
}
pub mod r#gen;
pub mod i18n;
mod icon;
pub mod links;
pub mod model;
pub mod probe_verdict;
pub mod quic_probe;
pub mod rt;
pub mod sys;
pub mod tls_ping;
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

/// What the app does with one `wgpu` surface status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SurfaceDisposition {
    /// Reconfigure the surface, then draw again.
    Reconfigure,
    /// Recreate the surface, then draw again.
    RecreateSurface,
    /// Drop this frame. `hidden` marks a frame the window's own visibility
    /// explains (minimized, or behind another window), which needs no retry —
    /// every other skip asks for the frame that retries.
    Skip { hidden: bool },
}

/// Map a surface status to the action the app takes with it.
///
/// egui-wgpu's default handler skips a frame for every status other than
/// `Outdated` and `Lost`, and its skip path schedules nothing: with an
/// event-driven repaint policy the status then never changes — nothing asks
/// for another frame — and the window freezes silently. The app keeps the
/// default actions and adds the request that retries them.
fn surface_disposition(status: &eframe::wgpu::CurrentSurfaceTexture) -> SurfaceDisposition {
    use eframe::wgpu::CurrentSurfaceTexture as Status;

    match status {
        // The compositor changed the surface (resize, scale, output): wgpu
        // requires a reconfigure before the next acquire, and skipping would
        // strand the app in `Outdated` forever.
        Status::Outdated => SurfaceDisposition::Reconfigure,
        // The underlying surface is gone: a fresh one is needed.
        Status::Lost => SurfaceDisposition::RecreateSurface,
        // A hidden window legitimately draws nothing, and the wake that
        // restores it arrives with the window's own events.
        Status::Occluded => SurfaceDisposition::Skip { hidden: true },
        // A timeout, or a validation error inside the acquire — a lost device
        // is the usual reason — may clear on its own: ask for the frame that
        // finds out. A device loss is reported to the app through its
        // device-lost callback, which owns the recovery from there.
        _ => SurfaceDisposition::Skip { hidden: false },
    }
}

/// The UI context a dropped frame wakes when it asks for another one.
///
/// [`wgpu_options`] builds the surface-status handler before an app (and
/// therefore a context) exists, so the handler cannot capture the context; the
/// app records its own here at construction.
static UI_CONTEXT: std::sync::OnceLock<egui::Context> = std::sync::OnceLock::new();

/// Record the context a dropped frame wakes. The first context recorded wins,
/// and a second one could not reach the handler anyway: a process runs one app,
/// and the test boots that share a binary never build a wgpu configuration.
pub(crate) fn record_ui_context(ctx: &egui::Context) {
    let _ = UI_CONTEXT.set(ctx.clone());
}

/// How long a skipped frame waits before the retry the app asks for.
///
/// The retry must not be immediate: a surface that keeps failing — a device
/// that stays lost, a window that stays unusable — would otherwise repaint in
/// a tight loop, re-running a failing acquire every millisecond. A quarter
/// second hides a transient failure while keeping the failing case at a few
/// frames per second, and it costs nothing once the window is hidden, which is
/// what a device loss ends in.
const SURFACE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// Whether a device loss has already taken rendering out for this run.
///
/// The surface-status handler stops scheduling retries once it is set: a
/// retry exists for a failure that may clear on its own, and a lost device
/// clears only when the process restarts, so the frames after this point
/// belong to the events that arrive anyway.
static RENDER_LOST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Record that rendering is over for this run: the device is gone and the
/// window is hidden (see the app's render-lost state).
pub(crate) fn note_render_lost() {
    RENDER_LOST.store(true, std::sync::atomic::Ordering::Release);
}

/// The app's surface-status handler: [`surface_disposition`]'s action, the
/// repaint a skipped frame needs, and the diagnostic the default handler
/// printed — that line is the only record a dropped frame leaves in `app.log`.
fn on_surface_status(
    status: &eframe::wgpu::CurrentSurfaceTexture,
) -> eframe::egui_wgpu::SurfaceErrorAction {
    match surface_disposition(status) {
        SurfaceDisposition::Reconfigure => eframe::egui_wgpu::SurfaceErrorAction::Reconfigure,
        SurfaceDisposition::RecreateSurface => {
            eframe::egui_wgpu::SurfaceErrorAction::RecreateSurface
        }
        SurfaceDisposition::Skip { hidden } => {
            if hidden {
                tracing::trace!("Skipping frame due to occlusion.");
            } else {
                tracing::warn!("Dropped frame with error: {status:?}");
                if !RENDER_LOST.load(std::sync::atomic::Ordering::Acquire)
                    && let Some(ctx) = UI_CONTEXT.get()
                {
                    ctx.request_repaint_after(SURFACE_RETRY_DELAY);
                }
            }
            eframe::egui_wgpu::SurfaceErrorAction::SkipFrame
        }
    }
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
    options.on_surface_status = std::sync::Arc::new(on_surface_status);
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
    use super::{SurfaceDisposition, select_backends, surface_disposition};
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

    #[test]
    fn surface_status_maps_to_the_action_that_recovers_from_it() {
        use eframe::wgpu::CurrentSurfaceTexture as Status;

        // A reconfigure or a fresh surface is what the compositor change
        // needs, and the acquire that uses it belongs to the next frame.
        assert_eq!(
            surface_disposition(&Status::Outdated),
            SurfaceDisposition::Reconfigure
        );
        assert_eq!(
            surface_disposition(&Status::Lost),
            SurfaceDisposition::RecreateSurface
        );
        // A hidden window explains its own skipped frames; nothing else does.
        // A timeout or a validation error — a lost device is the usual reason
        // — must ask for the frame that finds out whether it cleared.
        assert_eq!(
            surface_disposition(&Status::Occluded),
            SurfaceDisposition::Skip { hidden: true }
        );
        for retried in [Status::Timeout, Status::Validation] {
            assert_eq!(
                surface_disposition(&retried),
                SurfaceDisposition::Skip { hidden: false },
                "{retried:?} must ask for another frame"
            );
        }
    }
}
