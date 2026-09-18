use crate::rt::{CorePhase, CoreTransport};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IconState {
    Stopped,
    CoreRunning,
    Tun,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IconDetail {
    None,
    CoreError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IconPresentation {
    pub(crate) state: IconState,
    pub(crate) detail: IconDetail,
}

impl IconPresentation {
    pub(crate) fn tooltip(self, lang: crate::model::settings::Language) -> String {
        use crate::i18n::{Key, t};
        match self.state {
            IconState::Stopped => t(lang, Key::TrayTooltipStopped).into(),
            IconState::Error => t(lang, Key::IconTooltipError).into(),
            IconState::CoreRunning => t(lang, Key::IconTooltipCoreRunning).into(),
            IconState::Tun => t(lang, Key::IconTooltipTun).into(),
        }
    }
}

pub(crate) fn classify(phase: &CorePhase, transport: Option<CoreTransport>) -> IconPresentation {
    match phase {
        CorePhase::Error(_) => IconPresentation {
            state: IconState::Error,
            detail: IconDetail::CoreError,
        },
        // Not running and not about to be: the tray must not claim the core
        // is up.
        CorePhase::Stopped => IconPresentation {
            state: IconState::Stopped,
            detail: IconDetail::None,
        },
        CorePhase::Running if transport == Some(CoreTransport::Tun) => IconPresentation {
            state: IconState::Tun,
            detail: IconDetail::None,
        },
        // Running with the direct transport (or a yet-unknown transport),
        // and the transitional phases (Starting, Backoff): the icon
        // distinguishes the active transport and errors only.
        _ => IconPresentation {
            state: IconState::CoreRunning,
            detail: IconDetail::None,
        },
    }
}

const ICON_FRAME_SIZES: [u32; 9] = [16, 20, 24, 32, 40, 48, 64, 96, 256];

fn resource_name(state: IconState) -> &'static str {
    match state {
        IconState::Stopped => "BROCCOLI_STOPPED",
        IconState::CoreRunning => "BROCCOLI_CORE_RUNNING",
        IconState::Tun => "BROCCOLI_TUN",
        IconState::Error => "BROCCOLI_ERROR",
    }
}

fn frame_size(logical_size: u32, scale_factor: f64) -> u32 {
    let requested = (f64::from(logical_size) * scale_factor)
        .ceil()
        .clamp(1.0, 256.0) as u32;
    ICON_FRAME_SIZES
        .into_iter()
        .find(|size| *size >= requested)
        .unwrap_or(256)
}

pub(crate) struct IconAssets;

impl IconAssets {
    pub(crate) const fn new() -> Self {
        Self
    }

    #[cfg(windows)]
    pub(crate) fn apply_window(
        &self,
        window: &winit::window::Window,
        state: IconState,
    ) -> Result<(), String> {
        use winit::dpi::PhysicalSize;
        use winit::platform::windows::{IconExtWindows, WindowExtWindows};

        let name = resource_name(state);
        let scale_factor = window.scale_factor();
        let small_size = frame_size(16, scale_factor);
        let taskbar_size = frame_size(24, scale_factor);
        let taskbar = winit::window::Icon::from_resource_name(
            name,
            Some(PhysicalSize::new(taskbar_size, taskbar_size)),
        )
        .map_err(|error| format!("failed to load {name} {taskbar_size}px taskbar icon: {error}"))?;
        let small = winit::window::Icon::from_resource_name(
            name,
            Some(PhysicalSize::new(small_size, small_size)),
        )
        .map_err(|error| format!("failed to load {name} {small_size}px window icon: {error}"))?;

        window.set_taskbar_icon(Some(taskbar));
        window.set_window_icon(Some(small));
        Ok(())
    }

    #[cfg(windows)]
    pub(crate) fn tray_icon(
        &self,
        state: IconState,
        scale_factor: Option<f64>,
    ) -> Result<tray_icon::Icon, String> {
        let name = resource_name(state);
        let size = scale_factor.map(|scale_factor| frame_size(16, scale_factor));
        tray_icon::Icon::from_resource_name(name, size.map(|size| (size, size))).map_err(|error| {
            match size {
                Some(size) => format!("failed to load {name} {size}px tray icon: {error}"),
                None => format!("failed to load default {name} tray icon: {error}"),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag::Diag;
    use crate::i18n::Key;
    use crate::rt::PhaseError;
    use std::path::{Path, PathBuf};

    const SIZES: [u32; 9] = [16, 20, 24, 32, 40, 48, 64, 96, 256];
    const SLUGS: [&str; 5] = ["neutral", "core-running", "tun", "error", "stopped"];

    fn assets() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("assets")
    }

    /// A terminal phase for the classifier matrix: production payloads are
    /// keyed, so the fixture uses a key too.
    fn error_phase() -> CorePhase {
        CorePhase::Error(PhaseError::new(Diag::new(Key::RtPhaseRestartCancelled)))
    }

    fn expected(state: IconState, detail: IconDetail) -> IconPresentation {
        IconPresentation { state, detail }
    }

    #[test]
    fn classifies_truthful_live_state_with_documented_precedence() {
        let cases = vec![
            (
                "stopped",
                CorePhase::Stopped,
                None,
                expected(IconState::Stopped, IconDetail::None),
            ),
            (
                "starting tun",
                CorePhase::Starting,
                Some(CoreTransport::Tun),
                expected(IconState::CoreRunning, IconDetail::None),
            ),
            (
                "retrying",
                CorePhase::Backoff { attempt: 3 },
                Some(CoreTransport::Tun),
                expected(IconState::CoreRunning, IconDetail::None),
            ),
            (
                "direct core",
                CorePhase::Running,
                Some(CoreTransport::Direct),
                expected(IconState::CoreRunning, IconDetail::None),
            ),
            (
                "tun core",
                CorePhase::Running,
                Some(CoreTransport::Tun),
                expected(IconState::Tun, IconDetail::None),
            ),
            (
                "missing live transport",
                CorePhase::Running,
                None,
                expected(IconState::CoreRunning, IconDetail::None),
            ),
            (
                "core error",
                error_phase(),
                Some(CoreTransport::Direct),
                expected(IconState::Error, IconDetail::CoreError),
            ),
            (
                "error precedes tun transport",
                error_phase(),
                Some(CoreTransport::Tun),
                expected(IconState::Error, IconDetail::CoreError),
            ),
        ];

        for (name, phase, transport, presentation) in cases {
            assert_eq!(classify(&phase, transport), presentation, "{name}");
        }
    }

    #[test]
    fn tooltips_cover_every_presentation_detail() {
        let cases = [
            (
                expected(IconState::Stopped, IconDetail::None),
                "broccoli — Stopped",
            ),
            (
                expected(IconState::CoreRunning, IconDetail::None),
                "broccoli — Xray core running",
            ),
            (
                expected(IconState::Tun, IconDetail::None),
                "broccoli — TUN active",
            ),
            (
                expected(IconState::Error, IconDetail::CoreError),
                "broccoli — Error. Open broccoli for details.",
            ),
        ];

        for (presentation, tooltip) in cases {
            assert_eq!(
                presentation.tooltip(crate::model::settings::Language::En),
                tooltip
            );
        }
    }

    #[test]
    fn resource_names_and_dpi_frames_are_exact() {
        let names = [
            (IconState::Stopped, "BROCCOLI_STOPPED"),
            (IconState::CoreRunning, "BROCCOLI_CORE_RUNNING"),
            (IconState::Tun, "BROCCOLI_TUN"),
            (IconState::Error, "BROCCOLI_ERROR"),
        ];
        for (state, name) in names {
            assert_eq!(resource_name(state), name);
        }

        assert_eq!(frame_size(16, 1.0), 16);
        assert_eq!(frame_size(16, 1.01), 20);
        assert_eq!(frame_size(16, 1.25), 20);
        assert_eq!(frame_size(16, 1.5), 24);
        assert_eq!(frame_size(24, 1.25), 32);
        assert_eq!(frame_size(24, 2.0), 48);
        assert_eq!(frame_size(24, 8.0), 256);
        assert_eq!(frame_size(24, 20.0), 256);
    }

    #[test]
    fn committed_png_and_ico_matrices_match_the_asset_contract() {
        let assets = assets();

        for size in SIZES {
            for slug in SLUGS {
                let path = assets
                    .join("icons")
                    .join("png")
                    .join(size.to_string())
                    .join(format!("broccoli-{slug}.png"));
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
                let decoded = image::load_from_memory(&bytes)
                    .unwrap_or_else(|error| panic!("decode {}: {error}", path.display()));
                assert_eq!(
                    decoded.color(),
                    image::ColorType::Rgba8,
                    "{} is not 8-bit RGBA",
                    path.display()
                );
                let rgba = decoded.into_rgba8();
                assert_eq!(rgba.dimensions(), (size, size), "{}", path.display());

                let mut saw_transparent_pixel = false;
                for pixel in rgba.pixels() {
                    if pixel[3] == 0 {
                        saw_transparent_pixel = true;
                        assert_eq!(
                            &pixel.0[..3],
                            &[0, 0, 0],
                            "{} retains RGB under zero alpha",
                            path.display()
                        );
                    }
                }
                assert!(
                    saw_transparent_pixel,
                    "{} has no transparent background",
                    path.display()
                );
            }
        }

        for size in [16_u32, 32, 256] {
            let mut variants = Vec::new();
            for slug in SLUGS {
                let path = assets
                    .join("icons")
                    .join("png")
                    .join(size.to_string())
                    .join(format!("broccoli-{slug}.png"));
                let pixels = image::load_from_memory(&std::fs::read(&path).expect("read PNG"))
                    .expect("decode PNG")
                    .into_rgba8()
                    .into_raw();
                variants.push((slug, pixels));
            }
            for left in 0..variants.len() {
                for right in (left + 1)..variants.len() {
                    assert_ne!(
                        variants[left].1, variants[right].1,
                        "{}px variants {} and {} are identical",
                        size, variants[left].0, variants[right].0
                    );
                }
            }
        }

        for slug in SLUGS {
            let path = assets
                .join("icons")
                .join("ico")
                .join(format!("broccoli-{slug}.ico"));
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            assert!(bytes.len() >= 6 + 16 * SIZES.len(), "{}", path.display());
            assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 0);
            assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 1);
            assert_eq!(
                usize::from(u16::from_le_bytes([bytes[4], bytes[5]])),
                SIZES.len()
            );

            let mut next_image_offset = 6 + 16 * SIZES.len();
            for (index, expected_size) in SIZES.into_iter().enumerate() {
                let entry = 6 + index * 16;
                let width = if bytes[entry] == 0 {
                    256
                } else {
                    u32::from(bytes[entry])
                };
                let height = if bytes[entry + 1] == 0 {
                    256
                } else {
                    u32::from(bytes[entry + 1])
                };
                assert_eq!((width, height), (expected_size, expected_size));
                assert_eq!(u16::from_le_bytes([bytes[entry + 4], bytes[entry + 5]]), 1);
                assert_eq!(u16::from_le_bytes([bytes[entry + 6], bytes[entry + 7]]), 32);
                let image_len = u32::from_le_bytes(
                    bytes[entry + 8..entry + 12]
                        .try_into()
                        .expect("ICO image length"),
                ) as usize;
                let image_offset = u32::from_le_bytes(
                    bytes[entry + 12..entry + 16]
                        .try_into()
                        .expect("ICO image offset"),
                ) as usize;
                assert_eq!(image_offset, next_image_offset);
                let end = image_offset
                    .checked_add(image_len)
                    .expect("ICO image range overflow");
                assert!(end <= bytes.len(), "{}", path.display());
                let png = &bytes[image_offset..end];
                assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
                assert_eq!(
                    u32::from_be_bytes(png[16..20].try_into().expect("PNG width")),
                    expected_size
                );
                assert_eq!(
                    u32::from_be_bytes(png[20..24].try_into().expect("PNG height")),
                    expected_size
                );
                next_image_offset = end;
            }
            assert_eq!(next_image_offset, bytes.len(), "{}", path.display());
        }

        assert_eq!(
            std::fs::read(assets.join("icon.png")).expect("read root PNG"),
            std::fs::read(
                assets
                    .join("icons")
                    .join("png")
                    .join("256")
                    .join("broccoli-neutral.png")
            )
            .expect("read neutral PNG")
        );
        assert_eq!(
            std::fs::read(assets.join("icon.ico")).expect("read root ICO"),
            std::fs::read(
                assets
                    .join("icons")
                    .join("ico")
                    .join("broccoli-neutral.ico")
            )
            .expect("read neutral ICO")
        );
    }
}
