//! Theme-aware status colors and the phase badge's presentation.
//!
//! The pre-theme UI hardcoded dark-tuned colors (`Color32::YELLOW`,
//! `from_rgb(0xe0, 0xa0, 0x40)`, …) that become unreadable on the Light
//! theme (light yellow on white). Every status text, dot, and error frame
//! must pick its color from [`status_colors`] / [`status_colors_of`] instead
//! of a raw literal, so both themes stay readable.
//!
//! The phase badge — the colored dot plus its caption, shown by the top bar
//! and the dashboard header — keeps its phase→presentation rule here too:
//! one match per fact, so a new [`CorePhase`] variant cannot be handled in
//! one surface and forgotten in the other.

use crate::i18n::{Key, t, t_fmt};
use crate::model::settings::Language;
use crate::rt::CorePhase;
use egui::{Color32, Ui};

/// Semantic status palette for one theme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusColors {
    pub ok: Color32,
    pub warn: Color32,
    pub err: Color32,
}

/// Palettes for the two themes. Every value passes WCAG AA (contrast ≥ 4.5:1)
/// against its theme's panel background — enforced by the tests below.
pub const fn status_colors(dark: bool) -> StatusColors {
    if dark {
        // egui dark panel background ≈ #1b1b1b.
        StatusColors {
            ok: Color32::from_rgb(0x4f, 0xaf, 0x4f),
            warn: Color32::from_rgb(0xe0, 0xa0, 0x40),
            err: Color32::from_rgb(0xe0, 0x60, 0x60),
        }
    } else {
        // White panel background.
        StatusColors {
            ok: Color32::from_rgb(0x2e, 0x7d, 0x32),
            warn: Color32::from_rgb(0x8a, 0x5e, 0x00),
            err: Color32::from_rgb(0xb0, 0x2a, 0x2a),
        }
    }
}

/// Palette for the theme `ui` is currently rendering in.
pub fn status_colors_of(ui: &Ui) -> StatusColors {
    status_colors(ui.visuals().dark_mode)
}

/// Which wording a phase badge uses: the top bar's chip caption or the
/// dashboard header's status word. The two surfaces word the same phase
/// differently ("Starting…" beside the action button, "Starting" as a row
/// label, "Retrying (attempt 2)" versus "Retry #2"), but which variant a
/// phase maps to is one rule, written once below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PhaseBadgeWording {
    Topbar,
    Dashboard,
}

/// Pure phase → badge caption. One arm per phase — the wording selects the
/// key set, never the shape (an error phase stays a phase word in both: its
/// message is the terminal error block, not a badge payload).
pub(crate) fn phase_badge_text(
    p: &CorePhase,
    lang: Language,
    wording: PhaseBadgeWording,
) -> String {
    let (topbar, dashboard, attempt) = match p {
        CorePhase::Stopped => (Key::AppPhaseStopped, Key::DashboardPhaseStopped, None),
        CorePhase::Starting => (Key::AppPhaseStarting, Key::DashboardPhaseStarting, None),
        CorePhase::Running => (Key::AppPhaseRunning, Key::DashboardPhaseRunning, None),
        CorePhase::Backoff { attempt } => (
            Key::AppPhaseRetrying,
            Key::DashboardPhaseRetry,
            Some(*attempt),
        ),
        CorePhase::Error(_) => (Key::AppPhaseError, Key::DashboardPhaseError, None),
    };
    let key = match wording {
        PhaseBadgeWording::Topbar => topbar,
        PhaseBadgeWording::Dashboard => dashboard,
    };
    match attempt {
        Some(attempt) => t_fmt(lang, key, &[&attempt]),
        None => t(lang, key).into(),
    }
}

/// Pure phase → badge dot color, from the theme's status palette.
pub(crate) fn phase_badge_color(p: &CorePhase, colors: StatusColors) -> Color32 {
    match p {
        CorePhase::Stopped => Color32::GRAY,
        CorePhase::Starting => colors.warn,
        CorePhase::Running => colors.ok,
        CorePhase::Backoff { .. } => colors.warn,
        CorePhase::Error(_) => colors.err,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every phase maps to a badge caption in both wordings, and an error
    /// phase stays a phase word in each: the failure's message belongs to the
    /// terminal error block, never to the phase readout. One table over the
    /// phase, since that is the rule this module owns.
    #[test]
    fn phase_badge_captions_cover_every_phase_in_both_wordings() {
        let error = CorePhase::Error(crate::rt::PhaseError::new(crate::diag::Diag::new(
            Key::RtPhaseRestartCancelled,
        )));
        let cases = [
            (CorePhase::Stopped, "Stopped", "Stopped"),
            (CorePhase::Starting, "Starting…", "Starting"),
            (CorePhase::Running, "Running", "Running"),
            (
                CorePhase::Backoff { attempt: 3 },
                "Retrying (attempt 3)",
                "Retry #3",
            ),
        ];
        for (phase, topbar, dashboard) in cases {
            assert_eq!(
                phase_badge_text(&phase, Language::En, PhaseBadgeWording::Topbar),
                topbar,
                "{phase:?}"
            );
            assert_eq!(
                phase_badge_text(&phase, Language::En, PhaseBadgeWording::Dashboard),
                dashboard,
                "{phase:?}"
            );
        }
        let headline = t(Language::En, Key::RtPhaseRestartCancelled);
        for wording in [PhaseBadgeWording::Topbar, PhaseBadgeWording::Dashboard] {
            let caption = phase_badge_text(&error, Language::En, wording);
            assert_eq!(caption, "Error", "the badge must read the phase word");
            assert!(
                !caption.contains(headline),
                "the failure's message must not stand where the phase belongs"
            );
        }
    }

    /// The dot color follows the theme's palette role for each phase.
    #[test]
    fn phase_badge_color_follows_the_palette() {
        let colors = status_colors(true);
        assert_eq!(
            phase_badge_color(&CorePhase::Stopped, colors),
            Color32::GRAY
        );
        assert_eq!(phase_badge_color(&CorePhase::Starting, colors), colors.warn);
        assert_eq!(phase_badge_color(&CorePhase::Running, colors), colors.ok);
        assert_eq!(
            phase_badge_color(&CorePhase::Backoff { attempt: 1 }, colors),
            colors.warn
        );
        assert_eq!(
            phase_badge_color(
                &CorePhase::Error(crate::rt::PhaseError::new(crate::diag::Diag::new(
                    Key::RtPhaseConfigError
                ))),
                colors
            ),
            colors.err
        );
    }

    /// WCAG relative luminance of an sRGB color.
    fn luminance(c: Color32) -> f64 {
        let [r, g, b, _] = c.to_srgba_unmultiplied();
        let linear = |v: u8| {
            let s = f64::from(v) / 255.0;
            if s <= 0.04045 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
    }

    fn contrast(a: Color32, b: Color32) -> f64 {
        let (hi, lo) = if luminance(a) >= luminance(b) {
            (luminance(a), luminance(b))
        } else {
            (luminance(b), luminance(a))
        };
        (hi + 0.05) / (lo + 0.05)
    }

    /// Regression lock for the Light-theme readability bug: every status
    /// role must be legible on BOTH themes' panel backgrounds.
    #[test]
    fn status_colors_pass_wcag_aa_on_both_themes() {
        // egui dark panel background ≈ #1b1b1b; light panels are white.
        let backgrounds = [
            ("light", false, Color32::WHITE),
            ("dark", true, Color32::from_rgb(0x1b, 0x1b, 0x1b)),
        ];
        for (theme_name, dark, bg) in backgrounds {
            let colors = status_colors(dark);
            for (role, color) in [
                ("ok", colors.ok),
                ("warn", colors.warn),
                ("err", colors.err),
            ] {
                let ratio = contrast(color, bg);
                assert!(
                    ratio >= 4.5,
                    "{theme_name} {role} {color:?} has contrast {ratio:.2}:1, needs ≥ 4.5:1"
                );
            }
        }
    }
}
