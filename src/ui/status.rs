//! Theme-aware semantic status colors.
//!
//! The pre-theme UI hardcoded dark-tuned colors (`Color32::YELLOW`,
//! `from_rgb(0xe0, 0xa0, 0x40)`, …) that become unreadable on the Light
//! theme (light yellow on white). Every status text, dot, and error frame
//! must pick its color from [`status_colors`] / [`status_colors_of`] instead
//! of a raw literal, so both themes stay readable.

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

#[cfg(test)]
mod tests {
    use super::*;

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
