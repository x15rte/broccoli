//! The icon glyphs the screens carry are emoji, and the system emoji font
//! draws them in color: `epaint` rasterizes the font's COLR/bitmap glyph and
//! the tessellator keeps the glyph's own colors instead of tinting it.
//!
//! This pins that path for the glyphs the UI actually ships. A symbol swapped
//! for a non-emoji, or the font provider dropped, shows up here as a glyph that
//! would render monochrome and silently ignore the label's color.

// The glyphs come from the platform's own emoji font, which this app only
// ships on Windows.
#![cfg(windows)]

use std::sync::Arc;

use broccoli::i18n::{Key, t};
use broccoli::model::settings::Language;
use broccoli::ui::widgets::{MOVE_DOWN_GLYPH, MOVE_UP_GLYPH};

/// The first character of every UI string that opens with an icon, plus the
/// compact move pair's own glyphs.
fn icon_glyphs() -> Vec<char> {
    let keys = [
        Key::DeleteRow,
        Key::ProbeRow,
        Key::DashboardRateUp,
        Key::DashboardRateDown,
        Key::GridUpTotal,
        Key::GridDownTotal,
        Key::NavSpeedUp,
        Key::NavSpeedDown,
        Key::SrvImportOkMark,
        Key::SrvImportIgnoredMark,
    ];
    let mut glyphs: Vec<char> = keys
        .into_iter()
        .filter_map(|key| t(Language::En, key).chars().next())
        .collect();
    glyphs.extend(MOVE_UP_GLYPH.chars().next());
    glyphs.extend(MOVE_DOWN_GLYPH.chars().next());
    glyphs
}

#[test]
fn every_icon_glyph_is_drawn_by_the_color_emoji_font() {
    let ctx = egui::Context::default();
    ctx.add_font_provider(Arc::new(
        egui_system_font_provider::SystemFontProvider::new(),
    ));

    let mut report: Vec<(char, bool)> = Vec::new();
    let mut output = ctx.run_ui(Default::default(), |ctx| {
        report = ctx.fonts_mut(|fonts| {
            let text: String = icon_glyphs().into_iter().collect();
            let galley =
                fonts.layout_no_wrap(text, egui::FontId::proportional(14.0), egui::Color32::WHITE);
            galley
                .rows
                .iter()
                .flat_map(|row| row.glyphs.iter())
                // The variation selector is a zero-width layout glyph with no
                // drawing of its own.
                .filter(|glyph| glyph.chr != '\u{FE0F}')
                .map(|glyph| (glyph.chr, glyph.is_color))
                .collect()
        });
    });
    output.textures_delta.clear();

    assert_eq!(
        report.len(),
        icon_glyphs().len(),
        "every icon glyph must lay out"
    );
    for (chr, is_color) in report {
        assert!(
            is_color,
            "{chr:?} (U+{:04X}) must render as a color emoji glyph",
            chr as u32
        );
    }
}
