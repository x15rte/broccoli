//! About screen: the app's identity, the state of the parts it runs on, and
//! the attribution each of those parts requires.
//!
//! A lockup (brand mark, wordmark with version, tagline, repository link)
//! sits over a ledger with one row per component. Everything is left-aligned
//! in one column that stops short of the line length where reading slows.

use std::sync::Arc;

use egui::text::{LayoutJob, TextFormat};
use egui::{Color32, FontId, Galley, Image, Rect, RichText, Ui, Vec2, pos2};

use super::UiCtx;
use super::status::status_colors_of;
use super::widgets;
use crate::i18n::{Key, t, t_fmt};
use crate::model::settings::Language;
use crate::sys;

/// Width of the screen's column; wrapped text never runs wider.
const COLUMN_WIDTH: f32 = 600.0;
/// Height of the brand mark, in points.
const MARK_SIZE: f32 = 104.0;
/// The part of the 256 px icon canvas that holds the artwork: the icon is
/// drawn left-aligned in its canvas, so showing the whole texture would leave
/// a blank strip between the mark and the wordmark.
const MARK_UV: Rect = Rect::from_min_max(pos2(0.0, 0.04), pos2(0.78, 0.85));
/// Width over height of [`MARK_UV`]'s region.
const MARK_ASPECT: f32 = 0.78 / 0.81;
/// Wordmark size; the version shares its text line, so egui sets both on a
/// common baseline.
const WORDMARK_SIZE: f32 = 44.0;
const VERSION_SIZE: f32 = 18.0;
const SECTION_SIZE: f32 = 18.0;
/// Component names that are file names, not translatable words.
const WINTUN_FILE: &str = "wintun.dll";
const UPSTREAM_URL: &str = "https://github.com/XTLS/Xray-core";

/// The 256 px render of the tray's neutral icon: the same mark the window and
/// tray carry, so the About screen shows the app's own face.
const MARK_PNG: &[u8] = include_bytes!("../../assets/icons/png/256/broccoli-neutral.png");

/// Decode [`MARK_PNG`] into a texture, or `None` when the bytes do not decode.
/// The bytes are compiled in, so a failure is a build defect; the caller
/// remembers the outcome rather than decoding again every frame.
fn load_mark(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let rgba = image::load_from_memory(MARK_PNG).ok()?.into_rgba8();
    let size = [rgba.width() as usize, rgba.height() as usize];
    let image = egui::ColorImage::from_rgba_unmultiplied(size, rgba.as_raw());
    Some(ctx.load_texture("about-mark", image, egui::TextureOptions::LINEAR))
}

#[derive(Default)]
pub struct AboutScreen {
    /// The brand mark's texture, decoded on the first frame. The outer
    /// `Option` records that the decode ran, so a failed decode is not retried
    /// every frame.
    mark: Option<Option<egui::TextureHandle>>,
    /// The wordmark's laid-out galley, with the two text colors it was built
    /// for. The text itself is compile-time constant, so only those colors can
    /// change the layout; holding the galley keeps a frame free of the layout
    /// and string allocations that building it would repeat.
    wordmark: Option<(Color32, Color32, Arc<Galley>)>,
    /// Text that never changes while the language holds, built once.
    facts: Option<Facts>,
}

/// The screen's formatted text, rebuilt only when the language changes.
struct Facts {
    language: Language,
    /// `None` when the release repository is not a valid GitHub slug.
    repository: Option<String>,
    license_texts: String,
}

impl Facts {
    fn build(language: Language) -> Self {
        Self {
            language,
            repository: sys::selfupd::repository_url(),
            license_texts: t_fmt(
                language,
                Key::AboutLicenseTexts,
                &[&sys::paths::core_dir().display()],
            ),
        }
    }
}

impl AboutScreen {
    /// The wordmark galley for this frame's text colors, laid out once per
    /// color pair.
    fn wordmark(&mut self, ui: &Ui) -> Arc<Galley> {
        let strong = ui.visuals().strong_text_color();
        let weak = ui.visuals().weak_text_color();
        if let Some((cached_strong, cached_weak, galley)) = &self.wordmark
            && *cached_strong == strong
            && *cached_weak == weak
        {
            return galley.clone();
        }
        let galley = ui
            .ctx()
            .fonts_mut(|fonts| fonts.layout_job(wordmark_job(strong, weak)));
        self.wordmark = Some((strong, weak, galley.clone()));
        galley
    }

    pub fn show(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        if self.facts.as_ref().is_some_and(|f| f.language != lang) {
            self.facts = None;
        }
        let wordmark = self.wordmark(ui);
        let facts = self.facts.get_or_insert_with(|| Facts::build(lang));
        let mark = self
            .mark
            .get_or_insert_with(|| load_mark(ui.ctx()))
            .as_ref();

        // The shell already wraps this screen in a vertical ScrollArea.
        ui.add_space(12.0);
        ui.scope(|ui| {
            ui.set_max_width(COLUMN_WIDTH);
            lockup(ui, lang, mark, wordmark, facts.repository.as_deref());
            ui.add_space(32.0);

            ui.label(RichText::new(t(lang, Key::AboutComponents)).size(SECTION_SIZE));
            ui.add_space(4.0);
            // One ledger row per component: the rule between rows, then the
            // component's name beside the facts about it.
            ui.separator();
            widgets::ledger_row_multiline(
                ui,
                RichText::new(t(lang, Key::AboutXrayCore)).strong(),
                |ui| {
                    match ctx.core_version.as_deref() {
                        Some(version) => {
                            ui.label(version);
                        }
                        None => {
                            ui.label(
                                RichText::new(t(lang, Key::AboutCoreMissing))
                                    .color(status_colors_of(ui).warn),
                            );
                            ui.label(RichText::new(t(lang, Key::AboutCoreMissingHint)).weak());
                        }
                    }
                    ui.label(RichText::new(t(lang, Key::AboutLicenseXray)).weak());
                    ui.hyperlink_to(t(lang, Key::AboutUpstreamLink), UPSTREAM_URL);
                },
            );
            ui.separator();
            widgets::ledger_row(ui, RichText::new(WINTUN_FILE).strong(), |ui| {
                ui.label(RichText::new(t(lang, Key::AboutLicenseWintun)).weak());
            });
            ui.separator();

            ui.add_space(12.0);
            ui.label(RichText::new(&facts.license_texts).weak().small());
            ui.label(RichText::new(t(lang, Key::AboutBuiltWith)).weak().small());
        });
    }
}

/// The identity block: mark beside the wordmark, its version, the tagline,
/// and the repository link when the release repository is known.
fn lockup(
    ui: &mut Ui,
    lang: Language,
    mark: Option<&egui::TextureHandle>,
    wordmark: Arc<Galley>,
    repository: Option<&str>,
) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 20.0;
        if let Some(mark) = mark {
            ui.add(
                Image::new(mark)
                    .uv(MARK_UV)
                    .fit_to_exact_size(Vec2::new(MARK_SIZE * MARK_ASPECT, MARK_SIZE)),
            );
        }
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(wordmark);
            ui.label(t(lang, Key::AboutTagline));
            if let Some(url) = repository {
                ui.hyperlink_to(t(lang, Key::AboutRepoLink), url);
            }
        });
    });
}

/// "broccoli" large and the version small after it, in one galley.
fn wordmark_job(strong: Color32, weak: Color32) -> LayoutJob {
    let mut job = LayoutJob::default();
    job.append(
        env!("CARGO_PKG_NAME"),
        0.0,
        TextFormat::simple(FontId::proportional(WORDMARK_SIZE), strong),
    );
    job.append(
        env!("CARGO_PKG_VERSION"),
        12.0,
        TextFormat::simple(FontId::proportional(VERSION_SIZE), weak),
    );
    job
}
