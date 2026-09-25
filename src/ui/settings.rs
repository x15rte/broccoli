//! Settings screen: core knobs, update buttons, and the
//! raw-JSON forward-compat hatch.
//!
//! Xray-facing edits mutate `ctx.settings` + `ctx.mark_dirty()`; the shell
//! saves those edits, while global appearance zoom uses egui's persisted UI
//! memory. Apply now or Connect updates Xray.

use egui::{Color32, RichText, Ui};

use super::{CoreSetupMount, UiCtx, show_core_setup, status::status_colors_of, widgets};
use crate::diag::{Diag, DiagError};
use crate::i18n::{Key, t, t_fmt};
use crate::links::excerpt;
use crate::model::PolicyLevelCfg;
use crate::model::settings::{Language, geodata_cron_error, geodata_url_error};
use crate::rt::{CoreCmd, TestConfigReply};
use crate::sys;
use crate::sys::selfupd::UpdateCheckState;
use crate::ui::request::{Request, Terminal};

const LOG_LEVELS: [&str; 5] = ["debug", "info", "warning", "error", "none"];

/// Parse the raw override edit buffer: an empty/whitespace-only buffer is
/// `Err("")` (rendered as the paste hint), anything else is the JSON result.
fn parse_raw_override(buf: &str) -> Result<serde_json::Value, String> {
    if buf.trim().is_empty() {
        Err(String::new())
    } else {
        serde_json::from_str(buf).map_err(|error| excerpt(&error.to_string()))
    }
}

/// Size cap for the raw-override edit buffer: a full config.json is
/// structurally small (tens of KiB), so anything larger is hostile input and
/// is refused before any parse (worker or otherwise) sees it.
const RAW_OVERRIDE_MAX_BYTES: usize = 4 << 20; // 4 MiB

/// One delivered background parse of `raw_buf`: the result carries the
/// generation it parsed, so the UI can respawn when a stale result lands.
struct RawParseResult {
    generation: u64,
    result: Result<serde_json::Value, String>,
}

/// Latest raw-override parse state, kept current by the worker (or by the
/// size-cap refusal). `None` renders a spinner; `Ok`/`Err` gate the buttons.
#[derive(Debug)]
enum RawParseState {
    Empty,
    TooLarge(usize, usize),
    Ok(serde_json::Value),
    Err(String),
}

/// Per-file `(mtime, len)` fingerprint of the managed geo data (Settings →
/// Geodata): the memoization key that decides when a provenance
/// hash job must run. Two cheap metadata reads per rendered frame, never a
/// hash on the UI thread; a file that is missing or cannot be statted
/// fingerprints as absent, so its (re)appearance re-triggers a hash.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
struct GeoDataFingerprint {
    geoip: Option<(std::time::SystemTime, u64)>,
    geosite: Option<(std::time::SystemTime, u64)>,
}

/// Current `(mtime, len)` of each managed geo data file, or `None` overall
/// when the managed core directory itself is absent (there is then no geo
/// data to provenance and the status row stays hidden until a core exists).
fn geo_data_fingerprint() -> Option<GeoDataFingerprint> {
    let core = crate::sys::paths::core_dir();
    if !core.is_dir() {
        return None;
    }
    let stat = |payload: &str| {
        std::fs::metadata(core.join(payload))
            .ok()
            .and_then(|metadata| {
                metadata
                    .modified()
                    .ok()
                    .map(|modified| (modified, metadata.len()))
            })
    };
    Some(GeoDataFingerprint {
        geoip: stat("geoip.dat"),
        geosite: stat("geosite.dat"),
    })
}

/// Outcome of the last Restore click, rendered as a feedback line under the
/// section until the next click (raw-parse verdict persistence pattern).
#[derive(Debug, Clone)]
enum GeoDataRestoreFeedback {
    Done,
    Failed(String),
}

/// Rendered provenance status caption, memoized on `(result, language)`:
/// the mtime Debug string and sentence build allocate,
/// so idle frames only compare the cached key.
struct GeoDataCaption {
    lang: Language,
    result: crate::sys::core_dl::GeoDataProvenance,
    text: String,
}

/// Session state behind the Settings → Geodata provenance status line and
/// the Restore action. The status is recomputed each session —
/// never persisted — by hashing the on-disk geo data whenever the section
/// renders and the file fingerprint changed; Restore replaces the managed
/// geo data with the pin-verified pristine pair.
#[derive(Default)]
struct GeoDataProvenanceState {
    /// Fingerprint the last adopted result was computed from.
    fingerprint: Option<GeoDataFingerprint>,
    /// Last completed provenance (`None` until the first job lands; the
    /// no-core answer is adopted without a worker).
    result: Option<crate::sys::core_dl::GeoDataProvenance>,
    /// In-flight provenance hash job (the worker runs
    /// `core_dl::geo_data_provenance` — the full 27 MB-per-file SHA-256
    /// compare — so a render frame never hashes); never more than one at a
    /// time.
    job: Request<crate::sys::core_dl::GeoDataProvenance>,
    /// Fingerprint the in-flight job is hashing.
    job_fingerprint: Option<GeoDataFingerprint>,
    /// Rendered status caption (see [`GeoDataCaption`]).
    caption: Option<GeoDataCaption>,
    /// In-flight `restore_pristine_geo_data` run; the button disables while
    /// set.
    restore_job: Request<Result<(), DiagError>>,
    /// Outcome of the last Restore click.
    restore_feedback: Option<GeoDataRestoreFeedback>,
}

impl GeoDataProvenanceState {
    /// Per-frame driver of the provenance hash, called once per rendered
    /// frame of the section. Drains a landed hash job (adopting its answer
    /// only while the files still match the fingerprint it hashed — the
    /// raw-parse generation discipline, applied to bytes), fingerprints
    /// both geo data files (two metadata reads, cheap), and respawns the
    /// hash job when the fingerprint changed since the last completed hash
    /// or nothing is cached yet. Never hashes on the UI thread and never
    /// runs two hash jobs at once; while a restore runs, hash respawns
    /// wait for it (the restore rewrites the files a pending hash would
    /// read).
    fn update(&mut self, repaint: &egui::Context) {
        let fingerprint = geo_data_fingerprint();
        if self.job.is_pending() {
            match self.job.poll() {
                Some(Terminal::Answered(provenance)) if self.job_fingerprint == fingerprint => {
                    // The files are still exactly the ones the job hashed.
                    self.fingerprint = fingerprint;
                    self.result = Some(provenance);
                    self.caption = None;
                }
                Some(Terminal::Answered(_)) => {
                    // The files changed while the job hashed; its answer is
                    // stale and the fresh query below replaces it.
                    self.fingerprint = None;
                    self.result = None;
                    self.caption = None;
                }
                Some(Terminal::Exited) => {
                    // The worker closure has no panic path, so it cannot
                    // exit without sending; re-query defensively.
                    self.job_fingerprint = None;
                }
                None => {
                    // Still hashing; poll again next frame.
                    return;
                }
            }
        }
        if self.job.is_pending() || self.restore_job.is_pending() {
            // A hash is already in flight, or a restore is rewriting the
            // files the hash would read — never pile on.
            return;
        }
        let needs_query = match (&self.result, self.fingerprint) {
            (None, _) => true,
            (Some(_), None) => fingerprint.is_some(),
            (Some(_), Some(cached)) => Some(cached) != fingerprint,
        };
        if !needs_query {
            return;
        }
        match fingerprint {
            Some(fingerprint) => self.spawn_hash(repaint, fingerprint),
            None => {
                // No managed core directory: nothing exists to hash, so the
                // no-core answer is adopted without a worker.
                self.fingerprint = None;
                self.result = Some(sys::core_dl::GeoDataProvenance::NoCore);
                self.caption = None;
            }
        }
    }

    /// Spawn one provenance hash job for `fingerprint` (the files it must
    /// hash). Single-flight by construction: `update` calls this only while
    /// no job is pending and no restore is running.
    fn spawn_hash(&mut self, repaint: &egui::Context, fingerprint: GeoDataFingerprint) {
        let core = sys::paths::core_dir();
        // The closure owns its copy; the fallback below still borrows the
        // caller's `core` after the spawn attempt.
        let worker_core = core.clone();
        match Request::worker("broccoli-geodata-provenance", repaint, move |_| {
            // One full 27 MB-per-file SHA-256 compare, off the UI thread;
            // pure read, safe while the core runs.
            Some(sys::core_dl::geo_data_provenance(&worker_core))
        }) {
            Ok(job) => {
                self.job = job;
                self.job_fingerprint = Some(fingerprint);
            }
            Err(error) => {
                // Thread-spawn failure (resource exhaustion): fall back to a
                // synchronous query so the status still renders this frame —
                // the same degraded fallback tun.rs uses for its adapter
                // enumeration.
                tracing::warn!("geo data provenance worker spawn failed: {error}");
                self.result = Some(sys::core_dl::geo_data_provenance(&core));
                self.fingerprint = Some(fingerprint);
                self.caption = None;
            }
        }
    }

    /// Drain a landed restore result into the feedback line. A successful
    /// restore also resets the provenance memo, so the next frame re-hashes
    /// the restored pair and the status flips back to release-managed even
    /// when the replace kept the (mtime, len) fingerprint unchanged.
    fn poll_restore(&mut self, lang: Language) {
        let Some(terminal) = self.restore_job.poll() else {
            return;
        };
        let outcome = match terminal {
            Terminal::Answered(result) => result,
            Terminal::Exited => {
                // raw-parse discipline: a vanished worker is a terminal
                // with a generic reason.
                Err(DiagError::from(Diag::new(Key::WorkerExitedWithoutResult)))
            }
        };
        match outcome {
            Ok(()) => {
                self.fingerprint = None;
                self.result = None;
                self.caption = None;
                self.restore_feedback = Some(GeoDataRestoreFeedback::Done);
            }
            Err(error) => {
                self.restore_feedback = Some(GeoDataRestoreFeedback::Failed(t_fmt(
                    lang,
                    Key::SettingsGeodataRestoreFailed,
                    &[&error.text(lang)],
                )));
            }
        }
    }

    /// Start one restore worker (one per click; the button disables while
    /// it runs). `restore_pristine_geo_data` verifies the pristine pair
    /// against the compiled pins before touching any managed file, so only
    /// pin-verified bytes can ever be written.
    fn spawn_restore(&mut self, repaint: &egui::Context, lang: Language) {
        let core = sys::paths::core_dir();
        match Request::worker("broccoli-geodata-restore", repaint, move |_| {
            // The install's keyed chain travels whole: a running core's
            // deny-write locks surface as the sharing violation naming the
            // failed rename, and a missing pristine pair names the file
            // ("restore unavailable"), each rendered in the active language
            // at the feedback line.
            Some(sys::core_dl::restore_pristine_geo_data(&core))
        }) {
            Ok(job) => {
                self.restore_job = job;
                self.restore_feedback = None;
            }
            Err(error) => {
                self.restore_feedback = Some(GeoDataRestoreFeedback::Failed(t_fmt(
                    lang,
                    Key::SettingsGeodataRestoreWorkerFailed,
                    &[&error],
                )));
            }
        }
    }

    /// Rebuild the rendered status caption when the provenance result or
    /// the language changed; idle frames only compare the memo key.
    /// The update time renders as the SystemTime Debug string —
    /// the same representation the routing screen's geodata tooltip shows
    /// for these files' mtimes (the repo's only mtime display precedent).
    fn refresh_caption(&mut self, lang: Language) {
        let Some(result) = &self.result else {
            self.caption = None;
            return;
        };
        if self
            .caption
            .as_ref()
            .is_some_and(|caption| caption.lang == lang && &caption.result == result)
        {
            return;
        }
        let text = match result {
            sys::core_dl::GeoDataProvenance::ReleaseManaged => {
                t(lang, Key::SettingsGeodataProvenanceRelease).to_owned()
            }
            sys::core_dl::GeoDataProvenance::UserManaged { updated } => match updated {
                Some(modified) => t_fmt(
                    lang,
                    Key::SettingsGeodataProvenanceUserOn,
                    &[&format!("{modified:?}")],
                ),
                None => t(lang, Key::SettingsGeodataProvenanceUserUnknown).to_owned(),
            },
            sys::core_dl::GeoDataProvenance::NoCore => return,
        };
        self.caption = Some(GeoDataCaption {
            lang,
            result: result.clone(),
            text,
        });
    }
}

#[derive(Default)]
pub struct SettingsScreen {
    /// Local edit buffer for the raw override, loaded from settings on first
    /// open of the collapsing header.
    raw_buf: String,
    raw_loaded: bool,
    /// Latest parse state of `raw_buf`, kept current by the worker (or the
    /// size-cap refusal); never parsed on the UI thread.
    raw_parse: Option<RawParseState>,
    /// In-flight worker parse of `raw_buf` (idle while none runs or the
    /// buffer was refused).
    raw_parse_job: Request<RawParseResult>,
    /// Buffer generation counter: bumped on every edit, so a stale worker
    /// result (from an older buffer) is detected and respawned.
    raw_parse_generation: u64,
    /// Local edit buffers for the geodata URL/cron fields (Option<String>
    /// model, String edit buffers), loaded from settings on first open.
    geoip_url_buf: Option<String>,
    geosite_url_buf: Option<String>,
    geodata_cron_buf: Option<String>,
    /// Session state of the geo data provenance status line and the Restore
    /// action: memoized hash result + one in-flight job per
    /// action, kept while the screen lives so a re-open never re-hashes
    /// unchanged geo data.
    geodata_provenance: GeoDataProvenanceState,
    /// Whether the Cleanup modal is open.
    cleanup_modal: bool,
    /// Whether full cleanup was confirmed; consumed by the shell
    /// ([`Self::take_cleanup_request`]) so the app can stash it for `main`
    /// and quit through the normal shutdown path.
    cleanup_request: bool,
    /// Whether the Reset modal is open.
    reset_modal: bool,
    /// Whether Reset was confirmed; consumed by the shell
    /// ([`Self::take_reset_request`]) so the app can quit with the exit wipe
    /// that restores a fresh install's defaults while keeping the server
    /// list.
    reset_request: bool,
    /// In-flight `Validate with core` run (one per click): the runtime's
    /// terminal verdict lands on this request's reply channel and is polled
    /// every frame the raw-override header renders.
    test_pending: Request<TestConfigReply>,
    /// Latest core validation verdict, rendered under the raw-override
    /// header; replaced on every new click and every terminal.
    test_verdict: Option<(bool, String)>,
    /// UI-scale caption (`"{:.0}%"`), cached on the zoom factor — the
    /// appearance combo re-formats it every frame otherwise.
    /// `None` until the first appearance frame.
    zoom_caption: Option<(f32, String)>,
    /// Per-user-level policy headers, pre-rendered at the model-generation
    /// cadence — each `CollapsingHeader::new(t_fmt(...))` used to format
    /// per level per frame. `None` until the first frame.
    level_rows: Option<LevelRowCache>,
}

/// One generation of the per-user-level policy headers:
/// the name list the headers were built from plus the formatted titles.
/// The cache is invalidated by an exact name-list comparison — a level
/// add/remove is an interaction frame, never idle, so the per-frame check
/// is a plain element-wise string comparison, not an allocation.
struct LevelRowCache {
    lang: Language,
    names: Vec<String>,
    headers: Vec<String>,
}

impl SettingsScreen {
    pub fn show(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        // The shell already wraps this screen in a vertical ScrollArea.
        self.appearance_section(ui, ctx);
        self.core_section(ui, ctx);
        self.core_setup_section(ui, ctx);
        self.updates_section(ui, ctx);
        self.cleanup_section(ui, ctx);
        self.geodata_section(ui, ctx);
        self.advanced_section(ui, ctx);
    }

    /// (Re)start parsing `raw_buf` on the worker thread after a buffer edit
    /// (or the first open). Buffers over [`RAW_OVERRIDE_MAX_BYTES`] are
    /// refused up front with a message and never reach the worker. While a
    /// worker is already running for an older buffer, the stale result is
    /// detected by its generation and a fresh worker is spawned then.
    fn bump_raw_parse(&mut self, repaint: egui::Context, lang: Language) {
        self.raw_parse_generation = self.raw_parse_generation.wrapping_add(1);
        if self.raw_buf.len() > RAW_OVERRIDE_MAX_BYTES {
            self.raw_parse = Some(RawParseState::TooLarge(
                self.raw_buf.len(),
                RAW_OVERRIDE_MAX_BYTES,
            ));
            // Drop any in-flight job: its stale result can never be applied.
            self.raw_parse_job.cancel();
            return;
        }
        if self.raw_parse_job.is_pending() {
            // An older buffer's worker is still running; its stale result
            // (generation mismatch) respawns for this buffer when it lands.
            self.raw_parse = None;
            return;
        }
        self.spawn_raw_parse(repaint, lang);
    }

    fn spawn_raw_parse(&mut self, repaint: egui::Context, lang: Language) {
        let generation = self.raw_parse_generation;
        let buf = self.raw_buf.clone();
        match Request::worker("broccoli-raw-parse", &repaint, move |_| {
            Some(RawParseResult {
                generation,
                result: parse_raw_override(&buf),
            })
        }) {
            Ok(job) => {
                self.raw_parse_job = job;
                self.raw_parse = None; // busy until the result lands
            }
            Err(error) => {
                self.raw_parse = Some(RawParseState::Err(t_fmt(
                    lang,
                    Key::SettingsRawOverrideWorkerFailed,
                    &[&error],
                )));
            }
        }
    }

    /// Drain one finished raw-parse result per frame. A stale result (the
    /// buffer changed while the worker ran) respawns for the current buffer.
    fn poll_raw_parse(&mut self, repaint: egui::Context, lang: Language) {
        let Some(terminal) = self.raw_parse_job.poll() else {
            return;
        };
        let (generation, result) = match terminal {
            Terminal::Answered(RawParseResult { generation, result }) => (generation, result),
            Terminal::Exited => {
                self.raw_parse = Some(RawParseState::Err(
                    t(lang, Key::WorkerExitedWithoutResult).to_string(),
                ));
                return;
            }
        };
        if generation != self.raw_parse_generation {
            // The buffer changed while this worker ran; parse the current
            // buffer. (Only `bump_raw_parse` changes the buffer, and it
            // refuses oversize, so the current buffer is within the cap.)
            self.raw_parse = None;
            self.spawn_raw_parse(repaint, lang);
            return;
        }
        self.raw_parse = Some(match result {
            Ok(value) => RawParseState::Ok(value),
            Err(message) if message.is_empty() => RawParseState::Empty,
            Err(message) => RawParseState::Err(message),
        });
    }

    fn appearance_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        const SCALE_PRESETS: [f32; 5] = [1.0, 1.25, 1.5, 1.75, 2.0];

        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::SettingsAppearance), |ui| {
            let current_zoom = ui.ctx().zoom_factor();
            let mut selected_zoom = current_zoom;
            // The zoom caption formats "{:.0}%" from the factor; cache it on
            // the factor so idle frames don't re-format (the factor only
            // changes through this very combo).
            if !matches!(&self.zoom_caption, Some((factor, _)) if *factor == current_zoom) {
                self.zoom_caption = Some((current_zoom, format!("{:.0}%", current_zoom * 100.0)));
            }
            let zoom_caption = &self
                .zoom_caption
                .as_ref()
                .expect("zoom label populated above")
                .1;
            egui::ComboBox::from_label(t(lang, Key::SettingsUiScale))
                .selected_text(zoom_caption)
                .show_ui(ui, |ui| {
                    for preset in SCALE_PRESETS {
                        if ui
                            .selectable_value(
                                &mut selected_zoom,
                                preset,
                                format!("{:.0}%", preset * 100.0),
                            )
                            .changed()
                        {
                            ui.ctx().set_zoom_factor(selected_zoom);
                        }
                    }
                });
            ui.label(t(lang, Key::SettingsScaleHint));

            // Locale list. English is the only pack shipping today; adding a
            // locale is a `Language` variant + one i18n table + one match arm.
            ui.horizontal(|ui| {
                ui.label(t(ctx.settings.language, Key::Language));
                let mut language = ctx.settings.language;
                egui::ComboBox::from_id_salt("settings_language")
                    .selected_text(t(language, Key::LanguageEnglish))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut language,
                            Language::En,
                            t(Language::En, Key::LanguageEnglish),
                        );
                    });
                if language != ctx.settings.language {
                    ctx.settings.language = language;
                    // Display preference: persisted, but never raises the
                    // Apply gate.
                    ctx.mark_ui_dirty();
                }
            });

            // Theme radio. The preference lives in egui memory (persisted by
            // eframe under the "egui" key), so no broccoli-side persistence; only
            // the click is forwarded to `set_theme`.
            ui.horizontal(|ui| {
                ui.label(t(ctx.settings.language, Key::Theme));
                let mut preference = ui.ctx().options(|options| options.theme_preference);
                // One tuple per radio: preference, label key, hover key.
                for (pref, label, hint) in [
                    (
                        egui::ThemePreference::System,
                        Key::ThemeSystem,
                        Key::ThemeSystemHint,
                    ),
                    (
                        egui::ThemePreference::Dark,
                        Key::ThemeDark,
                        Key::ThemeDarkHint,
                    ),
                    (
                        egui::ThemePreference::Light,
                        Key::ThemeLight,
                        Key::ThemeLightHint,
                    ),
                ] {
                    if ui
                        .selectable_value(&mut preference, pref, t(ctx.settings.language, label))
                        .on_hover_text(t(ctx.settings.language, hint))
                        .clicked()
                    {
                        ui.ctx().set_theme(preference);
                    }
                }
            });

            // Accent: persisted in broccoli settings and re-applied live to both
            // dark and light visuals (custom `Visuals` are not serde-persisted
            // by eframe), so System mode carries the accent too.
            ui.horizontal(|ui| {
                ui.label(t(ctx.settings.language, Key::AccentColor));
                if ui
                    .add_enabled(
                        ctx.settings.accent_color.is_some(),
                        egui::Button::new(t(ctx.settings.language, Key::AccentColorReset)),
                    )
                    .on_hover_text(t(ctx.settings.language, Key::AccentColorResetHint))
                    .clicked()
                {
                    ctx.settings.accent_color = None;
                    apply_accent(ui.ctx(), None);
                    ctx.mark_ui_dirty();
                }
                // Picker starts at the accent actually in effect, read from
                // the live visuals: `apply_accent` writes the custom accent to
                // `selection.bg_fill`, and Reset restores the stock (blue)
                // accent there too — so the well can never drift from what
                // the UI shows (a hardcoded fallback did, showing green after
                // Reset).
                let mut color = picker_start_color(ctx.settings.accent_color, ui.visuals());
                if egui::color_picker::color_edit_button_srgba(
                    ui,
                    &mut color,
                    egui::color_picker::Alpha::Opaque,
                )
                .changed()
                {
                    let rgba = accent_rgba(color);
                    if ctx.settings.accent_color != Some(rgba) {
                        ctx.settings.accent_color = Some(rgba);
                        apply_accent(ui.ctx(), Some(rgba));
                        ctx.mark_ui_dirty();
                    }
                }
            });
            ui.label(
                RichText::new(t(ctx.settings.language, Key::AccentColorHint))
                    .weak()
                    .small(),
            );
        });
    }

    fn core_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::SettingsCore), |ui| {
            ui.horizontal(|ui| {
                ui.label(t(lang, Key::SettingsLogLevel));
                let mut lvl = if ctx.settings.log_level.is_empty() {
                    "warning".to_string()
                } else {
                    ctx.settings.log_level.clone()
                };
                egui::ComboBox::from_id_salt("settings_log_level")
                    .selected_text(lvl.as_str())
                    .show_ui(ui, |ui| {
                        for l in LOG_LEVELS {
                            ui.selectable_value(&mut lvl, l.to_string(), l);
                        }
                    });
                if lvl != ctx.settings.log_level {
                    ctx.settings.log_level = lvl;
                    ctx.mark_dirty();
                }
            });
            // Xray maps loglevel "none" to both log types off
            // (infra/conf/log.go Build), so the access toggle cannot take
            // effect at that level — disable it rather than promise
            // something the config cannot express.
            let access_available = ctx.settings.log_level != "none";
            if ui
                .add_enabled(
                    access_available,
                    egui::Checkbox::new(
                        &mut ctx.settings.access_log,
                        t(lang, Key::SettingsAccessLog),
                    ),
                )
                .on_disabled_hover_text(t(lang, Key::SettingsAccessLogHint))
                .changed()
            {
                ctx.mark_dirty();
            }
            ui.label(RichText::new(t(lang, Key::SettingsEnvVars)).weak());
            if widgets::kv_table(
                ui,
                lang,
                &mut ctx.settings.env,
                "XRAY_*",
                t(lang, Key::ValueLower),
            ) {
                ctx.mark_dirty();
            }
            ui.label(RichText::new(t(lang, Key::SettingsPolicyLevels)).weak());
            let mut changed = false;
            // The "0" level must exist (its header renders open by default).
            // A contains_key probe is allocation-free; the rare repair
            // insert only ever runs on the frame it is missing
            // (`entry("0".into())` used to allocate per frame).
            if !ctx.settings.policy.levels.contains_key("0") {
                ctx.settings
                    .policy
                    .levels
                    .insert("0".into(), PolicyLevelCfg::default());
            }
            let mut remove_level = None;
            // The per-level header text is a pure function of the sorted
            // level-name list and the language, so it is pre-rendered once
            // and invalidated by an exact name comparison (a level add or
            // remove is an interaction frame — the check never allocates).
            let stale = match &self.level_rows {
                Some(cache) => {
                    cache.lang != lang
                        || cache.names.len() != ctx.settings.policy.levels.len()
                        || cache
                            .names
                            .iter()
                            .zip(ctx.settings.policy.levels.keys())
                            .any(|(cached, live)| cached != live)
                }
                None => true,
            };
            if stale {
                self.level_rows = Some(LevelRowCache {
                    lang,
                    names: ctx.settings.policy.levels.keys().cloned().collect(),
                    headers: ctx
                        .settings
                        .policy
                        .levels
                        .keys()
                        .map(|name| t_fmt(lang, Key::SettingsUserLevel, &[name]))
                        .collect(),
                });
            }
            let level_rows = &self
                .level_rows
                .as_ref()
                .expect("level rows populated above");
            for ((name, level), header) in ctx
                .settings
                .policy
                .levels
                .iter_mut()
                .zip(level_rows.headers.iter())
            {
                egui::CollapsingHeader::new(header)
                    .id_salt(("policy-level", name.as_str()))
                    .default_open(name == "0")
                    .show(ui, |ui| {
                        changed |= policy_level_editor(ui, lang, level);
                        if name != "0"
                            && ui.small_button(t(lang, Key::SettingsRemoveLevel)).clicked()
                        {
                            remove_level = Some(name.clone());
                        }
                    });
            }
            if let Some(name) = remove_level {
                ctx.settings.policy.levels.remove(&name);
                changed = true;
            }
            if ui.button(t(lang, Key::SettingsAddUserLevel)).clicked() {
                let next = ctx
                    .settings
                    .policy
                    .levels
                    .keys()
                    .filter_map(|name| name.parse::<u32>().ok())
                    .max()
                    .unwrap_or(0)
                    .saturating_add(1)
                    .to_string();
                ctx.settings.policy.levels.entry(next).or_default();
                changed = true;
            }
            if changed {
                ctx.mark_dirty();
            }
        });
    }

    /// The permanent mount of the shared core setup surface: the same
    /// component the startup dialog shows, available in every core state —
    /// installed and verified, missing, stale, or failed verification.
    fn core_setup_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::SettingsCoreSetup), |ui| {
            ui.set_max_width(680.0);
            let _ = show_core_setup(ui, ctx, CoreSetupMount::Settings);
        });
    }

    fn updates_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::SettingsUpdates), |ui| {
            ui.set_max_width(680.0);
            ui.horizontal(|ui| {
                let checking = matches!(ctx.update_check, UpdateCheckState::Checking);
                if ui
                    .add_enabled(
                        !checking,
                        egui::Button::new(t(lang, Key::SettingsCheckForUpdates)),
                    )
                    .on_hover_text(t(lang, Key::SettingsCheckForUpdatesHint))
                    .clicked()
                {
                    // Fire-and-forget: the runtime does the fetch off the UI
                    // thread and emits exactly one terminal event.
                    ctx.send(CoreCmd::CheckUpdate);
                }
                match &ctx.update_check {
                    UpdateCheckState::Idle => {}
                    UpdateCheckState::Checking => {
                        ui.label(RichText::new(t(lang, Key::SettingsUpdateChecking)).weak());
                    }
                    UpdateCheckState::UpdateAvailable { version } => {
                        ui.label(t_fmt(lang, Key::SettingsUpdateDetected, &[version]));
                        if let Some(url) = sys::selfupd::release_url() {
                            ui.hyperlink_to(t(lang, Key::SettingsUpdateReleasesLink), url);
                        }
                    }
                    UpdateCheckState::UpToDate { version } => {
                        ui.label(
                            RichText::new(t_fmt(lang, Key::SettingsUpdateUpToDate, &[version]))
                                .weak(),
                        );
                    }
                    UpdateCheckState::Failed => {
                        ui.label(
                            RichText::new(t(lang, Key::SettingsUpdateFailed))
                                .color(status_colors_of(ui).warn),
                        );
                    }
                }
            });
        });
    }

    /// Exit-time maintenance: the section offers two
    /// actions — "Reset to default…" (the safer one, listed first) and
    /// "Clean Up and Exit". Reset opens a modal that confirms restoring a
    /// fresh install's defaults while keeping the server list; cleanup opens
    /// the full-cleanup modal. Confirmed requests are exposed via
    /// [`Self::take_reset_request`] / [`Self::take_cleanup_request`]; the
    /// shell stashes them for `main` and quits through the normal shutdown
    /// path, so the filesystem actions run only after the app has fully
    /// shut down.
    fn cleanup_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::SettingsCleanup), |ui| {
            ui.set_max_width(680.0);
            ui.label(t(lang, Key::SettingsCleanupHint));
            ui.add_space(4.0);
            if ui
                .button(t(lang, Key::SettingsResetToDefault))
                .on_hover_text(t(lang, Key::SettingsResetToDefaultHint))
                .clicked()
            {
                self.reset_modal = true;
            }
            if ui
                .button(t(lang, Key::SettingsCleanUpAndExit))
                .on_hover_text(t(lang, Key::SettingsCleanUpAndExitHint))
                .clicked()
            {
                self.cleanup_modal = true;
            }
        });
        if self.reset_modal {
            self.show_reset_modal(ui.ctx(), lang);
        }
        if self.cleanup_modal {
            self.show_cleanup_modal(ui.ctx(), lang);
        }
    }

    /// The cleanup confirmation modal — the `egui::Modal` pattern of the
    /// first-run wizard — with exactly two actions. Choosing full cleanup
    /// records the request and closes the modal; Cancel just closes it.
    fn show_cleanup_modal(&mut self, ctx: &egui::Context, lang: Language) {
        egui::Modal::new(egui::Id::new("broccoli-cleanup-modal")).show(ctx, |ui| {
            ui.set_max_width(520.0);
            ui.heading(t(lang, Key::SettingsCleanupTitle));
            ui.add_space(4.0);
            ui.add(
                egui::Label::new(RichText::new(t(lang, Key::SettingsCleanupBody)).weak()).wrap(),
            );
            ui.add_space(10.0);
            if ui
                .button(t(lang, Key::SettingsCleanupFull))
                .on_hover_text(t(lang, Key::SettingsCleanupFullHint))
                .clicked()
            {
                self.cleanup_request = true;
                self.cleanup_modal = false;
            }
            ui.add_space(8.0);
            ui.separator();
            if ui.button(t(lang, Key::Cancel)).clicked() {
                self.cleanup_modal = false;
            }
        });
    }

    /// The reset confirmation modal — the `egui::Modal` pattern of the
    /// first-run wizard — with exactly two actions. Confirming records the
    /// request and closes the modal; Cancel just closes it. Reset keeps the
    /// server list: the exit wipe clears generated configs and
    /// logs but preserves servers and the core.
    fn show_reset_modal(&mut self, ctx: &egui::Context, lang: Language) {
        egui::Modal::new(egui::Id::new("broccoli-reset-modal")).show(ctx, |ui| {
            ui.set_max_width(520.0);
            ui.heading(t(lang, Key::SettingsResetTitle));
            ui.add_space(4.0);
            ui.add(egui::Label::new(RichText::new(t(lang, Key::SettingsResetBody)).weak()).wrap());
            ui.add_space(10.0);
            if ui.button(t(lang, Key::SettingsResetConfirm)).clicked() {
                self.reset_request = true;
                self.reset_modal = false;
            }
            ui.add_space(8.0);
            ui.separator();
            if ui.button(t(lang, Key::Cancel)).clicked() {
                self.reset_modal = false;
            }
        });
    }

    /// Consume a confirmed full-cleanup request, if any. The shell calls
    /// this after `show` each frame, stashes the request for `main`, and
    /// quits through the normal shutdown path.
    pub(crate) fn take_cleanup_request(&mut self) -> bool {
        std::mem::take(&mut self.cleanup_request)
    }

    /// Consume a confirmed reset-to-default request, if any. The shell calls
    /// this after `show` each frame, stashes the request for `main`, and
    /// quits through the normal shutdown path so the exit wipe
    /// runs after the app has fully shut down.
    pub(crate) fn take_reset_request(&mut self) -> bool {
        std::mem::take(&mut self.reset_request)
    }

    /// Per-file optional HTTPS URLs for geoip.dat/geosite.dat plus the cron
    /// schedule (core-native `geodata` key). Broccoli only writes the
    /// config block — the pinned core downloads and reloads the dats itself.
    /// The provenance status line and the Restore action live at
    /// the bottom of this section; see [`Self::geodata_provenance_ui`].
    fn geodata_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::SettingsGeodata), |ui| {
            // Job drivers first so the status row below is current: drain a
            // landed restore, then drain/respawn the provenance hash. Both
            // are off the UI thread; per frame the section only stats the
            // two geo data files (cheap metadata reads).
            self.geodata_provenance.poll_restore(lang);
            self.geodata_provenance.update(ui.ctx());
            // File-name labels are config-contract literals (documented
            // bare-wire exception), like the `geoip.dat`/`geosite.dat`
            // resource file paths the core resolves.
            let geoip_url = self
                .geoip_url_buf
                .get_or_insert_with(|| ctx.settings.geodata.geoip_url.clone().unwrap_or_default());
            // Commit + mark dirty only when the value validates (probe_interval
            // pattern): an invalid draft stays in the edit buffer with its
            // inline error and can never block later generation.
            let changed = widgets::validated_field(
                ui,
                "geoip.dat",
                geoip_url,
                t(lang, Key::UrlHint),
                |value| geodata_url_error(value, lang),
            );
            if changed && geodata_url_error(geoip_url, lang).is_none() {
                ctx.settings.geodata.geoip_url =
                    (!geoip_url.is_empty()).then_some(geoip_url.clone());
                ctx.mark_dirty();
            }
            let geosite_url = self.geosite_url_buf.get_or_insert_with(|| {
                ctx.settings.geodata.geosite_url.clone().unwrap_or_default()
            });
            let changed = widgets::validated_field(
                ui,
                "geosite.dat",
                geosite_url,
                t(lang, Key::UrlHint),
                |value| geodata_url_error(value, lang),
            );
            if changed && geodata_url_error(geosite_url, lang).is_none() {
                ctx.settings.geodata.geosite_url =
                    (!geosite_url.is_empty()).then_some(geosite_url.clone());
                ctx.mark_dirty();
            }
            let cron = self
                .geodata_cron_buf
                .get_or_insert_with(|| ctx.settings.geodata.cron.clone().unwrap_or_default());
            let changed = widgets::validated_field(
                ui,
                t(lang, Key::SettingsGeodataCronLabel),
                cron,
                crate::model::settings::DEFAULT_GEODATA_CRON,
                |value| geodata_cron_error(value, lang),
            );
            if changed && geodata_cron_error(cron, lang).is_none() {
                ctx.settings.geodata.cron = (!cron.is_empty()).then_some(cron.clone());
                ctx.mark_dirty();
            }
            ui.label(
                RichText::new(t(lang, Key::SettingsGeodataCronHint))
                    .weak()
                    .small(),
            );
            ui.label(
                RichText::new(t(lang, Key::SettingsGeodataEmptyHint))
                    .weak()
                    .small(),
            );
            ui.label(
                RichText::new(t(lang, Key::SettingsGeodataScheduleHint))
                    .weak()
                    .small(),
            );
            ui.add_space(6.0);
            self.geodata_provenance_ui(ui, lang);
        });
    }

    /// The geo data provenance status line and the Restore action,
    /// under the section's fields and hints. Rendered from the
    /// memoized hash result — nothing here hashes; the caption is rebuilt
    /// only when the result or the language changed.
    ///
    /// Release-managed renders the status line with a disabled, inert
    /// Restore button; user-managed (bytes differ from the release pins —
    /// including while URLs are still configured, so "that URL served
    /// garbage, take me back" is one click) enables it. No managed core
    /// renders nothing: there is no geo data to provenance before install.
    fn geodata_provenance_ui(&mut self, ui: &mut Ui, lang: Language) {
        // A small clone of the enum keeps the draw free of self borrows; the
        // caption refresh below needs `&mut self`.
        let result = self.geodata_provenance.result.clone();
        let managed = match &result {
            Some(sys::core_dl::GeoDataProvenance::ReleaseManaged)
            | Some(sys::core_dl::GeoDataProvenance::UserManaged { .. }) => Some(matches!(
                result,
                Some(sys::core_dl::GeoDataProvenance::UserManaged { .. })
            )),
            _ => None,
        };
        if let Some(user_managed) = managed {
            self.geodata_provenance.refresh_caption(lang);
            let Some(caption) = &self.geodata_provenance.caption else {
                return;
            };
            if user_managed {
                ui.label(
                    RichText::new(caption.text.as_str())
                        .small()
                        .color(status_colors_of(ui).warn),
                );
            } else {
                ui.label(RichText::new(caption.text.as_str()).small().weak());
            }
            ui.add_space(4.0);
            // Enabled exactly when the on-disk bytes differ from the pins; a
            // running core's deny-write locks make the rename fail with a
            // sharing violation, which surfaces as the feedback line below —
            // the button stays clickable, the reason is never swallowed.
            let busy = self.geodata_provenance.restore_job.is_pending();
            let disabled_hint = if busy {
                t(lang, Key::SettingsGeodataRestoreBusy)
            } else {
                t(lang, Key::SettingsGeodataRestoreHint)
            };
            if ui
                .add_enabled(
                    user_managed && !busy,
                    egui::Button::new(t(lang, Key::SettingsGeodataRestore)).small(),
                )
                .on_hover_text(t(lang, Key::SettingsGeodataRestoreHint))
                .on_disabled_hover_text(disabled_hint)
                .clicked()
            {
                self.geodata_provenance.spawn_restore(ui.ctx(), lang);
            }
        }
        // Feedback renders even while the post-restore re-hash hides the
        // caption for a frame or two, so a just-finished restore never
        // flickers.
        match &self.geodata_provenance.restore_feedback {
            Some(GeoDataRestoreFeedback::Done) => {
                ui.label(
                    RichText::new(t(lang, Key::SettingsGeodataRestoreDone))
                        .small()
                        .color(status_colors_of(ui).ok),
                );
            }
            Some(GeoDataRestoreFeedback::Failed(message)) => {
                ui.label(
                    RichText::new(message.as_str())
                        .small()
                        .color(status_colors_of(ui).err),
                );
            }
            None => {}
        }
    }

    fn advanced_section(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::SettingsAdvanced), |ui| {
            widgets::section(ui, t(lang, Key::SettingsPingTest), |ui| {
                if widgets::text_field(
                    ui,
                    t(lang, Key::ProbeUrl),
                    &mut ctx.settings.probe_url,
                    "https://www.google.com/generate_204",
                ) {
                    ctx.mark_dirty();
                }
                ui.label(
                    RichText::new(t(lang, Key::SettingsPingTestHint))
                        .weak()
                        .small(),
                );
            });
            if ctx.settings.raw_override.is_some() {
                ui.label(
                    RichText::new(t(lang, Key::SettingsRawOverrideActive))
                        .color(status_colors_of(ui).warn)
                        .strong(),
                );
            }

            egui::CollapsingHeader::new(t(lang, Key::SettingsRawOverrideHeader))
                .id_salt("settings_raw_override")
                .show(ui, |ui| {
                    if !self.raw_loaded {
                        self.raw_buf = ctx.settings.raw_override.clone().unwrap_or_default();
                        self.raw_loaded = true;
                        self.bump_raw_parse(ui.ctx().clone(), lang);
                    }
                    self.poll_raw_parse(ui.ctx().clone(), lang);
                    ui.label(
                        RichText::new(t(lang, Key::SettingsRawOverrideExplain))
                            .weak()
                            .small(),
                    );
                    let raw_changed = ui
                        .add(
                            egui::TextEdit::multiline(&mut self.raw_buf)
                                .font(egui::TextStyle::Monospace)
                                .desired_rows(14)
                                .desired_width(f32::INFINITY),
                        )
                        .changed();
                    if raw_changed {
                        self.bump_raw_parse(ui.ctx().clone(), lang);
                    }
                    // `raw_parse` is kept current by the worker (or by the
                    // size-cap refusal); it is never parsed on the UI thread.
                    match self.raw_parse.as_ref() {
                        None => {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(t(lang, Key::SettingsRawOverrideParsing));
                            });
                        }
                        Some(RawParseState::Empty) => {
                            ui.label(
                                RichText::new(t(lang, Key::SettingsRawOverridePasteHint))
                                    .weak()
                                    .small(),
                            );
                        }
                        Some(RawParseState::TooLarge(len, limit)) => {
                            ui.label(
                                RichText::new(t_fmt(
                                    lang,
                                    Key::SettingsRawOverrideTooLarge,
                                    &[len, limit],
                                ))
                                .color(status_colors_of(ui).err),
                            );
                        }
                        Some(RawParseState::Ok(_)) => {}
                        Some(RawParseState::Err(message)) => {
                            ui.label(
                                RichText::new(t_fmt(lang, Key::InvalidJson, &[message]))
                                    .color(status_colors_of(ui).err),
                            );
                        }
                    }
                    let parsed_ok = matches!(self.raw_parse, Some(RawParseState::Ok(_)));
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                parsed_ok,
                                egui::Button::new(t(lang, Key::SettingsValidateWithCore)),
                            )
                            .on_hover_text(t(lang, Key::SettingsValidateHint))
                            .clicked()
                            && let Some(RawParseState::Ok(v)) = &self.raw_parse
                        {
                            // One oneshot channel per click: the runtime
                            // sends the terminal verdict back on the
                            // request's own reply and this screen adopts it
                            // as the request's channel.
                            self.test_verdict = None;
                            let (reply, receiver) = tokio::sync::oneshot::channel();
                            // A send failure means the runtime is gone and
                            // cannot answer, so no request is installed: the
                            // screen keeps its idle state and the next click
                            // (or the runtime's return) starts clean.
                            let sent = ctx
                                .cmd
                                .send(CoreCmd::TestConfig {
                                    config: v.clone(),
                                    reply,
                                })
                                .is_ok();
                            if sent {
                                self.test_pending = Request::reply(receiver);
                            }
                        }
                        if ui
                            .add_enabled(
                                parsed_ok,
                                egui::Button::new(t(lang, Key::SettingsEnableOverride)),
                            )
                            .on_hover_text(t(lang, Key::SettingsEnableOverrideHint))
                            .clicked()
                        {
                            ctx.settings.raw_override = Some(self.raw_buf.clone());
                            ctx.mark_dirty();
                        }
                        if ctx.settings.raw_override.is_some()
                            && ui.button(t(lang, Key::SettingsDisableOverride)).clicked()
                        {
                            ctx.settings.raw_override = None;
                            ctx.mark_dirty();
                        }
                    });
                    // Per-frame poll of the in-flight validation verdict:
                    // the runtime pokes the repaint after every send, so the
                    // terminal is picked up on the next frame. While the
                    // request is pending with no terminal, nothing renders;
                    // a runtime that vanished mid-run leaves no verdict.
                    match self.test_pending.poll() {
                        Some(Terminal::Answered(Ok((ok, output)))) => {
                            self.test_verdict = Some((ok, output.text(lang)));
                        }
                        Some(Terminal::Answered(Err(error))) => {
                            self.test_verdict = Some((false, error.text(lang)));
                        }
                        // Runtime went away without a terminal.
                        Some(Terminal::Exited) | None => {}
                    }
                    if let Some((ok, output)) = &self.test_verdict {
                        if *ok {
                            ui.label(
                                RichText::new(t(lang, Key::SettingsCoreAccepts))
                                    .color(status_colors_of(ui).ok),
                            );
                        } else {
                            ui.label(
                                RichText::new(t(lang, Key::SettingsCoreRejects))
                                    .color(status_colors_of(ui).err),
                            );
                        }
                        if !output.is_empty() {
                            ui.label(RichText::new(output.as_str()).monospace().small());
                        }
                    }
                });
        });
    }
}

/// Packed u32 RGBA ↔ [`Color32`] conversion shared by the accent picker and
/// the startup re-apply. The persisted layout is r<<24 | g<<16 | b<<8 | a,
/// using the unmultiplied sRGBA components (as authored by the picker).
fn accent_rgba(color: Color32) -> u32 {
    let [r, g, b, a] = color.to_srgba_unmultiplied();
    (u32::from(r) << 24) | (u32::from(g) << 16) | (u32::from(b) << 8) | u32::from(a)
}

fn color_from_accent(rgba: u32) -> Color32 {
    Color32::from_rgba_unmultiplied(
        (rgba >> 24) as u8,
        (rgba >> 16) as u8,
        (rgba >> 8) as u8,
        rgba as u8,
    )
}

/// The color the accent picker must display: the persisted custom accent, or
/// the stock accent in effect when none is set. The `None` case reads the
/// live visuals rather than a hardcoded default so the well matches the
/// applied accent after Reset (which restores egui's stock blue).
fn picker_start_color(accent: Option<u32>, visuals: &egui::Visuals) -> Color32 {
    accent
        .map(color_from_accent)
        .unwrap_or(visuals.selection.bg_fill)
}

/// Re-derive both themes' visuals from egui defaults, overlaying the
/// persisted accent (if any). Idempotent: `None` restores stock visuals.
///
/// eframe does not persist custom `Visuals` (`Options::dark_style` /
/// `light_style` are `serde(skip)`), so the accent lives in broccoli settings and
/// must be re-applied at startup and whenever the picker changes. Both themes
/// are set so System mode (which follows the Windows light/dark flag) carries
/// the accent too.
pub(crate) fn apply_accent(ctx: &egui::Context, accent: Option<u32>) {
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        let mut visuals = theme.default_visuals();
        if let Some(rgba) = accent {
            let color = color_from_accent(rgba);
            visuals.selection.bg_fill = color;
            visuals.hyperlink_color = color;
        }
        ctx.set_visuals_of(theme, visuals);
    }
}

fn policy_level_editor(ui: &mut Ui, lang: Language, level: &mut PolicyLevelCfg) -> bool {
    let mut changed = false;
    ui.label(
        RichText::new(t(lang, Key::SettingsTimeoutsHeader))
            .weak()
            .small(),
    );
    changed |= widgets::opt_u32(
        ui,
        t(lang, Key::SettingsHandshake),
        &mut level.handshake,
        0..=u32::MAX,
    );
    changed |= widgets::opt_u32(
        ui,
        t(lang, Key::SettingsConnIdle),
        &mut level.conn_idle,
        0..=u32::MAX,
    );
    changed |= widgets::opt_u32(
        ui,
        t(lang, Key::SettingsUplinkOnly),
        &mut level.uplink_only,
        0..=u32::MAX,
    );
    changed |= widgets::opt_u32(
        ui,
        t(lang, Key::SettingsDownlinkOnly),
        &mut level.downlink_only,
        0..=u32::MAX,
    );
    changed |= widgets::opt_i32(
        ui,
        t(lang, Key::SettingsBufferSize),
        &mut level.buffer_size,
        i32::MIN..=i32::MAX,
    );
    ui.horizontal(|ui| {
        changed |= ui
            .checkbox(
                &mut level.stats_user_uplink,
                t(lang, Key::SettingsStatsUserUplink),
            )
            .changed();
        changed |= ui
            .checkbox(
                &mut level.stats_user_downlink,
                t(lang, Key::SettingsStatsUserDownlink),
            )
            .changed();
        changed |= ui
            .checkbox(
                &mut level.stats_user_online,
                t(lang, Key::SettingsStatsUserOnline),
            )
            .changed();
    });
    changed
}

#[cfg(test)]
mod tests {
    use super::{
        GeoDataProvenanceState, GeoDataRestoreFeedback, RAW_OVERRIDE_MAX_BYTES, RawParseState,
        SettingsScreen, accent_rgba, apply_accent, color_from_accent, geo_data_fingerprint,
        parse_raw_override, picker_start_color,
    };
    use crate::diag::{Diag, DiagError};
    use crate::i18n::{Key, t, t_fmt};
    use crate::model::settings::Language;
    use crate::rt::{ApplyOutput, CoreCmd};
    use crate::sys::appdata::{APPDATA_ENV_LOCK, AppDataRedirect};
    use crate::sys::core_dl::GeoDataProvenance;
    use crate::sys::selfupd::{UpdateCheckState, Version};
    use crate::ui::test_rig::UiTestRig;
    use egui::Color32;
    use egui_kittest::{
        Harness,
        kittest::{NodeT as _, Queryable as _},
    };
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    #[test]
    fn appearance_scale_changes_global_zoom() {
        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder()
            .with_pixels_per_point(1.5)
            .build_ui_state(
                |ui, screen| screen.appearance_section(ui, &mut rig.ctx()),
                SettingsScreen::default(),
            );

        harness
            .get_by_role_and_label(egui::accesskit::Role::ComboBox, "UI scale")
            .click();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "150%")
            .click();
        harness.run();

        assert!((harness.ctx.zoom_factor() - 1.5).abs() < 1e-6);
        assert!((harness.ctx.pixels_per_point() - 2.25).abs() < 1e-6);
    }

    #[test]
    fn appearance_theme_radio_switches_preference_and_active_theme() {
        // egui's stock default is System; kittest's harness forces Dark on
        // its context, so assert the stock default on a fresh context.
        assert_eq!(
            egui::Context::default().options(|options| options.theme_preference),
            egui::ThemePreference::System
        );

        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.appearance_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        let preference =
            |h: &Harness<'_, SettingsScreen>| h.ctx.options(|options| options.theme_preference);

        harness
            .get_all_by_label("Dark")
            .next()
            .expect("Dark radio")
            .click();
        harness.run();
        assert_eq!(preference(&harness), egui::ThemePreference::Dark);
        assert_eq!(harness.ctx.theme(), egui::Theme::Dark);

        harness
            .get_all_by_label("Light")
            .next()
            .expect("Light radio")
            .click();
        harness.run();
        assert_eq!(preference(&harness), egui::ThemePreference::Light);
        assert_eq!(harness.ctx.theme(), egui::Theme::Light);

        harness
            .get_all_by_label("System")
            .next()
            .expect("System radio")
            .click();
        harness.run();
        assert_eq!(preference(&harness), egui::ThemePreference::System);
    }

    #[test]
    fn appearance_language_list_is_english_only_and_persists() {
        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.appearance_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        assert!(harness.query_by_label("Language").is_some());
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .find(|node| node.value().as_deref() == Some("English"))
            .expect("language combo shows English")
            .click();
        harness.run();
        assert!(
            harness.query_by_label("English").is_some(),
            "the one available locale must be listed"
        );
        drop(harness);
        assert_eq!(rig.settings.language, super::Language::En);
    }

    #[test]
    fn appearance_accent_row_exposes_picker_and_reset() {
        let mut rig = UiTestRig::default();
        let harness = Harness::builder().build_ui_state(
            |ui, screen| screen.appearance_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        assert!(harness.query_by_label("Accent color").is_some());
        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "Reset")
                .is_some(),
            "reset must be present (disabled while no accent is set)"
        );
        // Driving the popup color picker headlessly is not supported by
        // kittest; the picker's write path (u32 packing + apply_accent) is
        // covered by the dedicated unit tests below.
    }

    #[test]
    fn apply_accent_reaches_both_themes_and_resets_to_stock() {
        let ctx = egui::Context::default();
        let accent = 0x4f_af_4f_ff;
        apply_accent(&ctx, Some(accent));
        let expected = Color32::from_rgba_unmultiplied(0x4f, 0xaf, 0x4f, 0xff);
        for theme in [egui::Theme::Dark, egui::Theme::Light] {
            let visuals = &ctx.style_of(theme).visuals;
            assert_eq!(visuals.selection.bg_fill, expected, "{theme:?} accent");
            assert_eq!(visuals.hyperlink_color, expected, "{theme:?} accent");
        }

        apply_accent(&ctx, None);
        for theme in [egui::Theme::Dark, egui::Theme::Light] {
            let visuals = &ctx.style_of(theme).visuals;
            let stock = theme.default_visuals();
            assert_eq!(
                visuals.selection.bg_fill, stock.selection.bg_fill,
                "{theme:?} reset must restore stock"
            );
            assert_eq!(
                visuals.hyperlink_color, stock.hyperlink_color,
                "{theme:?} reset must restore stock"
            );
        }
    }

    #[test]
    fn picker_start_color_matches_applied_accent_after_reset() {
        // Regression: after Reset the applied accent is egui's stock one
        // (blue), and the well must show it — the old code fell back to a
        // hardcoded green, drifting from the blue the UI actually painted.
        for theme in [egui::Theme::Dark, egui::Theme::Light] {
            let stock = theme.default_visuals();
            assert_eq!(
                picker_start_color(None, &stock),
                stock.selection.bg_fill,
                "{theme:?} stock accent shown after reset"
            );
        }

        // A persisted custom accent wins over the visuals' selection color.
        let accent = 0x4f_af_4f_ff;
        let expected = Color32::from_rgba_unmultiplied(0x4f, 0xaf, 0x4f, 0xff);
        for theme in [egui::Theme::Dark, egui::Theme::Light] {
            let stock = theme.default_visuals();
            assert_eq!(
                picker_start_color(Some(accent), &stock),
                expected,
                "{theme:?} custom accent shown"
            );
        }
    }

    #[test]
    fn accent_packing_round_trips_through_u32() {
        // The picker is Alpha::Opaque, so persisted accents always carry
        // alpha 255 (premultiplied storage round-trips losslessly there).
        let color = Color32::from_rgba_unmultiplied(0x4f, 0xaf, 0x4f, 0xff);
        assert_eq!(accent_rgba(color), 0x4f_af_4f_ff);
        assert_eq!(color_from_accent(0x4f_af_4f_ff), color);
    }

    #[test]
    fn geodata_section_binds_url_fields_and_persists() {
        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.geodata_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        // geoip URL: the first (empty) text input.
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("geoip URL field")
            .click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("geoip URL field keeps focus")
            .type_text("https://example.com/geoip.dat");
        harness.run_steps(4);

        // geosite URL: a still-empty input (geoip now holds text).
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.value().as_deref() == Some(""))
            .expect("geosite URL field")
            .click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.value().as_deref() == Some(""))
            .expect("geosite URL field keeps focus")
            .type_text("https://example.com/geosite.dat");
        harness.run_steps(4);

        // cron: the last remaining empty input.
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.value().as_deref() == Some(""))
            .expect("cron field")
            .click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.value().as_deref() == Some(""))
            .expect("cron field keeps focus")
            .type_text("17 3 * * 1");
        harness.run_steps(4);

        assert!(
            harness
                .get_all_by_role(egui::accesskit::Role::TextInput)
                .any(|node| node.value().as_deref() == Some("17 3 * * 1")),
            "typed cron must land in its field"
        );

        drop(harness);
        assert_eq!(
            rig.settings.geodata.geoip_url.as_deref(),
            Some("https://example.com/geoip.dat")
        );
        assert_eq!(
            rig.settings.geodata.geosite_url.as_deref(),
            Some("https://example.com/geosite.dat")
        );
        assert_eq!(rig.settings.geodata.cron.as_deref(), Some("17 3 * * 1"));
        assert!(
            rig.requests.dirty,
            "geodata edits must mark the settings dirty"
        );
    }

    #[test]
    fn ping_test_section_binds_url_field_and_persists() {
        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.advanced_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        // The Ping test section renders its own probe URL field; it is the
        // only text input on this screen while the raw-override editor stays
        // behind a closed header.
        assert!(
            harness.query_by_label("Ping test").is_some(),
            "ping test section must render"
        );
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.value().as_deref() == Some(""))
            .expect("ping test probe URL field")
            .click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.value().as_deref() == Some(""))
            .expect("ping test probe URL field keeps focus")
            .type_text("https://example.com/generate_204");
        harness.run_steps(4);

        assert!(
            harness
                .get_all_by_role(egui::accesskit::Role::TextInput)
                .any(|node| node.value().as_deref() == Some("https://example.com/generate_204")),
            "typed URL must land in the ping test field"
        );

        drop(harness);
        assert_eq!(
            rig.settings.probe_url.as_str(),
            "https://example.com/generate_204"
        );
        assert!(
            rig.requests.dirty,
            "ping test URL edits must mark the settings dirty"
        );
    }

    #[test]
    fn updates_section_idle_shows_only_the_check_button() {
        let mut rig = UiTestRig::default();
        let harness = Harness::builder().build_ui_state(
            |ui, screen| screen.updates_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "Check for updates",)
                .is_some(),
            "idle state must render the check button"
        );
        assert!(
            harness.query_by_label("Checking…").is_none()
                && harness.query_by_label("Update check failed").is_none(),
            "idle state must not render any check status"
        );
    }

    #[test]
    fn updates_section_checking_state_disables_the_button_and_shows_status() {
        let mut rig = UiTestRig {
            update_check: UpdateCheckState::Checking,
            ..Default::default()
        };
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.updates_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        assert!(
            harness.query_by_label("Checking…").is_some(),
            "checking state must render Checking…"
        );
        // Re-click while in flight must be harmless: the disabled button
        // swallows the click, so no second command is queued.
        let button =
            harness.get_by_role_and_label(egui::accesskit::Role::Button, "Check for updates");
        button.click();
        harness.run();
        drop(harness);
        assert!(
            rig._cmd_rx.try_recv().is_err(),
            "clicking while a check is in flight must not send a second command"
        );
    }

    #[test]
    fn updates_section_update_available_shows_version_and_release_link() {
        let mut rig = UiTestRig {
            update_check: UpdateCheckState::UpdateAvailable {
                version: Version::parse("9.8.7").expect("test version"),
            },
            ..Default::default()
        };
        let harness = Harness::builder().build_ui_state(
            |ui, screen| screen.updates_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        assert!(
            harness.query_by_label("Update detected — v9.8.7").is_some(),
            "update-available state must render the remote version"
        );
        assert!(
            harness.query_by_label("Open the releases page").is_some(),
            "update-available state must link to the releases page"
        );
    }

    #[test]
    fn updates_section_up_to_date_shows_the_version() {
        let mut rig = UiTestRig {
            update_check: UpdateCheckState::UpToDate {
                version: Version::parse("1.2.3").expect("test version"),
            },
            ..Default::default()
        };
        let harness = Harness::builder().build_ui_state(
            |ui, screen| screen.updates_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        assert!(
            harness.query_by_label("Up to date (v1.2.3)").is_some(),
            "up-to-date state must render the version"
        );
    }

    #[test]
    fn updates_section_failed_state_is_retryable() {
        let mut rig = UiTestRig {
            update_check: UpdateCheckState::Failed,
            ..Default::default()
        };
        let harness = Harness::builder().build_ui_state(
            |ui, screen| screen.updates_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        assert!(
            harness.query_by_label("Update check failed").is_some(),
            "failed state must render the failure message"
        );
        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "Check for updates",)
                .is_some(),
            "failed state must keep the button retryable"
        );
    }

    #[test]
    fn updates_section_idle_click_sends_one_check_update_command() {
        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.updates_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Check for updates")
            .click();
        harness.run();
        drop(harness);
        assert!(
            matches!(rig._cmd_rx.try_recv(), Ok(CoreCmd::CheckUpdate)),
            "clicking the button must send exactly one CheckUpdate command"
        );
        assert!(
            rig._cmd_rx.try_recv().is_err(),
            "one click must send exactly one command"
        );
    }

    #[test]
    fn cleanup_section_renders_the_clean_up_and_exit_button() {
        let mut rig = UiTestRig::default();
        let harness = Harness::builder().build_ui_state(
            |ui, screen| screen.cleanup_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "Clean Up and Exit…")
                .is_some(),
            "the Cleanup section must render the Clean Up and Exit button"
        );
        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "Reset to default…")
                .is_some(),
            "the Cleanup section must render the Reset to default button"
        );
        assert!(
            harness.query_by_label("Full cleanup").is_none(),
            "the modal must be closed until the button is clicked"
        );
        assert!(
            harness.query_by_label("Reset to default").is_none(),
            "the reset modal must be closed until its button is clicked"
        );
    }

    #[test]
    fn cleanup_modal_opens_with_the_two_actions() {
        let mut rig = UiTestRig::default();
        let mut screen = SettingsScreen::default();
        let mut harness = Harness::builder()
            .build_ui_state(|ui, _state| screen.cleanup_section(ui, &mut rig.ctx()), ());

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Clean Up and Exit…")
            .click();
        harness.run();

        for label in ["Full cleanup", "Cancel"] {
            assert!(
                harness
                    .query_by_role_and_label(egui::accesskit::Role::Button, label)
                    .is_some(),
                "the modal must offer {label}"
            );
        }
    }

    #[test]
    fn cleanup_modal_cancel_closes_without_a_cleanup_request() {
        let mut rig = UiTestRig::default();
        let mut screen = SettingsScreen::default();
        let mut harness = Harness::builder()
            .build_ui_state(|ui, _state| screen.cleanup_section(ui, &mut rig.ctx()), ());

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Clean Up and Exit…")
            .click();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Cancel")
            .click();
        harness.run();
        drop(harness);

        assert!(
            !screen.take_cleanup_request(),
            "Cancel must not record a cleanup request"
        );
        assert!(!screen.cleanup_modal, "Cancel must close the modal");
    }

    #[test]
    fn cleanup_modal_full_cleanup_records_the_request_and_closes() {
        let mut rig = UiTestRig::default();
        let mut screen = SettingsScreen::default();
        let mut harness = Harness::builder()
            .build_ui_state(|ui, _state| screen.cleanup_section(ui, &mut rig.ctx()), ());

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Clean Up and Exit…")
            .click();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Full cleanup")
            .click();
        harness.run();
        drop(harness);

        assert!(
            screen.take_cleanup_request(),
            "Full cleanup must record the request for the shell"
        );
        assert!(
            !screen.cleanup_modal,
            "choosing a mode must close the modal"
        );
    }

    #[test]
    fn reset_modal_confirm_records_the_request_and_closes() {
        let mut rig = UiTestRig::default();
        let mut screen = SettingsScreen::default();
        let mut harness = Harness::builder()
            .build_ui_state(|ui, _state| screen.cleanup_section(ui, &mut rig.ctx()), ());

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Reset to default…")
            .click();
        harness.run();
        assert!(
            harness
                .query_all_by_label("Reset to default")
                .next()
                .is_some(),
            "the reset modal must open once its button is clicked"
        );
        // The modal heading and the confirm button share the "Reset to
        // default" label, so pick the Button node among the matches: label
        // matching lives at kittest level, role on the accesskit node.
        let confirm = harness
            .query_all_by_label("Reset to default")
            .find(|n| n.accesskit_node().role() == egui::accesskit::Role::Button)
            .expect("the reset modal must offer a confirm button");
        confirm.click();
        harness.run();
        drop(harness);

        assert!(
            screen.take_reset_request(),
            "Reset to default must record the request for the shell"
        );
        assert!(!screen.reset_modal, "confirming must close the reset modal");
    }

    #[test]
    fn reset_modal_cancel_closes_without_a_request() {
        let mut rig = UiTestRig::default();
        let mut screen = SettingsScreen::default();
        let mut harness = Harness::builder()
            .build_ui_state(|ui, _state| screen.cleanup_section(ui, &mut rig.ctx()), ());

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Reset to default…")
            .click();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Cancel")
            .click();
        harness.run();
        drop(harness);

        assert!(
            !screen.take_reset_request(),
            "Cancel must not record a reset request"
        );
        assert!(!screen.reset_modal, "Cancel must close the reset modal");
    }

    #[test]
    fn geodata_section_url_only_edit_marks_dirty_and_commits() {
        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.geodata_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        // Edit ONLY the geoip URL: the commit + dirty must not depend on any
        // other field's edit happening in the same frame.
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("geoip URL field")
            .click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("geoip URL field keeps focus")
            .type_text("https://example.com/geoip.dat");
        harness.run_steps(4);

        drop(harness);
        assert_eq!(
            rig.settings.geodata.geoip_url.as_deref(),
            Some("https://example.com/geoip.dat"),
            "a valid URL-only edit must commit to settings"
        );
        assert_eq!(rig.settings.geodata.geosite_url, None);
        assert_eq!(rig.settings.geodata.cron, None);
        assert!(
            rig.requests.dirty,
            "a URL-only edit must mark the settings dirty"
        );
    }

    #[test]
    fn geodata_section_shows_validation_errors() {
        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.geodata_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        // Non-HTTPS URL → inline error under the field.
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("geoip URL field")
            .click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("geoip URL field keeps focus")
            .type_text("http://example.com/geoip.dat");
        harness.run_steps(4);
        assert!(
            harness
                .query_by_label("URL must be HTTPS (https://…)")
                .is_some(),
            "a non-HTTPS geodata URL must show the inline validation error"
        );

        // 3-field cron → inline error under the cron row.
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .rfind(|node| node.value().as_deref() == Some(""))
            .expect("cron field")
            .click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .rfind(|node| node.value().as_deref() == Some(""))
            .expect("cron field keeps focus")
            .type_text("0 4 *");
        harness.run_steps(4);
        assert!(
            harness
                .query_by_label(
                    "Cron must have exactly 5 fields: minute hour day-of-month month day-of-week"
                )
                .is_some(),
            "a 3-field cron must show the inline validation error"
        );

        drop(harness);
        assert_eq!(
            rig.settings.geodata.geoip_url, None,
            "an invalid URL must stay in the edit buffer, never committed"
        );
        assert_eq!(
            rig.settings.geodata.cron, None,
            "an invalid cron must stay in the edit buffer, never committed"
        );
        assert!(
            !rig.requests.dirty,
            "invalid geodata edits must not mark the settings dirty"
        );
    }

    #[test]
    fn geodata_section_empty_is_unconfigured() {
        let mut rig = UiTestRig::default();
        let harness = Harness::builder().build_ui_state(
            |ui, screen| screen.geodata_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );

        assert!(
            harness
                .query_by_label("URL must be HTTPS (https://…)")
                .is_none(),
            "empty URLs must not show validation errors"
        );
        assert!(
            harness
                .query_by_label(
                    "Cron must have exactly 5 fields: minute hour day-of-month month day-of-week"
                )
                .is_none(),
            "empty cron must not show validation errors"
        );

        drop(harness);
        assert!(
            !rig.settings.geodata.is_configured(),
            "an untouched section must leave geodata unconfigured"
        );
        assert!(
            !rig.requests.dirty,
            "rendering the empty section must not dirty settings"
        );
    }

    // ------------------------------------------------------------------
    // Geo data provenance status + Restore. Always-run tests
    // redirect APPDATA to a temp root so the provenance/restore workers
    // hash fixture files, never the real installed core; release-managed
    // bytes exist only in a real installed core, so the full
    // click-restore-status-flip loop is the ignored test at the end.
    // ------------------------------------------------------------------

    /// Create `<root>/broccoli/core` with drifted (non-pin-matching) geo
    /// data files — the always-run stand-in for user-managed bytes. The
    /// path is joined component by component so it matches the canonical
    /// `%APPDATA%\broccoli\core` shape the workers compute.
    fn drifted_core(root: &Path) -> std::path::PathBuf {
        let core = root.join("broccoli").join("core");
        std::fs::create_dir_all(&core).expect("create fixture core dir");
        std::fs::write(core.join("geoip.dat"), b"drifted geoip bytes")
            .expect("write drifted geoip");
        std::fs::write(core.join("geosite.dat"), b"drifted geosite bytes")
            .expect("write drifted geosite");
        core
    }

    /// Rewrite `path`'s mtime so update-time assertions are deterministic.
    fn set_mtime(path: &Path, time: SystemTime) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .expect("open file to set mtime")
            .set_modified(time)
            .expect("set file mtime");
    }

    /// Build the provenance cache state whose memoized answer is `result`
    /// for the *current* fixture files (the fingerprint is read, not
    /// fabricated, so the per-frame stat check never respawns a job).
    fn seeded_provenance(result: GeoDataProvenance) -> GeoDataProvenanceState {
        GeoDataProvenanceState {
            fingerprint: Some(geo_data_fingerprint().expect("fixture core must stat")),
            result: Some(result),
            ..Default::default()
        }
    }

    /// Drive harness frames until the provenance hash job lands (the
    /// section polls it once per frame, exactly like the real app).
    fn run_until_provenance_known(harness: &mut Harness<'_, SettingsScreen>, what: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while harness.state().geodata_provenance.result.is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "{what}: provenance worker did not deliver in time"
            );
            harness.run();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Drive harness frames until the restore job lands.
    fn run_until_restore_lands(harness: &mut Harness<'_, SettingsScreen>, what: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while harness.state().geodata_provenance.restore_job.is_pending() {
            assert!(
                std::time::Instant::now() < deadline,
                "{what}: restore worker did not deliver in time"
            );
            harness.run();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn release_managed_provenance_renders_status_and_disables_restore() {
        // Drive the state, never click-simulation: the always-run suite has
        // no pin-matching bytes, so release-managed is unreachable through
        // the worker here and the memo is seeded directly.
        let _appdata_guard = APPDATA_ENV_LOCK.blocking_lock();
        let temporary = tempfile::tempdir().expect("temporary AppData root");
        let _appdata = AppDataRedirect::to(temporary.path());
        let _core = drifted_core(temporary.path());
        let screen = SettingsScreen {
            geodata_provenance: seeded_provenance(GeoDataProvenance::ReleaseManaged),
            ..Default::default()
        };
        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.geodata_section(ui, &mut rig.ctx()),
            screen,
        );
        harness.run();
        assert!(
            harness
                .query_by_label("Release-managed: the geo data matches the pinned release.")
                .is_some(),
            "the release-managed status line must render"
        );
        // The Restore button exists but is inert while the bytes match.
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Restore built-in geo data")
            .click();
        harness.run();
        assert!(
            !harness.state().geodata_provenance.restore_job.is_pending()
                && harness
                    .state()
                    .geodata_provenance
                    .restore_feedback
                    .is_none(),
            "clicking Restore while release-managed must not start a job"
        );
        assert!(
            harness
                .query_by_label("Release-managed: the geo data matches the pinned release.")
                .is_some(),
            "the release-managed status must survive the inert click"
        );
    }

    #[test]
    fn user_managed_provenance_enables_restore_and_surfaces_the_failure() {
        let _appdata_guard = APPDATA_ENV_LOCK.blocking_lock();
        let temporary = tempfile::tempdir().expect("temporary AppData root");
        let _appdata = AppDataRedirect::to(temporary.path());
        let core = drifted_core(temporary.path());
        let geoip_time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let geosite_time = geoip_time + Duration::from_secs(60);
        set_mtime(&core.join("geoip.dat"), geoip_time);
        set_mtime(&core.join("geosite.dat"), geosite_time);
        let screen = SettingsScreen {
            geodata_provenance: seeded_provenance(GeoDataProvenance::UserManaged {
                updated: Some(geosite_time),
            }),
            ..Default::default()
        };
        let mut rig = UiTestRig::default();
        // "Works both with URLs configured and with them cleared": the
        // updater URLs stay configured here — enablement must follow the
        // on-disk bytes, never the config.
        rig.settings.geodata.geoip_url = Some("https://example.com/geoip.dat".into());
        rig.settings.geodata.geosite_url = Some("https://example.com/geosite.dat".into());
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.geodata_section(ui, &mut rig.ctx()),
            screen,
        );
        harness.run();
        let expected_caption = t_fmt(
            Language::En,
            Key::SettingsGeodataProvenanceUserOn,
            &[&format!("{geosite_time:?}")],
        );
        assert!(
            harness.query_by_label(&expected_caption).is_some(),
            "the user-managed status line must render with the newest mtime \
             as the update time"
        );

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Restore built-in geo data")
            .click();
        harness.run();
        // The restore worker can land within the same run cycle (the fixture
        // fails fast: no pristine pair), so the pending-job window is not
        // asserted; the terminal feedback below is the contract.
        run_until_restore_lands(&mut harness, "restore failure");
        // The fixture has no pristine pair: restore must fail loudly,
        // naming the missing file, and the bytes stay drifted.
        match &harness.state().geodata_provenance.restore_feedback {
            Some(GeoDataRestoreFeedback::Failed(message)) => {
                assert_eq!(
                    message,
                    &t_fmt(
                        Language::En,
                        Key::SettingsGeodataRestoreFailed,
                        &[&t_fmt(
                            Language::En,
                            Key::CoreDlRestoreUnavailable,
                            &[&core.join("pristine").join("geoip.dat").display()],
                        )],
                    ),
                    "the keyed restore failure must render in the active language, \
                     naming the missing pristine file"
                );
            }
            other => panic!("expected a failed restore feedback, got {other:?}"),
        }
        harness.run();
        assert!(
            harness.query_by_label_contains("Restore failed:").is_some(),
            "the failed restore must render its feedback line"
        );
        assert_eq!(
            std::fs::read(core.join("geoip.dat")).unwrap(),
            b"drifted geoip bytes",
            "a refused restore must not touch the managed geo data"
        );
    }

    #[test]
    fn provenance_computes_on_first_render_and_follows_file_changes() {
        let _appdata_guard = APPDATA_ENV_LOCK.blocking_lock();
        let temporary = tempfile::tempdir().expect("temporary AppData root");
        let _appdata = AppDataRedirect::to(temporary.path());
        let core = drifted_core(temporary.path());
        let first = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        set_mtime(&core.join("geoip.dat"), first);
        set_mtime(&core.join("geosite.dat"), first);
        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.geodata_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );
        // The builder frames already ran the section; whether the first
        // query is still pending or already drained depends on worker
        // timing, so the landed result below is the contract. Hashing never
        // runs on the UI thread: the worker is the only hash path besides
        // the spawn-failure fallback.
        run_until_provenance_known(&mut harness, "first provenance query");
        let expected = t_fmt(
            Language::En,
            Key::SettingsGeodataProvenanceUserOn,
            &[&format!("{first:?}")],
        );
        assert!(
            harness.query_by_label(&expected).is_some(),
            "the computed user-managed status must render with the newest mtime"
        );
        // Memoized per session: unchanged files must never re-hash.
        harness.run_steps(5);
        assert!(
            !harness.state().geodata_provenance.job.is_pending(),
            "unchanged geo data must not respawn the hash job"
        );
        // A file change (a configured-URL refresh while the core ran)
        // re-dates the status on the next rendered frame.
        let later = first + Duration::from_secs(120);
        set_mtime(&core.join("geosite.dat"), later);
        harness.run();
        // No in-flight-window assert here: the worker can land within the
        // same run() drain, so the refreshed result below is the contract.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let up_to_date = matches!(
                &harness.state().geodata_provenance.result,
                Some(GeoDataProvenance::UserManaged { updated: Some(t) }) if *t == later
            );
            if up_to_date {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the refreshed provenance did not land in time"
            );
            harness.run();
            std::thread::sleep(Duration::from_millis(5));
        }
        let refreshed = t_fmt(
            Language::En,
            Key::SettingsGeodataProvenanceUserOn,
            &[&format!("{later:?}")],
        );
        assert!(
            harness.query_by_label(&refreshed).is_some(),
            "the status must re-render with the changed file's mtime"
        );
    }

    #[test]
    fn provenance_without_a_managed_core_renders_nothing_and_wakes_on_install() {
        let _appdata_guard = APPDATA_ENV_LOCK.blocking_lock();
        let temporary = tempfile::tempdir().expect("temporary AppData root");
        let _appdata = AppDataRedirect::to(temporary.path());
        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.geodata_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );
        harness.run_steps(3);
        // No managed core: the no-core answer is adopted without a worker
        // and the section renders no provenance row (the URL fields stay
        // usable for pre-install configuration).
        assert!(
            matches!(
                harness.state().geodata_provenance.result,
                Some(GeoDataProvenance::NoCore)
            ),
            "an absent core directory must adopt the no-core answer"
        );
        assert!(
            !harness.state().geodata_provenance.job.is_pending(),
            "no-core must not spawn hash workers"
        );
        assert!(
            harness
                .query_by_label("Restore built-in geo data")
                .is_none(),
            "no Restore button may render without a managed core"
        );
        // A core appearing later (first install) is picked up by the
        // per-frame fingerprint. No in-flight-window assert: the worker can
        // land within the same run() drain — the landed answer below is the
        // contract (the no-core answer cached above must be replaced).
        let _core = drifted_core(temporary.path());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if matches!(
                &harness.state().geodata_provenance.result,
                Some(GeoDataProvenance::UserManaged { .. })
            ) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the appearing core must replace the no-core answer"
            );
            harness.run();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn provenance_caption_formats_the_update_time_or_its_absence() {
        // Pure caption memoization: no UI, no filesystem.
        let mut screen = SettingsScreen::default();
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        screen.geodata_provenance.result = Some(GeoDataProvenance::UserManaged {
            updated: Some(time),
        });
        screen.geodata_provenance.refresh_caption(Language::En);
        assert_eq!(
            screen
                .geodata_provenance
                .caption
                .as_ref()
                .expect("caption after refresh")
                .text,
            t_fmt(
                Language::En,
                Key::SettingsGeodataProvenanceUserOn,
                &[&format!("{time:?}")]
            )
        );
        // Both files unreadable/missing → the no-time wording.
        screen.geodata_provenance.result = Some(GeoDataProvenance::UserManaged { updated: None });
        screen.geodata_provenance.refresh_caption(Language::En);
        assert_eq!(
            screen
                .geodata_provenance
                .caption
                .as_ref()
                .expect("caption after refresh")
                .text,
            t(Language::En, Key::SettingsGeodataProvenanceUserUnknown)
        );
        // Memoized: a same-result refresh must not rebuild the caption.
        screen.geodata_provenance.refresh_caption(Language::En);
        assert_eq!(
            screen
                .geodata_provenance
                .caption
                .as_ref()
                .expect("caption")
                .result,
            GeoDataProvenance::UserManaged { updated: None },
            "the caption memo must key on the result"
        );
    }

    #[test]
    #[ignore = "requires the installed managed core"]
    fn restore_round_trip_flips_the_section_back_to_release_managed() {
        // The full UI loop over pin-matching bytes: hash → release-managed
        // status, drift → user-managed status, one Restore click → Done
        // feedback and the status flips back automatically.
        let _appdata_guard = APPDATA_ENV_LOCK.blocking_lock();
        let installed = std::env::var_os("APPDATA").expect("real APPDATA must be available");
        let installed_core = std::path::PathBuf::from(installed).join("broccoli/core");
        let temporary = tempfile::tempdir().expect("temporary AppData root");
        let _appdata = AppDataRedirect::to(temporary.path());
        let core = temporary.path().join("broccoli/core");
        std::fs::create_dir_all(&core).expect("create copied core dir");
        for payload in ["geoip.dat", "geosite.dat"] {
            let source = installed_core.join(payload);
            assert!(
                source.is_file(),
                "the managed core must be installed before exercising restore \
                 (missing {})",
                source.display()
            );
            std::fs::copy(source, core.join(payload)).expect("copy installed geo data payload");
        }
        // The pristine pair is built from the clone's own managed bytes —
        // pin-matching because the clone is the real installed core.
        let pristine = core.join("pristine");
        std::fs::create_dir_all(&pristine).expect("create pristine dir");
        std::fs::copy(core.join("geoip.dat"), pristine.join("geoip.dat"))
            .expect("seed pristine geoip");
        std::fs::copy(core.join("geosite.dat"), pristine.join("geosite.dat"))
            .expect("seed pristine geosite");

        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.geodata_section(ui, &mut rig.ctx()),
            SettingsScreen::default(),
        );
        harness.run();
        run_until_provenance_known(&mut harness, "release-managed query");
        assert!(
            matches!(
                harness.state().geodata_provenance.result,
                Some(GeoDataProvenance::ReleaseManaged)
            ),
            "a clone of the installed core must report release-managed"
        );

        // Drift one DAT, wait for the status to flip to user-managed.
        std::fs::write(core.join("geoip.dat"), b"drifted").expect("drift managed geoip");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let drifted = matches!(
                harness.state().geodata_provenance.result,
                Some(GeoDataProvenance::UserManaged { .. })
            );
            if drifted {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the drifted status did not land in time"
            );
            harness.run();
            std::thread::sleep(Duration::from_millis(5));
        }
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Restore built-in geo data")
            .click();
        harness.run();
        assert!(
            harness.state().geodata_provenance.restore_job.is_pending(),
            "the Restore click must start the worker"
        );
        run_until_restore_lands(&mut harness, "restore success");
        assert!(
            matches!(
                &harness.state().geodata_provenance.restore_feedback,
                Some(GeoDataRestoreFeedback::Done)
            ),
            "a restore from the pin-verified pristine pair must succeed"
        );
        // The status flips back to release-managed once the re-hash lands.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let restored = matches!(
                harness.state().geodata_provenance.result,
                Some(GeoDataProvenance::ReleaseManaged)
            );
            if restored {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the restored status did not land in time"
            );
            harness.run();
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            harness
                .query_by_label("Release-managed: the geo data matches the pinned release.")
                .is_some(),
            "the section must re-render the release-managed status after restore"
        );
    }

    fn drain_raw_parse(screen: &mut SettingsScreen, deadline: std::time::Instant) {
        while screen.raw_parse_job.is_pending() {
            assert!(
                std::time::Instant::now() < deadline,
                "raw parse worker did not deliver in time"
            );
            screen.poll_raw_parse(egui::Context::default(), Language::En);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn raw_override_refuses_oversized_buffer_before_any_worker() {
        let mut screen = SettingsScreen {
            raw_buf: "x".repeat(RAW_OVERRIDE_MAX_BYTES + 1),
            ..Default::default()
        };
        screen.bump_raw_parse(egui::Context::default(), Language::En);
        assert!(
            !screen.raw_parse_job.is_pending(),
            "an oversized buffer must not spawn a worker"
        );
        match screen.raw_parse.as_ref() {
            Some(RawParseState::TooLarge(len, limit)) => {
                assert_eq!(*len, RAW_OVERRIDE_MAX_BYTES + 1);
                assert_eq!(*limit, RAW_OVERRIDE_MAX_BYTES);
            }
            other => panic!("expected TooLarge refusal, got {other:?}"),
        }
    }

    #[test]
    fn raw_override_worker_delivers_ok_via_poll() {
        let mut screen = SettingsScreen {
            raw_buf: r#"{"log": {"loglevel": "info"}}"#.to_string(),
            ..Default::default()
        };
        screen.bump_raw_parse(egui::Context::default(), Language::En);
        assert!(
            screen.raw_parse_job.is_pending(),
            "a raw-override parse must run off the UI thread"
        );
        drain_raw_parse(
            &mut screen,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        );
        assert!(
            matches!(screen.raw_parse.as_ref(), Some(RawParseState::Ok(_))),
            "valid JSON must parse on the worker: {:?}",
            screen.raw_parse
        );
    }

    #[test]
    fn raw_override_worker_delivers_error_via_poll() {
        let mut screen = SettingsScreen {
            raw_buf: "{ not json".to_string(),
            ..Default::default()
        };
        screen.bump_raw_parse(egui::Context::default(), Language::En);
        drain_raw_parse(
            &mut screen,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        );
        assert!(
            matches!(screen.raw_parse.as_ref(), Some(RawParseState::Err(_))),
            "invalid JSON must surface as an error state: {:?}",
            screen.raw_parse
        );
    }

    #[test]
    fn raw_override_stale_result_respawns_for_current_buffer() {
        let mut screen = SettingsScreen {
            raw_buf: r#"{"a": 1}"#.to_string(),
            ..Default::default()
        };
        // First edit spawns a worker for the valid buffer.
        screen.bump_raw_parse(egui::Context::default(), Language::En);
        // Second edit while the first worker is in flight: no new worker
        // spawns yet; the stale result must respawn for the current buffer.
        screen.raw_buf = "{ broken".to_string();
        screen.bump_raw_parse(egui::Context::default(), Language::En);
        assert!(
            screen.raw_parse.is_none(),
            "busy until the stale result lands"
        );
        drain_raw_parse(
            &mut screen,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        );
        assert!(
            matches!(screen.raw_parse.as_ref(), Some(RawParseState::Err(_))),
            "the second buffer must be the one parsed: {:?}",
            screen.raw_parse
        );
    }

    #[test]
    fn raw_override_parse_error_is_bounded_and_never_echoes_input() {
        // Serde errors can embed the offending token, and
        // the error is rendered via Key::InvalidJson. A multi-KB hostile token
        // must yield a small, bounded message that never echoes the payload.
        let payload = format!("{{\"a\": {}}}", "x".repeat(4096));
        let error = parse_raw_override(&payload).expect_err("hostile JSON must fail");
        assert!(
            !error.is_empty(),
            "a non-empty buffer must not render the paste hint"
        );
        assert!(
            error.len() < 100,
            "a multi-KB token must yield a bounded error ({} bytes): {error}",
            error.len()
        );
        assert!(
            !error.contains(&"x".repeat(16)),
            "the error must never echo the payload: {error}"
        );
        // Blank buffers keep resolving to the paste-hint error.
        assert_eq!(parse_raw_override("   "), Err(String::new()));
    }

    /// A settings screen whose raw-override buffer already parsed: the
    /// header opens straight onto the parsed state (worker-free, so the
    /// Validate button is deterministic from the first open frame).
    fn seeded_raw_override_screen() -> SettingsScreen {
        SettingsScreen {
            raw_buf: r#"{"log":{"loglevel":"info"}}"#.to_string(),
            raw_loaded: true,
            raw_parse: Some(RawParseState::Ok(serde_json::json!({
                "log": { "loglevel": "info" }
            }))),
            ..Default::default()
        }
    }

    #[test]
    fn raw_override_validate_click_arms_reply_poll_and_renders_accepted_verdict() {
        let screen = seeded_raw_override_screen();
        let rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, state: &mut (SettingsScreen, UiTestRig)| {
                state.0.advanced_section(ui, &mut state.1.ctx());
            },
            (screen, rig),
        );
        harness
            .get_by_label(t(Language::En, Key::SettingsRawOverrideHeader))
            .click();
        harness.run();
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::SettingsValidateWithCore),
            )
            .click();
        harness.run_steps(2);
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsCoreAccepts))
                .is_none()
                && harness
                    .query_by_label(t(Language::En, Key::SettingsCoreRejects))
                    .is_none(),
            "no verdict may render while the validation is in flight"
        );
        assert!(
            harness.state().0.test_pending.is_pending(),
            "the click must arm the per-frame receiver poll"
        );
        let cmd = harness
            .state_mut()
            .1
            ._cmd_rx
            .try_recv()
            .expect("one command must be queued");
        let reply = match cmd {
            CoreCmd::TestConfig { config, reply } => {
                assert_eq!(
                    config,
                    serde_json::json!({ "log": { "loglevel": "info" } }),
                    "the clicked buffer must be the validated config"
                );
                reply
            }
            other => panic!("expected TestConfig, got {other:?}"),
        };
        assert!(
            harness.state_mut().1._cmd_rx.try_recv().is_err(),
            "one click must send exactly one command"
        );

        reply
            .send(Ok((true, ApplyOutput::Text(String::new()))))
            .expect("reply channel must be open");
        harness.run_steps(2);
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsCoreAccepts))
                .is_some(),
            "an accepted verdict must render the accept label"
        );
        assert_eq!(harness.state().0.test_verdict, Some((true, String::new())));
        assert!(
            !harness.state().0.test_pending.is_pending(),
            "the terminal must clear the pending poll"
        );
    }

    #[test]
    fn raw_override_validate_err_verdict_renders_reject_text_and_output() {
        let screen = seeded_raw_override_screen();
        let rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, state: &mut (SettingsScreen, UiTestRig)| {
                state.0.advanced_section(ui, &mut state.1.ctx());
            },
            (screen, rig),
        );
        harness
            .get_by_label(t(Language::En, Key::SettingsRawOverrideHeader))
            .click();
        harness.run();
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::SettingsValidateWithCore),
            )
            .click();
        harness.run_steps(2);
        let reply = match harness
            .state_mut()
            .1
            ._cmd_rx
            .try_recv()
            .expect("one command must be queued")
        {
            CoreCmd::TestConfig { reply, .. } => reply,
            other => panic!("expected TestConfig, got {other:?}"),
        };

        // Err terminal: the runtime never ran the validation (rejection or
        // cancellation), so the screen renders the reject label + output.
        let reject = Diag::new(Key::RtFrameCommandRejectedBusy)
            .arg_message(Diag::new(Key::OperationUpdateCore));
        let reject_text = reject.text(Language::En);
        reply
            .send(Err(DiagError::from(reject)))
            .expect("reply channel must be open");
        harness.run_steps(2);
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsCoreRejects))
                .is_some(),
            "a rejection terminal must render the reject label"
        );
        assert!(
            harness.query_by_label(&reject_text).is_some(),
            "the rejection text must render in the verdict output"
        );
        assert_eq!(
            harness.state().0.test_verdict,
            Some((false, reject_text)),
            "the rejection terminal must be the verdict the screen parked"
        );
        assert!(!harness.state().0.test_pending.is_pending());
    }

    #[test]
    fn raw_override_validate_failed_run_verdict_renders_reject_text_and_output() {
        let screen = seeded_raw_override_screen();
        let rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, state: &mut (SettingsScreen, UiTestRig)| {
                state.0.advanced_section(ui, &mut state.1.ctx());
            },
            (screen, rig),
        );
        harness
            .get_by_label(t(Language::En, Key::SettingsRawOverrideHeader))
            .click();
        harness.run();
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::SettingsValidateWithCore),
            )
            .click();
        harness.run_steps(2);
        let reply = match harness
            .state_mut()
            .1
            ._cmd_rx
            .try_recv()
            .expect("one command must be queued")
        {
            CoreCmd::TestConfig { reply, .. } => reply,
            other => panic!("expected TestConfig, got {other:?}"),
        };

        // Ok((false, output)): the core ran the validation and rejected the
        // candidate — reject label + the core's output block.
        reply
            .send(Ok((
                false,
                ApplyOutput::Text("config invalid: missing api".into()),
            )))
            .expect("reply channel must be open");
        harness.run_steps(2);
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsCoreRejects))
                .is_some(),
            "a failed run must render the reject label"
        );
        assert!(
            harness
                .query_by_label("config invalid: missing api")
                .is_some(),
            "the core output must render in the verdict block"
        );
        assert_eq!(
            harness.state().0.test_verdict,
            Some((false, "config invalid: missing api".to_string()))
        );
        assert!(!harness.state().0.test_pending.is_pending());
    }

    #[test]
    fn raw_override_validate_closed_reply_clears_pending_without_a_verdict() {
        let screen = seeded_raw_override_screen();
        let rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, state: &mut (SettingsScreen, UiTestRig)| {
                state.0.advanced_section(ui, &mut state.1.ctx());
            },
            (screen, rig),
        );
        harness
            .get_by_label(t(Language::En, Key::SettingsRawOverrideHeader))
            .click();
        harness.run();
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::SettingsValidateWithCore),
            )
            .click();
        harness.run_steps(2);
        let reply = match harness
            .state_mut()
            .1
            ._cmd_rx
            .try_recv()
            .expect("one command must be queued")
        {
            CoreCmd::TestConfig { reply, .. } => reply,
            other => panic!("expected TestConfig, got {other:?}"),
        };
        assert!(harness.state().0.test_pending.is_pending());

        // Runtime went away without a terminal: the closed channel must
        // clear the pending poll and render nothing.
        drop(reply);
        harness.run_steps(2);
        assert!(
            !harness.state().0.test_pending.is_pending(),
            "a closed reply must clear the pending poll"
        );
        assert_eq!(
            harness.state().0.test_verdict,
            None,
            "no terminal may fabricate a verdict"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsCoreAccepts))
                .is_none()
                && harness
                    .query_by_label(t(Language::En, Key::SettingsCoreRejects))
                    .is_none(),
            "a closed reply must leave the verdict block empty"
        );
    }

    /// The per-level header captions are pre-rendered from
    /// the sorted level-name list, so the list drives the UI — an add
    /// renders the new level's header on the following frame, a remove
    /// drops it, and idle frames repaint the cached headers untouched.
    #[test]
    fn policy_level_headers_follow_add_and_remove() {
        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 1000.0))
            .build_ui_state(
                |ui, screen| screen.core_section(ui, &mut rig.ctx()),
                SettingsScreen::default(),
            );

        harness.run();
        // The "0" level is repaired on first display when missing (the
        // level list starts empty in a fresh model).
        harness
            .get_all_by_label("User level 0")
            .next()
            .expect("the repair-inserted level 0 header renders");
        harness.run_steps(5);
        harness
            .get_all_by_label("User level 0")
            .next()
            .expect("idle frames keep rendering the cached level 0 header");

        // An added level renders its pre-rendered header on the next frame.
        harness
            .get_all_by_label("+ Add user level")
            .next()
            .expect("add button")
            .click();
        harness.run();
        harness
            .get_all_by_label("User level 1")
            .next()
            .expect("an added level renders its header on the next frame");

        // The remove button lives in the level body: open level 1 first.
        harness
            .get_all_by_label("User level 1")
            .next()
            .expect("level 1 header")
            .click();
        harness.run();
        harness
            .get_all_by_label("Remove level")
            .next()
            .expect("remove button")
            .click();
        harness.run();
        harness.run();
        assert!(
            harness.query_all_by_label("User level 1").next().is_none(),
            "the removed level's header disappears"
        );
        harness
            .get_all_by_label("User level 0")
            .next()
            .expect("level 0 survives the removal");
    }
}
