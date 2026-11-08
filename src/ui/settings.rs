//! Settings screen: the app's and the core's own identity settings, update
//! buttons, and the raw-JSON forward-compat hatch. Functional settings live
//! on their screen's Settings tab (Geodata on Routing; the latency-test and
//! subscription settings on Servers).
//!
//! Xray-facing edits mutate `ctx.settings` + `ctx.hooks.mark_dirty()`; the
//! shell saves those edits, while global appearance zoom uses egui's
//! persisted UI memory. Apply now or Connect updates Xray.

use egui::{Color32, RichText, Ui};

use super::{CoreSetupMount, SettingsCtx, show_core_setup, status::status_colors_of, widgets};
use crate::excerpt::excerpt;
use crate::i18n::{Key, t, t_fmt};
use crate::model::PolicyLevelCfg;
use crate::model::settings::Language;
use crate::rt::{CoreCmd, JobKind, TestConfigReply};
use crate::sys;
use crate::sys::selfupd::UpdateCheckState;
use crate::ui::popup;
use crate::ui::request::{Request, Terminal};

const LOG_LEVELS: [&str; 5] = ["debug", "info", "warning", "error", "none"];

/// Parse the raw override edit buffer: an empty/whitespace-only buffer is
/// `Err("")` (the empty draft), anything else is the JSON result.
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

#[derive(Default)]
pub struct SettingsScreen {
    /// Edit draft for the raw override, seeded from settings on first open of
    /// the collapsing header.
    raw_buf: widgets::Draft,
    /// Latest parse state of `raw_buf`, kept current by the worker (or the
    /// size-cap refusal); never parsed on the UI thread.
    raw_parse: Option<RawParseState>,
    /// In-flight worker parse of `raw_buf` (idle while none runs or the
    /// buffer was refused).
    raw_parse_job: Request<RawParseResult>,
    /// Buffer generation counter: bumped on every edit, so a stale worker
    /// result (from an older buffer) is detected and respawned.
    raw_parse_generation: u64,
    /// Layout generation of `raw_buf` for the memoized editor layouter:
    /// advanced by the tracked buffer on every mutation (a same-length
    /// in-place edit keeps the buffer's pointer and length, so the layout
    /// must key on a revision, not on the buffer's shape).
    raw_layout_revision: widgets::TextRevision,
    /// Cached layout of `raw_buf` for the raw-override editor: an unchanged
    /// buffer at an unchanged width reuses the galley instead of copying and
    /// laying out up to [`RAW_OVERRIDE_MAX_BYTES`] every frame.
    raw_layout: widgets::TextLayoutMemo,
    /// Whether the Cleanup modal is open.
    cleanup_modal: bool,
    /// Whether the Clean Up Network State modal is open. Confirming it sends
    /// `CoreCmd::CleanUp`; unlike the two exit actions below, this one keeps
    /// the app running.
    network_cleanup_modal: bool,
    /// Whether the Reset modal is open.
    reset_modal: bool,
    /// In-flight `Validate with core` run (one per click): the runtime's
    /// terminal verdict lands on this request's reply channel and is polled
    /// every frame the raw-override header renders.
    test_pending: Request<TestConfigReply>,
    /// Latest core validation verdict, rendered under the raw-override
    /// header; replaced on every new click and every terminal.
    test_verdict: Option<(bool, String)>,
    /// UI-scale caption (`"{:.0}%"`), memoized on the zoom factor — the
    /// appearance combo would re-format it every frame otherwise.
    zoom_caption: widgets::Memo<f32, String>,
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
    pub fn show(&mut self, ui: &mut Ui, ctx: &mut SettingsCtx) {
        // The shell already wraps this screen in a vertical ScrollArea.
        self.appearance_section(ui, ctx);
        self.privacy_section(ui, ctx);
        self.core_section(ui, ctx);
        self.core_setup_section(ui, ctx);
        self.updates_section(ui, ctx);
        self.cleanup_section(ui, ctx);
        self.advanced_section(ui, ctx);
    }

    /// (Re)start parsing `raw_buf` on the worker thread after a buffer edit
    /// (or the first open). Buffers over [`RAW_OVERRIDE_MAX_BYTES`] are
    /// refused up front with a message and never reach the worker. While a
    /// worker is already running for an older buffer, the stale result is
    /// detected by its generation and a fresh worker is spawned then.
    fn bump_raw_parse(&mut self, repaint: egui::Context, lang: Language) {
        self.raw_parse_generation = self.raw_parse_generation.wrapping_add(1);
        if self.raw_buf.text().len() > RAW_OVERRIDE_MAX_BYTES {
            self.raw_parse = Some(RawParseState::TooLarge(
                self.raw_buf.text().len(),
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
        let buf = self.raw_buf.text().to_owned();
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

    fn appearance_section(&mut self, ui: &mut Ui, ctx: &mut SettingsCtx) {
        const SCALE_PRESETS: [f32; 5] = [1.0, 1.25, 1.5, 1.75, 2.0];

        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::SettingsAppearance), |ui| {
            let current_zoom = ui.ctx().zoom_factor();
            let mut selected_zoom = current_zoom;
            // The zoom caption formats "{:.0}%" from the factor; cache it on
            // the factor so idle frames don't re-format (the factor only
            // changes through this very combo).
            let zoom_caption = self
                .zoom_caption
                .get(&current_zoom, || format!("{:.0}%", current_zoom * 100.0));
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
                    ctx.hooks.mark_ui_dirty();
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
                    ctx.hooks.mark_ui_dirty();
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
                .on_hover_text(t(ctx.settings.language, Key::AccentColorNote))
                .changed()
                {
                    let rgba = accent_rgba(color);
                    if ctx.settings.accent_color != Some(rgba) {
                        ctx.settings.accent_color = Some(rgba);
                        apply_accent(ui.ctx(), Some(rgba));
                        ctx.hooks.mark_ui_dirty();
                    }
                }
            });
        });
    }

    /// The Privacy group: what the Servers screen hides on its own. The
    /// credentials are always masked until revealed; this switch decides
    /// whether the server information takes part in that masking too.
    fn privacy_section(&mut self, ui: &mut Ui, ctx: &mut SettingsCtx) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::SettingsPrivacy), |ui| {
            if ui
                .checkbox(
                    &mut ctx.settings.hide_server_info,
                    t(lang, Key::SettingsHideServerInfo),
                )
                .on_hover_text(t(lang, Key::SettingsHideServerInfoNote))
                .changed()
            {
                // Display preference: persisted, but never raises the Apply
                // gate — the value never reaches the generated configuration.
                ctx.hooks.mark_ui_dirty();
            }
        });
    }

    fn core_section(&mut self, ui: &mut Ui, ctx: &mut SettingsCtx) {
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
                    ctx.hooks.mark_dirty();
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
                ctx.hooks.mark_dirty();
            }
            ui.label(RichText::new(t(lang, Key::SettingsEnvVars)).weak());
            if widgets::kv_table(
                ui,
                lang,
                &mut ctx.settings.env,
                "XRAY_*",
                t(lang, Key::ValueLower),
                t(lang, Key::AddKvRow),
            ) {
                ctx.hooks.mark_dirty();
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
                ctx.hooks.mark_dirty();
            }
        });
    }

    /// The permanent mount of the shared core setup surface: the same
    /// component the startup dialog shows, available in every core state —
    /// installed and verified, missing, stale, or failed verification.
    fn core_setup_section(&mut self, ui: &mut Ui, ctx: &mut SettingsCtx) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::SettingsCoreSetup), |ui| {
            ui.set_max_width(680.0);
            let _ = show_core_setup(ui, &mut ctx.core_setup_surface(), CoreSetupMount::Settings);
        });
    }

    fn updates_section(&mut self, ui: &mut Ui, ctx: &mut SettingsCtx) {
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
                    ctx.hooks.send(CoreCmd::CheckUpdate);
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

    /// Exit-time maintenance: the section offers three
    /// actions — "Clean Up Network State…" (the runtime repair, which keeps
    /// the app running), "Reset to default…" (the safer of the two exit
    /// actions, listed before the full cleanup) and "Clean Up and Exit…".
    /// Reset opens a modal that confirms restoring a
    /// fresh install's defaults while keeping the server list; cleanup opens
    /// the full-cleanup modal. Confirmed exit actions raise
    /// [`crate::ui::FrameHooks::request_reset`] /
    /// [`crate::ui::FrameHooks::request_cleanup_exit`];
    /// the shell stashes them for `main` and quits through the normal
    /// shutdown path, so the filesystem actions run only after the app has
    /// fully shut down.
    fn cleanup_section(&mut self, ui: &mut Ui, ctx: &mut SettingsCtx) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::SettingsCleanup), |ui| {
            ui.set_max_width(680.0);
            ui.label(t(lang, Key::SettingsCleanupHint));
            ui.add_space(4.0);
            let cleanup_ready = !ctx.busy.blocks(JobKind::CleanUp);
            if ui
                .add_enabled(
                    cleanup_ready,
                    egui::Button::new(t(lang, Key::SettingsCleanUpNetwork)),
                )
                .on_hover_text(t(lang, Key::SettingsCleanUpNetworkHint))
                .clicked()
            {
                self.network_cleanup_modal = true;
            }
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
        if self.network_cleanup_modal && self.show_network_cleanup_modal(ui.ctx(), lang) {
            self.network_cleanup_modal = false;
            // The runtime decides whether anything needs cleaning; the adapter
            // name is the effective one the TUN settings derive, because a
            // cleanup has no staged config to read it from.
            let adapter_name = ctx.settings.tun.effective_name().to_owned();
            ctx.hooks.send(CoreCmd::CleanUp { adapter_name });
        }
        if self.reset_modal && self.show_reset_modal(ui.ctx(), lang) {
            ctx.hooks.request_reset();
        }
        if self.cleanup_modal && self.show_cleanup_modal(ui.ctx(), lang) {
            ctx.hooks.request_cleanup_exit();
        }
    }

    /// The network-state cleanup confirmation: one action, because the repair
    /// itself is reversible — it restores what a session took over and
    /// removes only what that session left behind. Returns whether the user
    /// confirmed; Cancel closes it without a command.
    fn show_network_cleanup_modal(&mut self, ctx: &egui::Context, lang: Language) -> bool {
        let mut confirmed = false;
        let mut resolved = false;
        let declined = popup::modal(
            ctx,
            "settings.network-cleanup",
            t(lang, Key::SettingsCleanUpNetworkTitle),
            520.0,
            |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(t(lang, Key::SettingsCleanUpNetworkNote)).weak(),
                    )
                    .wrap(),
                )
                .on_hover_text(t(lang, Key::SettingsCleanUpNetworkDetail));
                ui.add_space(10.0);
                if ui
                    .button(t(lang, Key::SettingsCleanUpNetworkConfirm))
                    .clicked()
                {
                    confirmed = true;
                }
                ui.add_space(8.0);
                ui.separator();
                if ui.button(t(lang, Key::Cancel)).clicked() {
                    resolved = true;
                }
            },
        );
        if declined || resolved {
            self.network_cleanup_modal = false;
        }
        confirmed
    }

    /// The cleanup confirmation — rendered in the main window, which it dims
    /// and blocks — with exactly two actions. Choosing full cleanup raises
    /// the request and closes it; Cancel just closes it. Returns whether the
    /// user confirmed.
    fn show_cleanup_modal(&mut self, ctx: &egui::Context, lang: Language) -> bool {
        let mut confirmed = false;
        let mut resolved = false;
        let declined = popup::modal(
            ctx,
            "settings.cleanup",
            t(lang, Key::SettingsCleanupTitle),
            520.0,
            |ui| {
                ui.add(
                    egui::Label::new(RichText::new(t(lang, Key::SettingsCleanupNote)).weak())
                        .wrap(),
                )
                .on_hover_text(t(lang, Key::SettingsCleanupDetail));
                ui.add_space(10.0);
                if ui
                    .button(t(lang, Key::SettingsCleanupFull))
                    .on_hover_text(t(lang, Key::SettingsCleanupFullHint))
                    .clicked()
                {
                    confirmed = true;
                    resolved = true;
                }
                ui.add_space(8.0);
                ui.separator();
                if ui.button(t(lang, Key::Cancel)).clicked() {
                    resolved = true;
                }
            },
        );
        if declined || resolved {
            self.cleanup_modal = false;
        }
        confirmed
    }

    /// The reset confirmation — rendered in the main window, which it dims and
    /// blocks — with exactly two actions. Confirming raises the request and
    /// closes it; Cancel just closes it. Reset keeps the server list: the exit
    /// wipe clears generated configs and logs but preserves servers and the
    /// core. Returns whether the user confirmed.
    fn show_reset_modal(&mut self, ctx: &egui::Context, lang: Language) -> bool {
        let mut confirmed = false;
        let mut resolved = false;
        let declined = popup::modal(
            ctx,
            "settings.reset",
            t(lang, Key::SettingsResetTitle),
            520.0,
            |ui| {
                ui.add(
                    egui::Label::new(RichText::new(t(lang, Key::SettingsResetNote)).weak()).wrap(),
                )
                .on_hover_text(t(lang, Key::SettingsResetDetail));
                ui.add_space(10.0);
                if ui.button(t(lang, Key::SettingsResetConfirm)).clicked() {
                    confirmed = true;
                    resolved = true;
                }
                ui.add_space(8.0);
                ui.separator();
                if ui.button(t(lang, Key::Cancel)).clicked() {
                    resolved = true;
                }
            },
        );
        if declined || resolved {
            self.reset_modal = false;
        }
        confirmed
    }

    fn advanced_section(&mut self, ui: &mut Ui, ctx: &mut SettingsCtx) {
        let lang = ctx.settings.language;
        widgets::section(ui, t(lang, Key::SettingsAdvanced), |ui| {
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
                    let raw_response = {
                        // Seeded on first open; afterwards the draft is the
                        // buffer on screen until Enable override commits it.
                        let raw = self
                            .raw_buf
                            .begin(|| ctx.settings.raw_override.clone().unwrap_or_default());
                        // The tracked buffer advances the layout revision on
                        // every mutation, so an in-place same-length edit
                        // re-lays the text while an unchanged frame reuses
                        // the cached galley.
                        let mut layouter = self
                            .raw_layout
                            .layouter(&self.raw_layout_revision, egui::TextStyle::Monospace);
                        let mut tracked =
                            widgets::TrackedBuffer::new(raw, &self.raw_layout_revision);
                        ui.add(
                            egui::TextEdit::multiline(&mut tracked)
                                .font(egui::TextStyle::Monospace)
                                .desired_rows(14)
                                .desired_width(f32::INFINITY)
                                .layouter(&mut layouter),
                        )
                    };
                    let raw_changed = raw_response.changed();
                    // The seeding frame is the first open; every edit drives
                    // a fresh parse too, so the verdict always describes the
                    // buffer on screen.
                    if raw_changed || self.raw_buf.reseeded() {
                        self.bump_raw_parse(ui.ctx().clone(), lang);
                    }
                    self.poll_raw_parse(ui.ctx().clone(), lang);
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
                            raw_response.on_hover_text(t(lang, Key::SettingsRawOverridePasteNote));
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
                            let sent = ctx.hooks.send(CoreCmd::TestConfig {
                                config: v.clone(),
                                reply,
                            });
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
                            && self.raw_buf.commit_if(
                                // The worker's parse report is the gate: an
                                // override may only be enabled once the
                                // buffer itself parses.
                                |_| parsed_ok,
                                |text| ctx.settings.raw_override = Some(text.to_owned()),
                            )
                        {
                            ctx.hooks.mark_dirty();
                        }
                        if ctx.settings.raw_override.is_some()
                            && ui.button(t(lang, Key::SettingsDisableOverride)).clicked()
                        {
                            ctx.settings.raw_override = None;
                            ctx.hooks.mark_dirty();
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
                })
                .header_response
                .on_hover_text(t(lang, Key::SettingsRawOverrideExplain));
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
        RAW_OVERRIDE_MAX_BYTES, RawParseState, SettingsScreen, accent_rgba, apply_accent,
        color_from_accent, parse_raw_override, picker_start_color,
    };
    use crate::diag::{Diag, DiagError};
    use crate::i18n::{Key, t};
    use crate::model::settings::Language;
    use crate::rt::{ApplyOutput, CoreCmd};
    use crate::sys::selfupd::{UpdateCheckState, Version};
    use crate::ui::test_rig::UiTestRig;
    use crate::ui::test_rig::harness_builder;
    use egui::Color32;
    use egui_kittest::{
        Harness,
        kittest::{NodeT as _, Queryable as _},
    };

    #[test]
    fn appearance_scale_changes_global_zoom() {
        let mut rig = UiTestRig::default();
        let mut harness = harness_builder().with_pixels_per_point(1.5).build_ui_state(
            |ui, screen| screen.appearance_section(ui, &mut rig.ctx().settings()),
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
        let mut harness = harness_builder().build_ui_state(
            |ui, screen| screen.appearance_section(ui, &mut rig.ctx().settings()),
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
        let mut harness = harness_builder().build_ui_state(
            |ui, screen| screen.appearance_section(ui, &mut rig.ctx().settings()),
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
        let harness = harness_builder().build_ui_state(
            |ui, screen| screen.appearance_section(ui, &mut rig.ctx().settings()),
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
    fn settings_screen_keeps_identity_sections_and_mounts_no_moved_settings() {
        let mut rig = UiTestRig::default();
        let harness = harness_builder().build_ui_state(
            |ui, screen| screen.show(ui, &mut rig.ctx().settings()),
            SettingsScreen::default(),
        );

        for section in [
            "Appearance",
            "Privacy",
            "Core",
            "Core setup",
            "Updates",
            "Cleanup",
        ] {
            assert!(
                harness.query_by_label(section).is_some(),
                "the Settings screen must keep the {section:?} section"
            );
        }
        assert!(
            harness.query_by_label("Raw Override (danger)").is_some(),
            "the raw override must stay on the Settings screen"
        );
        assert!(
            harness.query_by_label("Geodata").is_none(),
            "Geodata must move to the Routing screen"
        );
        assert!(
            harness.query_by_label("Update schedule (cron):").is_none(),
            "the geodata cron field must not render on Settings"
        );
        assert!(
            harness
                .query_by_label("Restore built-in geo data")
                .is_none(),
            "the geodata Restore action must not render on Settings"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsLatencyTest))
                .is_none(),
            "the latency test settings must move to the Servers screen"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsSubscriptions))
                .is_none(),
            "the subscription settings must move to the Servers screen"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::ProbeUrl))
                .is_none(),
            "the probe URL field must not render on Settings"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsSubscriptionUserAgent))
                .is_none(),
            "the subscription User-Agent field must not render on Settings"
        );
    }

    #[test]
    fn updates_section_idle_shows_only_the_check_button() {
        let mut rig = UiTestRig::default();
        let harness = harness_builder().build_ui_state(
            |ui, screen| screen.updates_section(ui, &mut rig.ctx().settings()),
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
        let mut harness = harness_builder().build_ui_state(
            |ui, screen| screen.updates_section(ui, &mut rig.ctx().settings()),
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
        let harness = harness_builder().build_ui_state(
            |ui, screen| screen.updates_section(ui, &mut rig.ctx().settings()),
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
        let harness = harness_builder().build_ui_state(
            |ui, screen| screen.updates_section(ui, &mut rig.ctx().settings()),
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
        let harness = harness_builder().build_ui_state(
            |ui, screen| screen.updates_section(ui, &mut rig.ctx().settings()),
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
        let mut harness = harness_builder().build_ui_state(
            |ui, screen| screen.updates_section(ui, &mut rig.ctx().settings()),
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
        let harness = harness_builder().build_ui_state(
            |ui, screen| screen.cleanup_section(ui, &mut rig.ctx().settings()),
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
    fn cleanup_section_renders_the_network_cleanup_button() {
        let mut rig = UiTestRig::default();
        let harness = harness_builder().build_ui_state(
            |ui, screen| screen.cleanup_section(ui, &mut rig.ctx().settings()),
            SettingsScreen::default(),
        );

        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "Clean Up Network State…")
                .is_some(),
            "the Cleanup section must render the network cleanup button"
        );
        assert!(
            harness.query_by_label("Clean Up Network State").is_none(),
            "the network cleanup modal must be closed until the button is clicked"
        );
    }

    #[test]
    fn network_cleanup_modal_confirm_sends_one_clean_up_command() {
        let mut rig = UiTestRig::default();
        let mut screen = SettingsScreen::default();
        let mut harness = harness_builder().build_ui_state(
            |ui, _state| screen.cleanup_section(ui, &mut rig.ctx().settings()),
            (),
        );

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Clean Up Network State…")
            .click();
        harness.run();
        assert!(
            harness.query_by_label("Clean Up Network State").is_some(),
            "the button must open the confirmation"
        );
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Clean up")
            .click();
        harness.run();
        drop(harness);

        match rig._cmd_rx.try_recv() {
            Ok(CoreCmd::CleanUp { adapter_name }) => assert_eq!(
                adapter_name, "broccoli0",
                "the command carries the settings' default adapter name"
            ),
            other => panic!("confirming must send exactly one CleanUp command: {other:?}"),
        }
        assert!(
            rig._cmd_rx.try_recv().is_err(),
            "one confirmation must send exactly one command"
        );
        assert!(
            !screen.network_cleanup_modal,
            "confirming must close the modal"
        );
    }

    #[test]
    fn network_cleanup_modal_cancel_sends_nothing() {
        let mut rig = UiTestRig::default();
        let mut screen = SettingsScreen::default();
        let mut harness = harness_builder().build_ui_state(
            |ui, _state| screen.cleanup_section(ui, &mut rig.ctx().settings()),
            (),
        );

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Clean Up Network State…")
            .click();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Cancel")
            .click();
        harness.run();
        drop(harness);

        assert!(
            rig._cmd_rx.try_recv().is_err(),
            "Cancel must not command a cleanup"
        );
        assert!(!screen.network_cleanup_modal, "Cancel must close the modal");
    }

    #[test]
    fn cleanup_modal_opens_with_the_two_actions() {
        let mut rig = UiTestRig::default();
        let mut screen = SettingsScreen::default();
        let mut harness = harness_builder().build_ui_state(
            |ui, _state| screen.cleanup_section(ui, &mut rig.ctx().settings()),
            (),
        );

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
        let mut harness = harness_builder().build_ui_state(
            |ui, _state| screen.cleanup_section(ui, &mut rig.ctx().settings()),
            (),
        );

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
            !rig.requests.cleanup,
            "Cancel must not record a cleanup request"
        );
        assert!(!screen.cleanup_modal, "Cancel must close the modal");
    }

    #[test]
    fn cleanup_modal_full_cleanup_records_the_request_and_closes() {
        let mut rig = UiTestRig::default();
        let mut screen = SettingsScreen::default();
        let mut harness = harness_builder().build_ui_state(
            |ui, _state| screen.cleanup_section(ui, &mut rig.ctx().settings()),
            (),
        );

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
            rig.requests.cleanup,
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
        let mut harness = harness_builder().build_ui_state(
            |ui, _state| screen.cleanup_section(ui, &mut rig.ctx().settings()),
            (),
        );

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
            rig.requests.reset,
            "Reset to default must record the request for the shell"
        );
        assert!(!screen.reset_modal, "confirming must close the reset modal");
    }

    #[test]
    fn reset_modal_cancel_closes_without_a_request() {
        let mut rig = UiTestRig::default();
        let mut screen = SettingsScreen::default();
        let mut harness = harness_builder().build_ui_state(
            |ui, _state| screen.cleanup_section(ui, &mut rig.ctx().settings()),
            (),
        );

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
            !rig.requests.reset,
            "Cancel must not record a reset request"
        );
        assert!(!screen.reset_modal, "Cancel must close the reset modal");
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
        let mut screen = SettingsScreen::default();
        screen
            .raw_buf
            .begin(|| "x".repeat(RAW_OVERRIDE_MAX_BYTES + 1));
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
        let mut screen = SettingsScreen::default();
        screen
            .raw_buf
            .begin(|| r#"{"log": {"loglevel": "info"}}"#.to_owned());
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
        let mut screen = SettingsScreen::default();
        screen.raw_buf.begin(|| "{ not json".to_owned());
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
        let mut screen = SettingsScreen::default();
        screen.raw_buf.begin(|| r#"{"a": 1}"#.to_owned());
        // First edit spawns a worker for the valid buffer.
        screen.bump_raw_parse(egui::Context::default(), Language::En);
        // Second edit while the first worker is in flight: no new worker
        // spawns yet; the stale result must respawn for the current buffer.
        screen.raw_buf.text_mut().clear();
        screen.raw_buf.text_mut().push_str("{ broken");
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
        let mut screen = SettingsScreen::default();
        // The draft is already seeded, so opening the header keeps this text
        // instead of reloading the (absent) model override.
        screen
            .raw_buf
            .begin(|| r#"{"log":{"loglevel":"info"}}"#.to_owned());
        screen.raw_parse = Some(RawParseState::Ok(serde_json::json!({
            "log": { "loglevel": "info" }
        })));
        screen
    }

    #[test]
    fn raw_override_validate_click_arms_reply_poll_and_renders_accepted_verdict() {
        let screen = seeded_raw_override_screen();
        let rig = UiTestRig::default();
        let mut harness = harness_builder().build_ui_state(
            |ui, state: &mut (SettingsScreen, UiTestRig)| {
                state.0.advanced_section(ui, &mut state.1.ctx().settings());
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
        let mut harness = harness_builder().build_ui_state(
            |ui, state: &mut (SettingsScreen, UiTestRig)| {
                state.0.advanced_section(ui, &mut state.1.ctx().settings());
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
        let mut harness = harness_builder().build_ui_state(
            |ui, state: &mut (SettingsScreen, UiTestRig)| {
                state.0.advanced_section(ui, &mut state.1.ctx().settings());
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
        let mut harness = harness_builder().build_ui_state(
            |ui, state: &mut (SettingsScreen, UiTestRig)| {
                state.0.advanced_section(ui, &mut state.1.ctx().settings());
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
        let mut harness = harness_builder()
            .with_size(egui::vec2(800.0, 1000.0))
            .build_ui_state(
                |ui, screen| screen.core_section(ui, &mut rig.ctx().settings()),
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
