//! Geodata settings: the core-native geo data updater (file URLs and cron)
//! plus the managed geo data's provenance status and Restore action.
//!
//! One self-contained component: its own edit drafts, provenance state, and
//! worker live here, so the Routing screen mounts the same surface the
//! Settings screen used to own instead of copying it.

use egui::{RichText, Ui};

use super::FrameHooks;
use super::status::status_colors_of;
use super::widgets;
use crate::diag::{Diag, DiagError};
use crate::i18n::{Key, t, t_fmt};
use crate::model::Settings;
use crate::model::settings::{Language, geodata_cron_error, geodata_url_error};
use crate::sys;
use crate::ui::request::{Request, Terminal};

/// Per-file `(mtime, len)` fingerprint of the managed geo data: the
/// memoization key that decides when a provenance hash job must run. The
/// section stats it at most once per [`GEO_DATA_STAT_INTERVAL`] — the files
/// change on user-managed edits, not per frame — and never hashes on the UI
/// thread; a file that is missing or cannot be statted fingerprints as
/// absent, so its (re)appearance re-triggers a hash.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
struct GeoDataFingerprint {
    geoip: Option<(std::time::SystemTime, u64)>,
    geosite: Option<(std::time::SystemTime, u64)>,
}

/// How long a [`geo_data_fingerprint`] stat stays fresh. One second keeps
/// the provenance status responsive to a file change without paying the
/// syscalls — `core_dir().is_dir()` plus two `metadata` calls — on every
/// rendered frame.
const GEO_DATA_STAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

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
/// the mtime Debug string and sentence build allocate, so idle frames only
/// compare the cached key.
struct GeoDataCaption {
    lang: Language,
    result: crate::sys::core_dl::GeoDataProvenance,
    text: String,
}

/// Session state behind the Geodata provenance status line and the Restore
/// action. The status is recomputed each session — never persisted — by
/// hashing the on-disk geo data whenever the section renders and the file
/// fingerprint changed; Restore replaces the managed geo data with the
/// pin-verified pristine pair.
#[derive(Default)]
struct GeoDataProvenanceState {
    /// Last `geo_data_fingerprint()` stat and when it ran: the section's
    /// per-frame driver re-stats at most once per
    /// [`GEO_DATA_STAT_INTERVAL`], reusing the cached value in between (an
    /// `is_dir` plus two `metadata` reads per rendered frame were the
    /// section's idle cost). Events that rewrite the files invalidate it.
    stat: Option<(std::time::Instant, Option<GeoDataFingerprint>)>,
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
    /// raw-parse generation discipline, applied to bytes), stats both geo
    /// data files (at most once per [`GEO_DATA_STAT_INTERVAL`], reusing the
    /// cached fingerprint in between, plus one fresh stat when a hash lands
    /// because the files may have changed while it ran), and respawns the
    /// hash job when the fingerprint changed since the last completed hash
    /// or nothing is cached yet. Never hashes on the UI thread and never
    /// runs two hash jobs at once; while a restore runs, hash respawns wait
    /// for it (the restore rewrites the files a pending hash would read).
    fn update(&mut self, repaint: &egui::Context) {
        if self.job.is_pending() {
            match self.job.poll() {
                Some(Terminal::Answered(provenance)) => {
                    // A landed hash is a provenance event: the files may have
                    // changed while it ran, so judge its answer against a
                    // fresh stat instead of the throttle's cached one.
                    let fingerprint = self.fingerprint_stat(true);
                    if self.job_fingerprint == fingerprint {
                        // The files are still exactly the ones the job hashed.
                        self.fingerprint = fingerprint;
                        self.result = Some(provenance);
                        self.caption = None;
                    } else {
                        // The files changed while the job hashed; its answer
                        // is stale and the fresh query below replaces it.
                        self.fingerprint = None;
                        self.result = None;
                        self.caption = None;
                    }
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
        let fingerprint = self.fingerprint_stat(false);
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

    /// The managed geo data's current fingerprint: the cached stat while it
    /// is younger than [`GEO_DATA_STAT_INTERVAL`], otherwise — or when
    /// `force` asks, because a landed hash's files may have changed — one
    /// fresh `is_dir` plus two `metadata` batch.
    fn fingerprint_stat(&mut self, force: bool) -> Option<GeoDataFingerprint> {
        let now = std::time::Instant::now();
        if !force
            && let Some((stat_at, cached)) = self.stat
            && now.duration_since(stat_at) < GEO_DATA_STAT_INTERVAL
        {
            return cached;
        }
        let fingerprint = geo_data_fingerprint();
        self.stat = Some((now, fingerprint));
        fingerprint
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
                // The restore rewrote the files: drop the cached stat so
                // the next frame fingerprints them immediately instead of
                // reusing a stat taken before the rewrite.
                self.stat = None;
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
    /// The update time renders as the UTC calendar text the routing
    /// screen's geodata tooltip also shows for these files' mtimes
    /// ([`crate::ui::utc_timestamp`]) — the repo's only mtime display.
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
                Some(modified) => {
                    let modified = crate::ui::utc_timestamp(*modified)
                        .unwrap_or_else(|| t(lang, Key::GeodataModifiedUnavailable).to_owned());
                    t_fmt(lang, Key::SettingsGeodataProvenanceUserOn, &[&modified])
                }
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

/// The Geodata settings section: file URLs, cron schedule, provenance
/// status, and Restore. Mounted by the Routing screen's Settings side.
#[derive(Default)]
pub(crate) struct GeodataSection {
    /// Edit drafts for the geodata URL/cron fields (Option<String> model),
    /// seeded from settings on first open and committed only when the
    /// field's own rule accepts the text.
    geoip_url_buf: widgets::Draft,
    geosite_url_buf: widgets::Draft,
    geodata_cron_buf: widgets::Draft,
    /// Session state of the geo data provenance status line and the Restore
    /// action: memoized hash result + one in-flight job per action, kept
    /// while the screen lives so a re-open never re-hashes unchanged geo
    /// data.
    provenance: GeoDataProvenanceState,
}

impl GeodataSection {
    /// Per-file optional HTTPS URLs for geoip.dat/geosite.dat plus the cron
    /// schedule (core-native `geodata` key). Broccoli only writes the
    /// config block — the pinned core downloads and reloads the dats itself.
    /// The provenance status line and the Restore action live at the bottom
    /// of this section; see [`Self::provenance_ui`].
    pub(crate) fn show(
        &mut self,
        ui: &mut Ui,
        settings: &mut Settings,
        hooks: &mut FrameHooks<'_>,
    ) {
        let lang = settings.language;
        widgets::section(ui, t(lang, Key::SettingsGeodata), |ui| {
            // Job drivers first so the status row below is current: drain a
            // landed restore, then drain/respawn the provenance hash. Both
            // are off the UI thread; per frame the section only stats the
            // two geo data files (cheap metadata reads).
            self.provenance.poll_restore(lang);
            self.provenance.update(ui.ctx());
            // File-name labels are config-contract literals (documented
            // bare-wire exception), like the `geoip.dat`/`geosite.dat`
            // resource file paths the core resolves.
            let geoip_url = self
                .geoip_url_buf
                .begin(|| settings.geodata.geoip_url.clone().unwrap_or_default());
            // Commit + mark dirty only when the value validates (probe_interval
            // pattern): an invalid draft stays in the edit buffer with its
            // inline error and can never block later generation.
            let changed = widgets::noted(ui, t(lang, Key::SettingsGeodataEmptyNote), |ui| {
                widgets::validated_field(
                    ui,
                    "geoip.dat",
                    geoip_url,
                    t(lang, Key::UrlHint),
                    |value| geodata_url_error(value, lang),
                )
            });
            if changed
                && self.geoip_url_buf.commit_if(
                    |value| geodata_url_error(value, lang).is_none(),
                    |value| {
                        settings.geodata.geoip_url = (!value.is_empty()).then_some(value.clone());
                    },
                )
            {
                hooks.mark_dirty();
            }
            let geosite_url = self
                .geosite_url_buf
                .begin(|| settings.geodata.geosite_url.clone().unwrap_or_default());
            let changed = widgets::noted(ui, t(lang, Key::SettingsGeodataEmptyNote), |ui| {
                widgets::validated_field(
                    ui,
                    "geosite.dat",
                    geosite_url,
                    t(lang, Key::UrlHint),
                    |value| geodata_url_error(value, lang),
                )
            });
            if changed
                && self.geosite_url_buf.commit_if(
                    |value| geodata_url_error(value, lang).is_none(),
                    |value| {
                        settings.geodata.geosite_url = (!value.is_empty()).then_some(value.clone());
                    },
                )
            {
                hooks.mark_dirty();
            }
            let cron = self
                .geodata_cron_buf
                .begin(|| settings.geodata.cron.clone().unwrap_or_default());
            let changed = widgets::noted(ui, t(lang, Key::SettingsGeodataCronNote), |ui| {
                widgets::validated_field(
                    ui,
                    t(lang, Key::SettingsGeodataCronLabel),
                    cron,
                    crate::model::settings::DEFAULT_GEODATA_CRON,
                    |value| geodata_cron_error(value, lang),
                )
            });
            if changed
                && self.geodata_cron_buf.commit_if(
                    |value| geodata_cron_error(value, lang).is_none(),
                    |value| {
                        settings.geodata.cron = (!value.is_empty()).then_some(value.clone());
                    },
                )
            {
                hooks.mark_dirty();
            }
            self.provenance_ui(ui, lang);
        });
    }

    /// The geo data provenance status line and the Restore action, under the
    /// section's fields. Rendered from the memoized hash result — nothing
    /// here hashes; the caption is rebuilt only when the result or the
    /// language changed.
    ///
    /// Release-managed renders the status line with a disabled, inert
    /// Restore button; user-managed (bytes differ from the release pins —
    /// including while URLs are still configured, so "that URL served
    /// garbage, take me back" is one click) enables it. No managed core
    /// renders nothing: there is no geo data to provenance before install.
    fn provenance_ui(&mut self, ui: &mut Ui, lang: Language) {
        // A small clone of the enum keeps the draw free of self borrows; the
        // caption refresh below needs `&mut self`.
        let result = self.provenance.result.clone();
        let managed = match &result {
            Some(sys::core_dl::GeoDataProvenance::ReleaseManaged)
            | Some(sys::core_dl::GeoDataProvenance::UserManaged { .. }) => Some(matches!(
                result,
                Some(sys::core_dl::GeoDataProvenance::UserManaged { .. })
            )),
            _ => None,
        };
        if let Some(user_managed) = managed {
            self.provenance.refresh_caption(lang);
            let Some(caption) = &self.provenance.caption else {
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
            let busy = self.provenance.restore_job.is_pending();
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
                self.provenance.spawn_restore(ui.ctx(), lang);
            }
        }
        // Feedback renders even while the post-restore re-hash hides the
        // caption for a frame or two, so a just-finished restore never
        // flickers.
        match &self.provenance.restore_feedback {
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
}

#[cfg(test)]
mod tests {
    use super::{
        GeoDataProvenanceState, GeoDataRestoreFeedback, GeodataSection, geo_data_fingerprint,
    };
    use crate::i18n::{Key, t, t_fmt};
    use crate::model::settings::Language;
    use crate::sys::appdata::{APPDATA_ENV_LOCK, AppDataRedirect};
    use crate::sys::core_dl::GeoDataProvenance;
    use crate::ui::test_rig::{UiTestRig, harness_builder};
    use egui_kittest::{Harness, kittest::Queryable as _};
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    /// Render the component inside the shared rig's Settings slice.
    fn harness(
        rig: UiTestRig,
        section: GeodataSection,
    ) -> Harness<'static, (GeodataSection, UiTestRig)> {
        harness_builder().build_ui_state(
            |ui, state: &mut (GeodataSection, UiTestRig)| {
                let mut uictx = state.1.ctx();
                let mut ctx = uictx.settings();
                let settings = &mut *ctx.settings;
                let hooks = &mut ctx.hooks;
                state.0.show(ui, settings, hooks);
            },
            (section, rig),
        )
    }

    #[test]
    fn geodata_section_binds_url_fields_and_persists() {
        let mut harness = harness(UiTestRig::default(), GeodataSection::default());

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

        let state = harness.state();
        assert_eq!(
            state.1.settings.geodata.geoip_url.as_deref(),
            Some("https://example.com/geoip.dat")
        );
        assert_eq!(
            state.1.settings.geodata.geosite_url.as_deref(),
            Some("https://example.com/geosite.dat")
        );
        assert_eq!(state.1.settings.geodata.cron.as_deref(), Some("17 3 * * 1"));
        assert!(
            state.1.requests.dirty,
            "geodata edits must mark the settings dirty"
        );
    }

    #[test]
    fn geodata_section_url_only_edit_marks_dirty_and_commits() {
        let mut harness = harness(UiTestRig::default(), GeodataSection::default());

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

        let state = harness.state();
        assert_eq!(
            state.1.settings.geodata.geoip_url.as_deref(),
            Some("https://example.com/geoip.dat"),
            "a valid URL-only edit must commit to settings"
        );
        assert_eq!(state.1.settings.geodata.geosite_url, None);
        assert_eq!(state.1.settings.geodata.cron, None);
        assert!(
            state.1.requests.dirty,
            "a URL-only edit must mark the settings dirty"
        );
    }

    #[test]
    fn geodata_section_shows_validation_errors() {
        let mut harness = harness(UiTestRig::default(), GeodataSection::default());

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

        let state = harness.state();
        assert_eq!(
            state.1.settings.geodata.geoip_url, None,
            "an invalid URL must stay in the edit buffer, never committed"
        );
        assert_eq!(
            state.1.settings.geodata.cron, None,
            "an invalid cron must stay in the edit buffer, never committed"
        );
        assert!(
            !state.1.requests.dirty,
            "invalid geodata edits must not mark the settings dirty"
        );
    }

    #[test]
    fn geodata_section_empty_is_unconfigured() {
        let harness = harness(UiTestRig::default(), GeodataSection::default());

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

        let state = harness.state();
        assert!(
            !state.1.settings.geodata.is_configured(),
            "an untouched section must leave geodata unconfigured"
        );
        assert!(
            !state.1.requests.dirty,
            "rendering the empty section must not dirty settings"
        );
    }

    // ------------------------------------------------------------------
    // Geo data provenance status + Restore. Always-run tests redirect
    // APPDATA to a temp root so the provenance/restore workers hash
    // fixture files, never the real installed core; release-managed bytes
    // exist only in a real installed core, so the full
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
    fn run_until_provenance_known(
        harness: &mut Harness<'_, (GeodataSection, UiTestRig)>,
        what: &str,
    ) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while harness.state().0.provenance.result.is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "{what}: provenance worker did not deliver in time"
            );
            harness.run();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Drive harness frames until the restore job lands.
    fn run_until_restore_lands(harness: &mut Harness<'_, (GeodataSection, UiTestRig)>, what: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while harness.state().0.provenance.restore_job.is_pending() {
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
        let section = GeodataSection {
            provenance: seeded_provenance(GeoDataProvenance::ReleaseManaged),
            ..Default::default()
        };
        let mut harness = harness(UiTestRig::default(), section);
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
            !harness.state().0.provenance.restore_job.is_pending()
                && harness.state().0.provenance.restore_feedback.is_none(),
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
        let section = GeodataSection {
            provenance: seeded_provenance(GeoDataProvenance::UserManaged {
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
        let mut harness = harness(rig, section);
        harness.run();
        let stamp =
            crate::ui::utc_timestamp(geosite_time).expect("an epoch-second fixture renders");
        let expected_caption = t_fmt(
            Language::En,
            Key::SettingsGeodataProvenanceUserOn,
            &[&stamp],
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
        match &harness.state().0.provenance.restore_feedback {
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
        let mut harness = harness(UiTestRig::default(), GeodataSection::default());
        // The builder frames already ran the section; whether the first
        // query is still pending or already drained depends on worker
        // timing, so the landed result below is the contract. Hashing never
        // runs on the UI thread: the worker is the only hash path besides
        // the spawn-failure fallback.
        run_until_provenance_known(&mut harness, "first provenance query");
        let stamp = crate::ui::utc_timestamp(first).expect("an epoch-second fixture renders");
        let expected = t_fmt(
            Language::En,
            Key::SettingsGeodataProvenanceUserOn,
            &[&stamp],
        );
        assert!(
            harness.query_by_label(&expected).is_some(),
            "the computed user-managed status must render with the newest mtime"
        );
        // Memoized per session: unchanged files must never re-hash.
        harness.run_steps(5);
        assert!(
            !harness.state().0.provenance.job.is_pending(),
            "unchanged geo data must not respawn the hash job"
        );
        // A file change (a configured-URL refresh while the core ran)
        // re-dates the status once the fingerprint stat window turns over.
        let later = first + Duration::from_secs(120);
        set_mtime(&core.join("geosite.dat"), later);
        harness.run();
        // No in-flight-window assert here: the worker can land within the
        // same run() drain, so the refreshed result below is the contract.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let up_to_date = matches!(
                &harness.state().0.provenance.result,
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
        let stamp = crate::ui::utc_timestamp(later).expect("an epoch-second fixture renders");
        let refreshed = t_fmt(
            Language::En,
            Key::SettingsGeodataProvenanceUserOn,
            &[&stamp],
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
        let mut harness = harness(UiTestRig::default(), GeodataSection::default());
        harness.run_steps(3);
        // No managed core: the no-core answer is adopted without a worker
        // and the section renders no provenance row (the URL fields stay
        // usable for pre-install configuration).
        assert!(
            matches!(
                harness.state().0.provenance.result,
                Some(GeoDataProvenance::NoCore)
            ),
            "an absent core directory must adopt the no-core answer"
        );
        assert!(
            !harness.state().0.provenance.job.is_pending(),
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
                &harness.state().0.provenance.result,
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
        let mut section = GeodataSection::default();
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        section.provenance.result = Some(GeoDataProvenance::UserManaged {
            updated: Some(time),
        });
        section.provenance.refresh_caption(Language::En);
        let stamp = crate::ui::utc_timestamp(time).expect("an epoch-second fixture renders");
        assert_eq!(
            section
                .provenance
                .caption
                .as_ref()
                .expect("caption after refresh")
                .text,
            t_fmt(
                Language::En,
                Key::SettingsGeodataProvenanceUserOn,
                &[&stamp]
            )
        );
        // Both files unreadable/missing → the no-time wording.
        section.provenance.result = Some(GeoDataProvenance::UserManaged { updated: None });
        section.provenance.refresh_caption(Language::En);
        assert_eq!(
            section
                .provenance
                .caption
                .as_ref()
                .expect("caption after refresh")
                .text,
            t(Language::En, Key::SettingsGeodataProvenanceUserUnknown)
        );
        // Memoized: a same-result refresh must not rebuild the caption.
        section.provenance.refresh_caption(Language::En);
        assert_eq!(
            section.provenance.caption.as_ref().expect("caption").result,
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

        let mut harness = harness(UiTestRig::default(), GeodataSection::default());
        harness.run();
        run_until_provenance_known(&mut harness, "release-managed query");
        assert!(
            matches!(
                harness.state().0.provenance.result,
                Some(GeoDataProvenance::ReleaseManaged)
            ),
            "a clone of the installed core must report release-managed"
        );

        // Drift one DAT, wait for the status to flip to user-managed.
        std::fs::write(core.join("geoip.dat"), b"drifted").expect("drift managed geoip");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let drifted = matches!(
                harness.state().0.provenance.result,
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
            harness.state().0.provenance.restore_job.is_pending(),
            "the Restore click must start the worker"
        );
        run_until_restore_lands(&mut harness, "restore success");
        assert!(
            matches!(
                &harness.state().0.provenance.restore_feedback,
                Some(GeoDataRestoreFeedback::Done)
            ),
            "a restore from the pin-verified pristine pair must succeed"
        );
        // The status flips back to release-managed once the re-hash lands.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let restored = matches!(
                harness.state().0.provenance.result,
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
}
