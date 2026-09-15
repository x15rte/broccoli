//! UI layer: screen enum, shared context, and per-screen modules.

pub mod about;
pub mod dashboard;
pub mod dns;
pub mod inbounds;
pub mod logs;
pub mod profile_preview;
pub(crate) mod request;
pub mod routing;
pub mod servers;
pub mod settings;
pub mod status;
pub mod topbar;
pub mod tun;
pub mod widgets;
pub mod wizard;

#[cfg(test)]
pub(crate) mod test_rig;

use crate::i18n::{Key, t, t_fmt};
use crate::metrics::{MetricsHandle, WorkCounter};
use crate::model::settings::{Language, Mode};
use crate::model::{ServerProfile, ServersFile, Settings};
use crate::probe_verdict::{dead_verdict_line, warn_summary};
use crate::rt::{
    CoreCmd, CorePhase, DownloadState, LatencyProbeResult, OperationKind, OutboundStatusView,
    StatsTick,
};
use crate::sys;
use crate::sys::selfupd::UpdateCheckState;
use egui::RichText;
use std::collections::VecDeque;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Servers,
    ProfilePreview,
    Routing,
    Dns,
    Inbounds,
    Tun,
    Logs,
    Settings,
    About,
}

impl Screen {
    pub const ALL: [Screen; 10] = [
        Screen::Dashboard,
        Screen::Servers,
        Screen::ProfilePreview,
        Screen::Routing,
        Screen::Dns,
        Screen::Inbounds,
        Screen::Tun,
        Screen::Logs,
        Screen::Settings,
        Screen::About,
    ];

    pub fn label(self, language: Language) -> &'static str {
        match self {
            Screen::Dashboard => t(language, Key::ScreenDashboard),
            Screen::Servers => t(language, Key::ScreenServers),
            Screen::ProfilePreview => t(language, Key::ScreenProfilePreview),
            Screen::Routing => t(language, Key::ScreenRouting),
            Screen::Dns => t(language, Key::ScreenDns),
            Screen::Inbounds => t(language, Key::ScreenInbounds),
            Screen::Tun => t(language, Key::ScreenTun),
            Screen::Logs => t(language, Key::ScreenLogs),
            Screen::Settings => t(language, Key::ScreenSettings),
            Screen::About => t(language, Key::ScreenAbout),
        }
    }
}

/// Single source of truth for lifecycle actions shown by the top bar,
/// Dashboard, and tray.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseAction {
    Connect,
    Disconnect,
    CancelRetry,
}

impl PhaseAction {
    pub fn for_phase(phase: &CorePhase) -> Self {
        match phase {
            CorePhase::Running | CorePhase::Starting => Self::Disconnect,
            CorePhase::Backoff { .. } => Self::CancelRetry,
            CorePhase::Stopped | CorePhase::NoConfig | CorePhase::Error(_) => Self::Connect,
        }
    }

    pub fn label(self, language: Language) -> &'static str {
        match self {
            Self::Connect => t(language, Key::PhaseConnect),
            Self::Disconnect => t(language, Key::PhaseDisconnect),
            Self::CancelRetry => t(language, Key::PhaseCancelRetry),
        }
    }
}

///
/// The runtime-lifecycle inputs (`phase`, `stats`, `observatory`,
/// `core_version`, `download`) are borrowed from the app's generation-gated
/// [`UiCtxSnapshot`], so a frame assembles this struct at
/// reference-copy cost through [`UiCtx::new`]; the snapshot itself is rebuilt
/// only when a drained event changes its inputs.
pub struct UiCtx<'a> {
    pub servers: &'a mut ServersFile,
    pub settings: &'a mut Settings,
    pub cmd: &'a tokio::sync::mpsc::UnboundedSender<CoreCmd>,
    pub phase: &'a CorePhase,
    /// Runtime-owned mutually-exclusive lifecycle/update transaction.
    pub operation: Option<OperationKind>,
    /// Persistent reason Connect is disabled. Screens must use this instead of
    /// deriving capability from `phase` or managed-core presence alone.
    pub connect_blocked_reason: &'a Option<String>,
    /// The shell's stored config-generation error for the current model
    /// revision — its generator text is excerpt-bounded by the generation
    /// boundary before any label or log can see it, and its raw-override
    /// validation failures are fixed catalog strings — or `None` when the
    /// last generation succeeded. Screens render this where they used to run
    /// the generator themselves: generating a candidate binds the ephemeral
    /// control-plane port, so it stays on the shell's boot and persist paths.
    pub config_error: &'a Option<String>,
    pub(crate) connect_requested: &'a mut bool,
    pub(crate) stop_requested: &'a mut bool,
    pub stats: &'a Option<StatsTick>,
    pub stats_history: &'a VecDeque<StatsTick>,
    pub observatory: &'a [OutboundStatusView],
    /// (from_core, line), newest last, capped by the app.
    pub logs: &'a VecDeque<(bool, String)>,
    /// Monotonic push count of the app's log ring: the Logs
    /// screen keys its memoized filtered view on this plus the ring length,
    /// so the identity changes exactly when the ring's content changes —
    /// even when empty lines rotate through a full ring.
    pub logs_generation: u64,
    pub core_version: &'a Option<String>,
    pub download: &'a DownloadState,
    /// Renderable state of the on-demand update check.
    pub update_check: &'a UpdateCheckState,
    pub is_elevated: bool,
    /// Outcome slot of the one single-flight latency probe: the shell parks
    /// the drained result here and the servers screen adopts it through its
    /// `ShellParked` request — the app-owned screen-feedback slot that
    /// replaced the request/response bus. A result landing while the user
    /// is elsewhere waits in the slot until the servers screen takes it;
    /// the single slot is exact because the probe is single-flight and the
    /// UI pending gate holds until the take.
    pub(crate) probe_feedback: &'a mut request::ParkedSlot<LatencyProbeResult>,
    pub(crate) dirty: &'a mut bool,
    /// UI-only edits (traffic unit, language, accent): persisted like
    /// `dirty` but never enter the config-apply gate — no revision bump, no
    /// "changes pending"/Apply-now (the running core's config is unaffected
    /// by display preferences).
    pub(crate) ui_dirty: &'a mut bool,
    /// Monotonic persistence-generation counter: bumped once per persist of
    /// the servers/settings model. Screens memoize per-frame work on
    /// `(config_revision, dirty)` so it re-runs only when the model changed
    /// (the dashboard's latency grid and the inbounds validation cache key
    /// on it).
    pub config_revision: u64,
    /// Always-on performance instrumentation:
    /// screens bump their work counters through this handle. Owned by the
    /// app; borrowed here at zero cost.
    pub metrics: &'a MetricsHandle,
    /// Monotonic per-input generations for screens' memoization keys
    /// (dashboard plot and latency-grid caches): `stats_generation` advances
    /// once per stats tick, `latency_generation` once per observatory tick
    /// and once per consumed latency-probe result, all bumped by the app's
    /// event drain.
    pub stats_generation: u64,
    pub latency_generation: u64,
}

/// Per-frame borrows and scalars every [`UiCtx::new`] construction site
/// supplies: model references, the frame-flag
/// locals, and the lifecycle scalars. Each frame site in the app shell
/// inlines its own parts literal (central screen dispatch, first-run
/// wizard, leave modal); the shared test rig inlines its own from its
/// fields. [`UiCtx::new`] is the only consumer.
pub(crate) struct UiCtxParts<'a> {
    pub(crate) servers: &'a mut ServersFile,
    pub(crate) settings: &'a mut Settings,
    pub(crate) cmd: &'a tokio::sync::mpsc::UnboundedSender<CoreCmd>,
    pub(crate) stats_history: &'a VecDeque<StatsTick>,
    pub(crate) logs: &'a VecDeque<(bool, String)>,
    /// Monotonic push count of the app's log ring: the Logs
    /// screen keys its memoized filtered view on `(len, logs_generation)`,
    /// so the identity changes exactly when the ring's content changes.
    pub(crate) logs_generation: u64,
    pub(crate) probe_feedback: &'a mut request::ParkedSlot<LatencyProbeResult>,
    pub(crate) metrics: &'a MetricsHandle,
    pub(crate) dirty: &'a mut bool,
    pub(crate) ui_dirty: &'a mut bool,
    pub(crate) connect_requested: &'a mut bool,
    pub(crate) stop_requested: &'a mut bool,
    pub(crate) connect_blocked_reason: &'a Option<String>,
    /// The shell's stored config-generation error (the same value the
    /// top-bar config chip renders), projected into [`UiCtx::config_error`].
    pub(crate) config_error: &'a Option<String>,
    pub(crate) operation: Option<OperationKind>,
    pub(crate) is_elevated: bool,
    pub(crate) config_revision: u64,
}

/// Which runtime presentation a [`UiCtx::new`] construction site wants: the
/// live generation-gated snapshot inputs, or the onboarding presentation
/// that blanks live runtime inputs regardless of snapshot state.
pub(crate) enum UiCtxView<'a> {
    /// Central frames and overlays surface the live snapshot.
    Live { snapshot: &'a UiCtxSnapshot },
    /// The first-run wizard never surfaces live runtime inputs: stats and
    /// observatory are blanked even if the snapshot holds stale values.
    Onboarding { snapshot: &'a UiCtxSnapshot },
}

/// Blanked stats for onboarding contexts: a `'static` resting value so the
/// wizard's context never borrows the snapshot's live stats.
static BLANK_STATS: Option<StatsTick> = None;

impl<'a> UiCtx<'a> {
    /// Single construction point for a frame's UI context:
    /// every app-shell frame site and the shared test rig build
    /// [`UiCtx`] here instead of repeating the field-by-field wiring, so
    /// adding a context input is a one-edit change and the constructor is
    /// the one place that states which inputs a frame must supply.
    ///
    /// Inputs arrive in two bundles. [`UiCtxParts`] carries the per-frame
    /// borrows and scalars a site already holds (model references, the
    /// frame-flag locals, lifecycle scalars). [`UiCtxView`] picks the
    /// runtime presentation: the live generation-gated snapshot inputs,
    /// or the onboarding presentation that blanks live
    /// inputs. Production hands the snapshot inputs over from its
    /// [`UiCtxSnapshot`], which the app rebuilds only when a drained event
    /// changed it. This constructor never rebuilds a snapshot — the rebuild
    /// decision is the app's single per-frame policy (see `BroccoliApp::ui`),
    /// inherited by every site by construction.
    ///
    /// Per-frame cost: every input is copied by reference — no allocation,
    /// no clone, no snapshot comparison.
    pub(crate) fn new(parts: UiCtxParts<'a>, view: UiCtxView<'a>) -> Self {
        let UiCtxParts {
            servers,
            settings,
            cmd,
            stats_history,
            logs,
            logs_generation,
            probe_feedback,
            metrics,
            dirty,
            ui_dirty,
            connect_requested,
            stop_requested,
            connect_blocked_reason,
            config_error,
            operation,
            is_elevated,
            config_revision,
        } = parts;
        let idle_observatory: &'a [OutboundStatusView] = &[];
        let (
            phase,
            stats,
            observatory,
            core_version,
            download,
            update_check,
            stats_generation,
            latency_generation,
        ) = match view {
            UiCtxView::Live { snapshot } => (
                &snapshot.phase,
                &snapshot.stats,
                &snapshot.observatory[..],
                &snapshot.core_version,
                &snapshot.download,
                &snapshot.update_check,
                snapshot.stats_generation,
                snapshot.latency_generation,
            ),
            UiCtxView::Onboarding { snapshot } => (
                &snapshot.phase,
                &BLANK_STATS,
                idle_observatory,
                &snapshot.core_version,
                &snapshot.download,
                &snapshot.update_check,
                snapshot.stats_generation,
                snapshot.latency_generation,
            ),
        };
        Self {
            servers,
            settings,
            cmd,
            stats_history,
            logs,
            logs_generation,
            probe_feedback,
            metrics,
            dirty,
            ui_dirty,
            connect_requested,
            stop_requested,
            operation,
            connect_blocked_reason,
            config_error,
            is_elevated,
            config_revision,
            phase,
            stats,
            observatory,
            core_version,
            download,
            update_check,
            stats_generation,
            latency_generation,
        }
    }

    pub fn mark_dirty(&mut self) {
        *self.dirty = true;
    }

    /// Persist a display-only preference (traffic unit, language, accent):
    /// saved to settings.json like any edit, but without entering the
    /// config-apply pipeline — no "changes pending" chip, no Apply now.
    pub fn mark_ui_dirty(&mut self) {
        *self.ui_dirty = true;
    }

    /// Bump one work counter through the app-owned metrics handle. Screens
    /// call this on real events (a rebuild, a parse, a search, a read, an
    /// enumeration) — never per frame.
    pub fn bump_work(&self, counter: WorkCounter) {
        self.metrics.bump_work(counter);
    }

    /// Request Connect through the shell so every screen shares persistence,
    /// recovery, listener, and runtime-operation gates.
    pub fn request_connect(&mut self) {
        *self.connect_requested = true;
    }

    /// Request Disconnect/Cancel through the shell so the runtime listener is
    /// stopped through the normal operation path.
    pub fn request_stop(&mut self) {
        *self.stop_requested = true;
    }

    /// Fire-and-forget command send. The control channel is closed only
    /// once the runtime thread has exited; a command dropped then is logged
    /// here, and the core-setup surface renders the closed channel next to
    /// the buttons it explains, so a user-initiated action can never
    /// vanish silently.
    pub fn send(&self, cmd: CoreCmd) {
        if self.cmd.send(cmd).is_err() {
            tracing::warn!("core command not sent: runtime control channel is closed");
        }
    }
    /// Launch an isolated one-shot probe over every server profile (probe
    /// scope "all"). No settings mutation or dirty marker is involved. The
    /// outcome is single-flight: the app parks it in the probe-feedback
    /// slot and the servers screen takes it — pairing is structural, no
    /// correlation id.
    pub fn request_latency_probe(&mut self) -> Result<(), String> {
        let profiles = self.servers.profiles.clone();
        if profiles.is_empty() {
            let lang = self.settings.language;
            return Err(t(lang, Key::LatencyRequiresProfile).to_string());
        }
        self.send_latency_probe(profiles)
    }

    /// Launch an isolated one-shot probe over one server profile (probe
    /// scope "one"). Any profiles the probed profile chains
    /// through (`proxySettings.tag` / `sockopt.dialerProxy`) ride along in
    /// the probe child so the referenced outbounds exist; the probed profile
    /// stays first and its status is the reported one. Unresolvable targets
    /// are left out — builtins resolve inside the child, anything else fails
    /// loudly at config generation, exactly like the all-profile probe.
    pub fn request_latency_probe_for(&mut self, profile: ServerProfile) -> Result<(), String> {
        let mut chain = vec![profile];
        let mut seen = std::collections::BTreeSet::new();
        seen.insert(chain[0].tag());
        let mut index = 0;
        while index < chain.len() {
            let target = chain[index].chain_target();
            if let Some(target) = target
                && seen.insert(target.to_string())
                && let Some(dep) = self
                    .servers
                    .profiles
                    .iter()
                    .find(|profile| profile.tag() == target)
            {
                chain.push(dep.clone());
            }
            index += 1;
        }
        self.send_latency_probe(chain)
    }

    /// Send one isolated one-shot probe over the given profile list.
    fn send_latency_probe(&mut self, profiles: Vec<ServerProfile>) -> Result<(), String> {
        let probe_url = self.settings.ping_test_probe_url().to_owned();
        let lang = self.settings.language;
        // While TUN mode is active, carry the TUN outbound
        // interface setting so the probe dials bypass the TUN; with TUN off
        // there is no capture to bypass and the probe stays unbound. The
        // TUN adapter's own name rides along so the resolution excludes it
        // (the shared derivation's wire default when the GUI name is
        // cleared).
        let tun_enabled = self.settings.mode == Mode::Tun;
        let tun_outbound_interface =
            tun_enabled.then(|| self.settings.tun.auto_outbounds_interface.clone());
        let tun_adapter_name =
            tun_enabled.then(|| sys::netif::tun_adapter_name(&self.settings.tun.name).to_owned());
        self.cmd
            .send(CoreCmd::ProbeLatency {
                profiles,
                probe_url,
                tun_outbound_interface,
                tun_adapter_name,
            })
            .map_err(|_| t(lang, Key::LatencyCoreUnavailable).to_string())
    }
}

/// Owned, generation-gated snapshot of the per-frame UI-context inputs:
/// rebuilt only when a drained runtime event changes
/// them — never per frame. [`UiCtx`] borrows from it at reference-copy
/// cost; the first-run wizard reuses the same snapshot instead of building
/// a second one.
pub(crate) struct UiCtxSnapshot {
    pub(crate) phase: CorePhase,
    pub(crate) stats: Option<StatsTick>,
    pub(crate) observatory: Vec<OutboundStatusView>,
    pub(crate) core_version: Option<String>,
    pub(crate) download: DownloadState,
    pub(crate) update_check: UpdateCheckState,
    pub(crate) stats_generation: u64,
    pub(crate) latency_generation: u64,
}

impl UiCtxSnapshot {
    /// True when `other` carries the same inputs as this snapshot. The app
    /// skips no-op rebuilds with this (e.g. the initial `State(Stopped)`
    /// drain, duplicate events), so the rebuild counter counts actual input
    /// changes. Field-wise because the payload types derive only `Clone`,
    /// not `PartialEq`.
    pub(crate) fn same_inputs(&self, other: &UiCtxSnapshot) -> bool {
        self.stats_generation == other.stats_generation
            && self.latency_generation == other.latency_generation
            && self.observatory == other.observatory
            && self.core_version == other.core_version
            && stats_tick_same(&self.stats, &other.stats)
            && phase_same(&self.phase, &other.phase)
            && download_same(&self.download, &other.download)
            && self.update_check == other.update_check
    }
}

fn stats_tick_same(a: &Option<StatsTick>, b: &Option<StatsTick>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.up == b.up
                && a.down == b.down
                && a.uptime_secs == b.uptime_secs
                && a.goroutines == b.goroutines
                && a.alloc_bytes == b.alloc_bytes
                && a.sys_bytes == b.sys_bytes
                && a.live_objects == b.live_objects
                && a.num_gc == b.num_gc
                && a.per_outbound == b.per_outbound
                && a.per_inbound == b.per_inbound
                && a.total_up == b.total_up
                && a.total_down == b.total_down
                && a.per_inbound_totals == b.per_inbound_totals
        }
        _ => false,
    }
}

fn phase_same(a: &CorePhase, b: &CorePhase) -> bool {
    match (a, b) {
        (CorePhase::Stopped, CorePhase::Stopped)
        | (CorePhase::NoConfig, CorePhase::NoConfig)
        | (CorePhase::Starting, CorePhase::Starting)
        | (CorePhase::Running, CorePhase::Running) => true,
        (CorePhase::Backoff { attempt: x }, CorePhase::Backoff { attempt: y }) => x == y,
        (CorePhase::Error(x), CorePhase::Error(y)) => x == y,
        _ => false,
    }
}

fn download_same(a: &DownloadState, b: &DownloadState) -> bool {
    match (a, b) {
        (DownloadState::Idle, DownloadState::Idle) => true,
        (
            DownloadState::Working {
                stage: x,
                done: xd,
                total: xt,
            },
            DownloadState::Working {
                stage: y,
                done: yd,
                total: yt,
            },
        ) => x == y && xd == yd && xt == yt,
        (DownloadState::Done(x), DownloadState::Done(y)) => x == y,
        (DownloadState::Failed(x), DownloadState::Failed(y)) => x == y,
        _ => false,
    }
}

/// Whether a core setup source is currently owned by the runtime.
pub(crate) fn core_setup_busy(ctx: &UiCtx<'_>) -> bool {
    matches!(&ctx.download, DownloadState::Working { .. }) || ctx.operation.is_some()
}

/// Result of one frame of the shared core-setup surface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CoreSetupOutcome {
    /// First-run "Continue" clicked once install and health check finished.
    pub continue_clicked: bool,
    /// First-run "Set up later" clicked.
    pub later_clicked: bool,
}

/// Render the one shared pinned-core setup surface.
///
/// Mirrors the Settings screen idiom: a state row in the top-bar "colored
/// dot + text" style, option rows as `label + control`, `weak().small()`
/// hint lines below their control, stock buttons, and `colored_label`
/// status lines.
///
/// `show_continue` is used only by the first-run adapter: it adds a
/// "Set up later" footer and a "Continue" button once install finished.
pub(crate) fn show_core_setup(
    ui: &mut egui::Ui,
    ctx: &mut UiCtx<'_>,
    show_continue: bool,
) -> CoreSetupOutcome {
    let version = sys::core_dl::pinned_release_version();
    let archive = sys::core_dl::pinned_release_archive();
    let url = sys::core_dl::pinned_release_url();

    let mut outcome = CoreSetupOutcome::default();
    let lang = ctx.settings.language;

    // Core state row, same idiom as the top bar: colored dot + state text.
    let colors = crate::ui::status::status_colors(ui.visuals().dark_mode);
    let (state_color, state_text, not_installed) = match &ctx.download {
        DownloadState::Working { .. } => (colors.warn, t(lang, Key::CoreSetupDownloading), false),
        DownloadState::Failed(_) => (colors.err, t(lang, Key::CoreSetupFailed), false),
        _ if ctx.core_version.is_some() => (colors.ok, t(lang, Key::CoreSetupInstalled), false),
        _ => (
            egui::Color32::GRAY,
            t(lang, Key::CoreSetupNotInstalled),
            true,
        ),
    };
    ui.horizontal(|ui| {
        ui.colored_label(state_color, "●");
        ui.label(RichText::new(t(lang, Key::CoreSetupXrayCore)).strong());
        ui.separator();
        ui.colored_label(state_color, state_text);
    });

    // First-run hint: the core is not bundled, it downloads on first use.
    if not_installed {
        ui.add_space(4.0);
        ui.label(
            RichText::new(t(lang, Key::CoreSetupFirstUseHint))
                .weak()
                .small(),
        );
    }

    // Pinned release option row, in the settings "label + control" style.
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(t(lang, Key::CoreSetupPinnedRelease));
        ui.hyperlink_to(t_fmt(lang, Key::CoreSetupVersionLink, &[&version]), url)
            .on_hover_text(t(lang, Key::CoreSetupOpenReleaseHint));
        ui.label(t_fmt(lang, Key::CoreSetupArchiveSep, &[&archive]));
    });
    // The URL that the copy action targets, with the button flush against it.
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        if ui.small_button(t(lang, Key::CoreSetupCopyLink)).clicked() {
            ui.ctx().copy_text(url.to_owned());
        }
        ui.add(
            egui::Label::new(RichText::new(url).weak().monospace().small())
                .wrap()
                .selectable(true),
        );
    });

    // Actions: stock buttons, like every other screen.
    let phase_allows_install = matches!(
        &ctx.phase,
        CorePhase::Stopped | CorePhase::NoConfig | CorePhase::Error(_)
    );
    let busy = core_setup_busy(ctx);
    let can_install = phase_allows_install && !busy;
    let disabled_reason = if !phase_allows_install {
        t(lang, Key::CoreSetupStopFirst)
    } else if busy {
        t(lang, Key::CoreSetupBusy)
    } else {
        ""
    };

    ui.add_space(10.0);
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                can_install,
                egui::Button::new(t(lang, Key::CoreSetupDownloadButton)),
            )
            .on_disabled_hover_text(disabled_reason)
            .clicked()
        {
            ctx.send(CoreCmd::UpdateCore);
        }
        if ui
            .add_enabled(
                can_install,
                egui::Button::new(t(lang, Key::CoreSetupImportZip)),
            )
            .on_disabled_hover_text(disabled_reason)
            .clicked()
            && let Some(path) = rfd::FileDialog::new()
                .add_filter(t(lang, Key::ShellXrayArchiveFilter), &["zip"])
                .pick_file()
        {
            ctx.send(CoreCmd::ImportCoreArchive(path));
        }
    });

    // A closed control channel means the runtime thread is gone: the
    // actions above — and the update check rendered just below this surface
    // in Settings — cannot reach it. [`UiCtx::send`] logs the dropped
    // command; this line is the on-screen half, in the same status-line
    // idiom as the core state row above.
    if ctx.cmd.is_closed() {
        ui.add_space(6.0);
        ui.colored_label(
            colors.err,
            RichText::new(t(lang, Key::RuntimeChannelClosed)).small(),
        );
    }

    // Hint under its control, settings style.
    ui.add_space(6.0);
    ui.add(egui::Label::new(RichText::new(t(lang, Key::CoreSetupHint)).weak().small()).wrap());

    // Live status: stock progress bar or colored status lines.
    match &ctx.download {
        DownloadState::Idle => {}
        DownloadState::Working { stage, done, total } => {
            ui.add_space(8.0);
            let stage_text = stage.text(lang);
            let bar =
                if *total > 0 {
                    egui::ProgressBar::new((*done as f32 / *total as f32).clamp(0.0, 1.0)).text(
                        t_fmt(lang, Key::CoreSetupProgress, &[&stage_text, &done, &total]),
                    )
                } else {
                    egui::ProgressBar::new(0.0).text(stage_text)
                };
            ui.add(bar);
        }
        DownloadState::Done(done_version) => {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.colored_label(
                    egui::Color32::LIGHT_GREEN,
                    t_fmt(lang, Key::CoreSetupInstalledVersion, &[&done_version]),
                );
                if ctx.operation.is_some() {
                    ui.add_space(8.0);
                    ui.spinner();
                    ui.weak(t(lang, Key::CoreSetupHealthCheck));
                }
                if show_continue {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(
                                !core_setup_busy(ctx),
                                egui::Button::new(t(lang, Key::CoreSetupContinue)),
                            )
                            .on_disabled_hover_text(t(lang, Key::CoreSetupContinueDisabled))
                            .clicked()
                        {
                            outcome.continue_clicked = true;
                        }
                    });
                }
            });
        }
        DownloadState::Failed(error) => {
            ui.add_space(8.0);
            ui.colored_label(
                crate::ui::status::status_colors_of(ui).err,
                t_fmt(lang, Key::CoreSetupFailedError, &[&error.text(lang)]),
            );
        }
    }

    // First-run footer.
    if show_continue {
        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);
        if ui
            .add_enabled(!busy, egui::Button::new(t(lang, Key::CoreSetupSetUpLater)))
            .on_disabled_hover_text(t(lang, Key::CoreSetupLaterDisabled))
            .clicked()
        {
            outcome.later_clicked = true;
        }
    }

    outcome
}

/// Severity of a latency-probe feedback message; the render site picks the
/// label color (ok/warn/err).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FeedbackLevel {
    Ok,
    Warn,
    Err,
}

/// Human-readable verdict for one consumed latency-probe result. A dead
/// verdict anywhere in the result makes the feedback a warn-colored
/// summary naming each dead server; all-alive results keep the historical
/// green wording.
pub(crate) fn format_latency_probe_feedback(
    language: Language,
    result: LatencyProbeResult,
    profiles: &[ServerProfile],
) -> (FeedbackLevel, String) {
    let requested = result.tags.len();
    match result.result {
        Ok(statuses) => {
            if statuses.iter().any(|status| !status.alive) {
                (
                    FeedbackLevel::Warn,
                    warn_summary(language, profiles, &statuses),
                )
            } else {
                let reported = statuses.len();
                let message = if reported == requested {
                    t_fmt(language, Key::LatencyFeedbackComplete, &[&reported])
                } else {
                    t_fmt(
                        language,
                        Key::LatencyFeedbackPartial,
                        &[&reported, &requested],
                    )
                };
                (FeedbackLevel::Ok, message)
            }
        }
        Err(error) => (
            FeedbackLevel::Err,
            // The feedback carries the headline plus the
            // diagnostics wall — the same text the log records — so
            // the label and the log cannot drift. A failure without a
            // captured tail (`full == headline`) degrades to the
            // headline-only text.
            t_fmt(
                language,
                Key::LatencyFeedbackFailed,
                &[&error.full(language)],
            ),
        ),
    }
}

/// Human-readable verdict for one consumed single-profile latency-probe
/// result (probe scope "one"): the profile's name — or the raw tag when the
/// profile vanished mid-probe — plus the outcome. A chained probe also
/// reports its chain dependencies' statuses; the requested profile's own
/// status is the verdict.
pub(crate) fn format_single_latency_probe_feedback(
    language: Language,
    result: LatencyProbeResult,
    profiles: &[ServerProfile],
) -> (FeedbackLevel, String) {
    let requested = result.tags.first();
    let profile = requested.and_then(|tag| profiles.iter().find(|profile| profile.tag() == *tag));
    let label = profile
        .map(|profile| profile.name.as_str())
        .unwrap_or(requested.map_or("?", String::as_str));
    match result.result {
        Ok(statuses) => {
            // A chained probe reports its dependencies' statuses too; only
            // the requested profile's status is the verdict.
            let status =
                requested.and_then(|tag| statuses.iter().find(|status| &status.tag == tag));
            match status {
                Some(status) if status.alive => (
                    FeedbackLevel::Ok,
                    t_fmt(
                        language,
                        Key::LatencyProbeOneResponded,
                        &[&label, &status.delay_ms],
                    ),
                ),
                Some(status) => {
                    // A dead row returned by a probe run that
                    // produced output carries the run's diagnostics tail;
                    // the verdict label appends the wall so the root cause
                    // is visible inline. Rows without a tail degrade to
                    // today's headline-only sentence.
                    let message = dead_verdict_line(
                        language,
                        label,
                        profile.and_then(ServerProfile::server_address).as_deref(),
                        status.last_error.as_deref(),
                    );
                    (
                        FeedbackLevel::Err,
                        crate::probe_verdict::with_diagnostics_wall(
                            language,
                            message,
                            status.diagnostics.as_deref().unwrap_or(""),
                        ),
                    )
                }
                None => (
                    FeedbackLevel::Err,
                    dead_verdict_line(language, label, None, None),
                ),
            }
        }
        Err(error) => (
            FeedbackLevel::Err,
            // Same as the all-scope formatter — the full failure
            // text (headline + diagnostics wall) rides the label.
            t_fmt(
                language,
                Key::LatencyProbeOneFailed,
                &[&label, &error.full(language)],
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FeedbackLevel, PhaseAction, format_latency_probe_feedback,
        format_single_latency_probe_feedback, show_core_setup,
    };
    use crate::diag::Diag;
    use crate::i18n::{Key, t, t_fmt};
    use crate::model::settings::Language;
    use crate::model::{OutboundModel, Protocol, ProtocolSettings, ServerProfile};
    use crate::rt::{CoreCmd, CorePhase, LatencyProbeResult, OutboundStatusView, ProbeFailure};
    use crate::ui::test_rig::UiTestRig;
    use egui_kittest::{Harness, kittest::Queryable as _};

    #[test]
    fn no_config_phase_offers_connect() {
        assert_eq!(
            PhaseAction::for_phase(&CorePhase::NoConfig),
            PhaseAction::Connect
        );
    }

    #[test]
    fn core_setup_not_installed_renders_first_use_hint() {
        let rig = UiTestRig::default();
        let harness = Harness::new_ui_state(
            |ui, rig: &mut UiTestRig| {
                let _ = show_core_setup(ui, &mut rig.ctx(), false);
            },
            rig,
        );

        assert!(
            harness
                .query_by_label(t(Language::En, Key::CoreSetupFirstUseHint))
                .is_some(),
            "not-installed state must hint that the core downloads on first use"
        );
    }

    #[test]
    fn core_setup_installed_state_omits_first_use_hint() {
        let rig = UiTestRig {
            core_version: Some("v1.8.24".to_string()),
            ..Default::default()
        };
        let harness = Harness::new_ui_state(
            |ui, rig: &mut UiTestRig| {
                let _ = show_core_setup(ui, &mut rig.ctx(), false);
            },
            rig,
        );

        assert!(
            harness
                .query_by_label(t(Language::En, Key::CoreSetupFirstUseHint))
                .is_none(),
            "installed state must not render the first-use hint"
        );
    }

    fn single_probe_result(
        tag: String,
        statuses: Result<Vec<OutboundStatusView>, ProbeFailure>,
    ) -> LatencyProbeResult {
        LatencyProbeResult {
            tags: vec![tag],
            result: statuses,
        }
    }

    #[test]
    fn latency_probe_sends_the_ping_test_probe_url() {
        let mut rig = UiTestRig::default();
        rig.settings.probe_url = "https://example.com/generate_204".into();
        rig.settings.routing.observatory.probe_url =
            "https://observatory.example/generate_204".into();
        let profile = ServerProfile::new("probe", OutboundModel::new(Protocol::Freedom));
        rig.ctx()
            .request_latency_probe_for(profile)
            .expect("probe request must be accepted");
        let command = rig._cmd_rx.try_recv().expect("one command must be queued");
        match command {
            CoreCmd::ProbeLatency { probe_url, .. } => {
                assert_eq!(probe_url, "https://example.com/generate_204")
            }
            _ => panic!("expected a ProbeLatency command"),
        }
    }

    #[test]
    fn latency_probe_falls_back_to_the_observatory_probe_url() {
        let mut rig = UiTestRig::default();
        rig.settings.routing.observatory.probe_url =
            "https://observatory.example/generate_204".into();
        let profile = ServerProfile::new("probe", OutboundModel::new(Protocol::Freedom));
        rig.ctx()
            .request_latency_probe_for(profile)
            .expect("probe request must be accepted");
        let command = rig._cmd_rx.try_recv().expect("one command must be queued");
        match command {
            CoreCmd::ProbeLatency { probe_url, .. } => {
                assert_eq!(probe_url, "https://observatory.example/generate_204")
            }
            _ => panic!("expected a ProbeLatency command"),
        }
    }

    #[test]
    fn single_latency_feedback_responded_uses_profile_name_and_ms() {
        let profile = ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom));
        let tag = profile.tag();
        let result = single_probe_result(
            tag.clone(),
            Ok(vec![OutboundStatusView {
                health_ping: None,
                tag,
                alive: true,
                delay_ms: 23,
                last_error: None,
                diagnostics: None,
            }]),
        );
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(message, "Server 'Tokyo edge' responded in 23 ms.");
        assert_eq!(
            level,
            FeedbackLevel::Ok,
            "a responding server is a success verdict"
        );
    }

    #[test]
    fn single_latency_feedback_dead_status_is_a_no_response() {
        let profile = ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom));
        let tag = profile.tag();
        let result = single_probe_result(
            tag.clone(),
            Ok(vec![OutboundStatusView {
                health_ping: None,
                tag: profile.tag(),
                alive: false,
                delay_ms: 0,
                last_error: None,
                diagnostics: None,
            }]),
        );
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(message, "Server 'Tokyo edge' did not respond.");
        assert_eq!(
            level,
            FeedbackLevel::Err,
            "a dead server is not a success verdict"
        );
    }

    #[test]
    fn single_latency_feedback_zero_statuses_is_a_no_response() {
        let profile = ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom));
        let result = single_probe_result(profile.tag(), Ok(vec![]));
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(message, "Server 'Tokyo edge' did not respond.");
        assert_eq!(level, FeedbackLevel::Err);
    }

    #[test]
    fn single_latency_feedback_failure_carries_profile_name_and_error() {
        let profile = ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom));
        let result = single_probe_result(
            profile.tag(),
            Err(ProbeFailure::plain(Diag::new(Key::ProbeNoProfiles))),
        );
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(
            message,
            t_fmt(
                Language::En,
                Key::LatencyProbeOneFailed,
                &[&"Tokyo edge", &t(Language::En, Key::ProbeNoProfiles)],
            )
        );
        assert_eq!(level, FeedbackLevel::Err);
    }

    #[test]
    fn single_latency_feedback_falls_back_to_tag_when_profile_vanished() {
        // The profile can be deleted while the probe child runs; the verdict
        // must then name the raw tag instead of a missing profile.
        let profile = ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom));
        let tag = profile.tag();
        let result = single_probe_result(
            tag.clone(),
            Ok(vec![OutboundStatusView {
                health_ping: None,
                tag: tag.clone(),
                alive: true,
                delay_ms: 23,
                last_error: None,
                diagnostics: None,
            }]),
        );
        let (level, message) = format_single_latency_probe_feedback(Language::En, result, &[]);
        assert_eq!(message, format!("Server '{tag}' responded in 23 ms."));
        assert_eq!(level, FeedbackLevel::Ok);
    }

    #[test]
    fn single_latency_feedback_prefers_the_profile_matching_the_tag() {
        let profiles = vec![
            ServerProfile::new("First", OutboundModel::new(Protocol::Freedom)),
            ServerProfile::new("Second", OutboundModel::new(Protocol::Freedom)),
        ];
        let tag = profiles[1].tag();
        let result = single_probe_result(
            tag.clone(),
            Ok(vec![OutboundStatusView {
                health_ping: None,
                tag,
                alive: true,
                delay_ms: 42,
                last_error: None,
                diagnostics: None,
            }]),
        );
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &profiles);
        assert_eq!(message, "Server 'Second' responded in 42 ms.");
        assert_eq!(level, FeedbackLevel::Ok);
    }

    #[test]
    fn single_latency_feedback_picks_the_requested_status_among_chain_deps() {
        // A chained probe reports the chain dependencies' statuses too; the
        // verdict must come from the requested profile's own status.
        let profile = ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom));
        let dep = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        let tag = profile.tag();
        let result = single_probe_result(
            tag.clone(),
            Ok(vec![
                OutboundStatusView {
                    health_ping: None,
                    tag: dep.tag(),
                    alive: true,
                    delay_ms: 5,
                    last_error: None,
                    diagnostics: None,
                },
                OutboundStatusView {
                    health_ping: None,
                    tag: tag.clone(),
                    alive: true,
                    delay_ms: 23,
                    last_error: None,
                    diagnostics: None,
                },
            ]),
        );
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(message, "Server 'Tokyo edge' responded in 23 ms.");
        assert_eq!(level, FeedbackLevel::Ok);
    }

    #[test]
    fn single_latency_feedback_dead_requested_status_wins_over_alive_chain_deps() {
        let profile = ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom));
        let dep = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        let tag = profile.tag();
        let result = single_probe_result(
            tag.clone(),
            Ok(vec![
                OutboundStatusView {
                    health_ping: None,
                    tag: dep.tag(),
                    alive: true,
                    delay_ms: 5,
                    last_error: None,
                    diagnostics: None,
                },
                OutboundStatusView {
                    health_ping: None,
                    tag: tag.clone(),
                    alive: false,
                    delay_ms: 0,
                    last_error: None,
                    diagnostics: None,
                },
            ]),
        );
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(message, "Server 'Tokyo edge' did not respond.");
        assert_eq!(level, FeedbackLevel::Err);
    }
    fn vless_profile(name: &str, address: &str, port: u16) -> ServerProfile {
        let mut profile = ServerProfile::new(name, OutboundModel::new(Protocol::Vless));
        let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
            unreachable!("Vless is the default protocol");
        };
        settings.address = address.into();
        settings.port = port;
        profile
    }

    #[test]
    fn single_latency_feedback_dead_status_reports_reason_and_address() {
        let profile = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let tag = profile.tag();
        let result = single_probe_result(
            tag.clone(),
            Ok(vec![OutboundStatusView {
                health_ping: None,
                tag,
                alive: false,
                delay_ms: 0,
                last_error: Some("connection refused".into()),
                diagnostics: None,
            }]),
        );
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(
            message,
            "Server 'Tokyo edge' (1.2.3.4:443) did not respond: connection refused."
        );
        assert_eq!(level, FeedbackLevel::Err);
    }

    #[test]
    fn single_latency_feedback_dead_status_omits_reason_when_empty() {
        let profile = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let tag = profile.tag();
        let result = single_probe_result(
            tag.clone(),
            Ok(vec![OutboundStatusView {
                health_ping: None,
                tag,
                alive: false,
                delay_ms: 0,
                last_error: None,
                diagnostics: None,
            }]),
        );
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(
            message,
            "Server 'Tokyo edge' (1.2.3.4:443) did not respond."
        );
        assert_eq!(level, FeedbackLevel::Err);
    }

    #[test]
    fn single_latency_feedback_dead_status_omits_address_when_protocol_has_none() {
        // Freedom carries no server endpoint; the verdict degrades to
        // name + reason only.
        let profile = ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom));
        let tag = profile.tag();
        let result = single_probe_result(
            tag.clone(),
            Ok(vec![OutboundStatusView {
                health_ping: None,
                tag,
                alive: false,
                delay_ms: 0,
                last_error: Some("connection refused".into()),
                diagnostics: None,
            }]),
        );
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(
            message,
            "Server 'Tokyo edge' did not respond: connection refused."
        );
        assert_eq!(level, FeedbackLevel::Err);
    }

    #[test]
    fn single_latency_feedback_dead_status_bare_when_no_reason_or_address() {
        let profile = ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom));
        let tag = profile.tag();
        let result = single_probe_result(
            tag.clone(),
            Ok(vec![OutboundStatusView {
                health_ping: None,
                tag,
                alive: false,
                delay_ms: 0,
                last_error: None,
                diagnostics: None,
            }]),
        );
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(message, "Server 'Tokyo edge' did not respond.");
        assert_eq!(level, FeedbackLevel::Err);
    }

    #[test]
    fn single_latency_feedback_dead_status_appends_the_diagnostics_wall() {
        // The row carries the run's captured diagnostics tail;
        // the dead-verdict label must append the wall under the shared
        // header so the root cause is visible inline.
        let profile = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let tag = profile.tag();
        let result = single_probe_result(
            tag.clone(),
            Ok(vec![OutboundStatusView {
                health_ping: None,
                tag,
                alive: false,
                delay_ms: 0,
                last_error: Some("connection refused".into()),
                diagnostics: Some("[stderr] rejected: unknown SNI".into()),
            }]),
        );
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(
            message,
            format!(
                "Server 'Tokyo edge' (1.2.3.4:443) did not respond: connection refused.\n{}\n\
                 [stderr] rejected: unknown SNI",
                t(Language::En, Key::ProbeDiagnosticsWall)
            )
        );
        assert_eq!(level, FeedbackLevel::Err);
    }

    #[test]
    fn single_latency_feedback_alive_status_ignores_row_diagnostics() {
        // Alive rows must stay byte-identical even when the run produced a
        // tail: the wall only ever rides dead verdicts.
        let profile = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let tag = profile.tag();
        let result = single_probe_result(
            tag.clone(),
            Ok(vec![OutboundStatusView {
                health_ping: None,
                tag,
                alive: true,
                delay_ms: 23,
                last_error: None,
                diagnostics: Some("[stderr] irrelevant".into()),
            }]),
        );
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(message, "Server 'Tokyo edge' responded in 23 ms.");
        assert_eq!(level, FeedbackLevel::Ok);
    }

    #[test]
    fn single_latency_feedback_failure_with_wall_carries_the_full_text() {
        let profile = ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom));
        let failure = ProbeFailure {
            headline: Diag::new(Key::ProbeExitStatus).arg(1),
            tail: "[stderr] boom".into(),
        };
        let expected = failure.full(Language::En);
        assert!(
            expected.ends_with(&format!(
                "\n{}\n[stderr] boom",
                t(Language::En, Key::ProbeDiagnosticsWall)
            )),
            "premise: the captured tail rides the wall, got: {expected}"
        );
        let result = single_probe_result(profile.tag(), Err(failure));
        let (level, message) =
            format_single_latency_probe_feedback(Language::En, result, &[profile]);
        assert_eq!(
            message,
            t_fmt(
                Language::En,
                Key::LatencyProbeOneFailed,
                &[&"Tokyo edge", &expected],
            )
        );
        assert_eq!(level, FeedbackLevel::Err);
    }

    fn probe_all_result(
        tags: Vec<String>,
        statuses: Result<Vec<OutboundStatusView>, ProbeFailure>,
    ) -> LatencyProbeResult {
        LatencyProbeResult {
            tags,
            result: statuses,
        }
    }

    #[test]
    fn probe_all_feedback_partial_with_dead_rows_is_warn_summary() {
        let tokyo = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let osaka = vless_profile("Osaka", "10.0.0.2", 443);
        let result = probe_all_result(
            vec![tokyo.tag(), osaka.tag()],
            Ok(vec![
                OutboundStatusView {
                    health_ping: None,
                    tag: tokyo.tag(),
                    alive: true,
                    delay_ms: 10,
                    last_error: None,
                    diagnostics: None,
                },
                OutboundStatusView {
                    health_ping: None,
                    tag: osaka.tag(),
                    alive: false,
                    delay_ms: 0,
                    last_error: Some("connection refused".into()),
                    diagnostics: None,
                },
            ]),
        );
        let (level, message) = format_latency_probe_feedback(Language::En, result, &[tokyo, osaka]);
        assert_eq!(
            message,
            "1 of 2 outbounds responded.\n\
             Server 'Osaka' (10.0.0.2:443) did not respond: connection refused."
        );
        assert_eq!(level, FeedbackLevel::Warn);
    }

    #[test]
    fn probe_all_feedback_complete_rows_with_a_dead_verdict_is_warn() {
        // Every requested row arrived but one server is dead: the feedback
        // must not report green "complete" while a dead verdict stays silent.
        let tokyo = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let osaka = vless_profile("Osaka", "10.0.0.2", 443);
        let result = probe_all_result(
            vec![tokyo.tag(), osaka.tag()],
            Ok(vec![
                OutboundStatusView {
                    health_ping: None,
                    tag: tokyo.tag(),
                    alive: false,
                    delay_ms: 0,
                    last_error: Some("refused".into()),
                    diagnostics: None,
                },
                OutboundStatusView {
                    health_ping: None,
                    tag: osaka.tag(),
                    alive: true,
                    delay_ms: 20,
                    last_error: None,
                    diagnostics: None,
                },
            ]),
        );
        let (level, message) = format_latency_probe_feedback(Language::En, result, &[tokyo, osaka]);
        assert_eq!(
            message,
            "1 of 2 outbounds responded.\n\
             Server 'Tokyo edge' (1.2.3.4:443) did not respond: refused."
        );
        assert_eq!(level, FeedbackLevel::Warn);
    }

    #[test]
    fn probe_all_feedback_partial_all_alive_stays_ok() {
        let result = probe_all_result(
            vec!["srv-a".into(), "srv-b".into()],
            Ok(vec![OutboundStatusView {
                health_ping: None,
                tag: "srv-a".into(),
                alive: true,
                delay_ms: 10,
                last_error: None,
                diagnostics: None,
            }]),
        );
        let (level, message) = format_latency_probe_feedback(Language::En, result, &[]);
        assert_eq!(
            message,
            "Latency test complete: received 1 of 2 requested outbound status(es)."
        );
        assert_eq!(level, FeedbackLevel::Ok);
    }

    #[test]
    fn probe_all_feedback_failure_is_err_with_headline_and_wall() {
        // The whole-probe failure feedback
        // carries the headline plus the diagnostics wall — the same
        // text the log records.
        let failure = ProbeFailure {
            headline: Diag::new(Key::ProbeExitStatus).arg(1),
            tail: "[stderr] boom".into(),
        };
        let expected = failure.full(Language::En);
        let result = probe_all_result(vec!["srv-a".into()], Err(failure));
        let (level, message) = format_latency_probe_feedback(Language::En, result, &[]);
        assert_eq!(level, FeedbackLevel::Err);
        assert_eq!(
            message,
            t_fmt(Language::En, Key::LatencyFeedbackFailed, &[&expected])
        );
    }

    #[test]
    fn probe_all_feedback_failure_without_tail_is_headline_only() {
        // A failure without captured child output (full == headline) must
        // degrade to the headline-only label text.
        let failure = ProbeFailure::plain(Diag::new(Key::ProbeConfigRejected).arg("x"));
        let expected = failure.headline.text(Language::En);
        let result = probe_all_result(vec!["srv-a".into()], Err(failure));
        let (level, message) = format_latency_probe_feedback(Language::En, result, &[]);
        assert_eq!(level, FeedbackLevel::Err);
        assert_eq!(
            message,
            t_fmt(Language::En, Key::LatencyFeedbackFailed, &[&expected])
        );
        assert!(
            !message.contains(t(Language::En, Key::ProbeDiagnosticsWall)),
            "a failure without a tail must not fabricate the wall"
        );
    }

    fn chained_profile(target: Option<String>) -> ServerProfile {
        let mut profile = ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom));
        profile.outbound.proxy_tag = target;
        profile
    }

    #[test]
    fn request_latency_probe_for_includes_chain_dependencies() {
        let mut rig = UiTestRig::default();
        let dep = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        let main = chained_profile(Some(dep.tag()));
        rig.servers.profiles.push(main.clone());
        rig.servers.profiles.push(dep.clone());
        rig.ctx()
            .request_latency_probe_for(main.clone())
            .expect("probe request");
        let cmd = rig._cmd_rx.try_recv().expect("probe command");
        if let CoreCmd::ProbeLatency { profiles, .. } = cmd {
            assert_eq!(profiles.len(), 2, "the chain dependency must ride along");
            assert_eq!(
                profiles[0].tag(),
                main.tag(),
                "the probed profile must stay first"
            );
            assert_eq!(profiles[1].tag(), dep.tag());
        } else {
            panic!("expected ProbeLatency, got a different command");
        }
    }

    #[test]
    fn request_latency_probe_for_includes_transitive_chain_dependencies() {
        // Tokyo → Osaka → Nagoya: the probe child must contain the whole chain.
        let mut rig = UiTestRig::default();
        let leaf = ServerProfile::new("Nagoya", OutboundModel::new(Protocol::Freedom));
        let mut middle = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        middle.outbound.proxy_tag = Some(leaf.tag());
        let main = chained_profile(Some(middle.tag()));
        rig.servers.profiles.push(main.clone());
        rig.servers.profiles.push(middle.clone());
        rig.servers.profiles.push(leaf.clone());
        rig.ctx()
            .request_latency_probe_for(main.clone())
            .expect("probe request");
        let cmd = rig._cmd_rx.try_recv().expect("probe command");
        if let CoreCmd::ProbeLatency { profiles, .. } = cmd {
            let tags: Vec<String> = profiles.iter().map(ServerProfile::tag).collect();
            assert_eq!(tags, vec![main.tag(), middle.tag(), leaf.tag()]);
        } else {
            panic!("expected ProbeLatency, got a different command");
        }
    }

    #[test]
    fn request_latency_probe_for_leaves_builtin_and_missing_targets_out() {
        let mut rig = UiTestRig::default();
        let via_builtin = chained_profile(Some("direct".into()));
        let via_missing = chained_profile(Some("srv-deadbeef".into()));
        rig.servers.profiles.push(via_builtin.clone());
        rig.servers.profiles.push(via_missing.clone());
        rig.ctx()
            .request_latency_probe_for(via_builtin)
            .expect("probe request");
        let cmd = rig._cmd_rx.try_recv().expect("probe command");
        if let CoreCmd::ProbeLatency { profiles, .. } = cmd {
            assert_eq!(profiles.len(), 1, "builtin targets are not profiles");
        } else {
            panic!("expected ProbeLatency, got a different command");
        }
        rig.ctx()
            .request_latency_probe_for(via_missing)
            .expect("probe request");
        let cmd = rig._cmd_rx.try_recv().expect("probe command");
        if let CoreCmd::ProbeLatency { profiles, .. } = cmd {
            assert_eq!(
                profiles.len(),
                1,
                "an unresolvable target fails loudly at config generation, not here"
            );
        } else {
            panic!("expected ProbeLatency, got a different command");
        }
    }

    #[test]
    fn request_latency_probe_for_terminates_on_a_chain_cycle() {
        let mut rig = UiTestRig::default();
        let b = ServerProfile::new("B", OutboundModel::new(Protocol::Freedom));
        let a = chained_profile(Some(b.tag()));
        let mut b = b;
        b.outbound.proxy_tag = Some(a.tag());
        rig.servers.profiles.push(a.clone());
        rig.servers.profiles.push(b.clone());
        rig.ctx()
            .request_latency_probe_for(a)
            .expect("probe request");
        let cmd = rig._cmd_rx.try_recv().expect("probe command");
        if let CoreCmd::ProbeLatency { profiles, .. } = cmd {
            assert_eq!(profiles.len(), 2, "the expansion must terminate on a cycle");
        } else {
            panic!("expected ProbeLatency, got a different command");
        }
    }

    #[test]
    fn request_latency_probe_for_sends_exactly_one_profile() {
        let mut rig = UiTestRig::default();
        let profile = ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(profile.clone());
        rig.ctx()
            .request_latency_probe_for(profile.clone())
            .expect("single-profile probe request");
        let cmd = rig._cmd_rx.try_recv().expect("probe request must be sent");
        if let CoreCmd::ProbeLatency { profiles, .. } = cmd {
            assert_eq!(
                profiles.len(),
                1,
                "single scope must send exactly one profile"
            );
            assert_eq!(profiles[0].tag(), profile.tag());
        } else {
            panic!("expected ProbeLatency, got a different command");
        }
    }

    #[test]
    fn request_latency_probe_sends_all_profiles() {
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(ServerProfile::new(
            "First",
            OutboundModel::new(Protocol::Freedom),
        ));
        rig.servers.profiles.push(ServerProfile::new(
            "Second",
            OutboundModel::new(Protocol::Freedom),
        ));
        rig.ctx()
            .request_latency_probe()
            .expect("all-profile probe request");
        let cmd = rig._cmd_rx.try_recv().expect("probe request must be sent");
        if let CoreCmd::ProbeLatency { profiles, .. } = cmd {
            assert_eq!(profiles.len(), 2, "all scope must send every profile");
        } else {
            panic!("expected ProbeLatency, got a different command");
        }
    }
}
