//! UI layer: screen enum, shared context, and per-screen modules.

pub mod about;
pub mod dashboard;
pub mod dns;
pub(crate) mod gate;
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
use crate::model::settings::Language;
use crate::model::{ServerProfile, ServersFile, Settings};
use crate::probe_verdict::{dead_verdict_line, warn_summary};
use crate::rt::{
    AppMessage, CoreCmd, CorePhase, CoreTransport, DownloadState, JobKind, LatencyProbeResult,
    OutboundStatusView, StatsTick,
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
            CorePhase::Stopped | CorePhase::Error(_) => Self::Connect,
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
    /// The transport the live phase owns: `Some` while a launch is starting
    /// or running (the backend it manages), `None` in every other phase. The
    /// runtime publishes it with the phase itself, so a screen asking "is the
    /// TUN active" reads one fact instead of deriving it from the mode
    /// setting and the phase together.
    pub transport: Option<CoreTransport>,
    /// The busy window: the runtime-owned mutually-exclusive
    /// lifecycle/update transaction. Screens gate their controls on this
    /// value instead of deriving the window from their own inputs.
    pub(crate) busy: gate::BusyWindow,
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
    pub(crate) verify_core_requested: &'a mut bool,
    pub(crate) open_core_folder_requested: &'a mut bool,
    pub(crate) open_core_setup_requested: &'a mut bool,
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
    /// The installed tree's own version and its last verification failure,
    /// for the core setup surface.
    pub(crate) core_setup: &'a CoreSetupState,
    /// The terminal message the content area renders, and the compact chip
    /// the status zone carries while one stands.
    pub(crate) terminal_error: &'a Option<TerminalErrorView>,
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
    /// The model's edit generation: bumped by every mutation hook
    /// ([`UiCtx::mark_dirty`] and [`UiCtx::mark_ui_dirty`]), so a screen's
    /// per-frame cache keyed on it re-derives in the frame after any edit —
    /// including edits inside the persist throttle window, which the
    /// persist-time [`UiCtx::config_revision`] cannot cover.
    pub(crate) model_generation: &'a mut u64,
    /// Monotonic persistence-generation counter: bumped once per persist of
    /// the servers/settings model. It names *which persisted configuration* a
    /// value belongs to (an apply verdict carries it back), never "the UI
    /// should re-derive": screens memoize on [`UiCtx::model_generation`].
    pub config_revision: u64,
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
    pub(crate) dirty: &'a mut bool,
    pub(crate) ui_dirty: &'a mut bool,
    pub(crate) model_generation: &'a mut u64,
    pub(crate) connect_requested: &'a mut bool,
    pub(crate) stop_requested: &'a mut bool,
    pub(crate) connect_blocked_reason: &'a Option<String>,
    /// The shell's stored config-generation error (the same value the
    /// top-bar config chip renders), projected into [`UiCtx::config_error`].
    pub(crate) config_error: &'a Option<String>,
    pub(crate) verify_core_requested: &'a mut bool,
    pub(crate) open_core_folder_requested: &'a mut bool,
    pub(crate) open_core_setup_requested: &'a mut bool,
    /// The raw window the shell drained from the runtime's operation
    /// bookends: [`UiCtx::new`] derives [`UiCtx::busy`] from it once per
    /// frame, and screens read the window through that value.
    pub(crate) operation: Option<JobKind>,
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
            dirty,
            ui_dirty,
            model_generation,
            connect_requested,
            stop_requested,
            verify_core_requested,
            open_core_folder_requested,
            open_core_setup_requested,
            connect_blocked_reason,
            config_error,
            operation,
            is_elevated,
            config_revision,
        } = parts;
        let idle_observatory: &'a [OutboundStatusView] = &[];
        let (
            phase,
            transport,
            stats,
            observatory,
            core_version,
            core_setup,
            terminal_error,
            download,
            update_check,
            stats_generation,
            latency_generation,
        ) = match view {
            UiCtxView::Live { snapshot } => (
                &snapshot.phase,
                snapshot.transport,
                &snapshot.stats,
                &snapshot.observatory[..],
                &snapshot.core_version,
                &snapshot.core_setup,
                &snapshot.terminal_error,
                &snapshot.download,
                &snapshot.update_check,
                snapshot.stats_generation,
                snapshot.latency_generation,
            ),
            UiCtxView::Onboarding { snapshot } => (
                &snapshot.phase,
                snapshot.transport,
                &BLANK_STATS,
                idle_observatory,
                &snapshot.core_version,
                &snapshot.core_setup,
                &snapshot.terminal_error,
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
            phase,
            transport,
            stats_history,
            logs,
            logs_generation,
            probe_feedback,
            dirty,
            ui_dirty,
            model_generation,
            connect_requested,
            stop_requested,
            verify_core_requested,
            open_core_folder_requested,
            open_core_setup_requested,
            busy: gate::BusyWindow::from_operation(operation),
            connect_blocked_reason,
            config_error,
            is_elevated,
            config_revision,
            stats,
            observatory,
            core_version,
            core_setup,
            terminal_error,
            download,
            update_check,
            stats_generation,
            latency_generation,
        }
    }

    /// Record a model edit: the persist request for the config pipeline, and
    /// the generation bump every screen's cache keys on. One hook, so no
    /// mutation site can change the model without invalidating the caches
    /// derived from it.
    pub fn mark_dirty(&mut self) {
        *self.dirty = true;
        self.bump_model_generation();
    }

    /// Persist a display-only preference (traffic unit, language, accent):
    /// saved to settings.json like any edit, but without entering the
    /// config-apply pipeline — no "changes pending" chip, no Apply now.
    pub fn mark_ui_dirty(&mut self) {
        *self.ui_dirty = true;
        self.bump_model_generation();
    }

    fn bump_model_generation(&mut self) {
        *self.model_generation = self.model_generation.wrapping_add(1);
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

    /// Request a fresh pinned-payload verification of the installed core (the
    /// core setup surface's Verify action). The shell runs the pass and
    /// records the verdict; re-verification never touches the core itself.
    pub fn request_core_verify(&mut self) {
        *self.verify_core_requested = true;
    }

    /// Open the managed core directory in the shell's file browser.
    pub fn request_open_core_folder(&mut self) {
        *self.open_core_folder_requested = true;
    }

    /// Open the Settings screen, where the core setup surface stays mounted
    /// in every core state.
    pub fn request_open_core_setup(&mut self) {
        *self.open_core_setup_requested = true;
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
    /// through (`sockopt.dialerProxy`) ride along in
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
        // The probe carries the TUN outbound interface setting and the TUN
        // adapter's own name so its dials can bypass the capture and its
        // resolution exclude the adapter. Whether either is *used* is the
        // runtime's decision — its own backend's transport ownership — so the
        // request does not re-derive it from the mode setting: one decision,
        // taken where the live backend is known.
        let tun_outbound_interface = Some(self.settings.tun.auto_outbounds_interface.clone());
        let tun_adapter_name =
            Some(sys::netif::tun_adapter_name(&self.settings.tun.name).to_owned());
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
    pub(crate) transport: Option<CoreTransport>,
    pub(crate) stats: Option<StatsTick>,
    pub(crate) observatory: Vec<OutboundStatusView>,
    pub(crate) core_version: Option<String>,
    /// The installed tree's own version and its last verification failure.
    pub(crate) core_setup: CoreSetupState,
    /// The terminal message the content area renders (the failure's keyed
    /// headline plus the captured core output behind it).
    pub(crate) terminal_error: Option<TerminalErrorView>,
    pub(crate) download: DownloadState,
    pub(crate) update_check: UpdateCheckState,
    pub(crate) stats_generation: u64,
    pub(crate) latency_generation: u64,
}

impl UiCtxSnapshot {
    /// True when `other` carries the same inputs as this snapshot. The app
    /// skips no-op rebuilds with this (e.g. the initial `State(Stopped)`
    /// drain, duplicate events), so the snapshot is replaced only when an
    /// input actually changed. Every compared type publishes its own
    /// equality rule, so "did this input change" has one definition per type
    /// and no copy here to drift from it.
    pub(crate) fn same_inputs(&self, other: &UiCtxSnapshot) -> bool {
        self.stats_generation == other.stats_generation
            && self.latency_generation == other.latency_generation
            && self.observatory == other.observatory
            && self.core_version == other.core_version
            && self.core_setup == other.core_setup
            && self.terminal_error == other.terminal_error
            && self.stats == other.stats
            && self.phase == other.phase
            && self.download == other.download
            && self.update_check == other.update_check
    }
}

/// Whether a core setup source is currently owned by the runtime.
pub(crate) fn core_setup_busy(ctx: &UiCtx<'_>) -> bool {
    matches!(&ctx.download, DownloadState::Working { .. }) || ctx.busy.is_held()
}

/// The managed core's setup state as the core setup surface renders it.
///
/// The verified version stays on [`UiCtx::core_version`] (the top-bar caption
/// and the About screen read it); this bundle carries the two facts only the
/// setup surface needs: the version the installed tree's own release metadata
/// names — set even when the tree does not match the compiled pins, so a stale
/// install can name both versions — and the verification failure for a tree
/// that did not verify.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct CoreSetupState {
    /// The version the installed tree's release metadata names, even when the
    /// tree does not match the compiled pins.
    pub(crate) installed_version: Option<String>,
    /// The verification failure for a present tree, keyed so it renders in
    /// the active language at the label site.
    pub(crate) verification_error: Option<AppMessage>,
}

/// The terminal message the content area renders: the already-rendered
/// message text and the captured core output behind it. The shell owns the
/// message's lifetime (the phase it describes moves on, or an action
/// succeeds) and renders the keyed message once per language change, so the
/// block and the status chip only borrow these strings — no per-frame
/// formatting on either path.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct TerminalErrorView {
    /// The failure's message text, rendered when the failure was recorded.
    pub(crate) text: String,
    /// Captured core output (empty for an app-authored failure).
    pub(crate) output: String,
}

/// Which mount renders the shared core-setup surface. The component is one,
/// mounted twice: the startup dialog adds the first-run footer, and the
/// Settings section carries the standing explanation of what the state, the
/// install, and the failure attribution mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoreSetupMount {
    /// The first-run dialog: "Set up later" and a "Continue" once the install
    /// finished.
    Dialog,
    /// The permanent Settings section.
    Settings,
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
/// Both mounts render the same facts in every core state: the installed and
/// the required version, the verification state with the failure's own
/// reason, both install methods, and Verify / Open core folder.
///
/// [`CoreSetupMount::Dialog`] adds the first-run footer (a "Set up later"
/// button and a "Continue" button once install finished);
/// [`CoreSetupMount::Settings`] adds the note that explains the state, the
/// install flow, and the failure attribution in place.
pub(crate) fn show_core_setup(
    ui: &mut egui::Ui,
    ctx: &mut UiCtx<'_>,
    mount: CoreSetupMount,
) -> CoreSetupOutcome {
    let show_continue = matches!(mount, CoreSetupMount::Dialog);
    let version = sys::core_dl::pinned_release_version();
    // The pin in the release metadata's spelling (no leading `v`), so the two
    // versions read as one pair.
    let required = sys::core_dl::pinned_core_version();
    let archive = sys::core_dl::pinned_release_archive();
    let url = sys::core_dl::pinned_release_url();

    let mut outcome = CoreSetupOutcome::default();
    let lang = ctx.settings.language;
    let verified = ctx.core_version.is_some();
    // The verified version is the installed tree's own version when the tree
    // passed verification (its metadata matched the compiled pins); the setup
    // state carries the version of a tree that did not verify.
    let installed = ctx
        .core_setup
        .installed_version
        .as_deref()
        .or(ctx.core_version.as_deref());
    let verification_error = ctx.core_setup.verification_error.as_ref();
    // A managed tree exists in any verified or unverified state; only the
    // missing state has nothing to verify and shows the first-use hint.
    let tree_present = verified || verification_error.is_some();

    // Core state row, same idiom as the top bar: colored dot + state text.
    let colors = crate::ui::status::status_colors(ui.visuals().dark_mode);
    let (state_color, state_text) = match &ctx.download {
        DownloadState::Working { .. } => (colors.warn, t(lang, Key::CoreSetupDownloading)),
        DownloadState::Failed(_) => (colors.err, t(lang, Key::CoreSetupFailed)),
        _ if verified => (colors.ok, t(lang, Key::CoreSetupInstalled)),
        // A tree that names another release is an update; a tree that does
        // not name one at all is not a managed install.
        _ if installed.is_some() => (colors.warn, t(lang, Key::CoreSetupUpdateRequired)),
        _ => (egui::Color32::GRAY, t(lang, Key::CoreSetupNotInstalled)),
    };
    ui.horizontal(|ui| {
        ui.colored_label(state_color, "●");
        ui.label(RichText::new(t(lang, Key::CoreSetupXrayCore)).strong());
        ui.separator();
        ui.colored_label(state_color, state_text);
    });

    // The standing explanation of what this state, an install, and a failure
    // mean: the Settings mount carries it in place, right under the state
    // row; the first-run dialog keeps its own shorter wording.
    if matches!(mount, CoreSetupMount::Settings) {
        ui.add_space(4.0);
        ui.add(egui::Label::new(RichText::new(t(lang, Key::CoreSetupNote)).weak().small()).wrap());
    }

    // First-run hint: the core is not bundled, it downloads on first use.
    if !tree_present {
        ui.add_space(4.0);
        ui.label(
            RichText::new(t(lang, Key::CoreSetupFirstUseHint))
                .weak()
                .small(),
        );
    }

    // Versions row: what is installed and what this build needs, in every
    // state — a stale core names both, a missing one names only the pin.
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        let installed_text = match installed {
            Some(installed) => t_fmt(lang, Key::CoreSetupInstalledVersionRow, &[&installed]),
            None => t(lang, Key::CoreSetupNoInstalledVersion).to_owned(),
        };
        ui.label(RichText::new(installed_text).weak());
        ui.label(RichText::new("·").weak());
        ui.label(RichText::new(t_fmt(lang, Key::CoreSetupRequiredVersionRow, &[&required])).weak());
    });

    // Verification state with its reason: the verification error's own text,
    // wrapped because a failed pin compare names the payload and its hashes.
    if let Some(error) = verification_error {
        ui.add_space(4.0);
        ui.add(
            egui::Label::new(
                RichText::new(t_fmt(
                    lang,
                    Key::CoreSetupVerificationFailed,
                    &[&error.text(lang)],
                ))
                .color(colors.err)
                .small(),
            )
            .wrap(),
        );
    } else if verified {
        ui.add_space(4.0);
        ui.label(
            RichText::new(t(lang, Key::CoreSetupVerifiedHint))
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
    let phase_allows_install = matches!(&ctx.phase, CorePhase::Stopped | CorePhase::Error(_));
    let busy = core_setup_busy(ctx);
    let can_install = phase_allows_install && !busy;
    // Verify re-hashes the installed payloads; with no tree to open there is
    // nothing for it to answer.
    let can_verify = can_install && tree_present;
    let install_disabled_reason = if !phase_allows_install {
        t(lang, Key::CoreSetupStopFirst)
    } else if busy {
        t(lang, Key::CoreSetupBusy)
    } else {
        ""
    };
    let verify_disabled_reason = if !phase_allows_install {
        t(lang, Key::CoreSetupStopFirst)
    } else if busy {
        t(lang, Key::CoreSetupBusy)
    } else {
        t(lang, Key::CoreSetupVerifyNoCore)
    };

    ui.add_space(10.0);
    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(can_verify, egui::Button::new(t(lang, Key::CoreSetupVerify)))
            .on_disabled_hover_text(verify_disabled_reason)
            .clicked()
        {
            ctx.request_core_verify();
        }
        if ui
            .add_enabled(
                can_install,
                egui::Button::new(t(lang, Key::CoreSetupDownloadButton)),
            )
            .on_disabled_hover_text(install_disabled_reason)
            .clicked()
        {
            ctx.send(CoreCmd::UpdateCore);
        }
        if ui
            .add_enabled(
                can_install,
                egui::Button::new(t(lang, Key::CoreSetupImportArchive)),
            )
            .on_disabled_hover_text(install_disabled_reason)
            .clicked()
            && let Some(path) = rfd::FileDialog::new()
                .add_filter(t(lang, Key::ShellXrayArchiveFilter), &["zip"])
                .pick_file()
        {
            ctx.send(CoreCmd::ImportCoreArchive(path));
        }
        if ui
            .button(t(lang, Key::CoreSetupOpenFolder))
            .on_hover_text(sys::paths::core_dir().display().to_string())
            .clicked()
        {
            ctx.request_open_core_folder();
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
                if ctx.busy.is_held() {
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
        AppMessage, CoreSetupMount, CoreSetupState, FeedbackLevel, UiCtxSnapshot,
        format_latency_probe_feedback, format_single_latency_probe_feedback, show_core_setup,
    };
    use crate::diag::{Diag, DiagError};
    use crate::i18n::{Key, t, t_fmt};
    use crate::model::settings::Language;
    use crate::model::{OutboundModel, Protocol, ProtocolSettings, ServerProfile};
    use crate::rt::{
        CoreCmd, CorePhase, DownloadState, LatencyProbeResult, OutboundStatusView, ProbeFailure,
        StatsTick,
    };
    use crate::sys;
    use crate::sys::selfupd::UpdateCheckState;
    use crate::ui::test_rig::UiTestRig;
    use egui_kittest::{Harness, kittest::NodeT as _, kittest::Queryable as _};

    #[test]
    fn core_setup_not_installed_renders_first_use_hint() {
        let rig = UiTestRig::default();
        let harness = Harness::new_ui_state(
            |ui, rig: &mut UiTestRig| {
                let _ = show_core_setup(ui, &mut rig.ctx(), CoreSetupMount::Settings);
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
                let _ = show_core_setup(ui, &mut rig.ctx(), CoreSetupMount::Settings);
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

    /// Render the shared surface over one rig state and hand back the
    /// harness, so each test states only the state it is about.
    fn core_setup_harness(rig: UiTestRig) -> Harness<'static, UiTestRig> {
        Harness::new_ui_state(
            |ui, rig: &mut UiTestRig| {
                let _ = show_core_setup(ui, &mut rig.ctx(), CoreSetupMount::Settings);
            },
            rig,
        )
    }

    /// The installed and the required version render in every core state.
    #[test]
    fn core_setup_states_render_both_versions() {
        for rig in [
            UiTestRig {
                core_version: Some("v26.9.9".into()),
                ..Default::default()
            },
            UiTestRig {
                core_setup: CoreSetupState {
                    installed_version: Some("26.7.28".into()),
                    verification_error: Some(AppMessage::Message(Diag::new(
                        Key::CoreDlMetadataMismatch,
                    ))),
                },
                ..Default::default()
            },
            UiTestRig::default(),
        ] {
            let harness = core_setup_harness(rig);
            assert!(
                harness
                    .query_by_label(&t_fmt(
                        Language::En,
                        Key::CoreSetupRequiredVersionRow,
                        &[&sys::core_dl::pinned_core_version()],
                    ))
                    .is_some(),
                "every core state must name the required version"
            );
        }
    }

    /// A verified core reports the verified state with its version.
    #[test]
    fn core_setup_verified_state_names_the_installed_version() {
        let harness = core_setup_harness(UiTestRig {
            core_version: Some("26.9.9".into()),
            ..Default::default()
        });
        assert!(
            harness
                .query_by_label(t(Language::En, Key::CoreSetupInstalled))
                .is_some(),
            "a verified core must read as installed and verified"
        );
        assert!(
            harness
                .query_by_label(&t_fmt(
                    Language::En,
                    Key::CoreSetupInstalledVersionRow,
                    &[&"26.9.9"],
                ))
                .is_some(),
            "the verified state must name the installed version"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::CoreSetupUpdateRequired))
                .is_none(),
            "a verified core must not ask for an update"
        );
    }

    /// A stale tree is an update, not a first install: the state, both
    /// versions and the verification reason all render.
    #[test]
    fn core_setup_stale_state_shows_both_versions_and_the_reason() {
        let reason = "the release metadata does not match the compiled pins";
        let harness = core_setup_harness(UiTestRig {
            core_setup: CoreSetupState {
                installed_version: Some("26.7.28".into()),
                verification_error: Some(AppMessage::Error(std::sync::Arc::new(
                    DiagError::new(Diag::new(Key::CoreDlMetadataMismatch)).caused_by_text(reason),
                ))),
            },
            ..Default::default()
        });
        assert!(
            harness
                .query_by_label(t(Language::En, Key::CoreSetupUpdateRequired))
                .is_some(),
            "a stale core must read as an update requirement"
        );
        for label in [
            t_fmt(
                Language::En,
                Key::CoreSetupInstalledVersionRow,
                &[&"26.7.28"],
            ),
            t_fmt(
                Language::En,
                Key::CoreSetupRequiredVersionRow,
                &[&sys::core_dl::pinned_core_version()],
            ),
        ] {
            assert!(
                harness.query_by_label(label.as_str()).is_some(),
                "a stale core must name both versions: {label:?}"
            );
        }
        assert!(
            harness.query_by_label_contains(reason).is_some(),
            "the verification failure's own text must render"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::CoreSetupFirstUseHint))
                .is_none(),
            "a present tree is not a first install"
        );
    }

    /// The four actions are reachable in the state they belong to: Verify and
    /// Open core folder raise their shell requests, the pinned download sends
    /// its command, and archive import is offered next to it.
    #[test]
    fn core_setup_actions_are_reachable() {
        let rig = UiTestRig {
            core_version: Some("26.9.9".into()),
            ..Default::default()
        };
        let mut harness = core_setup_harness(rig);
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::CoreSetupVerify),
            )
            .click();
        harness.run();
        assert!(
            harness.state().verify_core_requested,
            "Verify must raise the shell's verification request"
        );
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::CoreSetupOpenFolder),
            )
            .click();
        harness.run();
        assert!(
            harness.state().open_core_folder_requested,
            "Open core folder must raise the shell's folder request"
        );

        let rig = UiTestRig {
            core_version: Some("26.9.9".into()),
            ..Default::default()
        };
        let mut harness = core_setup_harness(rig);
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::CoreSetupDownloadButton),
            )
            .click();
        harness.run();
        assert!(
            matches!(
                harness.state_mut()._cmd_rx.try_recv(),
                Ok(CoreCmd::UpdateCore)
            ),
            "the pinned download must send UpdateCore"
        );
        // Archive import opens a native file dialog on click, so only its
        // reachability is asserted: the button renders and is enabled.
        let import = harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::CoreSetupImportArchive),
            )
            .accesskit_node()
            .is_disabled();
        assert!(!import, "archive import must be offered and enabled");
    }

    /// With no tree there is nothing to verify, and the surface says so on
    /// the disabled control; the download actions stay available.
    #[test]
    fn core_setup_verify_is_unavailable_without_a_tree() {
        let harness = core_setup_harness(UiTestRig::default());
        assert!(
            harness
                .get_by_role_and_label(
                    egui::accesskit::Role::Button,
                    t(Language::En, Key::CoreSetupVerify),
                )
                .accesskit_node()
                .is_disabled(),
            "a missing core has nothing to verify"
        );
        assert!(
            !harness
                .get_by_role_and_label(
                    egui::accesskit::Role::Button,
                    t(Language::En, Key::CoreSetupDownloadButton),
                )
                .accesskit_node()
                .is_disabled(),
            "a missing core is exactly what the download action is for"
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
        if let Some(target) = target {
            profile.outbound.chain_via(target);
        }
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
        middle.outbound.chain_via(leaf.tag());
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
        b.outbound.chain_via(a.tag());
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

    /// The resting input set of a snapshot — phase `Stopped`, nothing in
    /// flight — exactly as the app holds it when no runtime event moved
    /// anything.
    fn resting_snapshot() -> UiCtxSnapshot {
        UiCtxSnapshot {
            phase: CorePhase::Stopped,
            transport: None,
            stats: None,
            observatory: Vec::new(),
            core_version: None,
            core_setup: CoreSetupState::default(),
            terminal_error: None,
            download: DownloadState::Idle,
            update_check: UpdateCheckState::Idle,
            stats_generation: 0,
            latency_generation: 0,
        }
    }

    /// The UI-context snapshot's memoization key
    /// (`BroccoliApp::rebuild_ui_ctx_snapshot`'s gate): an unchanged input
    /// set schedules no rebuild — the idle-frame invariant — and one changed
    /// value in any input family flips the predicate. A log line changes
    /// none of these inputs, so a drained `CoreEvt::Log` can never force a
    /// rebuild.
    #[test]
    fn ui_ctx_snapshot_rebuilds_only_when_an_input_changes() {
        let resting = resting_snapshot();
        assert!(
            resting.same_inputs(&resting_snapshot()),
            "an unchanged input set must schedule no rebuild"
        );

        let changed_inputs = [
            (
                "stats generation",
                UiCtxSnapshot {
                    stats_generation: 1,
                    ..resting_snapshot()
                },
            ),
            (
                "latency generation",
                UiCtxSnapshot {
                    latency_generation: 1,
                    ..resting_snapshot()
                },
            ),
            (
                "phase",
                UiCtxSnapshot {
                    phase: CorePhase::Running,
                    ..resting_snapshot()
                },
            ),
            (
                "stats tick",
                UiCtxSnapshot {
                    stats: Some(StatsTick {
                        up: 1,
                        ..Default::default()
                    }),
                    ..resting_snapshot()
                },
            ),
            (
                "observatory rows",
                UiCtxSnapshot {
                    observatory: vec![OutboundStatusView {
                        tag: "edge".to_string(),
                        alive: true,
                        delay_ms: 1,
                        last_error: None,
                        health_ping: None,
                        diagnostics: None,
                    }],
                    ..resting_snapshot()
                },
            ),
            (
                "core version",
                UiCtxSnapshot {
                    core_version: Some("v1.8.24".to_string()),
                    ..resting_snapshot()
                },
            ),
            (
                "core setup",
                UiCtxSnapshot {
                    core_setup: CoreSetupState {
                        installed_version: Some("v1.8.24".to_string()),
                        ..CoreSetupState::default()
                    },
                    ..resting_snapshot()
                },
            ),
            (
                "download",
                UiCtxSnapshot {
                    download: DownloadState::Done("core.zip".to_string()),
                    ..resting_snapshot()
                },
            ),
            (
                "update check",
                UiCtxSnapshot {
                    update_check: UpdateCheckState::Failed,
                    ..resting_snapshot()
                },
            ),
        ];
        for (input, changed) in changed_inputs {
            assert!(
                !resting.same_inputs(&changed),
                "a changed {input} input must schedule a rebuild"
            );
        }
    }
}
