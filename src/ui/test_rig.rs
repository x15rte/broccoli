//! Shared screen-test rig: one minimal [`UiCtx`] backing for every screen
//! and app-shell test that drives real UI through egui's kittest harness.
//!
//! Every screen test module used to carry its own local rig —
//! the app shell's `ScreenRig`, the servers screen's rig, the ui-module rig
//! (three byte-identical copies), slimmer copies in dns/logs/settings, and
//! the stats/observatory-carrying copies in dashboard/inbounds. All of them
//! now build through [`UiTestRig`], so a change to how screens receive
//! inputs — a new UiCtx field, a constructor — is updated in exactly one
//! place: [`UiTestRig::ctx`] is the single UiCtx assembly point for the whole
//! test surface, routed through `UiCtx::new` exactly like the app shell's
//! frame sites.
//!
//! This module is `cfg(test)`-only and never ships. The full-app integration
//! suite (`tests/ui_smoke.rs`) drives the real eframe app and does not use
//! it.

use crate::model::{ServersFile, Settings};
use crate::rt::{
    CoreCmd, CorePhase, DownloadState, JobKind, LatencyProbeResult, OutboundStatusView, StatsTick,
};
use crate::sys::selfupd::UpdateCheckState;
use crate::ui::logs::LogLine;
use crate::ui::{
    CoreSetupState, TerminalErrorView, TrafficSample, UiCtx, UiCtxParts, UiCtxSnapshot, UiCtxView,
};
use egui_kittest::Harness;
use std::collections::VecDeque;

/// Minimal UiCtx backing shared by screen-level and app-shell-wiring tests:
/// real settings plus inert runtime fields, so a screen can be driven
/// through egui's kittest harness without constructing the full eframe app.
///
/// Tests seed the model (`servers`, `settings`, `logs`, …) directly, hand
/// the rig to the harness, and call [`UiTestRig::ctx`] every frame exactly
/// where the real app would assemble its UiCtx. Every UiCtx input that tests
/// ever vary is a field here with a resting default; [`UiTestRig::ctx`] is
/// the only place a UiCtx is assembled in the whole test surface.
pub(crate) struct UiTestRig {
    pub(crate) servers: ServersFile,
    pub(crate) settings: Settings,
    pub(crate) cmd: tokio::sync::mpsc::UnboundedSender<CoreCmd>,
    /// Kept alive so `cmd` sends succeed (probe requests error on a
    /// dropped receiver); tests that assert on sent commands drain it.
    pub(crate) _cmd_rx: tokio::sync::mpsc::UnboundedReceiver<CoreCmd>,
    pub(crate) phase: CorePhase,
    /// The transport the live phase owns, as the runtime publishes it with
    /// the phase (see `CoreEvt::State`).
    pub(crate) transport: Option<crate::rt::CoreTransport>,
    pub(crate) connect_blocked_reason: Option<String>,
    /// The shell's stored config-generation error — the text the dashboard
    /// renders inline under Connect, excerpt-bounded by the shell's
    /// generation boundary.
    pub(crate) config_error: Option<String>,
    /// The whole-model safety verdict the frame publishes. The shell memoizes
    /// one per generation; the rig recomputes it in [`UiTestRig::ctx`] so a
    /// test may seed the model directly — without the shell's dirty hook —
    /// and still have the screen read the verdict for what it seeded.
    pub(crate) safety: crate::model::safety::SafetyVerdicts,
    /// The validation verdict the frame publishes: the whole-model settings
    /// walk, rebuilt in [`UiTestRig::ctx`] exactly as the shell's generation
    /// fills it, so a seeded model is judged by the same pass the Apply gate
    /// runs. The API port is the fixed test port — the walk's collision rule
    /// only needs one concrete port, and no test drives the control plane.
    pub(crate) verdict: crate::model::validation::Verdict,
    /// The frame's requests, as the shell owns them: the rig hands the same
    /// bundle to every `ctx()` and tests read the fields a screen set.
    pub(crate) requests: crate::ui::FrameRequests,
    /// Outcome slot of the one single-flight latency probe, mirroring the
    /// app drain: probe UI tests park results here and the servers screen
    /// adopts them through its `ShellParked` request.
    pub(crate) probe_feedback: crate::ui::request::ParkedSlot<LatencyProbeResult>,
    pub(crate) stats: Option<StatsTick>,
    pub(crate) stats_history: VecDeque<TrafficSample>,
    pub(crate) observatory: Vec<OutboundStatusView>,
    pub(crate) logs: VecDeque<LogLine>,
    /// Monotonic push count mirroring the app's `LogBuffer::generation`
    /// [`UiTestRig::push_log`] keeps it in step with the ring.
    /// Tests that push lines while a Logs screen is live must route the
    /// pushes through [`UiTestRig::push_log`], or the memoized filtered
    /// view never rebuilds.
    pub(crate) logs_generation: u64,
    pub(crate) core_version: Option<String>,
    /// The installed tree's own version and its last verification failure,
    /// as the core setup surface reads them.
    pub(crate) core_setup: CoreSetupState,
    /// The terminal message the content area renders.
    pub(crate) terminal_error: Option<TerminalErrorView>,
    pub(crate) download: DownloadState,
    pub(crate) update_check: UpdateCheckState,
    /// The runtime's exclusive operation as the shell mirrors it — the busy
    /// window every gated control reads. `None` is the resting shell.
    pub(crate) operation: Option<JobKind>,
    /// Whether this process runs elevated: the TUN badge and the TUN hover
    /// copy read it.
    pub(crate) is_elevated: bool,

    /// The model's edit generation, as the shell publishes it. Tests that
    /// mutate the model between frames go through [`UiTestRig::edit`], the
    /// rig's one route to the mutation hook, so the caches a screen derived
    /// from the old model are invalidated exactly as they are in the app.
    pub(crate) model_generation: u64,
    /// The generation the rig publishes its verdict at. `None` follows
    /// [`Self::model_generation`], so a test that edits the model needs no
    /// extra step. [`Self::publish_verdict_at`] pins it independently, which
    /// is how a test models the shell's throttled republication: the persist
    /// runs after the edit frame, so a verdict can arrive stamped with a
    /// generation whose edit frame already rendered against the previous one.
    pub(crate) verdict_generation: Option<u64>,
    pub(crate) stats_generation: u64,
    pub(crate) latency_generation: u64,
    /// Staging store for [`UiTestRig::ctx`]: the runtime inputs are
    /// refreshed from the flat fields above on every `ctx()` call, then the
    /// live view borrows this field — so the returned [`UiCtx`] may outlive
    /// the call.
    pub(crate) snapshot: UiCtxSnapshot,
}

impl Default for UiTestRig {
    fn default() -> Self {
        let (cmd, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            servers: ServersFile::default(),
            settings: Settings::default(),
            cmd,
            _cmd_rx: cmd_rx,
            phase: CorePhase::Stopped,
            transport: None,
            connect_blocked_reason: None,
            config_error: None,
            safety: Default::default(),
            verdict: Default::default(),
            requests: crate::ui::FrameRequests::default(),
            probe_feedback: Default::default(),
            stats: None,
            stats_history: VecDeque::new(),
            observatory: Vec::new(),
            logs: VecDeque::new(),
            logs_generation: 0,
            core_version: None,
            core_setup: CoreSetupState::default(),
            terminal_error: None,
            download: DownloadState::Idle,
            update_check: UpdateCheckState::Idle,
            operation: None,
            is_elevated: false,
            model_generation: 0,
            verdict_generation: None,
            stats_generation: 0,
            latency_generation: 0,
            snapshot: UiCtxSnapshot {
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
            },
        }
    }
}

/// The viewport the screen harnesses render at: the app's minimum window
/// size, so a screen test lays out the width a user's window can actually
/// have. A test that needs another width asks for one explicitly.
pub(crate) const DEFAULT_TEST_VIEWPORT: egui::Vec2 = egui::Vec2::new(900.0, 600.0);

/// The control-plane port the rig hands the settings walk: any concrete port
/// serves the listener-collision rule, and no screen test binds it.
pub(crate) const TEST_API_PORT: u16 = 19999;

/// One screen's frame entry: each screen assembles its own slice from the
/// rig, exactly as the app assembles it from [`UiCtx`], so the shared rig can
/// drive any screen without a per-test closure.
pub(crate) trait ScreenShow {
    fn show_frame(&mut self, ui: &mut egui::Ui, rig: &mut UiTestRig);
}

macro_rules! screen_show {
    ($($screen:ty => $slice:ident),* $(,)?) => {
        $(impl ScreenShow for $screen {
            fn show_frame(&mut self, ui: &mut egui::Ui, rig: &mut UiTestRig) {
                self.show(ui, &mut rig.ctx().$slice());
            }
        })*
    };
}

screen_show!(
    crate::ui::about::AboutScreen => about,
    crate::ui::dashboard::DashboardScreen => dashboard,
    crate::ui::dns::DnsScreen => dns,
    crate::ui::inbounds::InboundsScreen => inbounds,
    crate::ui::logs::LogsScreen => logs,
    crate::ui::profile_preview::ProfilePreviewScreen => profile_preview,
    crate::ui::routing::RoutingScreen => routing,
    crate::ui::servers::ServersScreen => servers,
    crate::ui::settings::SettingsScreen => settings,
    crate::ui::tun::TunScreen => tun,
);

/// Drive one screen over the shared rig through a kittest harness: the
/// pair-shaped state the screen tests already read (`(screen, rig)`), the
/// frame closure that hands the screen its context, and the app-sized
/// viewport — the three things every screen test used to restate.
pub(crate) fn screen_harness<S: ScreenShow + 'static>(
    rig: UiTestRig,
    screen: S,
) -> Harness<'static, (S, UiTestRig)> {
    screen_harness_at(DEFAULT_TEST_VIEWPORT, rig, screen)
}

/// [`screen_harness`] at an explicit viewport, for the tests that assert
/// layout at a width of their own.
pub(crate) fn screen_harness_at<S: ScreenShow + 'static>(
    size: egui::Vec2,
    rig: UiTestRig,
    screen: S,
) -> Harness<'static, (S, UiTestRig)> {
    Harness::builder().with_size(size).build_ui_state(
        |ui, state: &mut (S, UiTestRig)| state.0.show_frame(ui, &mut state.1),
        (screen, rig),
    )
}

/// The servers screen plus the every-frame tail the app shell wires after it.
///
/// The shell runs the screen, then the leave modal, then the staged-quit
/// resume — a sequence the app-level tests have to reproduce to exercise the
/// quit paths at all. That reproduction lives here, once: a test passes what
/// its own case adds after the screen (`tail`), and the shell's own ordering
/// cannot drift from the tests that verify it.
pub(crate) fn servers_frame_harness<F>(
    size: egui::Vec2,
    rig: UiTestRig,
    tail: F,
) -> Harness<'static, (crate::ui::servers::ServersScreen, UiTestRig)>
where
    F: Fn(&mut crate::ui::servers::ServersScreen, &mut UiTestRig, &egui::Ui) + 'static,
{
    Harness::builder().with_size(size).build_ui_state(
        move |ui, state: &mut (crate::ui::servers::ServersScreen, UiTestRig)| {
            state.0.show(ui, &mut state.1.ctx().servers());
            // The screen just rendered, so its dialogs own their questions.
            state
                .0
                .show_leave_modal(ui.ctx(), &mut state.1.ctx().servers(), true);
            tail(&mut state.0, &mut state.1, ui);
        },
        (crate::ui::servers::ServersScreen::default(), rig),
    )
}

impl UiTestRig {
    /// Push one log line exactly like the app's `LogBuffer::push`:
    /// advances the ring's monotonic generation alongside the push.
    /// Every rig test that appends to `logs` between frames must go
    /// through this method — the Logs screen's memoized view is keyed on
    /// `logs_generation`, so a bare `logs.push_back` would leave the view
    /// stale. The wall-clock stamp the app adds is left off so row text
    /// stays deterministic; tests that assert the stamp build it explicitly.
    pub(crate) fn push_log(&mut self, from_core: bool, line: String) {
        self.logs_generation += 1;
        self.logs.push_back(LogLine {
            text: line,
            from_core,
            level: None,
            timestamp: None,
        });
    }

    /// Record a model edit between frames through the shell's own mutation
    /// hook: the rig assembles a `UiCtx` exactly as a frame does and calls
    /// `mark_dirty`, so the persist request and the generation bump stay one
    /// behaviour rather than a test-side copy of it.
    pub(crate) fn edit(&mut self) {
        self.ctx().hooks().mark_dirty();
    }

    /// Publish the next frames' verdict at `generation` without moving the
    /// model generation — the shell's throttled republication, modelled from
    /// the screen's side. The verdict content still follows the seeded model;
    /// only its stamp is pinned, so a test can render a verdict the previous
    /// frame's cache had no reason to expect.
    pub(crate) fn publish_verdict_at(&mut self, generation: u64) {
        self.verdict_generation = Some(generation);
    }

    /// Assemble the UiCtx the screen under test receives — through
    /// [`UiCtx::new`], the same single constructor the app shell uses, with
    /// the same two bundles: [`UiCtxParts`] over the rig's fields and a
    /// live [`UiCtxView`] over a snapshot cloned from the rig's runtime
    /// fields. Runtime inputs take their resting values unless a test sets
    /// them (phase `Stopped`, no stats or observatory, no operation, not
    /// elevated); the per-test state lives on the rig's mutable fields.
    pub(crate) fn ctx(&mut self) -> UiCtx<'_> {
        // Refresh the staging snapshot from the flat fields, then borrow it.
        self.snapshot = UiCtxSnapshot {
            phase: self.phase.clone(),
            transport: self.transport,
            stats: self.stats.clone(),
            observatory: self.observatory.clone(),
            core_version: self.core_version.clone(),
            core_setup: self.core_setup.clone(),
            terminal_error: self.terminal_error.clone(),
            download: self.download.clone(),
            update_check: self.update_check.clone(),
            stats_generation: self.stats_generation,
            latency_generation: self.latency_generation,
        };
        self.safety = crate::model::safety::SafetyVerdicts::of(&self.servers, &self.settings);
        self.verdict = crate::model::validation::validate_settings(
            &self.settings,
            &self.servers,
            TEST_API_PORT,
        );
        let verdict_generation = self.verdict_generation.unwrap_or(self.model_generation);
        UiCtx::new(
            UiCtxParts {
                servers: &mut self.servers,
                settings: &mut self.settings,
                cmd: &self.cmd,
                stats_history: &self.stats_history,
                logs: &self.logs,
                logs_generation: self.logs_generation,
                probe_feedback: &mut self.probe_feedback,
                requests: &mut self.requests,
                model_generation: &mut self.model_generation,
                safety: &self.safety,
                verdict: &self.verdict,
                verdict_generation,
                connect_blocked_reason: &self.connect_blocked_reason,
                config_error: &self.config_error,
                operation: self.operation,
                is_elevated: self.is_elevated,
            },
            UiCtxView::Live {
                snapshot: &self.snapshot,
            },
        )
    }
}

/// The busy window as the two screens that own a gated control show it: while
/// an exclusive operation is in flight, the control is disabled and its
/// disabled hover states the reason. Both assertions are what a user meets —
/// the disabled control and the text it shows — and each fails on its own if
/// the gate stops reading the busy window.
mod busy_window_gates {
    use super::{UiTestRig, screen_harness};
    use crate::i18n::{Key, t};
    use crate::model::settings::Language;
    use crate::model::{OutboundModel, Protocol, ServerProfile};
    use crate::rt::{CorePhase, JobKind};
    use crate::ui::logs::LogsScreen;
    use crate::ui::servers::ServersScreen;
    use egui::accesskit::Role;
    use egui_kittest::{kittest::NodeT as _, kittest::Queryable as _};

    #[test]
    fn a_busy_window_disables_the_latency_probe_and_states_the_reason() {
        let mut rig = UiTestRig {
            operation: Some(JobKind::Start),
            ..UiTestRig::default()
        };
        // A profile, so the gate under test is the busy window and not the
        // empty list's own "add a server first" reason.
        rig.servers.profiles.push(ServerProfile::new(
            "Tokyo",
            OutboundModel::new(Protocol::Freedom),
        ));
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();

        let label = t(Language::En, Key::TestLatency);
        {
            let probe = harness.get_by_role_and_label(Role::Button, label);
            assert!(
                probe.accesskit_node().is_disabled(),
                "an operation in flight must disable the latency probe"
            );
            probe.hover();
        }
        // The disabled hover waits out egui's tooltip delay, so the reason is
        // only on screen once a few frames have passed with the pointer still.
        harness.run_steps(4);
        let reason = t(Language::En, Key::SrvAnotherOperationWorking);
        assert!(
            harness.query_all_by_label(reason).next().is_some(),
            "the disabled latency probe must state why: {reason}"
        );
    }

    #[test]
    fn a_busy_window_disables_the_logger_restart_and_states_the_reason() {
        let rig = UiTestRig {
            phase: CorePhase::Running,
            operation: Some(JobKind::Start),
            ..UiTestRig::default()
        };
        let mut harness = screen_harness(rig, LogsScreen::default());
        harness.run();

        let label = t(Language::En, Key::LogsRestartLogger);
        {
            let restart = harness.get_by_role_and_label(Role::Button, label);
            assert!(
                restart.accesskit_node().is_disabled(),
                "an operation in flight must disable the logger restart"
            );
            restart.hover();
        }
        harness.run_steps(4);
        let reason = t(Language::En, Key::LogsRestartDisabledBusy);
        assert!(
            harness.query_all_by_label(reason).next().is_some(),
            "the disabled logger restart must state why: {reason}"
        );
    }
}
