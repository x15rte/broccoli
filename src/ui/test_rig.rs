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
use crate::ui::{CoreSetupState, TerminalErrorView, UiCtx, UiCtxParts, UiCtxSnapshot, UiCtxView};
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
    pub(crate) connect_requested: bool,
    pub(crate) stop_requested: bool,
    /// Core setup requests a screen raised this frame (Verify, Open core
    /// folder, open the core setup surface).
    pub(crate) verify_core_requested: bool,
    pub(crate) open_core_folder_requested: bool,
    pub(crate) open_core_setup_requested: bool,
    /// Outcome slot of the one single-flight latency probe, mirroring the
    /// app drain: probe UI tests park results here and the servers screen
    /// adopts them through its `ShellParked` request.
    pub(crate) probe_feedback: crate::ui::request::ParkedSlot<LatencyProbeResult>,
    pub(crate) stats: Option<StatsTick>,
    pub(crate) stats_history: VecDeque<StatsTick>,
    pub(crate) observatory: Vec<OutboundStatusView>,
    pub(crate) logs: VecDeque<(bool, String)>,
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
    pub(crate) dirty: bool,
    pub(crate) ui_dirty: bool,
    /// The model's edit generation, as the shell publishes it. Tests that
    /// mutate the model between frames go through [`UiTestRig::edit`], the
    /// rig's one route to the mutation hook, so the caches a screen derived
    /// from the old model are invalidated exactly as they are in the app.
    pub(crate) model_generation: u64,
    pub(crate) config_revision: u64,
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
            connect_requested: false,
            stop_requested: false,
            verify_core_requested: false,
            open_core_folder_requested: false,
            open_core_setup_requested: false,
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
            dirty: false,
            ui_dirty: false,
            model_generation: 0,
            config_revision: 0,
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

impl UiTestRig {
    /// Push one log line exactly like the app's `LogBuffer::push`:
    /// advances the ring's monotonic generation alongside the push.
    /// Every rig test that appends to `logs` between frames must go
    /// through this method — the Logs screen's memoized view is keyed on
    /// `logs_generation`, so a bare `logs.push_back` would leave the view
    /// stale.
    pub(crate) fn push_log(&mut self, from_core: bool, line: String) {
        self.logs_generation += 1;
        self.logs.push_back((from_core, line));
    }

    /// Record a model edit between frames through the shell's own mutation
    /// hook: the rig assembles a `UiCtx` exactly as a frame does and calls
    /// `mark_dirty`, so the persist request and the generation bump stay one
    /// behaviour rather than a test-side copy of it.
    pub(crate) fn edit(&mut self) {
        self.ctx().mark_dirty();
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
        UiCtx::new(
            UiCtxParts {
                servers: &mut self.servers,
                settings: &mut self.settings,
                cmd: &self.cmd,
                stats_history: &self.stats_history,
                logs: &self.logs,
                logs_generation: self.logs_generation,
                probe_feedback: &mut self.probe_feedback,
                dirty: &mut self.dirty,
                ui_dirty: &mut self.ui_dirty,
                model_generation: &mut self.model_generation,
                connect_requested: &mut self.connect_requested,
                stop_requested: &mut self.stop_requested,
                verify_core_requested: &mut self.verify_core_requested,
                open_core_folder_requested: &mut self.open_core_folder_requested,
                open_core_setup_requested: &mut self.open_core_setup_requested,
                connect_blocked_reason: &self.connect_blocked_reason,
                config_error: &self.config_error,
                operation: self.operation,
                is_elevated: self.is_elevated,
                config_revision: self.config_revision,
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
    use super::UiTestRig;
    use crate::i18n::{Key, t};
    use crate::model::settings::Language;
    use crate::model::{OutboundModel, Protocol, ServerProfile};
    use crate::rt::{CorePhase, JobKind};
    use crate::ui::logs::LogsScreen;
    use crate::ui::servers::ServersScreen;
    use egui::accesskit::Role;
    use egui_kittest::{Harness, kittest::NodeT as _, kittest::Queryable as _};

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
        let mut harness = Harness::new_ui_state(
            |ui, state: &mut (ServersScreen, UiTestRig)| {
                state.0.show(ui, &mut state.1.ctx());
            },
            (ServersScreen::default(), rig),
        );
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
        let mut harness = Harness::new_ui_state(
            |ui, state: &mut (LogsScreen, UiTestRig)| {
                state.0.show(ui, &mut state.1.ctx());
            },
            (LogsScreen::default(), rig),
        );
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
