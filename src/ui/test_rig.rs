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

use crate::metrics::MetricsHandle;
use crate::model::{ServersFile, Settings};
use crate::rt::{
    CoreCmd, CorePhase, DownloadState, LatencyProbeResult, OutboundStatusView, StatsTick,
};
use crate::sys::selfupd::UpdateCheckState;
use crate::ui::{UiCtx, UiCtxParts, UiCtxSnapshot, UiCtxView};
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
    pub(crate) connect_blocked_reason: Option<String>,
    /// The shell's stored config-generation error — the text the dashboard
    /// renders inline under Connect, excerpt-bounded by the shell's
    /// generation boundary.
    pub(crate) config_error: Option<String>,
    pub(crate) connect_requested: bool,
    pub(crate) stop_requested: bool,
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
    pub(crate) download: DownloadState,
    pub(crate) update_check: UpdateCheckState,
    pub(crate) dirty: bool,
    pub(crate) ui_dirty: bool,
    pub(crate) config_revision: u64,
    pub(crate) metrics: MetricsHandle,
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
            connect_blocked_reason: None,
            config_error: None,
            connect_requested: false,
            stop_requested: false,
            probe_feedback: Default::default(),
            stats: None,
            stats_history: VecDeque::new(),
            observatory: Vec::new(),
            logs: VecDeque::new(),
            logs_generation: 0,
            core_version: None,
            download: DownloadState::Idle,
            update_check: UpdateCheckState::Idle,
            dirty: false,
            ui_dirty: false,
            config_revision: 0,
            metrics: MetricsHandle::new(),
            stats_generation: 0,
            latency_generation: 0,
            snapshot: UiCtxSnapshot {
                phase: CorePhase::Stopped,
                stats: None,
                observatory: Vec::new(),
                core_version: None,
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

    /// Assemble the UiCtx the screen under test receives — through
    /// [`UiCtx::new`], the same single constructor the app shell uses, with
    /// the same two bundles: [`UiCtxParts`] over the rig's fields and a
    /// live [`UiCtxView`] over a snapshot cloned from the rig's runtime
    /// fields. Inert runtime inputs take their resting values (phase
    /// `Stopped`, no stats or observatory, no operation); the per-test
    /// state lives on the rig's mutable fields.
    pub(crate) fn ctx(&mut self) -> UiCtx<'_> {
        // Refresh the staging snapshot from the flat fields, then borrow it.
        self.snapshot = UiCtxSnapshot {
            phase: self.phase.clone(),
            stats: self.stats.clone(),
            observatory: self.observatory.clone(),
            core_version: self.core_version.clone(),
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
                metrics: &self.metrics,
                dirty: &mut self.dirty,
                ui_dirty: &mut self.ui_dirty,
                connect_requested: &mut self.connect_requested,
                stop_requested: &mut self.stop_requested,
                connect_blocked_reason: &self.connect_blocked_reason,
                config_error: &self.config_error,
                operation: None,
                is_elevated: false,
                config_revision: self.config_revision,
            },
            UiCtxView::Live {
                snapshot: &self.snapshot,
            },
        )
    }
}
