//! The runtime's lifecycle state: the phase, the live backend, and the
//! transition state a start, an exit or a rollback moves through.
//!
//! The run loop drives the transitions and the runtime's services execute
//! their steps, but the state they mutate is here, so a transition reads one
//! value instead of a scatter of fields on the loop. Decisions that need
//! nothing beyond their own inputs stay in [`super::policy`], the readiness
//! clock keeps its own home in [`super::readiness`], and the child's life
//! (spawn, attach, confirmed exit, forced release) belongs to
//! [`BackendState`].

use std::net::IpAddr;
use std::time::Instant;

use super::CorePhase;
use super::SpawnConfigSource;
use super::helper::ChildPhase;
use super::policy::CoreExitFacts;
use super::readiness::Readiness;
use super::state::{
    BackendState, Backoff, CandidateKind, CoreUpdatePending, ExitPolicy, PendingCandidate,
};
use crate::diag::Diag;

/// The one configuration a start runs: the source chosen for it and the
/// artefact captured for the elevated helper to stage.
///
/// Source selection consumes the one-shot flags that arm an update's health
/// gate and the post-rollback replay, so exactly one start observes them. The
/// capture records the exact bytes this build produced (a fresh apply's
/// validated candidate, a generation, or a stamped replay) together with the
/// app-owned DNS-takeover choice; the elevated helper never re-reads the
/// user-writable active path, so a same-user swap after capture cannot reach
/// the stage.
pub(super) struct SpawnConfig {
    source: SpawnConfigSource,
    gate_armed: bool,
    replay_armed: bool,
    captured: Option<Vec<u8>>,
    dns_takeover: bool,
}

impl SpawnConfig {
    pub(super) const fn new() -> Self {
        Self {
            source: SpawnConfigSource::SavedState,
            gate_armed: false,
            replay_armed: false,
            captured: None,
            dns_takeover: true,
        }
    }

    /// Choose this start's configuration source, consuming the one-shot gate
    /// and replay flags. A freshly committed configuration candidate
    /// supersedes the gate — the user's own start then carries the update's
    /// verdict — and the gate flag is consumed either way.
    pub(super) fn select_source(&mut self, config_candidate_pending: bool) -> SpawnConfigSource {
        let gate = std::mem::take(&mut self.gate_armed);
        let replay = std::mem::take(&mut self.replay_armed);
        self.source = if config_candidate_pending {
            SpawnConfigSource::Committed
        } else if gate {
            SpawnConfigSource::CoreGate
        } else if replay {
            SpawnConfigSource::RolledBackReplay
        } else {
            SpawnConfigSource::SavedState
        };
        self.source
    }

    /// Arm the next start's update health gate (`CoreGate` source).
    pub(super) fn arm_gate(&mut self) {
        self.gate_armed = true;
    }

    /// Arm the next start's replay of the restored last-known-good artefact.
    pub(super) fn arm_replay(&mut self) {
        self.replay_armed = true;
    }

    /// Record the artefact this start captured: the exact bytes a helper
    /// start stages and the app-owned DNS-takeover choice that goes with them.
    pub(super) fn capture(&mut self, bytes: Vec<u8>, dns_takeover: bool) {
        self.captured = Some(bytes);
        self.dns_takeover = dns_takeover;
    }

    /// The captured bytes, or `None` when no start has captured yet.
    pub(super) fn bytes(&self) -> Option<&[u8]> {
        self.captured.as_deref()
    }

    /// The app-owned DNS-takeover choice captured with the bytes; true when no
    /// apply has recorded another.
    pub(super) fn dns_takeover(&self) -> bool {
        self.dns_takeover
    }

    /// Drop the captured bytes because the active config changed under the
    /// runtime; the next helper start must capture the new file.
    pub(super) fn clear_capture(&mut self) {
        self.captured = None;
    }
}

/// One runtime's lifecycle state.
pub(super) struct Lifecycle {
    /// Owns the live backend slot (direct child or helper pipe), its event
    /// channel, and the derived alive/tun-ownership flags.
    pub(super) backend: BackendState,
    /// Stop/restart/silence policy for the in-flight expected exit.
    pub(super) exit_policy: ExitPolicy,
    /// A just-committed config candidate plus its armed rollback.
    pub(super) pending_transition: PendingCandidate,
    /// The configuration this start runs: the source chosen from the armed
    /// flags and the artefact captured for a helper start.
    pub(super) spawn_config: SpawnConfig,
    /// The core-swap candidate (durable health marker) plus its rollback.
    pub(super) core_update: CoreUpdatePending,
    /// Unexpected-exit backoff and the stability clock that resets it.
    pub(super) backoff: Backoff,
    pub(super) phase: CorePhase,
    pub(super) requested_tun_mode: bool,
    pub(super) shutting_down: bool,
    /// The live backend is the health gate's proof process: it runs the
    /// app-owned configuration, so its first readiness ACKs the update and
    /// then ends the process (the phase settles to Stopped). Set by the start
    /// that ran `SpawnConfigSource::CoreGate`, cleared on any backend exit.
    pub(super) gate_backend_alive: bool,
    /// Automatic retry count for a TUN candidate that exits before
    /// readiness. Reset on every fresh commit and on first readiness; the
    /// budget for one exit is a single attempt for the adapter teardown
    /// window and [`TUN_BIND_RACE_RETRIES`] extra for the dns-in bind race.
    pub(super) candidate_boot_retries: u8,
    pub(super) pending_restart: Option<Instant>,
    /// The in-tun DNS listeners this start must add to its running core,
    /// armed from the config the core runs: one address per gateway family the
    /// tunnel carries. Empty means nothing is pending — the add was not
    /// needed, succeeded, or spent its attempt budget.
    pub(super) dns_in_pending: Vec<IpAddr>,
    /// Add attempts spent for `dns_in_pending`, capped through the shared
    /// [`spend_retry_attempt`] rule ([`DNS_IN_ADD_ATTEMPTS`]).
    pub(super) dns_in_attempts: u8,
    /// This start has emitted its `connected` line: readiness settled and,
    /// for TUN, the in-tun DNS listener add finished (or spent its budget).
    /// Reset on every start, so a restart announces its own connection once.
    pub(super) connected_logged: bool,
    /// The readiness clock of this start: armed after the child is
    /// confirmed alive, disarmed while a TUN start is still staging in the
    /// elevated helper.
    pub(super) readiness: Readiness,
}

impl Lifecycle {
    pub(super) fn new() -> Self {
        Self {
            backend: BackendState::new(),
            exit_policy: ExitPolicy::idle(),
            pending_transition: PendingCandidate::new(CandidateKind::Configuration),
            spawn_config: SpawnConfig::new(),
            core_update: CoreUpdatePending::new(),
            backoff: Backoff::new(),
            phase: CorePhase::Stopped,
            requested_tun_mode: false,
            shutting_down: false,
            gate_backend_alive: false,
            candidate_boot_retries: 0,
            pending_restart: None,
            dns_in_pending: Vec::new(),
            dns_in_attempts: 0,
            connected_logged: false,
            readiness: Readiness::new(),
        }
    }

    /// The facts the exit classifier decides on, read from one place: the
    /// armed rollbacks, the pending candidates, the recorded exit intent and
    /// whether this exit ended a start that had not reached readiness.
    pub(super) fn exit_facts(&self, code: Option<i32>) -> CoreExitFacts {
        CoreExitFacts {
            config_rollback_armed: self.pending_transition.rollback_pending().is_some(),
            update_rollback_armed: self.core_update.rollback_pending().is_some(),
            intent: self.exit_policy.kind(),
            config_candidate_pending: self.pending_transition.is_candidate_pending(),
            update_candidate_pending: self.core_update.is_candidate_pending(),
            starting: matches!(self.phase, CorePhase::Starting),
            leak_install_failed: false,
            code,
        }
    }

    /// The elevated helper reports a phase and the PID of the child it
    /// spawned: the spawn confirmation arms the readiness clock, and the PID
    /// is what the owning-PID check compares against. Other phases are
    /// informational; an unknown (0) PID never records.
    pub(super) fn on_helper_state(&mut self, phase: ChildPhase, pid: u32) {
        if matches!(phase, ChildPhase::Starting | ChildPhase::Running) {
            self.backend.set_child_pid(pid);
        }
        self.readiness.on_helper_state(
            phase,
            self.pending_transition.is_candidate_pending(),
            self.backend.is_tun_owned(),
        );
    }

    /// Begin the final shutdown: drop every pending transition, close the
    /// exit policy, and open the stop window. The answer says whether a live
    /// backend still needs the runtime's stop sequence — with nothing live
    /// the shutdown is already over, and the caller has nothing left to stop.
    pub(super) fn begin_shutdown(&mut self) -> bool {
        self.pending_restart = None;
        self.pending_transition.clear();
        self.core_update.clear();
        self.gate_backend_alive = false;
        self.exit_policy.finish();
        if self.backend.as_backend().is_none() {
            self.backend.force_release();
            return false;
        }
        self.exit_policy.begin_stop(Instant::now());
        true
    }

    /// Take the armed config rollback now that the candidate's exit is
    /// confirmed. The candidate is cleared before the filesystem operation
    /// runs, which makes the retry one-shot even if the last-good replacement
    /// also fails to start. `None` means nothing was armed.
    pub(super) fn take_config_rollback(&mut self) -> Option<Diag> {
        let reason = self
            .pending_transition
            .take_rollback_after_confirmed_exit(true)?;
        self.pending_transition.clear_candidate();
        Some(reason)
    }

    /// Take the armed core rollback now that the candidate's exit is
    /// confirmed, under the same one-shot rule as the config rollback: the
    /// candidate is cleared before the swap, so a restored core that also
    /// fails cannot arm the same rollback twice. `None` means nothing was
    /// armed.
    pub(super) fn take_core_rollback(&mut self) -> Option<Diag> {
        let reason = self.core_update.take_rollback_after_confirmed_exit(true)?;
        self.core_update.clear_candidate();
        Some(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::{SpawnConfig, SpawnConfigSource};

    /// Precedence: committed candidate > armed gate > armed replay >
    /// regenerate, and each one-shot flag is consumed by the start that
    /// observes it.
    #[test]
    fn spawn_config_source_precedence_consumes_one_shot_flags() {
        // A frozen configuration candidate supersedes an armed gate; the gate
        // is consumed either way.
        let mut config = SpawnConfig::new();
        config.arm_gate();
        assert_eq!(
            config.select_source(true),
            SpawnConfigSource::Committed,
            "the committed candidate supersedes the gate"
        );
        assert_eq!(
            config.select_source(false),
            SpawnConfigSource::SavedState,
            "the gate is consumed even when the candidate superseded it"
        );

        // Gate beats replay; both one-shot flags are consumed by the start
        // that observes them, so the replay cannot leak into a later start.
        let mut config = SpawnConfig::new();
        config.arm_gate();
        config.arm_replay();
        assert_eq!(config.select_source(false), SpawnConfigSource::CoreGate);
        assert_eq!(
            config.select_source(false),
            SpawnConfigSource::SavedState,
            "the replay flag is consumed with the gate it was superseded by"
        );

        // Replay alone.
        let mut config = SpawnConfig::new();
        config.arm_replay();
        assert_eq!(
            config.select_source(false),
            SpawnConfigSource::RolledBackReplay
        );
        assert_eq!(config.select_source(false), SpawnConfigSource::SavedState);

        // Cold start regenerates.
        assert_eq!(
            SpawnConfig::new().select_source(false),
            SpawnConfigSource::SavedState
        );
    }

    /// The capture records the bytes and the DNS-takeover choice together, and
    /// a later start keeps the choice while replacing the bytes; clearing the
    /// capture drops both the start's artefact and its availability.
    #[test]
    fn spawn_config_capture_records_and_clears_once() {
        let mut config = SpawnConfig::new();
        assert!(config.bytes().is_none(), "no start has captured yet");
        assert!(
            config.dns_takeover(),
            "the established default preserves the takeover"
        );

        config.capture(b"gate".to_vec(), false);
        assert_eq!(config.bytes(), Some(b"gate".as_slice()));
        assert!(!config.dns_takeover());

        // A generation this start produced replaces the bytes, keeping the
        // captured takeover choice.
        config.capture(b"generated".to_vec(), config.dns_takeover());
        assert_eq!(config.bytes(), Some(b"generated".as_slice()));
        assert!(
            !config.dns_takeover(),
            "replacing the bytes must not reset the app-owned choice"
        );

        config.clear_capture();
        assert!(
            config.bytes().is_none(),
            "the active config changed; the next start recaptures"
        );
    }
}
