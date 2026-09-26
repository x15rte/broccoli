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

use std::time::Instant;

use super::CorePhase;
use super::dns_in;
use super::policy::CoreExitFacts;
use super::readiness::Readiness;
use super::state::{BackendState, Backoff, CoreUpdatePending, ExitPolicy, PendingTransition};
use crate::diag::Diag;

/// One runtime's lifecycle state.
pub(super) struct Lifecycle {
    /// Owns the live backend slot (direct child or helper pipe), its event
    /// channel, and the derived alive/tun-ownership flags.
    pub(super) backend: BackendState,
    /// Stop/restart/silence policy for the in-flight expected exit.
    pub(super) exit_policy: ExitPolicy,
    /// A just-committed config candidate plus its armed rollback.
    pub(super) pending_transition: PendingTransition,
    /// The exact config content a helper start must stage. A start that
    /// generated its configuration captures those bytes directly (regenerate,
    /// gate, rollback replay); a start carrying a fresh apply's committed
    /// artefact keeps the bytes the apply gate validated. The elevated helper
    /// never re-reads the user-writable active path, so a same-user swap after
    /// capture cannot reach the stage; `None` means no start has captured yet.
    pub(super) helper_config_bytes: Option<Vec<u8>>,
    /// The core-swap candidate (durable health marker) plus its rollback.
    pub(super) core_update: CoreUpdatePending,
    /// Unexpected-exit backoff and the stability clock that resets it.
    pub(super) backoff: Backoff,
    pub(super) phase: CorePhase,
    pub(super) requested_tun_mode: bool,
    pub(super) shutting_down: bool,
    /// The next start is a completed core update's health gate: it runs the
    /// app-owned configuration, never the user's profiles, so the gate
    /// answers only "does this binary run and answer". Armed when an install
    /// lands and when a durable pending-swap marker is adopted; consumed by
    /// the start it belongs to. A fresh apply supersedes it — the user's own
    /// start then carries the update's verdict.
    pub(super) update_gate_start: bool,
    /// The next start replays the restored last-known-good artefact instead of
    /// regenerating, because regeneration would reproduce the configuration a
    /// rolled-back candidate failed on. Set only where a deliberate rollback
    /// completed; the replay checks the artefact's stamp first and regenerates
    /// when it names another build.
    pub(super) replay_after_rollback: bool,
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
    /// The in-tun DNS listener this start must add to its running core,
    /// armed from the config the core runs. `None` means nothing is pending:
    /// the add was not needed, succeeded, or spent its attempt budget.
    pub(super) dns_in_listener: Option<dns_in::Listener>,
    /// Add attempts spent for `dns_in_listener`, capped through the shared
    /// [`spend_retry_attempt`] rule ([`DNS_IN_ADD_ATTEMPTS`]).
    pub(super) dns_in_attempts: u8,
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
            pending_transition: PendingTransition::new(),
            helper_config_bytes: None,
            core_update: CoreUpdatePending::new(),
            backoff: Backoff::new(),
            phase: CorePhase::Stopped,
            requested_tun_mode: false,
            shutting_down: false,
            update_gate_start: false,
            replay_after_rollback: false,
            gate_backend_alive: false,
            candidate_boot_retries: 0,
            pending_restart: None,
            dns_in_listener: None,
            dns_in_attempts: 0,
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
            code,
        }
    }

    /// The elevated helper reports a state and the PID of the child it
    /// spawned: the spawn confirmation arms the readiness clock, and the PID
    /// is what the owning-PID check compares against. Other states are
    /// informational; an unknown (0) PID never records.
    pub(super) fn on_helper_state(&mut self, state: &str, pid: u32) {
        if state == "starting" || state == "running" {
            self.backend.set_child_pid(pid);
        }
        self.readiness.on_helper_state(
            state,
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
