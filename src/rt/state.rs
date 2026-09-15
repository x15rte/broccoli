//! Private flag machine of the core runtime, grouped behind an internal seam.
//!
//! The Runtime machine is single-threaded (one select loop), so every group
//! here is a plain struct with no locks. Each group owns one slice of the
//! runtime's state machine and exposes transitions; [`super::Runtime`]
//! composes the cross-group transitions (rollback > core-rollback > silence >
//! stopping > candidate > core-candidate > exit-23 > backoff) in its handlers.
//!
//! State-machine invariants (previously scattered as Runtime field comments):
//! - [`BackendState`] derives `alive`/`tun_owned` from its slot plus the
//!   started bit: a direct child is always alive; a Tun backend has an idle
//!   connected-but-not-started state. `tun_owned` describes the *current*
//!   live backend, never the requested next mode; it is cleared only after
//!   exit/forced ownership release so every intentional kill attempts
//!   RemoveInbound first.
//! - [`PendingTransition`] keeps `(candidate ∧ rollback)` unrepresentable:
//!   arming a rollback clears the candidate.
//! - [`CoreUpdatePending`] mirrors the durable core-swap marker; its retained
//!   backup is ACKed only by first readiness, and arming a rollback
//!   deliberately does not clear the candidate (durable-marker continuity).
//! - A rollback is consumed exactly once, and only on the exact confirmed
//!   old-child exit ([`RollbackGate::take_after_confirmed_exit`]).
//! - [`ExitPolicy`] reachable states are exactly {Idle, Stop, Restart,
//!   Silenced}; restart implies stopping and silence implies stopping by
//!   construction.

use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use super::Backend;
use super::CoreTransport;
use super::helper;
use super::policy::{ExitIntent, TUN_BIND_RACE_RETRIES, rollback_armable, spend_retry_attempt};
use super::supervisor;
use crate::diag::{Diag, DiagError};
use crate::i18n::Key;

/// Backoff ceiling and base for unexpected core exits.
const BACKOFF_BASE_MS: u64 = 500;
const BACKOFF_MAX_MS: u64 = 30_000;
/// A core that stayed up this long resets the backoff counter.
const UPTIME_RESET: Duration = Duration::from_secs(60);

/// Reason retained while a failed candidate is being stopped. Rollback and
/// replacement spawn happen only from the confirmed-exit path; this gate is
/// shared by the config-apply group and the core-update group because the
/// consumption rule is identical. The reason stays a [`Diag`] until the
/// display boundary, so every composition site renders it in the active
/// language.
pub(super) struct RollbackGate(Option<Diag>);

impl RollbackGate {
    const fn new() -> Self {
        Self(None)
    }

    /// Whether a rollback reason is armed.
    pub(super) fn pending(&self) -> Option<&Diag> {
        self.0.as_ref()
    }

    /// The single most load-bearing rule: a rollback is consumed exactly once,
    /// and only on the exact confirmed exit of the old child.
    pub(super) fn take_after_confirmed_exit(
        &mut self,
        old_child_exit_confirmed: bool,
    ) -> Option<Diag> {
        old_child_exit_confirmed.then(|| self.0.take()).flatten()
    }

    /// Drain the armed reason without the confirmed-exit condition (helper
    /// loss and forced-termination fallbacks that must not spawn replacements).
    pub(super) fn drain(&mut self) -> Option<Diag> {
        self.0.take()
    }
}

/// A just-committed config candidate plus its armed rollback.
///
/// Invariant: `(candidate ∧ rollback)` is unrepresentable — arming a rollback
/// clears the candidate.
pub(super) struct PendingTransition {
    candidate: bool,
    rollback: RollbackGate,
}

impl PendingTransition {
    pub(super) const fn new() -> Self {
        Self {
            candidate: false,
            rollback: RollbackGate::new(),
        }
    }

    pub(super) fn is_candidate_pending(&self) -> bool {
        self.candidate
    }

    /// Commit a freshly applied config: the current/next start carries the
    /// unproven candidate and must use the short readiness deadline.
    pub(super) fn commit_candidate(&mut self) {
        self.candidate = true;
    }

    /// Arm a rollback before terminating a candidate that failed pre-readiness.
    /// Clears the candidate so `(candidate ∧ rollback)` stays unrepresentable.
    /// Returns false when there is nothing to roll back or one is already armed
    /// (the shared [`rollback_armable`] gate).
    pub(super) fn arm_rollback(&mut self, reason: Diag) -> bool {
        if !rollback_armable(self.candidate, self.rollback.pending().is_some()) {
            return false;
        }
        self.candidate = false;
        self.rollback = RollbackGate(Some(reason));
        true
    }

    pub(super) fn rollback_pending(&self) -> Option<&Diag> {
        self.rollback.pending()
    }

    /// Clear the armed rollback (explicit Stop/Shutdown). The candidate marker
    /// deliberately survives: the next explicit Start still carries the
    /// unproven config.
    pub(super) fn clear(&mut self) {
        self.rollback = RollbackGate::new();
    }

    /// First readiness (or a completed rollback) proves the candidate moot.
    pub(super) fn clear_candidate(&mut self) {
        self.candidate = false;
    }

    /// Drain the failure for the unconfirmed-exit path: take the armed
    /// rollback, else synthesize a reason from a still-pending candidate.
    pub(super) fn drain_failure(&mut self) -> Option<Diag> {
        let failure = self.rollback.drain().or_else(|| {
            self.candidate
                .then(|| Diag::new(Key::RtFrameCandidateLostHelper))
        });
        self.candidate = false;
        failure
    }

    /// Take the armed rollback, consumed only on the confirmed old-child exit.
    pub(super) fn take_rollback_after_confirmed_exit(&mut self, confirmed: bool) -> Option<Diag> {
        self.rollback.take_after_confirmed_exit(confirmed)
    }

    /// Housekeeping's forced-termination fallback drains the armed reason
    /// without the confirmed-exit condition (never clears the candidate).
    pub(super) fn drain_rollback(&mut self) -> Option<Diag> {
        self.rollback.drain()
    }
}

/// The core-swap candidate plus its armed rollback.
///
/// The candidate mirrors the durable core-swap health marker; unlike
/// [`PendingTransition`], arming a rollback deliberately does NOT clear the
/// candidate — the durable marker must remain set until the owning backend's
/// exit is confirmed, otherwise the rollback path loses the fact that it still
/// needs to restore `core.bak`.
pub(super) struct CoreUpdatePending {
    candidate: bool,
    rollback: RollbackGate,
    /// Automatic dns-in bind-race retries spent by the current update
    /// transaction (see [`TUN_BIND_RACE_RETRIES`]); reset when an install
    /// arms a new candidate.
    bind_race_retries: u8,
    /// Last bounded loopback gRPC readiness miss for a core-update candidate.
    /// Included in the terminal update result so a real failed install is
    /// diagnosable without guessing from a generic timeout. Kept as a
    /// [`Diag`] so the composed rollback reason renders in the active
    /// language.
    last_readiness_error: Option<Diag>,
}

impl CoreUpdatePending {
    pub(super) const fn new() -> Self {
        Self {
            candidate: false,
            rollback: RollbackGate::new(),
            bind_race_retries: 0,
            last_readiness_error: None,
        }
    }

    pub(super) fn is_candidate_pending(&self) -> bool {
        self.candidate
    }

    /// A completed install arms the health-gate start; the retained backup is
    /// ACKed only by first readiness.
    pub(super) fn commit_candidate(&mut self) {
        self.candidate = true;
        self.bind_race_retries = 0;
    }

    /// Spend one automatic retry for the TUN dns-in bind race on this
    /// update's health-gate start. Returns the attempt number while inside the
    /// budget, else `None` (the caller falls back to the rollback path). Each
    /// attempt is a fresh process, so the Go map-order roll is re-drawn — see
    /// [`TUN_BIND_RACE_RETRIES`].
    pub(super) fn spend_bind_race_retry(&mut self) -> Option<u8> {
        spend_retry_attempt(&mut self.bind_race_retries, TUN_BIND_RACE_RETRIES)
    }

    /// Adopt the durable pending-swap marker recovered at startup while
    /// preserving this session's in-memory candidate.
    pub(super) fn adopt_durable_marker(&mut self, durable_pending_update: bool) {
        self.candidate =
            super::preserve_core_update_readiness(self.candidate, durable_pending_update);
    }

    /// Arm a core-update rollback before termination. Keeps the candidate set
    /// (durable-marker continuity); returns false when there is nothing to
    /// roll back or one is already armed (the shared [`rollback_armable`]
    /// gate).
    pub(super) fn arm_rollback(&mut self, reason: Diag) -> bool {
        if !rollback_armable(self.candidate, self.rollback.pending().is_some()) {
            return false;
        }
        self.rollback = RollbackGate(Some(reason));
        true
    }

    pub(super) fn rollback_pending(&self) -> Option<&Diag> {
        self.rollback.pending()
    }

    pub(super) fn last_readiness_error(&self) -> Option<&Diag> {
        self.last_readiness_error.as_ref()
    }

    /// Record a bounded readiness miss only while a candidate is pending.
    pub(super) fn record_readiness_error(&mut self, error: Diag) {
        if self.candidate {
            self.last_readiness_error = Some(error);
        }
    }

    pub(super) fn clear_last_error(&mut self) {
        self.last_readiness_error = None;
    }

    /// Durable acknowledgement of the first successful readiness probe. The
    /// retained backup is ACKed only here; a failed ACK keeps both the
    /// candidate marker and the last API error intact so the next tick retries.
    pub(super) fn ack_ready(&mut self) -> Result<(), DiagError> {
        if !self.candidate {
            self.last_readiness_error = None;
            return Ok(());
        }
        if let Err(error) = crate::sys::core_dl::acknowledge_core_health() {
            return Err(DiagError::new(Diag::new(Key::RtLogUpdateAckFailed)).caused_by(error));
        }
        self.candidate = false;
        self.last_readiness_error = None;
        Ok(())
    }

    /// Clear the armed rollback (explicit Stop/Shutdown).
    pub(super) fn clear(&mut self) {
        self.rollback = RollbackGate::new();
    }

    /// Clear the candidate without touching the gate (spawn failure, completed
    /// rollback).
    pub(super) fn clear_candidate(&mut self) {
        self.candidate = false;
    }

    /// Drain the failure for the unconfirmed-exit path: take the armed
    /// rollback, else synthesize a reason from a still-pending candidate.
    pub(super) fn drain_failure(&mut self) -> Option<Diag> {
        let failure = self.rollback.drain().or_else(|| {
            self.candidate
                .then(|| Diag::new(Key::RtFrameUpdatedCoreLostHelper))
        });
        self.candidate = false;
        failure
    }

    /// Take the armed rollback, consumed only on the confirmed old-child exit.
    pub(super) fn take_rollback_after_confirmed_exit(&mut self, confirmed: bool) -> Option<Diag> {
        self.rollback.take_after_confirmed_exit(confirmed)
    }

    /// Housekeeping's forced-termination fallback drains the armed reason
    /// without the confirmed-exit condition (never clears the candidate).
    pub(super) fn drain_rollback(&mut self) -> Option<Diag> {
        self.rollback.drain()
    }

    /// The candidate exited on its own before first readiness. This exit is
    /// already confirmed (it is the candidate's own child), so the rollback is
    /// armed unconditionally and the candidate marker is dropped.
    pub(super) fn fail_before_readiness(&mut self, reason: Diag) {
        self.candidate = false;
        self.rollback = RollbackGate(Some(reason));
    }
}

/// Stop/restart/silence policy for the in-flight expected exit.
///
/// Reachable states are exactly {Idle, Stop, Restart, Silenced}; restart
/// implies stopping and silence implies stopping by construction. Each active
/// variant records the instant termination was requested (the old
/// `stop_since`).
pub(super) enum ExitPolicy {
    Idle,
    Stop(Instant),
    Restart(Instant),
    Silenced(Instant),
}

impl ExitPolicy {
    pub(super) const fn idle() -> Self {
        Self::Idle
    }

    /// The recorded exit intent without its recorded instant, for rules that
    /// classify a confirmed exit ([`ExitIntent`]).
    pub(super) fn kind(&self) -> ExitIntent {
        match self {
            Self::Idle => ExitIntent::Idle,
            Self::Stop(_) => ExitIntent::Stop,
            Self::Restart(_) => ExitIntent::Restart,
            Self::Silenced(_) => ExitIntent::Silenced,
        }
    }

    /// A stop/restart was requested: the next exit is expected.
    pub(super) fn stopping(&self) -> bool {
        matches!(self, Self::Stop(_) | Self::Restart(_) | Self::Silenced(_))
    }

    /// A plain stop (not a restart) was requested: `stopping && !restart`.
    /// Note that a silenced exit also qualifies — the phase was already
    /// reported by the error path that armed it.
    pub(super) fn is_explicit_stop(&self) -> bool {
        matches!(self, Self::Stop(_) | Self::Silenced(_))
    }

    pub(super) fn begin_stop(&mut self, now: Instant) {
        *self = Self::Stop(now);
    }

    pub(super) fn begin_restart(&mut self, now: Instant) {
        *self = Self::Restart(now);
    }

    pub(super) fn begin_silenced_stop(&mut self, now: Instant) {
        *self = Self::Silenced(now);
    }

    /// Clear the exit policy; returns whether the in-flight exit wanted a
    /// restart (housekeeping's `wanted_restart`). One-shot: a second call
    /// returns false.
    pub(super) fn finish(&mut self) -> bool {
        let wanted_restart = matches!(self, Self::Restart(_));
        *self = Self::Idle;
        wanted_restart
    }

    /// Whether the requested termination has exceeded `timeout` since it was
    /// requested. Never true while idle.
    pub(super) fn stop_timed_out(&self, now: Instant, timeout: Duration) -> bool {
        match self {
            Self::Idle => false,
            Self::Stop(since) | Self::Restart(since) | Self::Silenced(since) => {
                now.duration_since(*since) >= timeout
            }
        }
    }
}

/// Owns the live backend slot (direct child or helper pipe), its event
/// channel, and the derived alive/tun-ownership flags.
///
/// Invariants: `alive`/`tun_owned` are derived from the slot variant plus the
/// started bit — a `Direct` backend is always alive; a `Pipe` backend has an
/// idle connected-but-not-started state. `tun_owned` describes the *current*
/// live backend, never the requested next mode, and is cleared only after
/// exit/forced ownership release so every intentional kill attempts
/// RemoveInbound first.
pub(super) struct BackendState {
    pub(super) slot: Option<Backend>,
    pub(super) events: Option<mpsc::Receiver<helper::HelperEvent>>,
    alive: bool,
    tun_owned: bool,
    /// PID of the spawned xray child this backend owns (direct spawn, or the
    /// elevated helper's reported child in TUN mode). The owning-PID check at
    /// readiness compares the loopback listener's owner against it;
    /// `None` means no child is known, so verification fails closed.
    child_pid: Option<u32>,
}

impl BackendState {
    pub(super) fn new() -> Self {
        Self {
            slot: None,
            events: None,
            alive: false,
            tun_owned: false,
            child_pid: None,
        }
    }

    /// Test-only construction of a flag-level backend proxy (no child/pipe).
    #[cfg(test)]
    pub(super) fn for_test(alive: bool, tun_owned: bool) -> Self {
        Self {
            slot: None,
            events: None,
            alive,
            tun_owned,
            child_pid: None,
        }
    }

    pub(super) fn is_alive(&self) -> bool {
        self.alive
    }

    pub(super) fn is_tun_owned(&self) -> bool {
        self.tun_owned
    }

    pub(super) fn tun_owned_or_alive(&self) -> bool {
        self.alive || self.tun_owned
    }

    pub(super) fn transport(&self) -> CoreTransport {
        CoreTransport::from_backend_tun_owned(self.tun_owned)
    }

    /// A direct child is in the slot.
    pub(super) fn is_direct(&self) -> bool {
        matches!(self.slot, Some(Backend::Direct(_)))
    }

    /// An idle or started helper pipe is in the slot.
    pub(super) fn is_pipe(&self) -> bool {
        matches!(self.slot, Some(Backend::Pipe(_)))
    }

    pub(super) fn as_backend(&self) -> Option<&Backend> {
        self.slot.as_ref()
    }

    pub(super) fn as_backend_mut(&mut self) -> Option<&mut Backend> {
        self.slot.as_mut()
    }

    pub(super) fn child_mut(&mut self) -> Option<&mut supervisor::Child> {
        match self.slot.as_mut() {
            Some(Backend::Direct(child)) => Some(child.as_mut()),
            _ => None,
        }
    }

    pub(super) fn events_mut(&mut self) -> Option<&mut mpsc::Receiver<helper::HelperEvent>> {
        self.events.as_mut()
    }

    /// A direct spawn succeeded: the child is alive by construction.
    pub(super) fn spawn_direct(&mut self, child: Box<supervisor::Child>) {
        self.child_pid = Some(child.pid());
        self.slot = Some(Backend::Direct(child));
        self.events = None;
        self.alive = true;
        self.tun_owned = false;
    }

    /// The elevated helper reported the PID of the xray child it spawned.
    pub(super) fn set_child_pid(&mut self, pid: u32) {
        self.child_pid = (pid != 0).then_some(pid);
    }

    /// PID of the child this backend owns; `None` = not (yet) known.
    pub(super) fn child_pid(&self) -> Option<u32> {
        self.child_pid
    }

    /// An authenticated helper pipe connected; the xray child is not started
    /// yet, so this is the idle connected-but-not-started state.
    pub(super) fn attach_tun(
        &mut self,
        pipe: helper::HelperPipe,
        events: mpsc::Receiver<helper::HelperEvent>,
    ) {
        self.slot = Some(Backend::Pipe(pipe));
        self.events = Some(events);
        self.alive = false;
        self.tun_owned = false;
    }

    /// The helper confirms the xray child spawned. One-shot idle→alive
    /// transition; a no-op once already alive.
    pub(super) fn mark_tun_started(&mut self) {
        if !self.alive {
            self.alive = true;
            self.tun_owned = true;
        }
    }

    /// The backend's own exit was confirmed. A direct child is reaped (dropped
    /// to close its job handle); a Tun backend returns to the idle
    /// connected-but-not-started state with the pipe retained for reuse.
    pub(super) fn confirm_exit(&mut self) {
        self.alive = false;
        self.tun_owned = false;
        self.child_pid = None;
        if matches!(self.slot, Some(Backend::Direct(_))) {
            self.slot = None; // reaps the child, closes the job handle
        }
    }

    /// A stopped helper is still an elevated process. Close its authenticated
    /// pipe before replacing the backend with a direct child.
    pub(super) fn release_pipe(&mut self) {
        if matches!(self.slot, Some(Backend::Pipe(_))) {
            self.slot = None;
            self.events = None;
        }
    }

    /// Drop the backend and every handle it owns; clears all derived flags.
    pub(super) fn force_release(&mut self) {
        self.slot = None;
        self.events = None;
        self.alive = false;
        self.tun_owned = false;
        self.child_pid = None;
    }
}

/// Unexpected-exit backoff and the stability clock that resets it.
pub(super) struct Backoff {
    attempt: u32,
    since: Option<Instant>,
}

impl Backoff {
    pub(super) const fn new() -> Self {
        Self {
            attempt: 0,
            since: None,
        }
    }

    /// An explicit Start resets the counter.
    pub(super) fn reset(&mut self) {
        self.attempt = 0;
    }

    /// A new start clears the stability clock.
    pub(super) fn reset_since(&mut self) {
        self.since = None;
    }

    /// First readiness starts the stability clock.
    pub(super) fn mark_ready(&mut self, now: Instant) {
        self.since = Some(now);
    }

    /// Reset the counter after a stable minute (called from stats_poll).
    pub(super) fn maybe_reset(&mut self, now: Instant) {
        if self.attempt > 0
            && self
                .since
                .is_some_and(|since| now.duration_since(since) >= UPTIME_RESET)
        {
            self.attempt = 0;
        }
    }

    /// Compute the next exponential backoff delay for an unexpected exit.
    /// `jitter_ms` comes from the runtime's RNG; a core that stayed up for
    /// [`UPTIME_RESET`] resets the counter first. Returns the attempt index
    /// (0-based, for `CorePhase::Backoff`) and the full delay in milliseconds.
    pub(super) fn next(&mut self, now: Instant, jitter_ms: u64) -> (u32, u64) {
        let stable = self
            .since
            .is_some_and(|since| now.duration_since(since) >= UPTIME_RESET);
        if stable {
            self.attempt = 0;
        }
        let attempt = self.attempt;
        let base_ms = BACKOFF_BASE_MS
            .checked_shl(attempt)
            .unwrap_or(u64::MAX)
            .min(BACKOFF_MAX_MS);
        self.attempt = attempt.saturating_add(1);
        (attempt, base_ms + jitter_ms)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        BACKOFF_BASE_MS, BackendState, Backoff, CoreUpdatePending, ExitPolicy, PendingTransition,
        UPTIME_RESET,
    };
    use crate::diag::Diag;
    use crate::i18n::Key;

    /// A rollback reason carrying `key`; the states compare reasons by key.
    fn reason(key: Key) -> Diag {
        Diag::new(key)
    }

    // Migrated from rt/mod.rs with bodies nearly identical, exercising the
    // group transitions instead of the free functions.

    #[test]
    fn candidate_failure_queues_exactly_one_post_exit_rollback() {
        let mut transition = PendingTransition::new();
        transition.commit_candidate();
        assert!(transition.arm_rollback(reason(Key::RtFrameCandidateExited)));
        assert!(!transition.is_candidate_pending());
        assert_eq!(
            transition.rollback_pending().map(Diag::key),
            Some(Key::RtFrameCandidateExited)
        );
        assert!(
            !transition.arm_rollback(reason(Key::RtFrameUpdatedCoreExited)),
            "an armed rollback must reject a second arm"
        );
        assert_eq!(
            transition.rollback_pending().map(Diag::key),
            Some(Key::RtFrameCandidateExited)
        );
        assert_eq!(
            transition.take_rollback_after_confirmed_exit(false),
            None,
            "rollback must remain pending before old-child exit"
        );
        assert_eq!(
            transition
                .take_rollback_after_confirmed_exit(true)
                .map(|reason| reason.key()),
            Some(Key::RtFrameCandidateExited)
        );
        assert_eq!(
            transition.take_rollback_after_confirmed_exit(true),
            None,
            "confirmed exit consumes the one rollback exactly once"
        );
    }

    #[test]
    fn core_update_failure_queues_one_confirmed_exit_rollback() {
        let mut update = CoreUpdatePending::new();
        update.commit_candidate();
        assert!(update.arm_rollback(reason(Key::RtFrameUpdatedCoreReadyTimeout)));
        assert!(
            update.is_candidate_pending(),
            "timeout must not clear the health marker"
        );
        assert!(!update.arm_rollback(reason(Key::RtFrameCandidateReadyTimeout)));
        assert_eq!(
            update.take_rollback_after_confirmed_exit(false),
            None,
            "the update must stay marked unhealthy until direct-child exit"
        );
        assert_eq!(
            update
                .take_rollback_after_confirmed_exit(true)
                .map(|reason| reason.key()),
            Some(Key::RtFrameUpdatedCoreReadyTimeout)
        );
    }

    #[test]
    fn pending_transition_invariants() {
        let mut transition = PendingTransition::new();
        assert!(!transition.is_candidate_pending());
        assert!(
            !transition.arm_rollback(reason(Key::RtFrameCandidateExited)),
            "arming without a candidate is refused"
        );
        // `(candidate ∧ rollback)` unrepresentable: arming clears the candidate.
        transition.commit_candidate();
        assert!(transition.is_candidate_pending());
        assert!(transition.arm_rollback(reason(Key::RtFrameCandidateReadyTimeout)));
        assert!(!transition.is_candidate_pending());
        assert!(transition.rollback_pending().is_some());
        // clear() drops only the rollback; the candidate marker survives Stop.
        transition.commit_candidate();
        transition.clear();
        assert!(transition.is_candidate_pending());
        assert!(transition.rollback_pending().is_none());
        // drain_failure consumes either the armed reason or the candidate.
        transition.commit_candidate();
        assert_eq!(
            transition.drain_failure().map(|reason| reason.key()),
            Some(Key::RtFrameCandidateLostHelper)
        );
        assert!(!transition.is_candidate_pending());
        transition.commit_candidate();
        transition.arm_rollback(reason(Key::RtFrameCandidateExited));
        assert_eq!(
            transition.drain_failure().map(|reason| reason.key()),
            Some(Key::RtFrameCandidateExited)
        );
    }

    #[test]
    fn exit_policy_reachability_sweep() {
        let now = Instant::now();
        let mut policy = ExitPolicy::idle();
        assert!(!policy.stopping());
        assert!(!policy.is_explicit_stop());

        policy.begin_stop(now);
        assert!(policy.stopping());
        assert!(policy.is_explicit_stop());

        policy.begin_restart(now);
        assert!(
            policy.stopping(),
            "restart implies stopping by construction"
        );
        assert!(
            !policy.is_explicit_stop(),
            "a restart is not an explicit stop"
        );

        policy.begin_silenced_stop(now);
        assert!(
            policy.stopping(),
            "silence implies stopping by construction"
        );
        assert!(
            policy.is_explicit_stop(),
            "a silenced stop is still an explicit (non-restart) stop"
        );
    }

    #[test]
    fn exit_policy_finish_returns_wanted_restart_exactly_once() {
        let now = Instant::now();
        let mut policy = ExitPolicy::idle();
        assert!(!policy.finish(), "idle has no verdict");
        policy.begin_stop(now);
        assert!(
            !policy.finish(),
            "a plain stop must not report wanted-restart"
        );
        policy.begin_restart(now);
        assert!(policy.finish(), "finish must report the wanted restart");
        assert!(!policy.finish(), "the verdict is consumed exactly once");
        assert!(!policy.stopping(), "finish clears the exit policy");
    }

    #[test]
    fn exit_policy_stop_timed_out() {
        let now = Instant::now();
        let timeout = Duration::from_secs(5);
        let mut policy = ExitPolicy::idle();
        assert!(!policy.stop_timed_out(now, timeout), "idle never times out");
        policy.begin_stop(now);
        assert!(!policy.stop_timed_out(now + Duration::from_secs(4), timeout));
        assert!(policy.stop_timed_out(now + Duration::from_secs(5), timeout));
        policy.begin_restart(now);
        assert!(policy.stop_timed_out(now + Duration::from_secs(5), timeout));
        policy.begin_silenced_stop(now);
        assert!(policy.stop_timed_out(now + Duration::from_secs(5), timeout));
    }

    #[test]
    fn backend_confirm_exit_maps_tun_alive_to_idle() {
        // Tun-alive proxy: confirm_exit must clear the ownership flags while
        // retaining the (untestable here) pipe slot for reuse.
        let mut backend = BackendState::for_test(true, true);
        assert!(backend.is_alive());
        assert!(backend.is_tun_owned());
        assert!(backend.tun_owned_or_alive());
        backend.confirm_exit();
        assert!(!backend.is_alive());
        assert!(!backend.is_tun_owned());
        assert!(!backend.tun_owned_or_alive());
    }

    #[test]
    fn backend_confirm_exit_maps_direct_to_empty() {
        // Direct-alive proxy: confirm_exit must clear the alive flags and
        // leave the slot empty (a real `supervisor::Child` has no unit-test
        // constructor, so the reap itself is exercised by the runtime suite).
        let mut backend = BackendState::for_test(true, false);
        assert!(backend.is_alive());
        assert!(!backend.is_tun_owned());
        backend.confirm_exit();
        assert!(!backend.is_alive());
        assert!(!backend.is_tun_owned());
        assert!(backend.as_backend().is_none());
    }

    #[test]
    fn mark_tun_started_flips_only_idle_to_alive() {
        let mut backend = BackendState::for_test(false, false);
        assert!(!backend.is_alive());
        assert!(!backend.is_tun_owned());
        backend.mark_tun_started();
        assert!(backend.is_alive());
        assert!(backend.is_tun_owned());
        backend.mark_tun_started();
        assert!(
            backend.is_alive(),
            "mark is a one-shot idle->alive transition"
        );
        let mut live = BackendState::for_test(true, true);
        live.mark_tun_started();
        assert!(live.is_alive());
        assert!(live.is_tun_owned());
    }

    #[test]
    fn backoff_next_and_maybe_reset() {
        let now = Instant::now();
        let mut backoff = Backoff::new();
        let (attempt, delay) = backoff.next(now, 0);
        assert_eq!(attempt, 0);
        assert_eq!(delay, BACKOFF_BASE_MS, "first attempt is the base delay");
        let (attempt, delay) = backoff.next(now, 0);
        assert_eq!(attempt, 1);
        assert_eq!(delay, BACKOFF_BASE_MS * 2, "second attempt doubles");
        // Jitter lands inside the returned delay.
        let (attempt, delay) = backoff.next(now, 249);
        assert_eq!(attempt, 2);
        assert_eq!(delay, BACKOFF_BASE_MS * 4 + 249);

        // maybe_reset: with a running stability clock, only a stable minute
        // clears the counter.
        backoff.mark_ready(now);
        backoff.maybe_reset(now + UPTIME_RESET - Duration::from_millis(1));
        assert_eq!(
            backoff.next(now, 0).0,
            3,
            "sub-minute uptime must not reset"
        );
        backoff.maybe_reset(now + UPTIME_RESET);
        assert_eq!(
            backoff.next(now, 0).0,
            0,
            "stable minute resets the counter"
        );

        // next() also resets when the stability clock has run out.
        let mut backoff = Backoff::new();
        backoff.mark_ready(now);
        assert_eq!(backoff.next(now, 0).0, 0);
        assert_eq!(backoff.next(now, 0).0, 1);
        let (attempt, _) = backoff.next(now + UPTIME_RESET, 0);
        assert_eq!(attempt, 0, "stable uptime resets before the next delay");
    }
}
