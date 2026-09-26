//! The readiness clock of one start, and the verdict on the process that
//! answers it.
//!
//! The clock bounds the wait between "a start was accepted" and "the core
//! answers the control-plane RPCs". A direct start arms it right after the
//! child spawns. A TUN start does not: the elevated helper may still be
//! staging, validating the configuration (up to `CONFIG_TEST_TIMEOUT`) and
//! copying payloads before the xray child exists, so the clock stays disarmed
//! until the helper reports the spawn. The arming and firing decisions
//! themselves live in [`super::policy`]; this type owns the state they act on.

use std::time::Instant;

use super::policy::{helper_state_arms_readiness, readiness_deadline_reached, readiness_timeout};

/// The readiness clock. `deadline` is `Some` while armed, `None` while
/// disarmed (TUN staging, or nothing started yet).
pub(super) struct Readiness {
    deadline: Option<Instant>,
}

/// What the clock says at one instant.
pub(super) enum Poll {
    /// Disarmed: nothing started, or the start is still staging in the
    /// elevated helper.
    Unarmed,
    /// Armed, and the deadline is still ahead.
    Pending,
    /// Armed, and the deadline has been reached. The boundary counts as
    /// fired, so a poll that lands exactly on it must handle the timeout.
    Fired,
}

impl Readiness {
    pub(super) fn new() -> Self {
        Self { deadline: None }
    }

    /// Arm for a start. A TUN start that owns the backend never takes the
    /// short applied-candidate clock: its wintun adapter create legitimately
    /// waits out the previous session's teardown, and killing a core stuck
    /// mid-create wedges PnP device creation for every wintun user.
    pub(super) fn arm(&mut self, applied_candidate_pending: bool, tun_owned: bool) {
        self.deadline =
            Some(Instant::now() + readiness_timeout(applied_candidate_pending, tun_owned));
    }

    /// Disarm. A TUN start calls this between accepting the helper pipe and
    /// the helper's spawn confirmation.
    pub(super) fn defer(&mut self) {
        self.deadline = None;
    }

    /// Take one helper state report. Only the spawn confirmation arms the
    /// clock, and only while it is disarmed; the other states are
    /// informational.
    pub(super) fn on_helper_state(
        &mut self,
        state: &str,
        applied_candidate_pending: bool,
        tun_owned: bool,
    ) {
        if helper_state_arms_readiness(state, self.armed()) {
            self.arm(applied_candidate_pending, tun_owned);
        }
    }

    pub(super) fn armed(&self) -> bool {
        self.deadline.is_some()
    }

    /// What the clock says now.
    pub(super) fn poll(&self, now: Instant) -> Poll {
        match self.deadline {
            None => Poll::Unarmed,
            Some(deadline) if readiness_deadline_reached(deadline, now) => Poll::Fired,
            Some(_) => Poll::Pending,
        }
    }

    /// The armed deadline, for tests that compare it against the instant a
    /// start observed.
    #[cfg(test)]
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Arm at an explicit instant, for tests that need a spent clock without
    /// waiting it out.
    #[cfg(test)]
    pub(super) fn arm_at(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
    }
}

/// Whether the loopback listener on `api_port` is owned by `pid`.
///
/// The readiness probe trusts the control-plane responder only when the
/// process behind it is the child this start spawned: a same-user process
/// could answer `get_sys_stats` on an enumerated port, and a verified
/// responder is what clears the rollback gate and acknowledges the core-update
/// backup. A missing process table or an unknown owner is never trust.
pub(super) fn api_listener_owned_by(api_port: u16, pid: u32) -> bool {
    crate::sys::net_table::tcp_table().is_some_and(|rows| {
        crate::sys::net_table::loopback_api_listener_owned_by(&rows, api_port, pid)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_deferred_clock_stays_unarmed_however_late_the_poll_is() {
        let mut clock = Readiness::new();
        clock.arm(false, false);
        clock.defer();
        assert!(
            matches!(
                clock.poll(Instant::now() + Duration::from_secs(3600)),
                Poll::Unarmed
            ),
            "a deferred clock must not fire, the deadline of an earlier phase is not live"
        );
    }

    #[test]
    fn arming_again_replaces_the_deadline_of_the_previous_phase() {
        let mut clock = Readiness::new();
        clock.arm_at(Instant::now() - Duration::from_millis(1));
        assert!(matches!(clock.poll(Instant::now()), Poll::Fired));
        clock.defer();
        clock.arm(false, false);
        assert!(
            matches!(clock.poll(Instant::now()), Poll::Pending),
            "the spent deadline of the previous phase must not survive a re-arm"
        );
    }

    #[test]
    fn the_spawn_confirmation_arms_once_and_the_armed_clock_ignores_later_states() {
        let mut clock = Readiness::new();
        clock.defer();
        clock.on_helper_state("starting", false, true);
        assert!(clock.armed());
        let armed = clock.deadline();
        clock.on_helper_state("running", false, true);
        assert_eq!(
            clock.deadline(),
            armed,
            "an informational state must not re-arm or extend the clock"
        );
    }
}
