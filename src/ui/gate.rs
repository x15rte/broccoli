//! The busy window and the one refusal ladder every gated control reads.
//!
//! The window is the runtime's mutually-exclusive job: the shell publishes it
//! with the `Operation(Some(kind)/None)` bookends, [`BusyWindow`] carries it
//! into a frame, and [`verdict`] turns the three facts a control refuses on —
//! the core is not running, the window is held, the site's own request is in
//! flight — into one rung. A site maps the rung to its own text and takes its
//! enablement from the same verdict, so no control can paint one reason and
//! refuse for another.

use crate::rt::OperationKind;

/// The exclusive runtime job currently holding the busy window, if any: the
/// frame's copy of the fact the runtime publishes on its operation bookends.
///
/// One value per frame, derived where the frame context is assembled; screens
/// read it instead of deriving the window from their own inputs. The payload
/// is the holding kind — the transaction in flight names itself — while the
/// ladder reads only whether the window is held. `Copy`: no allocation, no
/// borrow, and every site reads the same fact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BusyWindow {
    /// The holding job, `None` at rest.
    holder: Option<OperationKind>,
}

impl BusyWindow {
    /// The window as the runtime publishes it: `Some(kind)` from the begin
    /// bookend until the job's end bookend, `None` at rest.
    pub(crate) fn from_operation(holder: Option<OperationKind>) -> Self {
        Self { holder }
    }

    /// Whether an exclusive job holds the window.
    pub(crate) fn is_held(&self) -> bool {
        self.holder.is_some()
    }
}

/// Which fact refuses a control, in the order the ladder checks them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rung {
    /// Nothing refuses the control.
    Ready,
    /// The core is not running — the site's own running fact.
    NotRunning,
    /// An exclusive job holds the busy window.
    Busy,
    /// The site's own request is still in flight.
    Pending,
}

/// One control's enablement together with the rung that refuses it, so a site
/// cannot paint a reason for a state its control is enabled in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GateVerdict {
    /// Whether the control may act this frame.
    pub(crate) enabled: bool,
    /// Why it may not, when it may not.
    pub(crate) rung: Rung,
}

/// The one refusal ladder: the core must be running, no exclusive job may hold
/// the busy window, and the site's own request must not be in flight.
///
/// Pure and total. The three facts arrive as the site itself states them, so a
/// site whose requests run regardless of the window passes `busy: false`
/// instead of inventing a rung, and a site whose own request is the window's
/// occupant — a probe occupying the window it holds — states that when it
/// builds `busy`. The rung order never varies by site.
pub(crate) fn verdict(running: bool, busy: bool, pending: bool) -> GateVerdict {
    let rung = if !running {
        Rung::NotRunning
    } else if busy {
        Rung::Busy
    } else if pending {
        Rung::Pending
    } else {
        Rung::Ready
    };
    GateVerdict {
        enabled: matches!(rung, Rung::Ready),
        rung,
    }
}

#[cfg(test)]
mod tests {
    use super::{Rung, verdict};

    #[test]
    fn ladder_refuses_by_rung_and_precedence() {
        let ready = verdict(true, false, false);
        assert_eq!(ready.rung, Rung::Ready);
        assert!(ready.enabled);

        let not_running = verdict(false, false, false);
        let busy = verdict(true, true, false);
        let pending = verdict(true, false, true);
        assert_eq!(not_running.rung, Rung::NotRunning);
        assert_eq!(busy.rung, Rung::Busy);
        assert_eq!(pending.rung, Rung::Pending);
        for refused in [not_running, busy, pending] {
            assert!(!refused.enabled, "{:?} must not act", refused.rung);
        }

        // Precedence: the phase rung outranks the window, and the window
        // outranks the site's own request.
        assert_eq!(verdict(false, true, true).rung, Rung::NotRunning);
        assert_eq!(verdict(true, true, true).rung, Rung::Busy);

        // A site whose own request occupies the window — the latency probe,
        // which runs its own isolated core — clears its own job from the busy
        // fact. That is how its pending rung wins over the busy rung the
        // window reports while the probe runs, without reordering the ladder.
        let window_held = true;
        let probe_in_flight = true;
        let probe = verdict(true, window_held && !probe_in_flight, probe_in_flight);
        assert_eq!(probe.rung, Rung::Pending);
        assert!(!probe.enabled);
    }
}
