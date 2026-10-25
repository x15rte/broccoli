//! Cooperative cancellation shared by the runtime's workers.
//!
//! One type for both sides of the seam: the job registry (a synchronous
//! context) only ever raises it, while a worker awaits it — between units of
//! blocking work, or inside a `tokio::select!` — instead of spinning a
//! sleep-poll loop over a flag. Built on `tokio::sync::watch`, so raising is
//! synchronous and non-blocking and a waiter wakes the moment the value
//! flips.
//!
//! Cloning is cheap (one sender handle), and the value is stored even with no
//! waiter subscribed, so a cancel raised before a worker starts waiting is
//! still observed.

use tokio::sync::watch;

/// One operation's cooperative cancel signal.
#[derive(Clone, Debug)]
pub struct Cancel {
    tx: watch::Sender<bool>,
}

impl Cancel {
    /// A fresh, not-yet-cancelled signal.
    pub fn new() -> Self {
        Cancel {
            tx: watch::channel(false).0,
        }
    }

    /// Raise the cancel. Synchronous and non-blocking, so a registry or
    /// GUI-thread path can raise it without an executor.
    ///
    /// Uses `send_replace`, not `send`: the value must land even when no
    /// waiter is subscribed yet (a record cancelled before its worker starts),
    /// and `send` would refuse that and drop the raise.
    pub fn cancel(&self) {
        self.tx.send_replace(true);
    }

    /// Whether the cancel was raised, for a synchronous boundary between
    /// blocking attempts that cannot await.
    pub fn is_cancelled(&self) -> bool {
        *self.tx.borrow()
    }

    /// Resolves once the cancel was raised, and only then. Cancel-safe in
    /// `tokio::select!`: dropping the future drops its subscription and loses
    /// nothing, because the value lives in the signal.
    pub async fn cancelled(&self) {
        let mut rx = self.tx.subscribe();
        while !*rx.borrow_and_update() {
            if rx.changed().await.is_err() {
                // Every sender is gone, so nobody can raise the cancel any
                // more; the operation waiting here was abandoned, and holding
                // the task open would leak it.
                return;
            }
        }
    }
}

impl Default for Cancel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Cancel;
    use std::time::Duration;

    /// A cancel raised before anyone waits must still be observed: the
    /// registry raises it on a record whose worker has not started, and the
    /// worker's later wait has to resolve immediately rather than hang.
    #[tokio::test(flavor = "current_thread")]
    async fn a_cancel_raised_before_the_wait_is_still_observed() {
        let cancel = Cancel::new();
        assert!(!cancel.is_cancelled());
        cancel.cancel();
        assert!(cancel.is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), cancel.cancelled())
            .await
            .expect("a pre-raised cancel must resolve a later wait");
    }

    /// The async half: a worker parked in `cancelled` wakes on the raise, and
    /// the signal is shared between clones.
    #[tokio::test(flavor = "current_thread")]
    async fn a_waiting_worker_wakes_on_the_raise() {
        let cancel = Cancel::new();
        let worker = cancel.clone();
        let waiter = tokio::spawn(async move { worker.cancelled().await });
        tokio::task::yield_now().await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("the waiter must wake on the raise")
            .expect("the waiter task joins");
    }
}
