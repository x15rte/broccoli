//! Screen background requests: one state machine for every off-frame job a
//! screen starts — worker threads and runtime reply channels alike.
//!
//! Screens used to hand-roll the same three-arm receive
//! (`Empty` / result / `Disconnected`) over `std::sync::mpsc` and
//! `tokio::sync::oneshot`, with their own pending/join/cancel fields and
//! worker-exit arms. The receive and the producer-exit handling now exist
//! once, here; a screen declares only its payload type, the delivery rule
//! and (in its poll's exit arm) the localized text for a producer that
//! exited without a terminal.
//!
//! A request is started in one of three shapes:
//!
//! - [`Request::worker`] runs a closure on a named thread over the
//!   request's own channel and pokes one repaint when a value lands.
//!   [`Request::cancel`] flips the worker's stop flag first, so a
//!   cooperative worker can abandon the run; dropping the receiver makes a
//!   late delivery find no listener.
//! - [`Request::reply`] adopts the reply channel a runtime command will
//!   answer (the `CoreCmd` oneshot pairs). A reply request has nothing to
//!   cancel: dropping the receiver is the cancel, and the runtime's reply
//!   send then fails.
//!
//! [`Request::park_in_shell`] declares the third shape: the outcome is not
//! carried by a screen-owned channel but parked by the shell in a
//! [`ParkedSlot`] and surfaced through `UiCtx` for any consumer (the
//! latency probe's single feedback slot).
//!
//! Polling is per frame and non-blocking. [`Request::poll`] reports a
//! producer exit exactly once and clears the request; a request that
//! accepted its terminal is idle again, so no screen can re-read a spent
//! channel.

use egui::Context;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::oneshot;

/// Where a request's outcome waits for its consumer.
///
/// The declaration is per request and is what the terminal paths read
/// ([`Request::poll`] serves screen-scoped channels,
/// [`Request::take_parked`] the shell's slot); no request changes its
/// delivery behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Delivery {
    /// The receiver lives on the screen: a result that lands while the
    /// user is elsewhere waits in the channel and surfaces on return.
    ScreenScoped,
    /// The shell owns the slot (a [`ParkedSlot`]) and surfaces the outcome
    /// through `UiCtx`, for any consumer.
    ShellParked,
}

/// The shell-owned slot a [`Delivery::ShellParked`] request's outcome
/// lands in — single-slot by construction, like the shell's probe-feedback
/// slot.
pub(crate) struct ParkedSlot<T> {
    value: Option<T>,
}

impl<T> ParkedSlot<T> {
    /// Park one outcome for its request to adopt.
    pub(crate) fn park(&mut self, value: T) {
        self.value = Some(value);
    }

    /// Take the parked outcome, if any.
    pub(crate) fn take(&mut self) -> Option<T> {
        self.value.take()
    }
}

impl<T> Default for ParkedSlot<T> {
    fn default() -> Self {
        Self { value: None }
    }
}

/// One request's terminal, reported by [`Request::poll`] exactly once.
#[derive(Debug)]
pub(crate) enum Terminal<T> {
    /// The worker returned a value, or the runtime answered the reply.
    Answered(T),
    /// The producer exited without a terminal (a panicked worker, or a
    /// dropped reply sender). The call site declares the handling: a
    /// localized message, or a silent exit where its own recovery policy
    /// applies.
    Exited,
}

enum State<T> {
    Idle,
    /// A worker thread's channel plus its cooperative stop flag.
    Worker {
        stop: Arc<AtomicBool>,
        rx: oneshot::Receiver<T>,
    },
    /// A runtime job's reply channel.
    Reply(oneshot::Receiver<T>),
    /// Shell-parked: no screen-owned channel; the shell's [`ParkedSlot`]
    /// carries the outcome.
    Parked,
}

/// One in-flight request parameterized by its payload type.
pub(crate) struct Request<T> {
    delivery: Delivery,
    state: State<T>,
}

impl<T> Default for Request<T> {
    fn default() -> Self {
        Self {
            delivery: Delivery::ScreenScoped,
            state: State::Idle,
        }
    }
}

impl<T: Send + 'static> Request<T> {
    /// Start a worker-thread request. `job` runs on the named thread and
    /// receives the request's stop flag; its `Some` return value is
    /// delivered over the request's channel and pokes one repaint, while
    /// `None` (a run the flag told to abandon) delivers nothing. The
    /// caller maps the spawn failure to its own localized message.
    pub(crate) fn worker<F>(name: &str, repaint: &Context, job: F) -> Result<Self, std::io::Error>
    where
        F: FnOnce(&AtomicBool) -> Option<T> + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = oneshot::channel();
        let worker_stop = Arc::clone(&stop);
        let repaint = repaint.clone();
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                if let Some(value) = job(&worker_stop) {
                    let _ = tx.send(value);
                    repaint.request_repaint();
                }
            })?;
        Ok(Self {
            delivery: Delivery::ScreenScoped,
            state: State::Worker { stop, rx },
        })
    }
}

impl<T> Request<T> {
    /// Adopt the reply channel a runtime job will answer: the terminal is
    /// delivered on `rx`, and dropping the receiver is the cancel.
    pub(crate) fn reply(rx: oneshot::Receiver<T>) -> Self {
        Self {
            delivery: Delivery::ScreenScoped,
            state: State::Reply(rx),
        }
    }

    /// Start a shell-parked request: the caller sends the runtime command,
    /// the shell parks the outcome in its [`ParkedSlot`], and
    /// [`Request::take_parked`] adopts it.
    pub(crate) fn park_in_shell() -> Self {
        Self {
            delivery: Delivery::ShellParked,
            state: State::Parked,
        }
    }

    /// True while a terminal can still arrive or be adopted.
    pub(crate) fn is_pending(&self) -> bool {
        !matches!(self.state, State::Idle)
    }

    /// Poll one frame. `None` means idle or still in flight; the first
    /// terminal clears the request and is returned exactly once.
    pub(crate) fn poll(&mut self) -> Option<Terminal<T>> {
        if self.delivery != Delivery::ScreenScoped {
            // A shell-parked request owns no channel; its terminal is
            // adopted with `take_parked`.
            return None;
        }
        let rx = match &mut self.state {
            State::Idle | State::Parked => return None,
            State::Worker { rx, .. } | State::Reply(rx) => rx,
        };
        let terminal = match rx.try_recv() {
            Ok(value) => Terminal::Answered(value),
            Err(oneshot::error::TryRecvError::Empty) => return None,
            Err(oneshot::error::TryRecvError::Closed) => Terminal::Exited,
        };
        self.state = State::Idle;
        Some(terminal)
    }

    /// Drop the request: a worker request flips its stop flag first (a
    /// cooperative worker abandons the run), and either family stops
    /// listening, so no terminal can land afterwards.
    pub(crate) fn cancel(&mut self) {
        if let State::Worker { stop, .. } = &self.state {
            stop.store(true, Ordering::Relaxed);
        }
        self.state = State::Idle;
    }

    /// Adopt the parked outcome of a [`Delivery::ShellParked`] request:
    /// `Some` once the shell's slot holds it, finishing the request.
    pub(crate) fn take_parked(&mut self, slot: &mut ParkedSlot<T>) -> Option<T> {
        if self.delivery != Delivery::ShellParked || !matches!(self.state, State::Parked) {
            return None;
        }
        let value = slot.take()?;
        self.state = State::Idle;
        Some(value)
    }
}

impl<T> Drop for Request<T> {
    fn drop(&mut self) {
        // Dropping a pending worker request cancels like [`Request::cancel`]:
        // the thread observes the stop flag and abandons its run instead of
        // finishing against a receiver that no longer exists. A dropped
        // reply request stops listening the same way a `cancel` does.
        if let State::Worker { stop, .. } = &self.state {
            stop.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Delivery, ParkedSlot, Request, Terminal};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    use tokio::sync::oneshot;

    /// Poll until a terminal lands or the deadline passes.
    fn poll_until_terminal<T>(request: &mut Request<T>) -> Terminal<T> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(terminal) = request.poll() {
                return terminal;
            }
            assert!(
                Instant::now() < deadline,
                "the request did not produce a terminal in time"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn a_reply_request_pends_until_the_answer_lands() {
        let (tx, rx) = oneshot::channel::<u8>();
        let mut request = Request::reply(rx);
        assert_eq!(request.delivery, Delivery::ScreenScoped);
        assert!(request.is_pending());
        assert!(request.poll().is_none(), "no terminal before the answer");

        tx.send(7).expect("the reply sender must have a listener");
        assert!(matches!(request.poll(), Some(Terminal::Answered(7))));
        assert!(
            !request.is_pending() && request.poll().is_none(),
            "an answered request must clear and never re-report"
        );
    }

    #[test]
    fn a_dropped_reply_sender_reports_the_exit_exactly_once() {
        // The runtime went away without a terminal: the screen's poll arm
        // declares the text for this exit (its localized
        // worker-exited-without-result message) and must see it once.
        let (tx, rx) = oneshot::channel::<u8>();
        let mut request = Request::reply(rx);
        drop(tx);

        assert!(matches!(request.poll(), Some(Terminal::Exited)));
        assert!(
            !request.is_pending() && request.poll().is_none(),
            "a vanished producer must clear the request and report once"
        );
    }

    #[test]
    fn a_worker_request_delivers_its_return_value_and_pokes_a_repaint() {
        let ctx = egui::Context::default();
        let mut request = Request::worker("broccoli-test-request", &ctx, |_| Some(11))
            .expect("the test worker must spawn");

        assert!(request.is_pending());
        assert!(matches!(
            poll_until_terminal(&mut request),
            Terminal::Answered(11)
        ));
        assert!(!request.is_pending());
        // The delivery pokes the repaint the per-frame poll depends on; the
        // poke happens on the worker thread right after the send.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ctx.has_requested_repaint() {
            assert!(Instant::now() < deadline, "the worker must poke a repaint");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn a_worker_that_exits_without_delivering_reports_the_exit() {
        // A panicked worker (the one producer that can vanish without a
        // terminal) must not leave the request pending forever: the exit
        // lands once, so the screen's declared handling runs and its
        // cadence resumes.
        let mut request =
            Request::<u8>::worker("broccoli-test-panicking", &egui::Context::default(), |_| {
                panic!("worker died before delivering")
            })
            .expect("the test worker must spawn");

        assert!(matches!(
            poll_until_terminal(&mut request),
            Terminal::Exited
        ));
        assert!(!request.is_pending());
    }

    #[test]
    fn cancel_flips_the_worker_stop_flag_and_drops_the_listener() {
        let observed = Arc::new(AtomicBool::new(false));
        let worker_observed = Arc::clone(&observed);
        let mut request = Request::worker(
            "broccoli-test-cancelled",
            &egui::Context::default(),
            move |stop| {
                worker_observed.store(true, Ordering::Relaxed);
                // Deliver only once the run is not cancelled: the cancel below
                // must reach the flag and the request must discard any late
                // value.
                (!stop.load(Ordering::Relaxed)).then_some(3)
            },
        )
        .expect("the test worker must spawn");
        assert!(request.is_pending());

        request.cancel();

        assert!(!request.is_pending());
        assert!(
            request.poll().is_none(),
            "a cancelled request has no terminal"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while !observed.load(Ordering::Relaxed) {
            assert!(
                Instant::now() < deadline,
                "the worker must have run before the cancel was observed"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // The worker's delivery finds a dropped receiver: nothing lands,
        // even though the worker ran to completion.
        std::thread::sleep(Duration::from_millis(10));
        assert!(request.poll().is_none());
    }

    #[test]
    fn a_parked_request_adopts_the_shell_slot_once() {
        let mut request = Request::<u8>::park_in_shell();
        assert_eq!(request.delivery, Delivery::ShellParked);
        assert!(request.is_pending());
        assert!(
            request.poll().is_none(),
            "a parked request has no channel to poll"
        );

        let mut slot = ParkedSlot::default();
        assert!(request.take_parked(&mut slot).is_none(), "empty slot");
        slot.park(5);
        assert_eq!(request.take_parked(&mut slot), Some(5));
        assert!(
            !request.is_pending() && request.take_parked(&mut slot).is_none(),
            "a parked request adopts its outcome once"
        );
    }

    #[test]
    fn a_parked_request_ignores_a_slot_that_lands_after_its_cancel() {
        let mut request = Request::<u8>::park_in_shell();
        request.cancel();
        let mut slot = ParkedSlot::default();
        slot.park(9);
        assert!(
            request.take_parked(&mut slot).is_none(),
            "a cancelled request must not adopt a later outcome"
        );
    }
}
