//! The runtime → GUI event stream: the one place that knows what happens to
//! an event, and to a core log line, when the shell is not draining.
//!
//! Every event the runtime publishes crosses this seam, so the policy lives
//! here instead of in the bodies of the modules that emit:
//!
//! - **Volatile events** are dropped when the bounded channel is full: they
//!   are superseded by a later event of the same class (stats ticks,
//!   observatory snapshots, download progress) or are diagnostic text whose
//!   loss is already tolerated. Dropping cannot change what the shell shows
//!   for longer than one tick.
//! - **Lifecycle, terminal and correlated events** wait one bounded drain
//!   window first, so a momentarily full channel (a batch drain in progress)
//!   never loses a phase, a verdict or a reply. Only a permanently undrained
//!   channel — the shell is shutting down — loses them, where nothing is
//!   observable anyway.
//! - **Core output lines** are coalesced rather than dropped: while the
//!   channel rejects them, the gate counts them and delivers one summary as
//!   soon as the channel accepts again, so a flooding core cannot grow the
//!   queue without bound (CWE-400/770) and the user still learns that lines
//!   were withheld.
//!
//! A repaint is requested after every accepted event, so the shell's next
//! frame drains the batch.

use crate::diag::Diag;
use crate::i18n::Key;
use crate::rt::jobs::JobKind;
use crate::rt::{AppMessage, CoreEvt, DownloadState};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a lifecycle event waits for room on a full channel before it is
/// dropped. The GUI drains every frame in normal operation, so this covers a
/// drain already in flight.
pub(super) const EVENT_SEND_BOUND: Duration = Duration::from_millis(250);
/// Retry cadence while waiting for that room.
pub(super) const EVENT_SEND_RETRY: Duration = Duration::from_millis(10);

/// The runtime's side of the GUI event channel.
pub(crate) struct EventStream {
    evt: SyncSender<CoreEvt>,
    repaint: egui::Context,
    /// Coalescing gate for core output lines, shared with the direct-mode
    /// pump closure and the helper path.
    gate: Arc<Mutex<LogGate>>,
}

impl EventStream {
    pub(crate) fn new(evt: SyncSender<CoreEvt>, repaint: egui::Context) -> Self {
        Self {
            evt,
            repaint,
            gate: Arc::new(Mutex::new(LogGate::new())),
        }
    }

    /// A cloneable handle for a worker task (the core downloader, the update
    /// check): it publishes under the same policy as the loop's own events.
    pub(super) fn handle(&self) -> Self {
        Self {
            evt: self.evt.clone(),
            repaint: self.repaint.clone(),
            gate: Arc::clone(&self.gate),
        }
    }

    /// A cloneable handle for a worker that logs outside the runtime loop (a
    /// spawn's release verification, a probe worker). It emits exactly what
    /// [`Self::app_log`] emits.
    pub(crate) fn sink(&self) -> AppLogSink {
        AppLogSink {
            evt: self.evt.clone(),
            repaint: self.repaint.clone(),
            gate: Arc::clone(&self.gate),
        }
    }

    /// Publish one event under the class policy above (see the module doc).
    pub(super) fn emit(&self, evt: CoreEvt) {
        queue_event(evt, &self.evt);
        self.repaint.request_repaint();
    }

    /// Publish one keyed message the shell renders in the display language.
    pub(super) fn app_log(&self, message: impl Into<AppMessage>) {
        self.emit(CoreEvt::AppLog(message.into()));
    }

    /// Forward one core output line through the coalescing gate: the line is
    /// dropped, counted, and summarized rather than growing the queue.
    pub(super) fn core_line(&self, line: String) {
        forward_core_line(&self.evt, &self.gate, &self.repaint, line);
    }

    /// Publish one busy-window bookend: the registry's payload is already the
    /// shape the shell reads.
    pub(super) fn bookend(&self, bookend: Option<JobKind>) {
        self.emit(CoreEvt::Operation(bookend));
    }

    /// The shell's repaint handle, for the sites that poke a frame without
    /// publishing an event.
    pub(super) fn repaint_handle(&self) -> egui::Context {
        self.repaint.clone()
    }

    /// Ask the shell for one frame.
    pub(super) fn repaint_now(&self) {
        self.repaint.request_repaint();
    }
}

/// One app-authored log line written from outside the runtime loop — a
/// spawn's release verification, a probe worker. Cloneable, so a worker owns
/// its own handle.
#[derive(Clone)]
pub(crate) struct AppLogSink {
    evt: SyncSender<CoreEvt>,
    repaint: egui::Context,
    gate: Arc<Mutex<LogGate>>,
}

impl AppLogSink {
    /// Queue one keyed message. Volatile by class (see [`is_volatile_event`]):
    /// a full GUI channel drops the line instead of blocking the worker that
    /// made the decision.
    pub(crate) fn log(&self, message: impl Into<AppMessage>) {
        queue_event(CoreEvt::AppLog(message.into()), &self.evt);
        self.repaint.request_repaint();
    }

    /// Forward one core output line through the same coalescing gate the
    /// runtime's own readers use.
    pub(crate) fn core_line(&self, line: String) {
        forward_core_line(&self.evt, &self.gate, &self.repaint, line);
    }
}

/// Forward one core output line through the coalescing gate and ask for the
/// frame a queued line needs: the one hand-off both GUI writers use (the
/// runtime's own readers and the worker handles that carry the same three
/// fields), so a change to the repaint policy lands once.
fn forward_core_line(
    evt: &SyncSender<CoreEvt>,
    gate: &Mutex<LogGate>,
    repaint: &egui::Context,
    line: String,
) {
    let queued = gate
        .lock()
        .map(|mut gate| gate.forward(line, evt) == Forward::Queued)
        .unwrap_or(false);
    if queued {
        repaint.request_repaint();
    }
}

/// Coalescing gate for core output lines forwarded to the GUI log. A flooding
/// core must not be able to grow the bounded GUI event queue without bound
/// (CWE-400/770): once the channel rejects a log event, later lines are
/// counted instead of queued, and the count is delivered as one summary
/// message as soon as the channel accepts again — coalescing rather than
/// dropping silently or blocking. Broccoli's own messages bypass the gate
/// (app-generated, low volume).
///
/// One gate serves both hops that forward core output: the runtime's own
/// readers write to the GUI channel, and the helper's pipe reader writes to
/// the helper→runtime channel. The policy — count while the channel refuses,
/// then deliver one summary — is here; what differs per hop is only its
/// channel, its values and its error shape, which [`LogHop`] supplies.
pub(crate) struct LogGate {
    /// Lines dropped since the last delivered summary.
    suppressed: u64,
}

/// The outcome of one non-blocking hand-off: delivered, no room right now, or
/// the receiving end is gone — with the value back in the two latter cases.
pub(crate) enum HandOff<T> {
    /// The channel took the value.
    Delivered,
    /// The channel has no room right now; a bounded wait may still find one.
    Full(T),
    /// The receiving end is gone: no retry can succeed.
    Closed(T),
}

/// Outcome of [`LogGate::forward`] for one core output line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Forward {
    /// The line, and any summary that was pending, were handed over.
    Queued,
    /// The line was withheld because the channel did not take it; counted
    /// toward the next summary.
    Suppressed,
    /// The receiving end is gone; the caller's reader must stop.
    Disconnected,
}

/// One hop of coalesced core output, as the gate sees it: how a bare line and
/// the summary of the withheld lines become this hop's own channel value, and
/// one non-blocking attempt to hand a value over.
///
/// The channels, the values and the error shapes are what the two hops
/// genuinely differ in; everything above them is one implementation.
pub(crate) trait LogHop<L> {
    /// The value this hop's bounded channel carries.
    type Value;

    /// Wrap one core output line as this hop's event.
    fn line(&self, line: L) -> Self::Value;

    /// Wrap the summary of the lines the gate withheld as this hop's event.
    fn summary(&self, suppressed: u64) -> Self::Value;

    /// One non-blocking attempt; the value comes back when the channel did
    /// not take it.
    fn try_hand(&self, value: Self::Value) -> HandOff<Self::Value>;
}

impl LogHop<String> for SyncSender<CoreEvt> {
    type Value = CoreEvt;

    fn line(&self, line: String) -> CoreEvt {
        CoreEvt::Log {
            line,
            from_core: true,
        }
    }

    fn summary(&self, suppressed: u64) -> CoreEvt {
        CoreEvt::AppLog(AppMessage::from(suppressed_summary(suppressed)))
    }

    fn try_hand(&self, value: CoreEvt) -> HandOff<CoreEvt> {
        match self.try_send(value) {
            Ok(()) => HandOff::Delivered,
            Err(std::sync::mpsc::TrySendError::Full(value)) => HandOff::Full(value),
            Err(std::sync::mpsc::TrySendError::Disconnected(value)) => HandOff::Closed(value),
        }
    }
}

impl LogGate {
    pub(crate) fn new() -> Self {
        LogGate { suppressed: 0 }
    }

    /// Forward one core output line over `hop`. A pending summary is
    /// delivered first, and only once the channel accepts it is the counter
    /// reset and the line itself handed over.
    pub(crate) fn forward<L, H: LogHop<L>>(&mut self, line: L, hop: &H) -> Forward {
        if self.suppressed > 0 {
            // Deliver the summary of previously suppressed lines first; if the
            // channel still rejects it, suppress this line too.
            match hop.try_hand(hop.summary(self.suppressed)) {
                HandOff::Delivered => self.suppressed = 0,
                HandOff::Full(_) => {
                    self.suppressed += 1;
                    return Forward::Suppressed;
                }
                HandOff::Closed(_) => return Forward::Disconnected,
            }
        }
        match hop.try_hand(hop.line(line)) {
            HandOff::Delivered => Forward::Queued,
            HandOff::Full(_) => {
                self.suppressed = 1;
                Forward::Suppressed
            }
            HandOff::Closed(_) => Forward::Disconnected,
        }
    }
}

/// Hand one value to a channel that just refused it, waiting up to `window`
/// for room and retrying at [`EVENT_SEND_RETRY`] cadence so the receiver's
/// next drain cycle picks it up within milliseconds. The value comes back
/// ([`HandOff`]) when the window ran out or the receiver is gone, so each hop
/// decides for itself what an undeliverable value means.
///
/// The wait is composed from `try_send` plus the retry sleep because std has
/// no bounded synchronous send on a stable toolchain — `SyncSender::send`
/// blocks without a deadline (and would deadlock the runtime thread against
/// the GUI thread's join on shutdown), while `send_timeout` is still nightly
/// — and the sender here is the std channel the GUI thread drains, outside
/// any async send primitive.
pub(crate) fn hand_within<T>(
    mut value: T,
    window: Duration,
    mut try_hand: impl FnMut(T) -> HandOff<T>,
) -> HandOff<T> {
    let deadline = Instant::now() + window;
    loop {
        match try_hand(value) {
            HandOff::Delivered => return HandOff::Delivered,
            HandOff::Full(pending) => {
                value = pending;
                if Instant::now() >= deadline {
                    return HandOff::Full(value);
                }
                std::thread::sleep(EVENT_SEND_RETRY);
            }
            HandOff::Closed(value) => return HandOff::Closed(value),
        }
    }
}

/// Message summarizing the core output lines the gate had to drop while the
/// GUI channel was full; the app renders it in the active language like every
/// other runtime-authored line.
pub(super) fn suppressed_summary(n: u64) -> Diag {
    if n == 1 {
        Diag::new(Key::RtLogSuppressedOne)
    } else {
        Diag::new(Key::RtLogSuppressedMany).arg(n)
    }
}

/// Queue an event on the GUI channel. Log events are routed through
/// [`LogGate`] (coalesced when the channel is full); every other event falls
/// back to a bounded wait when the channel is momentarily full.
pub(super) fn queue_event(evt: CoreEvt, sender: &SyncSender<CoreEvt>) {
    match sender.try_send(evt) {
        Ok(()) => {}
        Err(std::sync::mpsc::TrySendError::Full(evt)) => {
            if is_volatile_event(&evt) {
                return;
            }
            queue_lifecycle_with_bounded_wait(evt, sender);
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {}
    }
}

/// Wait one bounded drain window for a lifecycle event whose channel is
/// full, retrying at [`EVENT_SEND_RETRY`] cadence so the GUI's next drain
/// cycle picks it up within milliseconds. On timeout the GUI is not draining
/// (shutdown), and the event is dropped rather than deadlocking the runtime
/// thread against the GUI thread's join.
fn queue_lifecycle_with_bounded_wait(evt: CoreEvt, sender: &SyncSender<CoreEvt>) {
    // A value the GUI still has not drained after the window is dropped:
    // blocking this thread on the GUI thread's join would deadlock instead.
    let _ = hand_within(evt, EVENT_SEND_BOUND, |evt| sender.try_hand(evt));
}

/// Event classes that are safe to drop when the GUI channel is full: they
/// are either superseded by a later event of the same class (stats,
/// observatory snapshots, download progress) or diagnostic text whose loss
/// the log gate already tolerates. These never wait on the channel.
fn is_volatile_event(evt: &CoreEvt) -> bool {
    matches!(
        evt,
        CoreEvt::Stats(_)
            | CoreEvt::Observatory(_)
            | CoreEvt::Log { .. }
            | CoreEvt::AppLog(_)
            | CoreEvt::Download(DownloadState::Working { .. })
    )
}
