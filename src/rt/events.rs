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
        let queued = self
            .gate
            .lock()
            .map(|mut gate| gate.forward(line, &self.evt))
            .unwrap_or(false);
        if queued {
            self.repaint.request_repaint();
        }
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
        let queued = self
            .gate
            .lock()
            .map(|mut gate| gate.forward(line, &self.evt))
            .unwrap_or(false);
        if queued {
            self.repaint.request_repaint();
        }
    }
}

/// Coalescing gate for core output lines forwarded to the GUI log. A flooding
/// core must not be able to grow the bounded GUI event queue without bound
/// (CWE-400/770): once the channel rejects a log event, later lines are
/// counted instead of queued, and the count is delivered as one summary
/// message as soon as the channel accepts again — coalescing rather than
/// dropping silently or blocking. Broccoli's own messages bypass the gate
/// (app-generated, low volume).
pub(crate) struct LogGate {
    /// True while the GUI channel has rejected at least one log event.
    backed_up: bool,
    /// Lines dropped since the last delivered summary.
    suppressed: u64,
}

impl LogGate {
    pub(super) fn new() -> Self {
        LogGate {
            backed_up: false,
            suppressed: 0,
        }
    }

    /// Forward one core output line. Returns true when at least one event was
    /// actually queued (the caller requests a repaint then).
    pub(super) fn forward(&mut self, line: String, evt: &SyncSender<CoreEvt>) -> bool {
        if self.backed_up {
            // Deliver the summary of previously suppressed lines first; if the
            // channel still rejects it, suppress this line too.
            if evt
                .try_send(CoreEvt::AppLog(AppMessage::from(suppressed_summary(
                    self.suppressed,
                ))))
                .is_err()
            {
                self.suppressed += 1;
                return false;
            }
            self.backed_up = false;
            self.suppressed = 0;
        }
        match evt.try_send(CoreEvt::Log {
            line,
            from_core: true,
        }) {
            Ok(()) => true,
            Err(std::sync::mpsc::TrySendError::Full(_)) => {
                self.backed_up = true;
                self.suppressed = 1;
                false
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => false,
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
    let deadline = Instant::now() + EVENT_SEND_BOUND;
    let mut pending = evt;
    loop {
        match sender.try_send(pending) {
            Ok(()) => return,
            Err(std::sync::mpsc::TrySendError::Full(evt)) => {
                pending = evt;
                if Instant::now() >= deadline {
                    return;
                }
                std::thread::sleep(EVENT_SEND_RETRY);
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return,
        }
    }
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
