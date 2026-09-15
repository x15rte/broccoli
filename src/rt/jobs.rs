//! Runtime job registry: every UI request runs as a tracked
//! job. Exclusive jobs (apply, test config, update core, latency probe,
//! profile validation, and the lifecycle transitions) occupy the busy window
//! — at most one is
//! in flight — and carry the runtime's whole operation state on their
//! record: the pollable task handle, the keep-slot cancellation
//! flag, and the per-kind terminal pairing (sidecar) constructed at begin,
//! so a terminal can never be delivered to the wrong kind. Concurrent jobs
//! (the control-plane queries) run alongside each other and only reject
//! while an exclusive job holds the window. Every record carries a kind,
//! an abort handle, and a cancel flag — a query whose mutation pair must
//! reach its own terminal registers the handle without making it abortable
//! ([`super::seat::QuerySeat::RUNS_TO_OWN_TERMINAL`]) — and [`ReplyGuard`]
//! delivers exactly one terminal result per query job over a per-request
//! tokio one-shot channel on every path — completion, drop-without-send,
//! cancel, abort, join error, panic, exit.
//!
//! Busy-window bookends (the `CoreEvt::Operation(Some(kind)/None)` shape)
//! are emitted by the registry through the busy sink: `Some(kind)` on
//! exclusive begin, `None` on release. Release is decoupled from the
//! terminal verdict — a caller sends its terminal result, then decides
//! when to release the record ([`JobRegistry::finish_concurrent`] for a
//! concurrent query, [`JobRegistry::finish_exclusive`] for the exclusive
//! occupant; an apply that restarts the core stays busy until
//! readiness), which is exactly the busy window contract.
//!
//! Boundary: the registry decides job-vs-job conflicts only. Phase guards
//! ("core is not running"), field validation, and the two reject-message
//! flavors (the keyed busy rejection vs the seat's busy sentence) stay with
//! the dispatch side — in the per-kind seats and the shared query runner, or
//! in the exclusive arms' bespoke workers (`rt/mod.rs`).
//! Shutdown is not a job (the exit path drains); `SetTunMode` occupies as
//! `Restart` when it acts, `ImportCoreArchive` runs as `UpdateCore`;
//! `CheckUpdate` and `SetObservatory` are not jobs.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::oneshot;
use tokio::task::{AbortHandle, JoinHandle};

use crate::diag::DiagError;

use super::ApplyOutput;

/// Runtime-owned mutually-exclusive work (the busy-window bookend payload,
/// `CoreEvt::Operation(Some(kind)/None)`). The UI uses this state to
/// disable every command that would race a lifecycle or on-disk
/// transaction. Localized here with the registry; re-exported
/// from `rt` so external consumers import `crate::rt::OperationKind`
/// unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    Start,
    Stop,
    Restart,
    ApplyConfig,
    TestConfig,
    UpdateCore,
    LatencyProbe,
    ValidateProfiles,
}

/// Terminal verdict of one accepted `CoreCmd::TestConfig`: `Ok((accepted,
/// output))` when the core ran the validation, `Err` when it never did
/// (rejection or cancellation). The output renders in the active language and
/// the error side stays a keyed chain until the screen renders it. Travels
/// the request's own reply channel.
pub type TestConfigReply = Result<(bool, ApplyOutput), DiagError>;

/// The runtime work a UI request starts. The 13 variants mirror the
/// `CoreCmd` arms of `rt/mod.rs`; each kind's conflict rule and busy-window
/// bookend payload are declared with its seat or worker (see [`super::seat`])
/// and read through [`JobKind::rule`] / [`JobKind::exclusive_operation_kind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobKind {
    /// `CoreCmd::Start`.
    Start,
    /// `CoreCmd::Stop`.
    Stop,
    /// `CoreCmd::Restart`; `SetTunMode` occupies as this kind when it acts.
    Restart,
    /// `CoreCmd::ApplyConfig`.
    ApplyConfig,
    /// `CoreCmd::TestConfig`.
    TestConfig,
    /// `CoreCmd::UpdateCore`; `ImportCoreArchive` runs as this kind.
    UpdateCore,
    /// `CoreCmd::LatencyProbe`.
    LatencyProbe,
    /// `CoreCmd::ValidateProfiles`.
    ValidateProfiles,
    /// `CoreCmd::TestRoute`.
    TestRoute,
    /// `GetBalancerInfo`/`SetBalancerOverride`/`ClearBalancerOverride`.
    Balancer,
    /// `CoreCmd::RestartLogger`.
    LoggerRestart,
    /// `AddTrialRule`/`RemoveTrialRule`/`ListTrialRules`.
    TrialRules,
    /// `CoreCmd::ListRuntimeState`.
    RuntimeState,
}

/// The declarative conflict rule of a job kind — whether it occupies the
/// busy window, whether it preempts the exclusive occupant, and whether it
/// rejects while an exclusive job holds the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindRule {
    occupies: bool,
    preemptive: bool,
    blocked_by_exclusive: bool,
}

impl KindRule {
    /// Builds a rule from its three facts; the declarations live with each
    /// kind's seat or worker (see [`super::seat`]).
    pub(crate) const fn new(occupies: bool, preemptive: bool, blocked_by_exclusive: bool) -> Self {
        KindRule {
            occupies,
            preemptive,
            blocked_by_exclusive,
        }
    }
}

impl JobKind {
    /// The conflict rule of this kind, declared with its seat or worker
    /// (see [`super::seat`]). The registry's conflict checks read it, and
    /// the dispatch arms no longer carry a copy that could drift.
    pub fn rule(self) -> KindRule {
        super::seat::rule(self)
    }

    /// The [`OperationKind`] this job occupies the busy window as, when it
    /// is one of the exclusive kinds. Queries return `None` and never emit
    /// bookends; the busy sink therefore only ever produces `Some` for the
    /// eight exclusive kinds. Used by the runtime's bookend drain, where a
    /// `None` is a programming error (it cannot occur by construction).
    pub fn exclusive_operation_kind(self) -> Option<OperationKind> {
        super::seat::exclusive_operation_kind(self)
    }
}

/// Terminal payload of one exclusive job's task. Each variant is produced by
/// exactly one kind's worker and consumed by that kind's completion
/// handler, so the per-kind dispatch cannot mismatch.
pub enum ExclusiveOutcome {
    /// A TUN helper-connect worker (lifecycle Start/Restart span).
    HelperConnected(Result<super::helper::HelperPipe, super::HelperConnectFailure>),
    /// An apply validation worker (`CoreCmd::ApplyConfig` family).
    ApplyValidated {
        ok: bool,
        output: super::ApplyOutput,
        start_after_commit: bool,
        tun_mode: Option<bool>,
        api_port: u16,
    },
    /// A config test validation worker (`CoreCmd::TestConfig`).
    TestValidated {
        ok: bool,
        output: super::ApplyOutput,
    },
    /// A core-update worker (`CoreCmd::UpdateCore`/`ImportCoreArchive`).
    Download {
        state: super::DownloadState,
        kind: OperationKind,
    },
    /// A latency-probe worker (`CoreCmd::ProbeLatency`).
    LatencyProbe {
        tags: Vec<String>,
        /// Profiles at probe start; the completion handler resolves dead
        /// verdicts to names/addresses for the warn log line.
        profiles: Vec<crate::model::ServerProfile>,
        result: Result<Vec<super::grpc::OutboundStatusView>, super::ProbeFailure>,
    },
    /// A profile-validation worker (`CoreCmd::ValidateProfiles`): the
    /// accepted/rejected verdict, or the cancel terminal its own cooperative
    /// cancel boundary produced.
    ProfileValidation(super::ProfileValidationReply),
}

/// Per-kind terminal pairing parked on the exclusive record at begin: the
/// state a cancel/join-error terminal must report when the worker's own
/// outcome is lost. Only the kinds whose terminal can arrive without the
/// outcome carry one today.
#[derive(Debug)]
pub enum ExclusiveSidecar {
    /// Tags the latency-probe cancel/join-error terminal reports (probe:
    /// single-flight, so tags pair the terminal back to its request).
    LatencyTags(Vec<String>),
    /// The parked reply of the in-flight TestConfig task (exactly one
    /// terminal site takes and resolves it).
    TestReply(oneshot::Sender<TestConfigReply>),
    /// The parked reply of the in-flight profile validation (exactly one
    /// terminal site takes and resolves it).
    ProfileReply(oneshot::Sender<super::ProfileValidationReply>),
    /// Kinds whose terminal travels an event of its own (apply, download,
    /// helper connect) or that have no terminal (lifecycle spans).
    NoSidecar,
}

/// Why [`JobRegistry::try_begin`] rejected a kind: an exclusive job
/// (`active`) holds the busy window. The two reject text flavors are
/// dispatch-side and are not replicated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Busy {
    /// The exclusive job currently holding the busy window.
    pub active: JobKind,
}

/// RAII owner of a job's reply channel. Exactly-one terminal result by
/// construction: the worker forwards its real result through [`ReplyGuard::send`],
/// OR the guard is dropped — completion-without-send, cancel, abort, join
/// error, task panic, exit — and the stored `terminal` is delivered
/// instead. There is no path that delivers two messages: `send` consumes
/// the guard (and its sender); `Drop` only sends while the sender is still
/// held, which is exactly the never-sent case.
///
/// Because the struct implements `Drop`, its fields are `Option` and taken
/// with `.take()` — fields cannot move out of a `Drop` type.
pub struct ReplyGuard<T> {
    tx: Option<oneshot::Sender<T>>,
    terminal: Option<T>,
}

impl<T> ReplyGuard<T> {
    /// Wraps the job's reply channel. `terminal` is delivered if the guard
    /// is dropped without an explicit [`ReplyGuard::send`].
    pub fn new(tx: oneshot::Sender<T>, terminal: T) -> Self {
        ReplyGuard {
            tx: Some(tx),
            terminal: Some(terminal),
        }
    }

    /// Forwards `result` to the receiver and consumes the guard (the
    /// stored terminal is discarded — exactly one send attempt max). If
    /// the receiver is already gone, the result is returned — never
    /// delivered — and no terminal follows.
    pub fn send(mut self, result: T) -> Result<(), T> {
        match self.tx.take() {
            Some(tx) => tx.send(result),
            // Unreachable: `tx` is only taken here (and in `Drop`, which
            // runs after this consuming call returns). A sent result is
            // delivered or bounced above, never sent twice. Fail loudly
            // rather than swallow the result if the invariant ever breaks:
            // a silently dropped result would leave the requester with no
            // terminal.
            None => unreachable!("ReplyGuard::send called after its sender was taken"),
        }
    }
}

impl<T> Drop for ReplyGuard<T> {
    fn drop(&mut self) {
        // Terminal is present whenever the sender is: it is only taken
        // here, right after `tx`. `send` has already emptied `tx`, so a
        // dropped-after-send guard has nothing left to deliver.
        if let (Some(tx), Some(terminal)) = (self.tx.take(), self.terminal.take()) {
            match tx.send(terminal) {
                Ok(()) => {}
                Err(_) => {
                    // Receiver vanished before the terminal landed: with
                    // no listener left there is nothing to deliver, and
                    // exactly-one still holds — nothing further is sent.
                }
            }
        }
    }
}

/// One tracked job: its id, kind, shared cancel flag, and the abort handle
/// of the task running it (once the task reports in via
/// [`JobRegistry::set_abort`]). The exclusive record additionally carries
/// the runtime's whole operation state: the pollable task handle the
/// select loop awaits, the keep-slot cancellation flag, and the
/// per-kind terminal pairing (sidecar) parked at begin.
struct Record {
    id: u64,
    kind: JobKind,
    cancel: Arc<AtomicBool>,
    abort: Option<AbortHandle>,
    /// A task that must be left to its own terminal under every cancel path
    /// (registered with [`JobRegistry::set_abort_keep_running`]): the handle
    /// still evidences completion to the lazy sweep, but `request_cancel`
    /// never aborts it.
    keep_running: bool,
    /// The exclusive task the select loop polls (exclusive records only).
    task: Option<JoinHandle<ExclusiveOutcome>>,
    /// Flag-only cancel: set when Stop/Shutdown cancelled an
    /// in-flight UpdateCore install that `abort()` cannot interrupt. The
    /// record keeps occupying until the worker's terminal result lands.
    cancel_requested: bool,
    /// Per-kind terminal pairing parked at begin (exclusive records only).
    sidecar: Option<ExclusiveSidecar>,
}

impl Record {
    fn new(id: u64, kind: JobKind) -> Self {
        Record {
            id,
            kind,
            cancel: Arc::new(AtomicBool::new(false)),
            abort: None,
            keep_running: false,
            task: None,
            cancel_requested: false,
            sidecar: None,
        }
    }

    /// Sets the cancel flag and aborts the task if its handle was
    /// registered. Mirror of today's flag-only cancels (the helper
    /// connector check) plus the uniform abort of the migration drain.
    /// Store/load pair uses Release/Acquire like the ceremony's flags
    /// (`rt/mod.rs` cancel paths): workers poll the flag with Acquire
    /// loads between blocking attempts.
    ///
    /// A record registered via
    /// [`JobRegistry::set_abort_keep_running`] only gets the flag: its task
    /// must reach its own terminal.
    fn request_cancel(&self) {
        self.cancel.store(true, Ordering::Release);
        if self.keep_running {
            return;
        }
        if let Some(abort) = &self.abort {
            abort.abort();
        }
    }

    /// Cooperative keep-slot cancel: raises the worker's cancel flag — a
    /// worker that owns an on-disk artifact polls it between units of work —
    /// and records the keep-slot flag, aborting nothing. The record keeps
    /// occupying until the worker's own terminal lands.
    fn request_cooperative_cancel(&mut self) {
        self.cancel.store(true, Ordering::Release);
        self.cancel_requested = true;
    }
}

/// The job registry: at most one exclusive job plus any number
/// of concurrent jobs. The exclusive record carries the runtime's whole
/// operation state — pollable task, cancel flag, keep-slot flag,
/// per-kind sidecar — and is only ever released by the explicit
/// [`JobRegistry::finish_concurrent`]/[`JobRegistry::finish_exclusive`],
/// which the
/// caller times (release can lag the terminal: apply-then-restart and the
/// update health-gate stay busy through readiness). Busy-window bookends
/// (`Some(kind)` on exclusive begin, `None` on release) go to the busy
/// sink when one is set. Concurrent records whose task has finished are
/// reaped lazily at the top of [`JobRegistry::try_begin`].
pub struct JobRegistry {
    exclusive: Option<Record>,
    concurrent: Vec<Record>,
    next_id: u64,
    busy_sink: Option<Box<dyn Fn(Option<JobKind>) + Send>>,
}

impl JobRegistry {
    /// An empty registry with no busy sink.
    pub fn new() -> Self {
        JobRegistry {
            exclusive: None,
            concurrent: Vec::new(),
            next_id: 0,
            busy_sink: None,
        }
    }

    /// An empty registry that reports every busy-window bookend to
    /// `sink`: `Some(kind)` when an exclusive job begins, `None` when it
    /// releases. Queries never emit.
    pub fn with_busy_sink(sink: impl Fn(Option<JobKind>) + Send + 'static) -> Self {
        JobRegistry {
            exclusive: None,
            concurrent: Vec::new(),
            next_id: 0,
            busy_sink: Some(Box::new(sink)),
        }
    }

    /// The single entry point for starting a job. Rejects with the
    /// exclusive occupant while the busy window is held (unless the kind
    /// preempts); queries additionally only reject when the busy window is
    /// held and their rule says they must. Finished concurrent records are
    /// reaped lazily first ([`JobRegistry::sweep_concurrent`]).
    pub fn try_begin(&mut self, kind: JobKind) -> Result<u64, Busy> {
        self.sweep_concurrent();
        let rule = kind.rule();

        // Preemptive kinds (Stop) cancel the exclusive occupant first —
        // the old `cancel_operation`-then-`begin_operation` sequence
        // (bookend None then Some(new)) now happens inside the registry.
        // A record that runs to its own terminal is not preempted: aborting
        // its task would strand the artifact it owns (see
        // [`JobRegistry::exclusive_runs_to_terminal`]).
        if rule.preemptive
            && !self.exclusive_runs_to_terminal()
            && let Some(record) = self.exclusive.take()
        {
            record.request_cancel();
            self.emit_bookend(None);
        }

        if rule.occupies {
            if let Some(record) = &self.exclusive {
                return Err(Busy {
                    active: record.kind,
                });
            }
            let id = self.alloc_id();
            self.exclusive = Some(Record::new(id, kind));
            self.emit_bookend(Some(kind));
            Ok(id)
        } else if rule.blocked_by_exclusive {
            if let Some(record) = &self.exclusive {
                return Err(Busy {
                    active: record.kind,
                });
            }
            let id = self.alloc_id();
            self.concurrent.push(Record::new(id, kind));
            Ok(id)
        } else {
            // Query kind that never checks the busy window (trial rules,
            // runtime state).
            let id = self.alloc_id();
            self.concurrent.push(Record::new(id, kind));
            Ok(id)
        }
    }

    /// Explicitly releases a concurrent record; an unknown id is a no-op
    /// and nothing is emitted. Release can lag the terminal result — the
    /// caller sends the terminal, then decides when to release (e.g. after
    /// restart-to-readiness), which is exactly the busy window contract.
    /// The exclusive occupant has its own release,
    /// [`JobRegistry::finish_exclusive`]: it carries the `None` busy bookend
    /// and the guard that keeps a worker-owned record from being dropped
    /// while its task still runs, so this method deliberately cannot touch
    /// it.
    pub(crate) fn finish_concurrent(&mut self, id: u64) {
        if let Some(position) = self.concurrent.iter().position(|record| record.id == id) {
            self.concurrent.remove(position);
        }
    }

    /// The exclusive occupant, if any — the busy window.
    pub fn busy_kind(&self) -> Option<JobKind> {
        self.exclusive.as_ref().map(|record| record.kind)
    }

    /// Sets the cancel flag and aborts the task of one record. Does NOT
    /// remove it and emits nothing — the caller owns the release (the
    /// concurrent one, or [`JobRegistry::finish_exclusive`]) and the
    /// terminal timing.
    pub fn cancel(&mut self, id: u64) {
        if let Some(record) = self.find_mut(id) {
            record.request_cancel();
        }
    }

    /// Records the abort handle of the task spawned for a job (unknown id:
    /// no-op), so later cancels and the Stop/Shutdown drain can abort it.
    pub fn set_abort(&mut self, id: u64, abort: AbortHandle) {
        if let Some(record) = self.find_mut(id) {
            record.abort = Some(abort);
        }
    }

    /// Like [`JobRegistry::set_abort`] for a task that must be left to its
    /// own terminal (see [`super::seat::QuerySeat::RUNS_TO_OWN_TERMINAL`]):
    /// the handle still evidences completion to the lazy sweep, but no
    /// cancel path aborts the task — Stop/Shutdown raise the record's cancel
    /// flag only, and the task's own reply guard delivers its terminal.
    pub fn set_abort_keep_running(&mut self, id: u64, abort: AbortHandle) {
        if let Some(record) = self.find_mut(id) {
            record.abort = Some(abort);
            record.keep_running = true;
        }
    }

    /// The shared cancel flag of a record, for the worker to poll.
    pub fn cancel_flag(&self, id: u64) -> Option<Arc<AtomicBool>> {
        match self.exclusive.as_ref().filter(|record| record.id == id) {
            Some(record) => Some(Arc::clone(&record.cancel)),
            None => self
                .concurrent
                .iter()
                .find(|record| record.id == id)
                .map(|record| Arc::clone(&record.cancel)),
        }
    }

    /// How many jobs are tracked: one for the exclusive occupant (if any)
    /// plus every concurrent record.
    pub fn in_flight(&self) -> usize {
        self.concurrent.len() + usize::from(self.exclusive.is_some())
    }

    /// Sets the cancel flag and aborts every record. Does not remove
    /// anything and emits nothing: the Stop/Shutdown drain composes
    /// cancel + terminal + finish per record; non-abortable jobs keep
    /// their cancel-requested-until-terminal flag semantics.
    ///
    /// The exclusive record is skipped once its keep-slot cancellation was
    /// requested: that flag means an in-flight
    /// UpdateCore install must run to its terminal landing — aborting the
    /// record would release the busy window mid-install and let a second
    /// update overlap the swap still finishing on disk. The record's own
    /// terminal path releases it.
    pub fn abort_all(&mut self) {
        // See the doc comment above: an exclusive record under a
        // keep-slot cancellation owns its release and must not be flagged
        // or aborted here.
        let exclusive = self
            .exclusive
            .as_ref()
            .is_some_and(|record| !record.cancel_requested);
        if exclusive && let Some(record) = &self.exclusive {
            record.request_cancel();
        }
        for record in &self.concurrent {
            record.request_cancel();
        }
    }

    // -- exclusive-record API ----------------------------------

    /// The exclusive record's in-flight task, for the select loop to poll.
    /// `None` when no exclusive record is busy or its task already
    /// completed (the record can keep occupying after the task cleared —
    /// deferred release).
    pub fn exclusive_task_mut(&mut self) -> Option<&mut JoinHandle<ExclusiveOutcome>> {
        self.exclusive
            .as_mut()
            .and_then(|record| record.task.as_mut())
    }

    /// True while the exclusive record carries a task the select loop must
    /// poll.
    pub fn exclusive_task_active(&self) -> bool {
        self.exclusive
            .as_ref()
            .is_some_and(|record| record.task.is_some())
    }

    /// Clears the completed exclusive task after the select loop consumed
    /// its result. The record keeps occupying until its explicit release,
    /// so the busy window and its kind stay visible to guards while the
    /// per-kind completion handler runs.
    pub fn clear_exclusive_task(&mut self) {
        if let Some(record) = &mut self.exclusive {
            record.task = None;
        }
    }

    /// Attaches the spawned exclusive task to the record (spawn first, then
    /// register). Also registers the abort handle, so preemptive cancels
    /// and the drain can abort the task through the record.
    pub fn attach_exclusive_task(&mut self, task: JoinHandle<ExclusiveOutcome>) {
        if let Some(record) = &mut self.exclusive {
            record.abort = Some(task.abort_handle());
            record.task = Some(task);
        }
    }

    /// Parks the per-kind terminal pairing on the exclusive record.
    pub fn set_exclusive_sidecar(&mut self, sidecar: ExclusiveSidecar) {
        if let Some(record) = &mut self.exclusive {
            record.sidecar = Some(sidecar);
        }
    }

    /// Takes the per-kind terminal pairing off the exclusive record —
    /// exactly one terminal path may take it (a second one finds `None`).
    pub fn take_exclusive_sidecar(&mut self) -> Option<ExclusiveSidecar> {
        self.exclusive
            .as_mut()
            .and_then(|record| record.sidecar.take())
    }

    /// Requests cancellation of the exclusive occupant (cancel flag +
    /// abort). Does NOT remove it and emits nothing — the caller owns the
    /// terminal and the release timing.
    pub fn cancel_exclusive_record(&mut self) {
        if let Some(record) = &self.exclusive {
            record.request_cancel();
        }
    }

    /// The shared cancel flag of the exclusive record, for a worker to
    /// poll between blocking attempts (helper connector).
    pub fn exclusive_cancel_flag(&self) -> Option<Arc<AtomicBool>> {
        self.exclusive
            .as_ref()
            .map(|record| Arc::clone(&record.cancel))
    }

    /// Flag-only keep-slot cancel of the exclusive occupant: sets
    /// `cancel_requested`, aborts nothing, removes nothing, emits nothing.
    /// The record keeps occupying until its terminal landing releases it.
    pub fn request_cancel_flagged(&mut self) {
        if let Some(record) = &mut self.exclusive {
            record.cancel_requested = true;
        }
    }

    /// Cooperative keep-slot cancel of the exclusive occupant: raises the
    /// worker's cancel flag (polled between units of work) alongside the
    /// keep-slot flag, aborts nothing, removes nothing, emits nothing. The
    /// worker delivers its exactly-one terminal and only that terminal
    /// releases the record.
    pub fn request_cooperative_cancel(&mut self) {
        if let Some(record) = &mut self.exclusive {
            record.request_cooperative_cancel();
        }
    }

    /// Whether the exclusive occupant is under a keep-slot cancellation
    /// (an UpdateCore install Stop/Shutdown asked to cancel but could not
    /// abort). Read by the landing handler to suppress the health-gate
    /// restart.
    pub fn is_cancel_requested(&self) -> bool {
        self.exclusive
            .as_ref()
            .is_some_and(|record| record.cancel_requested)
    }

    /// True while the exclusive occupant must be left to its own terminal:
    /// its worker owns an on-disk artifact that a hard abort would strand
    /// (see [`super::seat::runs_to_own_terminal`]) and its task is still in
    /// flight. The preemptive begin, the lifecycle releases and the shutdown
    /// wait all read this one fact; the per-kind terminal clears it by
    /// clearing the task ([`JobRegistry::clear_exclusive_task`]).
    pub fn exclusive_runs_to_terminal(&self) -> bool {
        self.exclusive.as_ref().is_some_and(|record| {
            record.task.is_some() && super::seat::runs_to_own_terminal(record.kind)
        })
    }

    /// Releases the exclusive occupant, if any — the busy-window release.
    /// Emits the `None` bookend through the sink. A no-op when no record
    /// is busy; release can lag the terminal result. An occupant that runs to
    /// its own terminal ([`JobRegistry::exclusive_runs_to_terminal`]) is left
    /// alone: the lifecycle releases (readiness, core exit, a deferred start
    /// that failed) own the record of the operation that deferred its
    /// release, never a worker still holding its artifact.
    pub fn finish_exclusive(&mut self) {
        if self.exclusive.is_some() && !self.exclusive_runs_to_terminal() {
            self.exclusive = None;
            self.emit_bookend(None);
        }
    }

    /// Reaps finished concurrent records (called at the top of
    /// [`JobRegistry::try_begin`]). A record whose task has completed — its
    /// registered abort handle reports finished — can never deliver another
    /// terminal, so it only bloats the table. Records without an abort
    /// handle are kept: without one, completion cannot be proven. The
    /// exclusive record is never auto-swept: releasing it is the busy
    /// window contract, owned by the explicit
    /// [`JobRegistry::finish_exclusive`].
    fn sweep_concurrent(&mut self) {
        self.concurrent.retain(|record| match &record.abort {
            Some(abort) => !abort.is_finished(),
            None => true,
        });
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn find_mut(&mut self, id: u64) -> Option<&mut Record> {
        match &mut self.exclusive {
            Some(record) if record.id == id => Some(record),
            _ => self.concurrent.iter_mut().find(|record| record.id == id),
        }
    }

    fn emit_bookend(&self, kind: Option<JobKind>) {
        if let Some(sink) = &self.busy_sink {
            sink(kind);
        }
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        JobRegistry::new()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    use parking_lot::Mutex;
    use tokio::sync::oneshot::error::TryRecvError;

    use super::*;
    use crate::diag::Diag;
    use crate::i18n::Key;
    use crate::model::settings::Language;

    type Bookends = Arc<Mutex<Vec<Option<JobKind>>>>;

    /// A registry that records every busy-window bookend into `bookends`.
    fn recorder_registry(bookends: &Bookends) -> JobRegistry {
        let sink = Arc::clone(bookends);
        JobRegistry::with_busy_sink(move |kind| sink.lock().push(kind))
    }

    /// Every kind that occupies the busy window.
    const OCCUPYING: [JobKind; 7] = [
        JobKind::Start,
        JobKind::Restart,
        JobKind::ApplyConfig,
        JobKind::TestConfig,
        JobKind::UpdateCore,
        JobKind::LatencyProbe,
        JobKind::ValidateProfiles,
    ];

    /// Every kind that runs concurrently and rejects while an exclusive
    /// job holds the window.
    const BLOCKED_QUERIES: [JobKind; 3] = [
        JobKind::TestRoute,
        JobKind::Balancer,
        JobKind::LoggerRestart,
    ];

    /// Every kind, for whole-table invariants.
    const ALL_KINDS: [JobKind; 13] = [
        JobKind::Start,
        JobKind::Stop,
        JobKind::Restart,
        JobKind::ApplyConfig,
        JobKind::TestConfig,
        JobKind::UpdateCore,
        JobKind::LatencyProbe,
        JobKind::ValidateProfiles,
        JobKind::TestRoute,
        JobKind::Balancer,
        JobKind::LoggerRestart,
        JobKind::TrialRules,
        JobKind::RuntimeState,
    ];

    #[test]
    fn rule_table_matches_declared_rules() {
        // The expected matrix is the frozen conflict table the dispatch arms
        // were migrated against (2026-09-02); it must survive the rule
        // declarations moving beside each kind's seat or worker.
        let expect = |occupies: bool, preemptive: bool, blocked: bool| KindRule {
            occupies,
            preemptive,
            blocked_by_exclusive: blocked,
        };
        assert_eq!(JobKind::Start.rule(), expect(true, false, true));
        assert_eq!(JobKind::Stop.rule(), expect(true, true, true));
        assert_eq!(JobKind::Restart.rule(), expect(true, false, true));
        assert_eq!(JobKind::ApplyConfig.rule(), expect(true, false, true));
        assert_eq!(JobKind::TestConfig.rule(), expect(true, false, true));
        assert_eq!(JobKind::UpdateCore.rule(), expect(true, false, true));
        assert_eq!(JobKind::LatencyProbe.rule(), expect(true, false, true));
        assert_eq!(JobKind::ValidateProfiles.rule(), expect(true, false, true));
        assert_eq!(JobKind::TestRoute.rule(), expect(false, false, true));
        assert_eq!(JobKind::Balancer.rule(), expect(false, false, true));
        assert_eq!(JobKind::LoggerRestart.rule(), expect(false, false, true));
        assert_eq!(JobKind::TrialRules.rule(), expect(false, false, false));
        assert_eq!(JobKind::RuntimeState.rule(), expect(false, false, false));
    }

    #[test]
    fn bookend_payload_exists_exactly_for_occupying_kinds() {
        // The busy sink only ever emits `Some(kind)` for occupying kinds,
        // and the bookend drain resolves their `OperationKind` on the
        // assumption that every occupying kind carries one: a kind that
        // occupies without a payload (or a query kind that carries one)
        // would break the busy-window bookends.
        for kind in ALL_KINDS {
            assert_eq!(
                kind.rule().occupies,
                kind.exclusive_operation_kind().is_some(),
                "{kind:?}: occupancy and bookend payload must agree"
            );
        }
    }

    #[test]
    fn busy_rejection_matches_arms() {
        for occupant in [
            JobKind::Start,
            JobKind::ApplyConfig,
            JobKind::LatencyProbe,
            JobKind::UpdateCore,
        ] {
            let mut registry = JobRegistry::new();
            assert!(registry.try_begin(occupant).is_ok());
            // Every occupying kind rejects while the window is held,
            // except Stop, which preempts.
            for kind in OCCUPYING {
                if kind == occupant {
                    continue;
                }
                assert_eq!(
                    registry.try_begin(kind),
                    Err(Busy { active: occupant }),
                    "{occupant:?} busy: {kind:?} must reject"
                );
            }
            // The window-blocked queries reject too.
            for kind in BLOCKED_QUERIES {
                assert_eq!(
                    registry.try_begin(kind),
                    Err(Busy { active: occupant }),
                    "{occupant:?} busy: {kind:?} must reject"
                );
            }
            // Trial rules and runtime state never check the busy window.
            assert!(registry.try_begin(JobKind::TrialRules).is_ok());
            assert!(registry.try_begin(JobKind::RuntimeState).is_ok());
            // Stop ends the busy window by preempting (last: it mutates).
            assert!(registry.try_begin(JobKind::Stop).is_ok());
            assert_eq!(registry.busy_kind(), Some(JobKind::Stop));
        }
    }

    #[test]
    fn queries_coexist() {
        let mut registry = JobRegistry::new();
        assert!(registry.try_begin(JobKind::Balancer).is_ok());
        // Queries never conflict with each other.
        assert!(registry.try_begin(JobKind::TestRoute).is_ok());
        assert!(registry.try_begin(JobKind::TrialRules).is_ok());
        assert!(registry.try_begin(JobKind::RuntimeState).is_ok());
        assert!(registry.try_begin(JobKind::Balancer).is_ok());
        // None of them opened the busy window.
        assert_eq!(registry.busy_kind(), None);
        assert_eq!(registry.in_flight(), 5);
        // An exclusive begin while a query runs is allowed (no
        // cross-check today).
        assert!(registry.try_begin(JobKind::LatencyProbe).is_ok());
        assert_eq!(registry.busy_kind(), Some(JobKind::LatencyProbe));
        // With the window held, queries are blocked again and a second
        // exclusive begin rejects.
        assert_eq!(
            registry.try_begin(JobKind::TestRoute),
            Err(Busy {
                active: JobKind::LatencyProbe
            })
        );
        assert_eq!(
            registry.try_begin(JobKind::ApplyConfig),
            Err(Busy {
                active: JobKind::LatencyProbe
            })
        );
    }

    #[test]
    fn stop_preempts_exclusive() {
        let bookends: Bookends = Arc::new(Mutex::new(Vec::new()));
        let mut registry = recorder_registry(&bookends);
        let probe = registry.try_begin(JobKind::LatencyProbe).unwrap();
        let flag = registry.cancel_flag(probe).unwrap();
        assert!(!flag.load(Ordering::SeqCst));

        assert!(registry.try_begin(JobKind::Stop).is_ok());

        assert_eq!(registry.busy_kind(), Some(JobKind::Stop));
        assert!(
            flag.load(Ordering::SeqCst),
            "preempted record's cancel flag must be set"
        );
        assert_eq!(
            bookends.lock().as_slice(),
            &[Some(JobKind::LatencyProbe), None, Some(JobKind::Stop),]
        );
    }

    #[test]
    fn bookends() {
        let bookends: Bookends = Arc::new(Mutex::new(Vec::new()));
        let mut registry = recorder_registry(&bookends);

        let id = registry.try_begin(JobKind::ApplyConfig).unwrap();
        assert_eq!(bookends.lock().as_slice(), &[Some(JobKind::ApplyConfig)]);
        assert_eq!(registry.busy_kind(), Some(JobKind::ApplyConfig));

        // The exclusive release is the registry's own (`finish_exclusive`);
        // the id-addresses-a-concurrent-record release is `finish_concurrent`.
        registry.finish_concurrent(id);
        assert_eq!(registry.busy_kind(), Some(JobKind::ApplyConfig));
        registry.finish_exclusive();
        assert_eq!(
            bookends.lock().as_slice(),
            &[Some(JobKind::ApplyConfig), None]
        );
        assert_eq!(registry.busy_kind(), None);

        // Queries never emit a bookend, on begin or on release.
        let query = registry.try_begin(JobKind::Balancer).unwrap();
        registry.finish_concurrent(query);
        assert_eq!(
            bookends.lock().as_slice(),
            &[Some(JobKind::ApplyConfig), None]
        );
    }

    #[test]
    fn release_can_lag_terminal() {
        let bookends: Bookends = Arc::new(Mutex::new(Vec::new()));
        let mut registry = recorder_registry(&bookends);

        let id = registry.try_begin(JobKind::ApplyConfig).unwrap();
        let (tx, mut rx) = oneshot::channel();
        let guard = ReplyGuard::new(tx, "terminal");
        // The terminal verdict is delivered...
        assert!(guard.send("result").is_ok());
        assert_eq!(rx.try_recv(), Ok("result"));
        // ...but the busy window is still held until the explicit release
        // (apply-then-restart stays busy until readiness).
        assert_eq!(registry.busy_kind(), Some(JobKind::ApplyConfig));
        // Addressing an exclusive id through the concurrent release is a
        // no-op: only `finish_exclusive` ends the busy window.
        registry.finish_concurrent(id);
        assert_eq!(registry.busy_kind(), Some(JobKind::ApplyConfig));
        registry.finish_exclusive();
        assert_eq!(registry.busy_kind(), None);
        assert_eq!(
            bookends.lock().as_slice(),
            &[Some(JobKind::ApplyConfig), None]
        );
    }

    #[test]
    fn reply_guard_exactly_one() {
        // Send: the receiver gets the result, a second receive is Closed,
        // and dropping the consumed guard sends nothing more.
        let (tx, mut rx) = oneshot::channel();
        let guard = ReplyGuard::new(tx, "terminal");
        assert!(guard.send("result").is_ok());
        assert_eq!(rx.try_recv(), Ok("result"));
        assert_eq!(rx.try_recv(), Err(TryRecvError::Closed));

        // Drop-without-send: the terminal is delivered.
        let (tx, mut rx) = oneshot::channel();
        let guard = ReplyGuard::new(tx, "terminal");
        drop(guard);
        assert_eq!(rx.try_recv(), Ok("terminal"));
        assert_eq!(rx.try_recv(), Err(TryRecvError::Closed));

        // Receiver dropped before the send: the result is bounced back,
        // never delivered — no terminal follows either.
        let (tx, rx) = oneshot::channel();
        let guard = ReplyGuard::new(tx, "terminal");
        drop(rx);
        assert_eq!(guard.send("result"), Err("result"));
    }

    /// An exclusive id is only releasable through the exclusive release:
    /// aiming the concurrent release at it must leave the record — and its
    /// parked terminal sidecar — untouched, so the requester's exactly-one
    /// terminal can still land.
    #[test]
    fn concurrent_release_cannot_drop_an_exclusive_record() {
        let mut registry = JobRegistry::new();
        let id = registry.try_begin(JobKind::TestConfig).unwrap();
        let (tx, mut rx) = oneshot::channel::<TestConfigReply>();
        registry.set_exclusive_sidecar(ExclusiveSidecar::TestReply(tx));

        registry.finish_concurrent(id);

        assert_eq!(registry.busy_kind(), Some(JobKind::TestConfig));
        assert_eq!(registry.in_flight(), 1);
        let rejected = Diag::new(Key::SeatRuntimeStopping);
        match registry.take_exclusive_sidecar() {
            Some(ExclusiveSidecar::TestReply(reply)) => {
                assert!(
                    reply.send(Err(DiagError::from(rejected.clone()))).is_ok(),
                    "the parked reply receiver is alive"
                );
            }
            sidecar => panic!("the sidecar must survive an exclusive-id release: {sidecar:?}"),
        }
        let bounced = rx.try_recv().expect("the parked terminal lands");
        assert_eq!(
            bounced.expect_err("the terminal is a reject").diag().key(),
            rejected.key()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abort_delivers_terminal() {
        let mut registry = JobRegistry::new();
        let id = registry.try_begin(JobKind::LatencyProbe).unwrap();
        let (tx, rx) = oneshot::channel();
        let guard = ReplyGuard::new(tx, "terminal");
        let handle = tokio::spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        registry.set_abort(id, handle.abort_handle());
        registry.cancel(id);
        // The abort drops the task at the next scheduler pass; awaiting
        // the channel yields to the runtime, the guard's Drop runs during
        // that drop and delivers the terminal (consuming the channel, so
        // nothing further can ever arrive).
        assert_eq!(rx.await, Ok("terminal"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn panic_delivers_terminal() {
        let (tx, mut rx) = oneshot::channel();
        let guard = ReplyGuard::new(tx, "terminal");
        let handle = tokio::spawn(async move {
            let _guard = guard;
            panic!("worker panic");
        });
        assert!(handle.await.is_err(), "the task panicked");
        assert_eq!(
            rx.try_recv(),
            Ok("terminal"),
            "Drop during unwind must deliver the terminal"
        );
        assert_eq!(
            rx.try_recv(),
            Err(TryRecvError::Closed),
            "exactly one terminal"
        );
    }

    #[test]
    fn finish_unknown_id_is_noop() {
        let bookends: Bookends = Arc::new(Mutex::new(Vec::new()));
        let mut registry = recorder_registry(&bookends);
        registry.try_begin(JobKind::UpdateCore).unwrap();

        registry.finish_concurrent(999);

        assert_eq!(registry.busy_kind(), Some(JobKind::UpdateCore));
        // Only the begin bookend — the unknown finish emitted nothing.
        assert_eq!(
            bookends.lock().as_slice(),
            &[Some(JobKind::UpdateCore)],
            "unknown finish must not emit"
        );

        registry.finish_exclusive();
        assert_eq!(registry.busy_kind(), None);
        assert_eq!(
            bookends.lock().as_slice(),
            &[Some(JobKind::UpdateCore), None]
        );
    }

    #[test]
    fn ids_are_monotonic() {
        let mut registry = JobRegistry::new();
        let first = registry.try_begin(JobKind::Balancer).unwrap();
        let second = registry.try_begin(JobKind::TrialRules).unwrap();
        let third = registry.try_begin(JobKind::ApplyConfig).unwrap();
        assert!(first < second && second < third);
        assert_eq!((first, second, third), (0, 1, 2));
    }

    #[test]
    fn cancel_then_finish() {
        let bookends: Bookends = Arc::new(Mutex::new(Vec::new()));
        let mut registry = recorder_registry(&bookends);
        let id = registry.try_begin(JobKind::LatencyProbe).unwrap();

        registry.cancel(id);

        // Cancel leaves the record in place and emits nothing beyond the
        // begin bookend — the caller owns the finish and the terminal
        // timing.
        assert_eq!(registry.busy_kind(), Some(JobKind::LatencyProbe));
        assert_eq!(registry.in_flight(), 1);
        assert!(registry.cancel_flag(id).unwrap().load(Ordering::SeqCst));
        assert_eq!(bookends.lock().as_slice(), &[Some(JobKind::LatencyProbe)]);

        registry.finish_exclusive();

        assert_eq!(registry.busy_kind(), None);
        assert_eq!(
            bookends.lock().as_slice(),
            &[Some(JobKind::LatencyProbe), None]
        );
    }

    #[test]
    fn abort_all() {
        let bookends: Bookends = Arc::new(Mutex::new(Vec::new()));
        let mut registry = recorder_registry(&bookends);
        // Two concurrent queries first (they coexist), then the exclusive
        // occupant (blocked queries cannot begin while it holds the
        // window, so the concurrent records must predate it).
        let first = registry.try_begin(JobKind::Balancer).unwrap();
        let second = registry.try_begin(JobKind::Balancer).unwrap();
        let exclusive = registry.try_begin(JobKind::LatencyProbe).unwrap();
        let flags = [exclusive, first, second].map(|id| registry.cancel_flag(id).unwrap());
        for flag in &flags {
            assert!(!flag.load(Ordering::SeqCst));
        }

        registry.abort_all();

        // Every record is flagged (and aborted), but none is removed and
        // no bookend beyond the begin one is emitted.
        for flag in &flags {
            assert!(flag.load(Ordering::SeqCst));
        }
        assert_eq!(registry.in_flight(), 3);
        assert_eq!(registry.busy_kind(), Some(JobKind::LatencyProbe));
        assert_eq!(bookends.lock().as_slice(), &[Some(JobKind::LatencyProbe)]);

        // The drain composes cancel + terminal + finish per record; only
        // the exclusive release emits the single None bookend.
        registry.finish_exclusive();
        registry.finish_concurrent(first);
        registry.finish_concurrent(second);
        assert_eq!(registry.in_flight(), 0);
        assert_eq!(
            bookends.lock().as_slice(),
            &[Some(JobKind::LatencyProbe), None]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sweep_removes_finished_concurrent_records() {
        let mut registry = JobRegistry::new();
        let first = registry.try_begin(JobKind::Balancer).unwrap();
        let second = registry.try_begin(JobKind::TestRoute).unwrap();
        assert_eq!(registry.in_flight(), 2);

        // `first`'s task completes; the next begin sweeps its record.
        let task = tokio::spawn(async {});
        registry.set_abort(first, task.abort_handle());
        task.await.expect("the finished task");

        let third = registry.try_begin(JobKind::Balancer).unwrap();

        assert_eq!(
            registry.in_flight(),
            2,
            "the finished record must be reaped by the next try_begin"
        );
        assert!(
            registry.cancel_flag(first).is_none(),
            "the reaped record must no longer be tracked"
        );
        assert!(registry.cancel_flag(second).is_some());
        assert!(registry.cancel_flag(third).is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sweep_keeps_live_and_unregistered_records() {
        let mut registry = JobRegistry::new();
        let live = registry.try_begin(JobKind::Balancer).unwrap();
        let unregistered = registry.try_begin(JobKind::TrialRules).unwrap();
        let finished = registry.try_begin(JobKind::RuntimeState).unwrap();

        // A still-running task: its record must survive the sweep. The
        // sender stays alive to the end of the test, so the task never
        // resolves.
        let (_gate_tx, gate) = oneshot::channel::<()>();
        let live_task = tokio::spawn(async move {
            let _ = gate.await;
        });
        registry.set_abort(live, live_task.abort_handle());
        // A record with no abort handle at all: completion cannot be
        // proven, so it must survive too.
        let done = tokio::spawn(async {});
        registry.set_abort(finished, done.abort_handle());
        done.await.expect("the finished task");

        let extra = registry.try_begin(JobKind::Balancer).unwrap();

        assert_eq!(registry.in_flight(), 3);
        assert!(
            registry.cancel_flag(live).is_some(),
            "a live record must be kept"
        );
        assert!(
            registry.cancel_flag(unregistered).is_some(),
            "a record without an abort handle must be kept"
        );
        assert!(registry.cancel_flag(finished).is_none());
        assert!(registry.cancel_flag(extra).is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sweep_never_touches_exclusive_records() {
        let mut registry = JobRegistry::new();
        let id = registry.try_begin(JobKind::LatencyProbe).unwrap();
        let task = tokio::spawn(async {});
        registry.set_abort(id, task.abort_handle());
        task.await.expect("the finished task");

        // Even with the exclusive task finished, the sweep (which runs on
        // this rejecting begin) must leave the record in place: releasing
        // it is the busy-window contract, owned by the explicit
        // `finish_exclusive`.
        assert_eq!(
            registry.try_begin(JobKind::Start),
            Err(Busy {
                active: JobKind::LatencyProbe
            })
        );
        assert_eq!(registry.busy_kind(), Some(JobKind::LatencyProbe));
        assert_eq!(registry.in_flight(), 1);

        registry.finish_exclusive();
        assert_eq!(registry.busy_kind(), None);
        assert_eq!(registry.in_flight(), 0);
    }

    #[test]
    fn exclusive_operation_kind_maps_the_eight_bookend_kinds() {
        let exclusive = [
            (JobKind::Start, OperationKind::Start),
            (JobKind::Stop, OperationKind::Stop),
            (JobKind::Restart, OperationKind::Restart),
            (JobKind::ApplyConfig, OperationKind::ApplyConfig),
            (JobKind::TestConfig, OperationKind::TestConfig),
            (JobKind::UpdateCore, OperationKind::UpdateCore),
            (JobKind::LatencyProbe, OperationKind::LatencyProbe),
            (JobKind::ValidateProfiles, OperationKind::ValidateProfiles),
        ];
        for (job, operation) in exclusive {
            assert_eq!(job.exclusive_operation_kind(), Some(operation));
        }
        for query in [
            JobKind::TestRoute,
            JobKind::Balancer,
            JobKind::LoggerRestart,
            JobKind::TrialRules,
            JobKind::RuntimeState,
        ] {
            assert_eq!(
                query.exclusive_operation_kind(),
                None,
                "queries never emit bookends"
            );
        }
    }

    /// The run-to-terminal guard, exercised as the preemptive begin and the
    /// lifecycle release read it: an abortable record is preempted/released,
    /// a worker-owned one is left alone until its terminal clears the task.
    #[tokio::test(flavor = "current_thread")]
    async fn run_to_terminal_records_resist_preemption_and_release() {
        let bookends: Bookends = Arc::new(Mutex::new(Vec::new()));
        let mut registry = recorder_registry(&bookends);
        registry.try_begin(JobKind::ValidateProfiles).unwrap();
        let task = tokio::spawn(async { std::future::pending::<ExclusiveOutcome>().await });
        registry.attach_exclusive_task(task);
        assert!(registry.exclusive_runs_to_terminal());

        // Stop is preemptive, but not against a worker that owns its
        // artifact: the begin rejects instead of aborting it.
        assert_eq!(
            registry.try_begin(JobKind::Stop),
            Err(Busy {
                active: JobKind::ValidateProfiles
            })
        );
        // The lifecycle releases leave the record alone too.
        registry.finish_exclusive();
        assert_eq!(registry.busy_kind(), Some(JobKind::ValidateProfiles));
        assert_eq!(
            bookends.lock().as_slice(),
            &[Some(JobKind::ValidateProfiles)],
            "neither the rejected begin nor the skipped release may emit"
        );

        // The worker's own terminal clears the task; the explicit release
        // then ends the record (the terminal handler's order).
        registry.clear_exclusive_task();
        assert!(!registry.exclusive_runs_to_terminal());
        registry.finish_exclusive();
        assert_eq!(registry.busy_kind(), None);
        assert_eq!(
            bookends.lock().as_slice(),
            &[Some(JobKind::ValidateProfiles), None]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exclusive_task_attach_poll_and_clear() {
        let mut registry = JobRegistry::new();
        assert!(registry.exclusive_task_mut().is_none());
        assert!(!registry.exclusive_task_active());
        registry.try_begin(JobKind::LatencyProbe).unwrap();

        let task = tokio::spawn(async { std::future::pending::<ExclusiveOutcome>().await });
        registry.attach_exclusive_task(task);
        assert!(registry.exclusive_task_active());
        assert!(registry.exclusive_task_mut().is_some());

        registry.clear_exclusive_task();
        assert!(!registry.exclusive_task_active());
        assert!(registry.exclusive_task_mut().is_none());

        // The record keeps occupying after the task cleared (deferred
        // release) until the explicit finish.
        assert_eq!(registry.busy_kind(), Some(JobKind::LatencyProbe));
        registry.finish_exclusive();
        assert_eq!(registry.busy_kind(), None);
    }

    #[test]
    fn flagged_cancel_holds_the_record_until_finish() {
        let bookends: Bookends = Arc::new(Mutex::new(Vec::new()));
        let mut registry = recorder_registry(&bookends);
        let id = registry.try_begin(JobKind::UpdateCore).unwrap();

        assert!(!registry.is_cancel_requested());
        registry.request_cancel_flagged();

        // Keep-slot cancel: flag recorded, no removal, no bookend.
        assert!(registry.is_cancel_requested());
        assert_eq!(registry.busy_kind(), Some(JobKind::UpdateCore));
        assert_eq!(registry.in_flight(), 1);
        assert!(
            !registry
                .cancel_flag(id)
                .expect("record still occupies")
                .load(Ordering::SeqCst),
            "the flag-only cancel must not set the worker cancel flag"
        );
        assert_eq!(
            bookends.lock().as_slice(),
            &[Some(JobKind::UpdateCore)],
            "flagged cancel emits no bookend"
        );

        // The terminal landing releases the record; the None bookend then
        // follows.
        registry.finish_exclusive();
        assert_eq!(registry.busy_kind(), None);
        assert_eq!(
            bookends.lock().as_slice(),
            &[Some(JobKind::UpdateCore), None]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abort_all_skips_the_keep_slot_record() {
        let mut registry = JobRegistry::new();
        registry.try_begin(JobKind::UpdateCore).unwrap();
        // A live install task: the drain must not abort it.
        let task = tokio::spawn(async { std::future::pending::<ExclusiveOutcome>().await });
        let probe = task.abort_handle();
        registry.attach_exclusive_task(task);
        registry.request_cancel_flagged();

        // A concurrent query record rides the same drain and is aborted.
        let query = registry.try_begin(JobKind::RuntimeState).unwrap();
        let query_abort = registry.cancel_flag(query).unwrap();
        registry.abort_all();

        assert!(
            !probe.is_finished(),
            "abort_all must not abort the keep-slot install record"
        );
        assert!(
            query_abort.load(Ordering::SeqCst),
            "concurrent records still drain"
        );
        assert_eq!(registry.busy_kind(), Some(JobKind::UpdateCore));
        assert!(registry.is_cancel_requested());

        // The install's terminal landing clears the task, then releases the
        // record (the select loop's order).
        registry.clear_exclusive_task();
        registry.finish_exclusive();
        assert_eq!(registry.busy_kind(), None);
    }

    /// The Stop/Shutdown drain must not abort a record whose task runs to
    /// its own terminal (the trial-rule mutation pairs, which write to the
    /// core before reading the rule list back): aborting between the two
    /// RPCs would deliver "cancelled" for a mutation that is already live.
    /// The drain still raises the flag, and the task's own guard delivers
    /// the true verdict.
    #[tokio::test(flavor = "current_thread")]
    async fn abort_all_leaves_a_run_to_terminal_query_running() {
        let mut registry = JobRegistry::new();
        let id = registry.try_begin(JobKind::TrialRules).unwrap();
        let (tx, mut rx) = oneshot::channel();
        let guard = ReplyGuard::new(tx, "terminal");
        let (release_tx, release) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            // The read-back is in flight; only this test's release lets the
            // pair finish and deliver its verdict.
            release.await.expect("released by the test");
            guard.send("verdict").expect("reply channel alive");
        });
        registry.set_abort_keep_running(id, task.abort_handle());
        let flag = registry.cancel_flag(id).unwrap();

        registry.abort_all();

        assert!(flag.load(Ordering::SeqCst), "the drain raises the flag");
        assert!(
            !task.is_finished(),
            "abort_all must not abort a record that runs to its own terminal"
        );
        assert_eq!(
            rx.try_recv(),
            Err(TryRecvError::Empty),
            "no terminal may be manufactured while the task runs"
        );
        release_tx.send(()).expect("release the task");
        assert_eq!(rx.await, Ok("verdict"), "the task's own terminal lands");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sidecar_park_and_exactly_one_take() {
        let mut registry = JobRegistry::new();
        registry.try_begin(JobKind::TestConfig).unwrap();
        assert!(registry.take_exclusive_sidecar().is_none());

        let (tx, mut rx) = oneshot::channel::<TestConfigReply>();
        registry.set_exclusive_sidecar(ExclusiveSidecar::TestReply(tx));

        match registry.take_exclusive_sidecar() {
            Some(ExclusiveSidecar::TestReply(reply)) => {
                let verdict = (true, ApplyOutput::Text("valid".to_string()));
                assert!(
                    reply.send(Ok(verdict)).is_ok(),
                    "the parked reply receiver is alive in this test"
                );
            }
            Some(_) => panic!("expected the parked TestReply sidecar"),
            None => panic!("the parked sidecar must take exactly once"),
        }
        match rx.try_recv() {
            Ok(Ok((ok, output))) => {
                assert!(ok, "the parked verdict keeps its acceptance flag");
                assert_eq!(output.text(Language::En), "valid");
            }
            other => panic!("the parked terminal must land, got {other:?}"),
        }
        assert!(
            registry.take_exclusive_sidecar().is_none(),
            "a second terminal path must find no sidecar (exactly-one)"
        );
    }
}
