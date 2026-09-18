//! Core runtime: owns the xray-core backend — a direct
//! hidden child process, or the elevated helper pipe in TUN mode — plus gRPC
//! stats/observatory polling, config apply/validate/rollback, and core/dat
//! downloads. The GUI talks to it over `CoreCmd`/`CoreEvt` channels; every
//! event send is followed by an egui repaint request.

pub mod apply;
pub mod dns_in;
pub mod grpc;
pub mod helper;
pub mod jobs;
mod latency;
mod policy;
mod profiles;
mod seat;
mod state;
pub mod supervisor;
mod wfp;

use policy::{
    CANDIDATE_RETRY_DELAY, CoreExitFacts, DNS_IN_ADD_ATTEMPTS, ExitBranch, PreReadinessFailure,
    READY_TIMEOUT, READY_TIMEOUT_APPLIED, ReadinessTimeout, TUN_BIND_RACE_RETRIES,
    candidate_retry_budget, classify_core_exit, classify_pre_readiness_exit,
    helper_state_arms_readiness, readiness_deadline_reached, readiness_timeout,
    readiness_timeout_verdict, spend_retry_attempt, update_retries_bind_race,
};
use state::{BackendState, Backoff, CoreUpdatePending, ExitPolicy, PendingTransition};

use crate::diag::{Diag, DiagError};
use crate::i18n::Key;
use crate::metrics::{MetricsHandle, TickArm};
use crate::model::inbound::TUN_INBOUND_TAG;
use crate::model::settings::Language;
use crate::sys::selfupd::UpdateCheckState;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);
/// Per-RPC bound for the graceful TUN-close `RemoveInbound` call (3 s),
/// applied by [`grpc::GrpcClient`] as the request deadline. Both the main
/// process and the elevated helper wrap the same call in the outer
/// give-up deadline ([`TUN_CLOSE_DEADLINE`]), so the bound lives here in
/// the runtime root, not inside the client.
const TUN_RPC_TIMEOUT: Duration = Duration::from_secs(3);
/// Classification margin added to [`TUN_RPC_TIMEOUT`] for the outer
/// give-up wrap: after the RPC's own bound elapses, the caller waits this
/// long for the result to land before falling back to process teardown.
/// The RPC deadline fires first only while the margin is strictly
/// positive, so it must never be zeroed.
const TUN_CLOSE_MARGIN: Duration = Duration::from_millis(250);
/// Outer give-up deadline for a graceful TUN close: the per-RPC bound plus
/// the classification margin (3 s + 250 ms = 3.25 s). Single canonical
/// definition shared by the main process's `cleanup_tun` and the elevated
/// helper's kill path, so the two can never drift apart.
const TUN_CLOSE_DEADLINE: Duration = TUN_RPC_TIMEOUT.saturating_add(TUN_CLOSE_MARGIN);
/// Bound for joining the runtime worker at teardown. Covers the
/// worker's legitimate worst case: an in-flight profile validation shutdown
/// waits for ([`apply::VALIDATE_TIMEOUT`] — its child owns the scratch
/// config, so the runtime cannot finish before the worker's own terminal)
/// plus TUN cleanup ([`TUN_CLOSE_DEADLINE`]) plus STOP_TIMEOUT (5 s) plus
/// the Tokio shutdown (0.25 s) plus the bounded event sends during shutdown
/// (a few × EVENT_SEND_BOUND). A worker still alive after this bound is
/// pathologically stalled; [`RuntimeHandle::drop`]
/// detaches it so the GUI thread's teardown can never hang on the join.
const RUNTIME_JOIN_BOUND: Duration =
    Duration::from_secs(12).saturating_add(apply::VALIDATE_TIMEOUT);

use tokio::sync::mpsc;
use tokio::sync::oneshot;

use crate::rt::jobs::{Busy, ExclusiveOutcome, ExclusiveSidecar, JobKind, JobRegistry};

pub use grpc::{
    BalancerInfoView, GrpcClient, HealthPingView, OutboundStatusView, RuntimeEntryView, StatsTick,
};

/// WFP DNS-shield predicate (see [`wfp`]): true when the config runs a TUN
/// inbound alongside the DNS module's loopback listener. Re-exported from
/// the runtime root so the wire-tag coupling tests can pin the
/// shield against the emitted config without widening the `wfp` module.
pub use wfp::config_needs_dns_shield;

/// Terminal verdict of one accepted `CoreCmd::TestConfig`: `Ok((accepted,
/// output))` when the core ran the validation, `Err` when it never did
/// (rejection or cancellation text). Travels the request's own reply
/// channel. Defined with the registry (jobs.rs) where the
/// per-kind sidecar parks the reply sender; re-exported here unchanged.
pub use self::jobs::TestConfigReply;

/// One accepted `CoreCmd::ValidateProfiles` request (the profiles to
/// validate and the model snapshot they are staged against), its terminal
/// verdict, and the origin/draft-target types both carry. Defined with the
/// verb (`rt/profiles.rs`), which also owns the scratch-config contract;
/// re-exported here so the shell, the screen and the runtime share one
/// definition.
pub use self::profiles::{
    ProfileValidationOrigin, ProfileValidationReply, ProfileValidationRequest,
    ProfileValidationResult, ToolTarget,
};

/// Boot sweeps for files stranded by a crash or kill — the runtime's entry
/// points for the shell's startup cleanup. [`sweep_stale_scratch_configs`]
/// removes profile-validation scratch configs and [`sweep_stale_probe_dirs`]
/// the latency probe's temp dirs; both are age-bounded, both are name-checked
/// against the exact naming contract of the writer they clean up after, and
/// both return the number of files removed.
pub use self::latency::sweep_stale_probe_dirs;
pub use self::profiles::sweep_stale_scratch_configs;

/// Commands the GUI sends to the runtime. Not `Clone`: variants carrying
/// oneshot reply senders are single-owner by construction.
#[derive(Debug)]
pub enum CoreCmd {
    Start,
    Stop,
    Restart,
    /// Validate the candidate with `xray run -test`; on success commit it and
    /// restart the core if it was running, with automatic rollback to the last
    /// known-good config when the new one fails fast.
    ApplyConfig(serde_json::Value),
    /// Atomically commit a candidate and select the transport used by the
    /// resulting backend. This is the only command GUI apply flows should use
    /// when changing TUN mode while the core is active.
    ApplyConfigWithTunMode {
        value: serde_json::Value,
        tun_mode: bool,
        start_after_commit: bool,
    },
    /// Validate and commit the candidate, then start the core only after the
    /// commit succeeds. Used by Connect so an invalid candidate can never
    /// start a stale config.
    ApplyConfigAndStart(serde_json::Value),
    /// Validate only; never committed. The terminal verdict travels the
    /// request's own reply channel.
    TestConfig {
        config: serde_json::Value,
        reply: oneshot::Sender<TestConfigReply>,
    },
    /// Validate a batch of server profiles one by one: for each profile,
    /// generate a config for it, write that config to a scratch file in the
    /// config directory, and run the file through `xray run -test`. Never
    /// committed, never persisted. The terminal verdict (accepted/rejected
    /// lists) travels the request's own reply channel; cancelling is
    /// cooperative, so an in-flight validation child is never hard-aborted.
    /// Boxed: the request carries whole `Settings`/`ServersFile` snapshots
    /// and crosses a channel (clippy::large_enum_variant).
    ValidateProfiles {
        request: Box<ProfileValidationRequest>,
        reply: oneshot::Sender<ProfileValidationReply>,
    },
    /// Download and atomically install Broccoli's compiled pinned Xray release.
    /// Refused unless the core is stopped.
    UpdateCore,
    /// Install a user-selected archive only when it matches Broccoli's compiled
    /// release pin. Like `UpdateCore`, refused unless the core is stopped.
    ImportCoreArchive(PathBuf),
    /// On-demand update check: fetch the
    /// repository's default-branch Cargo.toml and compare its version against
    /// the compiled one. Not a core operation; the terminal result arrives as
    /// `CoreEvt::UpdateCheck`.
    CheckUpdate,
    Shutdown,
    /// EXTENSION (final name): when set, the core is started through the
    /// elevated helper (`--core-helper`, named pipe) so the TUN inbound's
    /// wintun works; when cleared, the core runs as a direct unprivileged
    /// child. If the core is running, changing this restarts it through the
    /// new transport.
    SetTunMode(bool),
    /// Enable/disable the observatory status read and choose the reported
    /// outbound tags (empty = every observed tag). The app derives the flag
    /// from the generated configuration's health engine, so the read runs
    /// exactly when a core-side extension can answer it.
    SetObservatory {
        enabled: bool,
        tags: Vec<String>,
    },
    /// Ask the running core how it would route a complete official
    /// `RoutingContext`. The terminal verdict travels the request's own
    /// reply channel.
    TestRoute {
        reply: oneshot::Sender<Result<String, DiagError>>,
        request: crate::model::routing::RouteTestRequest,
    },
    /// Launch a temporary, directly supervised Xray child and return one
    /// isolated Observatory snapshot without touching the main core. When
    /// the main core is up with TUN, `tun_outbound_interface` carries its
    /// `autoOutboundsInterface` setting and `tun_adapter_name` the TUN
    /// adapter's own name (excluded from resolution). Single
    /// flight: pairing the outcome back to this request is structural —
    /// there is no correlation id.
    ProbeLatency {
        profiles: Vec<crate::model::ServerProfile>,
        probe_url: String,
        tun_outbound_interface: Option<String>,
        tun_adapter_name: Option<String>,
    },
    /// Query the running core's ephemeral state for one configured balancer.
    /// The terminal result travels the request's own reply channel.
    GetBalancerInfo {
        reply: oneshot::Sender<Result<BalancerInfoView, DiagError>>,
        balancer_tag: String,
    },
    /// Pin a balancer to one exact, non-empty outbound tag until core
    /// restart. The terminal result travels the request's own reply channel.
    SetBalancerOverride {
        reply: oneshot::Sender<Result<(), DiagError>>,
        balancer_tag: String,
        target: String,
    },
    /// Clear a balancer's ephemeral target pin so its strategy chooses
    /// again. The terminal result travels the request's own reply channel.
    ClearBalancerOverride {
        reply: oneshot::Sender<Result<(), DiagError>>,
        balancer_tag: String,
    },
    /// Ask LoggerService to close and reopen its configured output targets.
    /// The terminal result travels the request's own reply channel.
    RestartLogger {
        reply: oneshot::Sender<Result<(), DiagError>>,
    },
    /// Inject one routing rule into the running core (`RoutingService.AddRule`,
    /// append mode). The rule is a trial rule — ephemeral, never persisted,
    /// lost on core restart or config commit. The terminal result is the
    /// read-back verdict ([`TrialRuleAddOutcome`]): `Ok` means the core holds
    /// the rule and carries the live inventory, `Err` means it does not. The
    /// add's own reply is never the verdict on its own — the core applies the
    /// mutation before/regardless of this client's wait. Boxed: the model
    /// `Rule` is large and the command crosses a channel
    /// (clippy::large_enum_variant).
    AddTrialRule {
        reply: oneshot::Sender<Result<TrialRuleAddOutcome, DiagError>>,
        rule: Box<crate::model::routing::Rule>,
    },
    /// Remove every live rule carrying `rule_tag` (`RoutingService.RemoveRule`).
    /// The terminal result carries the refreshed live rule list and travels
    /// the request's own reply channel.
    RemoveTrialRule {
        reply: oneshot::Sender<Result<Vec<(String, String)>, DiagError>>,
        rule_tag: String,
    },
    /// Refresh the live rule inventory (`RoutingService.ListRule`). The
    /// terminal result travels the request's own reply channel.
    ListTrialRules {
        reply: oneshot::Sender<Result<Vec<(String, String)>, DiagError>>,
    },
    /// Read the running core's live inbounds/outbounds (`ListInbounds` /
    /// `ListOutbounds`) for the runtime state view. The terminal result
    /// travels the request's own reply channel.
    ListRuntimeState {
        reply: oneshot::Sender<Result<RuntimeStateView, DiagError>>,
    },
}

/// Transport ownership of the backend that actually launched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreTransport {
    Direct,
    Tun,
}

impl CoreTransport {
    const fn from_backend_tun_owned(backend_tun_owned: bool) -> Self {
        if backend_tun_owned {
            Self::Tun
        } else {
            Self::Direct
        }
    }
}

/// One runtime-authored user-visible message: a keyed sentence, or a failure
/// chain whose app-authored layers carry keys and whose external causes stay
/// verbatim. Built where no [`Language`] exists and rendered with
/// [`AppMessage::text`] at the display boundary.
#[derive(Debug, Clone)]
pub enum AppMessage {
    /// A keyed sentence.
    Message(Diag),
    /// A keyed sentence with the underlying failure chain attached.
    Error(Arc<DiagError>),
}

impl AppMessage {
    /// Render the message in `language`.
    pub fn text(&self, language: Language) -> String {
        match self {
            Self::Message(message) => message.text(language),
            Self::Error(error) => error.text(language),
        }
    }

    /// The keyed headline of this message: the sentence itself, without a
    /// cause chain. Nesting the headline into another message keeps the
    /// chain with the outer record instead of repeating it.
    pub fn headline(&self) -> &Diag {
        match self {
            Self::Message(message) => message,
            Self::Error(error) => error.diag(),
        }
    }
}

/// English rendering, for the log file, tests, and `{}` sites that render
/// before the display boundary.
impl std::fmt::Display for AppMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text(Language::En))
    }
}

impl From<Diag> for AppMessage {
    fn from(message: Diag) -> Self {
        Self::Message(message)
    }
}

impl From<DiagError> for AppMessage {
    fn from(error: DiagError) -> Self {
        Self::Error(Arc::new(error))
    }
}

impl PartialEq for AppMessage {
    /// Structural for two keyed sentences, by rendered English text for two
    /// chains (a chain holds opaque sources and cannot be compared
    /// structurally). Used by the shell's snapshot equality checks.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Message(message), Self::Message(other)) => message == other,
            (Self::Error(error), Self::Error(other)) => {
                error.text(Language::En) == other.text(Language::En)
            }
            _ => false,
        }
    }
}

impl Eq for AppMessage {}

/// The text one apply verdict carries: a runtime-authored message, or the
/// captured `xray -test` output shown verbatim.
#[derive(Debug, Clone)]
pub enum ApplyOutput {
    /// A keyed runtime message, with its cause chain when one exists.
    Message(AppMessage),
    /// The captured validation output.
    Text(String),
}

impl ApplyOutput {
    /// Render the output in `language`.
    pub fn text(&self, language: Language) -> String {
        match self {
            Self::Message(message) => message.text(language),
            Self::Text(text) => text.clone(),
        }
    }
}

/// Events the runtime pushes to the GUI.
#[derive(Debug, Clone)]
pub enum CoreEvt {
    State(CorePhase),
    /// Exact committed configuration used by a successful launch and the
    /// transport ownership mode of the backend that just launched, not the
    /// next configured setting.
    ActiveConfig {
        snapshot: Result<String, AppMessage>,
        transport: CoreTransport,
    },
    /// One raw log line (core output, or a passthrough app-authored line that
    /// has no key): complete text, rendered verbatim.
    Log {
        line: String,
        from_core: bool,
    },
    /// One runtime-authored message: the app renders it with the active
    /// language and adds the `[broccoli] ` log prefix at drain time.
    AppLog(AppMessage),
    Stats(StatsTick),
    Observatory(Vec<OutboundStatusView>),
    /// Result of a committed apply (or its validation/commit failure).
    ApplyResult {
        ok: bool,
        output: ApplyOutput,
    },
    /// Result of the one automatic last-good rollback attempt. This is
    /// deliberately separate from [`CorePhase`]: a successfully started
    /// replacement must remain `Starting`/`Running`.
    RollbackResult {
        ok: bool,
        output: AppMessage,
    },
    /// Correlated result for an isolated one-shot latency child.
    LatencyProbe(LatencyProbeResult),
    Download(DownloadState),
    /// Terminal result of one accepted `CoreCmd::CheckUpdate`.
    UpdateCheck(UpdateCheckState),
    /// `Some` while the runtime owns a mutually-exclusive lifecycle/update
    /// operation, then `None` exactly once when it finishes or is cancelled.
    Operation(Option<OperationKind>),
}

/// Live inbounds and outbounds of the running core (runtime state), as read
/// through the control plane.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeStateView {
    pub inbounds: Vec<RuntimeEntryView>,
    pub outbounds: Vec<RuntimeEntryView>,
}

/// One trial-rule add's outcome: the live inventory read back after the
/// attempt. `Ok` always means the core holds the rule (either the add reply
/// was Ok, or the read-back lists the rule tag); `Err` means the add failed,
/// or its reply failed and the read-back could not confirm the tag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrialRuleAddOutcome {
    /// Live `(target tag, rule tag)` inventory; `None` when the read-back
    /// after a confirmed add failed.
    pub rules: Option<Vec<(String, String)>>,
}

/// GUI-relevant slice of `SysStatsResponse`, defaulting to zeros when the
/// core is unreachable so the 1 Hz tick never drops stats over a transient
/// `GetSysStats` failure.
#[derive(Debug, Clone, Copy, Default)]
struct SysStatsSnapshot {
    uptime_secs: u64,
    goroutines: u64,
    alloc_bytes: u64,
    sys_bytes: u64,
    live_objects: u64,
    num_gc: u64,
}

/// One folded inbound traffic sweep for the 1 Hz tick. `per_inbound` carries
/// the per-second deltas the dashboard's rates render, `per_inbound_totals`
/// the raw cumulative counters that sit next to them — one row per delta row,
/// in the same tag order — and `up`/`down` the aggregate deltas.
struct InboundFold {
    /// `(tag, up bytes/s, down bytes/s)` per inbound, sorted by tag.
    per_inbound: Vec<(String, u64, u64)>,
    /// `(tag, cumulative up bytes, cumulative down bytes)` per inbound, in
    /// `per_inbound`'s tag order.
    per_inbound_totals: Vec<(String, u64, u64)>,
    /// Aggregate uplink bytes/s across all inbounds.
    up: u64,
    /// Aggregate downlink bytes/s across all inbounds.
    down: u64,
}

/// Outcome of one isolated one-shot latency child. The probe is
/// single-flight, so pairing the result back to its request is structural —
/// no correlation id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatencyProbeResult {
    pub tags: Vec<String>,
    pub result: Result<Vec<OutboundStatusView>, ProbeFailure>,
}

/// Structured latency-probe failure: `headline` is the user-visible message
/// without the "Xray diagnostics:" wall, `tail` the captured child output.
/// [`ProbeFailure::full`] composes the two for one language, so the log
/// record and the UI text cannot diverge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeFailure {
    pub headline: Diag,
    pub tail: String,
}

impl ProbeFailure {
    /// A failure without a diagnostics tail.
    pub fn plain(headline: Diag) -> Self {
        Self {
            headline,
            tail: String::new(),
        }
    }

    /// The full failure text in `language`: the headline, then the
    /// diagnostics wall and the captured tail when the run produced one.
    pub fn full(&self, language: Language) -> String {
        crate::probe_verdict::with_diagnostics_wall(
            language,
            self.headline.text(language),
            &self.tail,
        )
    }
}

#[derive(Debug, Clone)]
pub enum CorePhase {
    Stopped,
    Starting,
    Running,
    Backoff {
        attempt: u32,
    },
    /// Terminal failure of the last start attempt: the keyed headline plus
    /// the captured core output the diagnostics wall renders.
    Error(PhaseError),
}

/// A phase failure: the keyed headline the phase badge renders, and the
/// captured core-output tail the log record appends under the shared
/// diagnostics wall. Both halves derive from one source so the badge and the
/// record cannot diverge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseError {
    pub message: AppMessage,
    pub tail: String,
}

impl PhaseError {
    /// A failure with no captured core output.
    pub fn new(message: impl Into<AppMessage>) -> Self {
        Self {
            message: message.into(),
            tail: String::new(),
        }
    }

    /// Attach the captured core-output tail the record renders under the
    /// diagnostics wall; an empty tail leaves the record headline-only.
    #[must_use]
    pub fn with_tail(mut self, tail: String) -> Self {
        self.tail = tail;
        self
    }

    /// The full record in `language`: the headline, then the diagnostics
    /// wall and the tail when the run captured output.
    pub fn record(&self, language: Language) -> String {
        crate::probe_verdict::with_diagnostics_wall(
            language,
            self.message.text(language),
            &self.tail,
        )
    }
}

impl std::fmt::Display for PhaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.record(Language::En))
    }
}

#[derive(Debug, Clone)]
pub enum DownloadState {
    Idle,
    Working {
        /// Keyed progress stage, rendered in the active language.
        stage: Diag,
        done: u64,
        total: u64,
    },
    Done(String),
    /// Terminal failure: the keyed message, with its cause chain when the
    /// failure has one.
    Failed(AppMessage),
}
/// Runtime-owned mutually-exclusive work. The UI can use this event state to
/// disable every command that would race a lifecycle or on-disk transaction.
/// Localized to the job registry; re-exported here so
/// consumers import `crate::rt::OperationKind` unchanged.
pub use self::jobs::OperationKind;

/// GUI-side owner of the runtime command channel and worker thread.
///
/// Dropping the handle sends `Shutdown`, closes the only owned command sender,
/// and joins the worker within `RUNTIME_JOIN_BOUND`. Runtime
/// teardown is otherwise bounded by the gRPC and process deadlines below, so
/// normal GUI destruction cannot return while a managed backend still owns
/// TUN cleanup.
pub struct RuntimeHandle {
    pub cmd: mpsc::UnboundedSender<CoreCmd>,
    worker: Option<std::thread::JoinHandle<()>>,
    /// Completion signal fired by the worker as its last act, so the bounded
    /// join in `drop` observes it without parking on the thread handle
    worker_done: Option<std::sync::mpsc::Receiver<()>>,
}

impl Drop for RuntimeHandle {
    fn drop(&mut self) {
        // Replace then drop the live sender so `recv()` also observes EOF if
        // Shutdown cannot be enqueued because the worker already exited.
        let (closed_replacement, replacement_rx) = mpsc::unbounded_channel();
        drop(replacement_rx);
        let cmd = std::mem::replace(&mut self.cmd, closed_replacement);
        let _ = cmd.send(CoreCmd::Shutdown);
        drop(cmd);

        // Bounded join: the worker signals completion as its last
        // act, and normal teardown lands far inside the bound (gRPC/process
        // deadlines plus the bounded event sends). A worker still alive after
        // the bound is pathologically stalled; detaching it lets the GUI
        // thread's teardown finish and process teardown terminates the
        // straggler.
        if let Some(done) = self.worker_done.take()
            && done.recv_timeout(RUNTIME_JOIN_BOUND).is_ok()
            && let Some(worker) = self.worker.take()
        {
            let _ = worker.join();
        }
    }
}

/// Spawn the runtime thread (own tokio current-thread runtime) and return its
/// command handle. `evt` receives every [`CoreEvt`]; `repaint` is poked after
/// each one so the GUI redraws promptly.
pub fn spawn_runtime(
    evt: SyncSender<CoreEvt>,
    repaint: egui::Context,
    metrics: MetricsHandle,
) -> RuntimeHandle {
    let (tx, rx) = mpsc::unbounded_channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("broccoli-rt".to_string())
        .spawn(move || {
            // Direct-runtime users (e2e harness) bypass lib.rs startup;
            // install the rustls crypto provider here so any reqwest client
            // built on this runtime cannot hit the "No provider set" panic.
            // Re-installation is a no-op.
            ensure_tls_provider();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime for broccoli-rt");
            rt.block_on(async move {
                // Runtime::new builds the tonic connect_lazy channel, which needs
                // a reactor context — construct inside block_on, not before it.
                Runtime::new(rx, evt, repaint, metrics).run().await
            });
            // A UAC consent prompt runs in a non-cancellable blocking worker.
            // Runtime cancellation drops its JoinHandle, then this bounded
            // shutdown releases the Tokio thread even if ShellExecuteW has not
            // returned. The detached closure holds only a cancellation token;
            // it cannot authenticate or start a helper after that token flips.
            rt.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
            // Signal completion as the very last act so the bounded join in
            // RuntimeHandle::drop can observe it.
            let _ = done_tx.send(());
        })
        .expect("spawning broccoli-rt thread");
    RuntimeHandle {
        cmd: tx,
        worker: Some(worker),
        worker_done: Some(done_rx),
    }
}

enum Backend {
    Direct(Box<supervisor::Child>),
    Pipe(helper::HelperPipe),
}

/// Verified source for the single core-update operation.
enum CoreUpdateSource {
    PinnedDownload,
    LocalArchive(PathBuf),
}

/// Which configuration one spawn runs. Every arm yields an artefact this
/// build produced and promoted through the candidate path; a stored
/// configuration written by another build is never replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpawnConfigSource {
    /// A fresh apply this session committed and validated the artefact: the
    /// spawn runs exactly it, so the validated bytes are what the core gets.
    Committed,
    /// A core update landed and its health gate runs the app-owned
    /// configuration, never the user's profiles.
    CoreGate,
    /// A failed candidate was deliberately rolled back: the restored
    /// last-known-good artefact runs instead of a regeneration that would
    /// reproduce the rejected configuration. Stamp-checked.
    RolledBackReplay,
    /// Cold boot, backoff retry, transport switch: generate from the saved
    /// server list and settings.
    SavedState,
}

impl SpawnConfigSource {
    /// The one app-authored line that records which configuration this
    /// start runs, in the user's words rather than the enum's.
    fn notice(self) -> Diag {
        Diag::new(match self {
            Self::Committed => Key::RtLogSpawnConfigCommitted,
            Self::CoreGate => Key::RtLogSpawnConfigGate,
            Self::RolledBackReplay => Key::RtLogSpawnConfigReplay,
            Self::SavedState => Key::RtLogSpawnConfigRegenerated,
        })
    }
}

/// Why a helper-connect attempt ended without a pipe: an abort raised by the
/// shared cancel flag (Stop/Shutdown won the race with the UAC prompt or the
/// handshake — not a failure), or the connect error itself.
pub enum HelperConnectFailure {
    /// The launch was cancelled; the runtime must not report an Error phase.
    Cancelled,
    /// The connect failed.
    Failed(Box<dyn std::error::Error + Send + Sync>),
}

impl HelperConnectFailure {
    /// The connect error, or `None` for a cancellation.
    pub fn error(self) -> Option<Box<dyn std::error::Error + Send + Sync>> {
        match self {
            Self::Cancelled => None,
            Self::Failed(error) => Some(error),
        }
    }
}

fn cancelled_helper_connect() -> ExclusiveOutcome {
    ExclusiveOutcome::HelperConnected(Err(HelperConnectFailure::Cancelled))
}

/// The UAC prompt cannot be cancelled, but an accepted prompt must not turn
/// into a pipe connection after Stop/Shutdown has cancelled this launch.
fn connect_after_helper_launch<T>(cancel: &AtomicBool, connect: impl FnOnce() -> T) -> Option<T> {
    (!cancel.load(Ordering::Acquire)).then(connect)
}
fn preserve_core_update_readiness(
    session_candidate_pending_readiness: bool,
    durable_pending_update: bool,
) -> bool {
    session_candidate_pending_readiness || durable_pending_update
}

/// Mark kept by [`should_emit_download_progress`] before the first snapshot:
/// an elapsed-millisecond value no real download can reach, so the mark never
/// collides with a stored emission.
const NO_PROGRESS_EMITTED: u64 = u64::MAX;

/// Decide whether one download-progress snapshot should reach the GUI,
/// recording the emission in `last_progress` as milliseconds elapsed since
/// the download started. Snapshots are coalesced to at most one per
/// [`DOWNLOAD_PROGRESS_INTERVAL`] — the millisecond mark can move one
/// coalesced snapshot earlier by under a millisecond, never later — except
/// that the completion snapshot (`done == total` with a known total) is never
/// hidden. The mark is an atomic rather than a lock because the callback is
/// handed to `download_core` by shared reference (so its state must be
/// `Sync`) and only the download's own task ever calls it.
fn should_emit_download_progress(
    last_progress: &AtomicU64,
    elapsed: Duration,
    done: u64,
    total: u64,
) -> bool {
    let now_ms = elapsed.as_millis() as u64;
    let previous_ms = last_progress.load(Ordering::Relaxed);
    let should_emit = previous_ms == NO_PROGRESS_EMITTED
        || Duration::from_millis(now_ms.saturating_sub(previous_ms)) >= DOWNLOAD_PROGRESS_INTERVAL
        || (total != 0 && done >= total);
    if should_emit {
        last_progress.store(now_ms, Ordering::Relaxed);
    }
    should_emit
}

/// Ring capacity for recent core output lines (error surfaces).
const OUTPUT_RING: usize = 200;
/// Excerpt lines from the output ring appended to core-start failure
/// messages (exit-23 config errors, readiness timeouts) under the shared
/// diagnostics wall. The exit path used six lines inline; the wall keeps
/// the same bound instead of inventing a new cap.
const START_FAILURE_EXCERPT_LINES: usize = 6;
/// Readiness poll cadence while Starting.
const READY_POLL: Duration = Duration::from_millis(250);
/// Retry cadence for adding the in-tun DNS listener to a running core
/// ([`dns_in`]). The first attempt lands at readiness; the cadence only
/// spaces the retries that race a still-coming-up wintun adapter, and the
/// spin is bounded by [`DNS_IN_ADD_ATTEMPTS`].
const DNS_IN_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// Hard kill fallback when a core ignores a stop request.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);
/// Wintun `WintunCreateAdapter`'s internal device-interface wait is 15 000 ms
/// (`WaitForInterface`, WireGuard wintun `api/adapter.c`, with the create
/// preamble before it). A TUN core that is unresponsive to the graceful close
/// is likely stuck inside that wait, and terminating it there wedges PnP
/// device creation for every wintun user on the machine (2026-08-28;
/// the 2026-09-09 reconnect outage replayed it — a stop during the stall
/// broke Throne's tun for minutes). The create resolves by itself within the
/// window: the child either exits (create failed) or serves the API again
/// (create succeeded), so the stop path waits this window before hard-killing
/// a TUN core that did not answer the graceful close. Lanes that never carry
/// a wintun create keep the short [`STOP_TIMEOUT`]. The elevated helper's
/// parent-death watchdog still kills immediately at app crash — killing then
/// is unavoidable (nobody is left to wait) and by design.
const TUN_STOP_WINDOW: Duration = Duration::from_secs(20);
/// Download UI redraw cadence. HTTP chunks can arrive far faster than egui
/// frames; coalescing their progress snapshots prevents an unbounded event
/// backlog from starving lifecycle commands.
const DOWNLOAD_PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
/// Capacity of the bounded GUI event channel. Core output lines are coalesced
/// through [`LogGate`] once it fills, so a flooding core cannot grow the GUI
/// queue without bound (CWE-400/770); 2048 slots cover many frames
/// of GUI drain, and lifecycle events stay rare enough that they never starve.
pub const EVT_CHANNEL_CAPACITY: usize = 2048;
/// Bounded wait for one lifecycle event whose channel is full.
/// The GUI drains every frame, so this covers many drain cycles; only a GUI
/// that has stopped draining (shutdown) can exhaust it. Kept small so a
/// shutdown stalls for at most one event's window.
const EVENT_SEND_BOUND: Duration = Duration::from_millis(250);
/// Retry cadence of the bounded full-channel fallback. Far shorter than a
/// GUI frame, so a drain cycle is picked up within a few milliseconds.
const EVENT_SEND_RETRY: Duration = Duration::from_millis(10);

/// Build one select-loop ticker with `MissedTickBehavior::Delay`.
///
/// Tokio's default `Burst` fires the next tick instantly after an overrun.
/// A wedged core (accepts TCP on the API port, never answers) makes each
/// stats poll overrun its 1 s period — three sequential RPCs at 500 ms
/// deadline plus slack ≈ 1.65 s worst case — so Burst chains zero-gap
/// timeout cycles that monopolize the single runtime thread, starving job
/// tasks, cmd dispatch, and the event pumps between cycles. `Delay` skips
/// the missed periods and re-aligns to the period after the poll
/// completes: an overrun costs one poll per period, not a busy cycle.
/// Every run-loop ticker (ready/stats/obs/house) is built
/// here so none can fall back to Burst.
fn ticker(period: Duration) -> tokio::time::Interval {
    let mut tick = tokio::time::interval(period);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick
}

struct Runtime {
    evt: SyncSender<CoreEvt>,
    repaint: egui::Context,
    cmd: mpsc::UnboundedReceiver<CoreCmd>,
    grpc: GrpcClient,
    api_port: u16,
    /// Always-on performance instrumentation:
    /// app-owned snapshot; this thread records control-plane tick durations
    /// through this clone.
    metrics: MetricsHandle,

    /// Owns the live backend slot (direct child or helper pipe), its event
    /// channel, and the derived alive/tun-ownership flags.
    backend: BackendState,
    /// Stop/restart/silence policy for the in-flight expected exit.
    exit_policy: ExitPolicy,
    /// A just-committed config candidate plus its armed rollback.
    pending_transition: PendingTransition,
    /// The exact config content a helper start must stage. A start that
    /// generated its configuration captures those bytes directly (regenerate,
    /// gate, rollback replay); a start carrying a fresh apply's committed
    /// artefact keeps the bytes the apply gate validated. The elevated helper
    /// never re-reads the user-writable active path, so a same-user swap after
    /// capture cannot reach the stage; `None` means no start has captured yet.
    helper_config_bytes: Option<Vec<u8>>,
    /// The core-swap candidate (durable health marker) plus its rollback.
    core_update: CoreUpdatePending,
    /// Unexpected-exit backoff and the stability clock that resets it.
    backoff: Backoff,
    phase: CorePhase,

    requested_tun_mode: bool,
    obs_enabled: bool,
    obs_tags: Vec<String>,

    /// Recent core output lines for error surfaces. Xray prints config errors
    /// to *stdout* (Go `fmt.Println`, main/run.go), so both streams are kept —
    /// a stderr-only ring would be empty exactly on exit 23.
    output_ring: Arc<Mutex<VecDeque<String>>>,

    shutting_down: bool,

    /// The next start is a completed core update's health gate: it runs the
    /// app-owned configuration, never the user's profiles, so the gate
    /// answers only "does this binary run and answer". Armed when an install
    /// lands and when a durable pending-swap marker is adopted; consumed by
    /// the start it belongs to. A fresh apply supersedes it — the user's own
    /// start then carries the update's verdict.
    update_gate_start: bool,
    /// The next start replays the restored last-known-good artefact instead of
    /// regenerating, because regeneration would reproduce the configuration a
    /// rolled-back candidate failed on. Set only where a deliberate rollback
    /// completed; the replay checks the artefact's stamp first and regenerates
    /// when it names another build.
    replay_after_rollback: bool,
    /// The live backend is the health gate's proof process: it runs the
    /// app-owned configuration, so its first readiness ACKs the update and
    /// then ends the process (the phase settles to Stopped). Set by the start
    /// that ran `SpawnConfigSource::CoreGate`, cleared on any backend exit.
    gate_backend_alive: bool,
    /// Automatic retry count for a TUN candidate that exits before
    /// readiness. Reset on every fresh commit and on first readiness; the
    /// budget for one exit is a single attempt for the adapter teardown
    /// window and [`TUN_BIND_RACE_RETRIES`] extra for the dns-in bind race.
    candidate_boot_retries: u8,
    pending_restart: Option<Instant>,
    /// The in-tun DNS listener this start must add to its running core,
    /// armed from the config the core runs. `None` means nothing is pending:
    /// the add was not needed, succeeded, or spent its attempt budget.
    dns_in_listener: Option<dns_in::Listener>,
    /// Add attempts spent for `dns_in_listener`, capped through the shared
    /// [`spend_retry_attempt`] rule ([`DNS_IN_ADD_ATTEMPTS`]).
    dns_in_attempts: u8,
    /// Readiness clock: `Some(deadline)` = armed, `None` = unarmed (TUN
    /// staging or nothing started). Direct starts arm immediately after
    /// `supervisor::spawn`; TUN starts arm only once the elevated helper
    /// reports the xray child spawned, so helper staging and validation never
    /// count against the deadline.
    readiness_deadline: Option<Instant>,

    prev_traffic: HashMap<String, (u64, u64)>,
    /// Cumulative inbound (listener traffic) counters, one baseline per tag,
    /// with the same eviction rule as `prev_traffic` (`fold_into`).
    prev_inbound_traffic: HashMap<String, (u64, u64)>,
    rng: u64,
    http: Option<reqwest::Client>,
    /// On-demand update check in flight: gates duplicate
    /// `CheckUpdate` commands so every accepted click yields exactly one
    /// terminal result, and flips the UI to the `Checking` state.
    update_check_busy: Arc<AtomicBool>,
    /// Job registry: every command runs as a tracked job. The
    /// exclusive occupant (apply, test config, update core, latency probe,
    /// profile validation, and the lifecycle transitions) carries the
    /// runtime's whole operation
    /// state on its record — kind, cancel flag, keep-slot flag,
    /// pollable task, per-kind sidecar. Concurrent query records (route
    /// test, balancer, trial rules, logger restart, runtime state) abort on
    /// the Stop/Shutdown drain.
    jobs: JobRegistry,
    /// Busy-window bookends the registry sink queued but not yet delivered
    /// to the GUI: `Some(kind)` on exclusive begin, `None` on release. The
    /// [`Runtime::begin_exclusive`] / [`Runtime::release_exclusive`]
    /// wrappers drain these synchronously at the mutation, so the GUI never
    /// lags the busy window across an await and no bookend waits for the
    /// next [`Runtime::emit`]; the emit drain-first and the select loop's
    /// bookend arm are backstops for anything queued between mutations.
    /// Draining ahead of every later event keeps bookend ordering global
    /// (an event emitted after a mutation follows that mutation's
    /// bookends; an event emitted before stays before).
    pending_bookends: mpsc::UnboundedReceiver<Option<JobKind>>,
    /// Coalescing gate for core output lines, shared with the
    /// direct-mode pump closure and the helper path.
    log_gate: Arc<Mutex<LogGate>>,
}

/// Coalescing gate for core output lines forwarded to the GUI log. A flooding
/// core must not be able to grow the bounded GUI event queue without bound
/// (CWE-400/770): once the channel rejects a log event, later
/// lines are counted instead of queued, and the count is delivered as one
/// summary message as soon as the channel accepts again — coalescing rather
/// than dropping silently or blocking. Broccoli's own messages bypass the
/// gate (app-generated, low volume).
struct LogGate {
    /// True while the GUI channel has rejected at least one log event.
    backed_up: bool,
    /// Lines dropped since the last delivered summary.
    suppressed: u64,
}

impl LogGate {
    fn new() -> Self {
        LogGate {
            backed_up: false,
            suppressed: 0,
        }
    }

    /// Forward one core output line. Returns true when at least one event was
    /// actually queued (the caller requests a repaint then).
    fn forward(&mut self, line: String, evt: &SyncSender<CoreEvt>) -> bool {
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
fn suppressed_summary(n: u64) -> Diag {
    if n == 1 {
        Diag::new(Key::RtLogSuppressedOne)
    } else {
        Diag::new(Key::RtLogSuppressedMany).arg(n)
    }
}

/// Queue an event on the GUI channel. Log events are routed through
/// [`LogGate`] (coalesced when the channel is full); every other event falls
/// back to a bounded wait when the channel is momentarily full.
///
/// The fallback must never block the runtime thread without bound:
/// the GUI drains every frame in normal operation, so a channel
/// that stays full can only mean the GUI has stopped draining — shutdown.
/// Volatile events (telemetry, progress, diagnostics) are therefore dropped
/// immediately on a full channel: they are superseded by a later event of
/// the same class or lost without user-visible effect. Lifecycle, terminal,
/// and correlated events wait one [`EVENT_SEND_BOUND`] drain window first —
/// in normal operation the GUI's next frame drain delivers them, so they are
/// never dropped while the GUI is alive; only a permanently undrained
/// channel (shutdown) loses them, where no event is observable anyway.
fn queue_event(evt: CoreEvt, sender: &SyncSender<CoreEvt>) {
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

/// One app-authored log line written from outside the runtime loop — a
/// spawn's release verification, a probe worker. It emits exactly what
/// [`Runtime::app_log`] emits: the message lands on the GUI channel as an
/// [`CoreEvt::AppLog`] event the app renders in the display language, and
/// one repaint is requested. Cloneable, so a worker owns its own handle.
#[derive(Clone)]
pub(crate) struct AppLogSink {
    evt: SyncSender<CoreEvt>,
    repaint: egui::Context,
}

impl AppLogSink {
    pub(crate) fn new(evt: SyncSender<CoreEvt>, repaint: egui::Context) -> Self {
        Self { evt, repaint }
    }

    /// Queue one keyed message. Volatile by class (see
    /// [`is_volatile_event`]): a full GUI channel drops the line instead of
    /// blocking the worker that made the decision.
    pub(crate) fn log(&self, message: impl Into<AppMessage>) {
        queue_event(CoreEvt::AppLog(message.into()), &self.evt);
        self.repaint.request_repaint();
    }
}

/// Install the aws-lc-rs crypto provider as rustls's process default.
///
/// The HTTP stack is reqwest 0.12 built with `rustls-tls-webpki-roots-no-provider`,
/// migrating off the unmaintained `ring` provider. That backend
/// resolves the crypto provider at client construction via
/// `CryptoProvider::get_default()` and panics with "No provider set" when none
/// is installed — enabling the `aws-lc-rs` feature on rustls (Cargo.toml) only
/// compiles the provider in; it does not install it. Call once at startup,
/// before any `reqwest::Client` is created.
pub(crate) fn ensure_tls_provider() {
    // `install_default` errors only when a provider is already installed,
    // which is the state this function exists to guarantee — the returned
    // error (the previously installed provider) is deliberately discarded.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

impl Runtime {
    fn new(
        cmd: mpsc::UnboundedReceiver<CoreCmd>,
        evt: SyncSender<CoreEvt>,
        repaint: egui::Context,
        metrics: MetricsHandle,
    ) -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64 ^ (d.as_secs() << 32))
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            ^ u64::from(std::process::id());
        // Every registry busy-window bookend (exclusive begin `Some(kind)`,
        // release `None`) rides this side channel into the runtime; the
        // begin/release wrappers below drain it onto the GUI event queue
        // synchronously at the mutation, with `emit`'s drain-first as a
        // backstop, so bookend ordering is preserved. The receiver outlives
        // the sender: the sink closure is owned by `jobs`, which this
        // struct owns.
        let (bookend_tx, bookend_rx) = mpsc::unbounded_channel();
        Self {
            evt,
            repaint,
            cmd,
            metrics,
            // The API port is ephemeral per launch and derived from
            // the active/candidate config at start and apply time, never from
            // Settings. 0 is a placeholder until the first derivation.
            grpc: GrpcClient::new(0),
            api_port: 0,
            backend: BackendState::new(),
            exit_policy: ExitPolicy::idle(),
            pending_transition: PendingTransition::new(),
            helper_config_bytes: None,
            core_update: CoreUpdatePending::new(),
            backoff: Backoff::new(),
            phase: CorePhase::Stopped,
            requested_tun_mode: false,
            obs_enabled: false,
            obs_tags: Vec::new(),
            output_ring: Arc::new(Mutex::new(VecDeque::with_capacity(OUTPUT_RING))),
            log_gate: Arc::new(Mutex::new(LogGate::new())),
            shutting_down: false,
            update_gate_start: false,
            replay_after_rollback: false,
            gate_backend_alive: false,
            candidate_boot_retries: 0,
            pending_restart: None,
            dns_in_listener: None,
            dns_in_attempts: 0,
            readiness_deadline: None,
            prev_traffic: HashMap::new(),
            prev_inbound_traffic: HashMap::new(),
            // xorshift64* state must be non-zero.
            rng: seed | 1,
            http: None,
            update_check_busy: Arc::new(AtomicBool::new(false)),
            jobs: JobRegistry::with_busy_sink(move |bookend| {
                let _ = bookend_tx.send(bookend);
            }),
            pending_bookends: bookend_rx,
        }
    }

    // -- event plumbing ------------------------------------------------------

    /// Queue a core-output log line through the coalescing gate,
    /// requesting a repaint only when an event actually made it onto the
    /// channel.
    fn emit_core_log(&self, line: String) {
        let queued = match self.log_gate.lock() {
            Ok(mut gate) => gate.forward(line, &self.evt),
            Err(_) => false,
        };
        if queued {
            self.repaint.request_repaint();
        }
    }

    fn emit(&mut self, evt: CoreEvt) {
        self.drain_pending_bookends();
        queue_event(evt, &self.evt);
        self.repaint.request_repaint();
    }

    /// Deliver every queued busy-window bookend onto the GUI event channel
    /// ahead of any event queued after the registry mutation that produced
    /// it. Every registry busy-window mutation now drains synchronously
    /// through [`Runtime::begin_exclusive`] / [`Runtime::release_exclusive`],
    /// so a bookend never sits undrained across an await and out-of-band
    /// emitters (the update-check worker's `queue_event`, download-progress
    /// `try_send`) cannot overtake a pending pair. The drain at the top of
    /// [`Runtime::emit`] and the select loop's bookend arm remain as
    /// backstops, preserving the global contract: an event emitted after a
    /// mutation follows that mutation's bookends on the GUI channel, and an
    /// event emitted before stays before.
    fn drain_pending_bookends(&mut self) {
        while let Ok(bookend) = self.pending_bookends.try_recv() {
            self.deliver_bookend(bookend);
        }
    }

    /// Queue one busy-window bookend onto the GUI event channel.
    fn deliver_bookend(&mut self, bookend: Option<JobKind>) {
        let event = match bookend {
            Some(kind) => {
                // Only exclusive kinds ever reach the sink (queries
                // never emit), so this cannot be None by construction.
                CoreEvt::Operation(Some(
                    kind.exclusive_operation_kind()
                        .expect("busy sink only emits exclusive kinds; queries never emit"),
                ))
            }
            None => CoreEvt::Operation(None),
        };
        queue_event(event, &self.evt);
    }

    fn emit_active_config(&mut self) {
        let snapshot = apply::read_active_contents().map_err(|error| {
            AppMessage::from(
                DiagError::new(Diag::new(Key::RtFramePreviewReadFailed)).caused_by(error),
            )
        });
        self.emit(CoreEvt::ActiveConfig {
            snapshot,
            transport: self.backend.transport(),
        });
    }

    fn set_phase(&mut self, phase: CorePhase) {
        self.phase = phase.clone();
        self.emit(CoreEvt::State(phase));
    }
    // -- exclusive-window helpers ----------------------

    /// Begin one exclusive job and deliver its `Some(kind)` bookend
    /// synchronously: `try_begin` queues the bookend on the side channel
    /// and the drain below puts it on the GUI event channel before this
    /// call returns, so the busy window is observable at the mutation even
    /// when the arm body then runs a long stretch (Stop's `kill_backend`
    /// await) before its first [`Runtime::emit`]. Query kinds keep
    /// `jobs.try_begin` — they never emit bookends. The drain also runs on
    /// the `Err(Busy)` side so reject re-emits (`Operation(Some(active))`)
    /// queue behind any bookend that reached the side channel before the
    /// rejected begin, exactly as `emit`'s drain-first would order them.
    fn begin_exclusive(&mut self, kind: JobKind) -> Result<u64, Busy> {
        let begun = self.jobs.try_begin(kind);
        self.drain_pending_bookends();
        begun
    }

    /// Release the busy window synchronously: `finish_exclusive` queues the
    /// `None` bookend on the side channel, and the immediate drain delivers
    /// it on the GUI event channel behind the terminal that preceded it
    /// before this call returns. A release never sits undrained across an
    /// await, where an out-of-band emitter (the update-check worker, the
    /// download-progress `try_send`) could overtake it.
    fn release_exclusive(&mut self) {
        self.jobs.finish_exclusive();
        self.drain_pending_bookends();
    }

    /// The busy-window rejection shared by every conflicting command: the
    /// occupant is named through its user-facing operation key, nested as a
    /// message so it renders in the display language.
    fn busy_reject_text(active: JobKind) -> Diag {
        Diag::new(Key::RtFrameCommandRejectedBusy).arg_message(seat::operation_name(active))
    }

    /// Cancel the busy exclusive record and release it (Stop/Shutdown/GUI
    /// channel closed). Exactly-one terminal per kind: the record's
    /// task-bearing terminal state is taken off the sidecar before the
    /// cancel, so a second terminal path can never fire.
    ///
    /// A kind whose worker runs to its own terminal is cancelled
    /// cooperatively instead: the record stays held, its cancel flag is
    /// raised, and the worker observes it between units of work. Hard
    /// aborting is never an option there — an in-flight core-update install
    /// runs in `spawn_blocking`, which `abort()` cannot interrupt (it only
    /// detaches the closure, so the update would land after the UI saw
    /// "cancelled" and a second install could overlap it), and an in-flight
    /// profile validation's `xray -test` child holds its scratch config open
    /// (Windows cannot delete the file under a live reader, so an abort would
    /// strand plaintext secrets and orphan the child).
    fn cancel_exclusive(&mut self, reason: &Diag) {
        let Some(kind) = self.jobs.busy_kind() else {
            return;
        };
        if self.jobs.exclusive_task_active() && seat::runs_to_own_terminal(kind) {
            // A worker with a cancel boundary observes the flag between units
            // of work; one without it finishes on its own and only needs the
            // keep-slot flag recorded.
            if seat::worker_polls_cancel_flag(kind) {
                self.jobs.request_cooperative_cancel();
            } else {
                self.jobs.request_cancel_flagged();
            }
            self.app_log(seat::cooperative_cancel_log(kind, reason));
            return;
        }
        self.cancel_task_exclusive(kind, reason);
    }

    /// Abort one in-flight exclusive task and settle the kind's exactly-one
    /// terminal. Task-less spans (lifecycle windows, a deferred
    /// apply-restart, a completed update awaiting readiness) deliver no
    /// terminal of their own — their result already landed or the exit path
    /// owns them.
    fn cancel_task_exclusive(&mut self, kind: JobKind, reason: &Diag) {
        // The worker's terminal state is taken before the cancel: the task
        // is aborted below, so the cancel path is the exactly-one terminal
        // when the outcome can no longer arrive.
        let task_active = self.jobs.exclusive_task_active();
        let sidecar = self.jobs.take_exclusive_sidecar();
        self.jobs.cancel_exclusive_record();
        self.app_log(
            Diag::new(Key::RtLogOperationCancelled)
                .arg_message(seat::operation_name(kind))
                .arg_message(reason.clone()),
        );
        if task_active {
            seat::deliver_cancel_terminal(kind, self, sidecar, reason);
        }
        self.release_exclusive();
    }

    /// An unexpected core exit (or TUN helper transport loss) must never
    /// silently drop a foreign in-flight user operation: the replacement
    /// backend's readiness path would otherwise release the record and
    /// discard the abandoned task's output, leaving the GUI revision stuck.
    /// Cancel ApplyConfig/TestConfig/LatencyProbe tasks explicitly and
    /// deliver their exactly-one terminal result. Task-less busy slots
    /// (Start/Restart spans, a completed UpdateCore awaiting readiness) are
    /// owned by the normal exit/readiness path and are left untouched. The
    /// current-thread executor makes the guard + take + abort atomic with
    /// respect to the select loop's task branch, so the terminal result is
    /// never doubled.
    fn cancel_exclusive_for_exit(&mut self, reason: &Diag) {
        let Some(kind) = self.jobs.busy_kind() else {
            return;
        };
        let foreign_task = self.jobs.exclusive_task_active() && seat::cancelled_on_exit(kind);
        if !foreign_task {
            return;
        }
        self.cancel_task_exclusive(kind, reason);
    }

    /// A worker task that died without a result (panic or join failure)
    /// must still settle its operation with the kind's exactly-one terminal.
    fn complete_exclusive_join_error(&mut self, kind: JobKind, error: tokio::task::JoinError) {
        let message = Diag::new(Key::RtFrameBackgroundFailed).arg(error);
        self.app_log(message.clone());
        let sidecar = self.jobs.take_exclusive_sidecar();
        seat::deliver_join_error_terminal(kind, self, sidecar, message);
        self.release_exclusive();
    }

    /// Queue one raw passthrough log line: complete text, `[broccoli] `
    /// prefixed here. Runtime-authored prose goes through [`Runtime::app_log`]
    /// instead, so it renders in the display language.
    fn log(&mut self, msg: &str) {
        self.emit(CoreEvt::Log {
            line: format!("[broccoli] {msg}"),
            from_core: false,
        });
    }

    /// Queue one runtime-authored message: the app renders it in the active
    /// language and adds the `[broccoli] ` log prefix at drain time.
    fn app_log(&mut self, message: impl Into<AppMessage>) {
        self.emit(CoreEvt::AppLog(message.into()));
    }

    /// A log handle for work that runs outside the runtime loop (a spawn's
    /// release verification, a probe worker); see [`AppLogSink`].
    fn log_sink(&self) -> AppLogSink {
        AppLogSink::new(self.evt.clone(), self.repaint.clone())
    }

    /// Route one decoded helper log record: a keyed record becomes a runtime
    /// message (the app renders it in the display language at the drain, like
    /// every other message), and an unknown record shape stays a raw
    /// passthrough line.
    fn emit_helper_log(&mut self, record: helper::HelperLog) {
        match record {
            helper::HelperLog::Message(error) => self.app_log(error),
            helper::HelperLog::Raw(line) => {
                self.push_ring(&line);
                self.emit_core_log(line);
            }
        }
    }

    fn output_tail(&self, n: usize) -> String {
        match self.output_ring.lock() {
            Ok(ring) => ring
                .iter()
                .rev()
                .take(n)
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n"),
            Err(_) => String::new(),
        }
    }

    fn next_rand(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    // -- main loop -----------------------------------------------------------

    async fn run(mut self) {
        self.emit(CoreEvt::State(CorePhase::Stopped));
        // Delay on every ticker (ready/stats/obs/dns/house), never Burst: a
        // wedged core overruns stats polls, and a zero-gap Burst catch-up
        // cycle would monopolize the runtime thread.
        let mut ready_tick = ticker(READY_POLL);
        let mut dns_tick = ticker(DNS_IN_RETRY_INTERVAL);
        let mut stats_tick = ticker(Duration::from_secs(1));
        let mut obs_tick = ticker(Duration::from_secs(5));
        let mut house_tick = ticker(Duration::from_millis(500));

        loop {
            tokio::select! {
                // Once Shutdown was handled the command channel is drained
                // and closed; an enabled arm would spin on the closed channel
                // while a worker-owned task still runs out its terminal.
                cmd = self.cmd.recv(), if !self.shutting_down => {
                    match cmd {
                        Some(cmd) => self.handle_cmd(cmd).await,
                        None => {
                            self.cancel_exclusive(&Diag::new(Key::RtReasonGuiChannelClosed));
                            self.shutting_down = true;
                        }
                    }
                }
                result = async {
                    let task = self
                        .jobs
                        .exclusive_task_mut()
                        .expect("exclusive task select guard");
                    task.await
                }, if self.jobs.exclusive_task_active() => {
                    let kind = self
                        .jobs
                        .busy_kind()
                        .expect("completed task still owns its record");
                    self.jobs.clear_exclusive_task();
                    match result {
                        Ok(outcome) => self.complete_exclusive(outcome).await,
                        Err(error) if error.is_cancelled() => {
                            // Explicit Stop/Shutdown already emitted its own
                            // terminal state. Never manufacture a second
                            // result after that cancellation.
                            self.release_exclusive();
                        }
                        Err(error) => self.complete_exclusive_join_error(kind, error),
                    }
                }
                bookend = self.pending_bookends.recv() => {
                    // Backstop arm: the begin/release wrappers drain every
                    // mutation synchronously, so a bookend waits here only
                    // in the window between a mutation and its drain.
                    // `recv()` has already popped the head bookend; deliver
                    // it first (bookend order), then drain anything queued
                    // behind it. A lone release must not leave the UI stuck
                    // busy, so the arm exists even when nothing else fires.
                    if let Some(bookend) = bookend {
                        self.deliver_bookend(bookend);
                        self.drain_pending_bookends();
                        self.repaint.request_repaint();
                    }
                    // `None` means the sender is gone with the runtime
                    // itself; the select loop is shutting down regardless.
                }
                status = async {
                    match self.backend.slot.as_mut() {
                        Some(Backend::Direct(child)) => child.wait().await.ok(),
                        _ => unreachable!(),
                    }
                }, if matches!(self.backend.slot, Some(Backend::Direct(_))) => {
                    let code = status.and_then(|s| s.code());
                    self.on_core_exit(code).await;
                }
                ev = async {
                    match self.backend.events.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => unreachable!(),
                    }
                }, if self.backend.events.is_some() => {
                    match ev {
                        Some(helper::HelperEvent::Log(record)) => self.emit_helper_log(record),
                        Some(helper::HelperEvent::Exit(code)) => {
                            self.on_core_exit(Some(code)).await;
                        }
                        Some(helper::HelperEvent::State { state, pid }) => {
                            self.on_helper_state(&state, pid);
                        }
                        None => {
                            // Pipe EOF is watchdog ownership release, but it is
                            // not an Xray Exit acknowledgement. Never launch a
                            // rollback/restart against possibly occupied ports.
                            let active = self.backend.is_alive() || self.exit_policy.stopping();
                            self.backend.force_release();
                            self.app_log(Diag::new(Key::RtLogHelperDisconnected));
                            if active {
                                self.on_unconfirmed_backend_loss();
                            }
                        }
                    }
                }
                _ = ready_tick.tick(), if matches!(self.phase, CorePhase::Starting) => {
                    let started = Instant::now();
                    self.ready_poll().await;
                    self.metrics.record_tick(TickArm::Ready, started.elapsed());
                }
                _ = dns_tick.tick(), if matches!(self.phase, CorePhase::Running) && self.dns_in_listener.is_some() => {
                    self.dns_in_poll().await;
                }
                _ = stats_tick.tick(), if matches!(self.phase, CorePhase::Running) => {
                    let started = Instant::now();
                    self.stats_poll().await;
                    self.metrics.record_tick(TickArm::Stats, started.elapsed());
                }
                _ = obs_tick.tick(), if matches!(self.phase, CorePhase::Running) && self.obs_enabled => {
                    let started = Instant::now();
                    self.obs_poll().await;
                    self.metrics.record_tick(TickArm::Observatory, started.elapsed());
                }
                _ = house_tick.tick(), if self.exit_policy.stopping() || self.pending_restart.is_some() => {
                    self.housekeeping().await;
                }
            }
            // Exit waits for a worker-owned record's exactly-one terminal: an
            // in-flight profile validation's child holds its scratch config
            // open, so tearing the runtime down here would strand plaintext
            // secrets and orphan the child. The loop keeps polling the task
            // arm (bounded by the child's own timeout) until that terminal
            // clears the record.
            if self.shutting_down && !self.jobs.exclusive_runs_to_terminal() {
                break;
            }
        }

        self.shutdown_backend().await;
    }

    fn push_ring(&mut self, line: &str) {
        if let Ok(mut ring) = self.output_ring.lock() {
            if ring.len() >= OUTPUT_RING {
                ring.pop_front();
            }
            ring.push_back(line.to_string());
        }
    }

    // -- command handling ----------------------------------------------------

    async fn handle_cmd(&mut self, cmd: CoreCmd) {
        match cmd {
            CoreCmd::Start => {
                match self.begin_exclusive(JobKind::Start) {
                    Ok(_) => {}
                    Err(Busy { active }) => {
                        // Whitelist-era void arm: log-only, no terminal.
                        self.app_log(Self::busy_reject_text(active));
                        return;
                    }
                }
                self.pending_restart = None;
                self.backoff.reset();
                if self.exit_policy.stopping() {
                    self.app_log(Diag::new(Key::RtLogConnectRejectedStopping));
                    self.release_exclusive();
                } else if self.backend.is_alive()
                    || matches!(self.phase, CorePhase::Starting | CorePhase::Running)
                {
                    self.app_log(Diag::new(Key::RtLogConnectIgnoredRunning));
                    self.release_exclusive();
                } else {
                    self.start_backend().await;
                }
            }
            CoreCmd::Stop => {
                let cancelled_operation = self.jobs.busy_kind().is_some();
                self.cancel_exclusive(&Diag::new(Key::RtReasonStopRequested));
                // Uniform drain: abort in-flight query jobs
                // (route test, balancer, trial rules, logger restart,
                // runtime state) alongside the exclusive cancel; their
                // reply guards deliver the terminal. A record under a
                // cooperative (keep-slot) cancellation is exempt — see
                // abort_all.
                self.jobs.abort_all();
                // A worker-owned record survives the cancel: an in-flight
                // UpdateCore install (its swap cannot be aborted) or an
                // in-flight profile validation (its child owns the scratch
                // config). Neither is preempted here and neither is released
                // here — the worker's own terminal ends the record, and the
                // update landing keeps the state it is mid-transaction with.
                let slot_kept = self.jobs.exclusive_runs_to_terminal();
                let update_landing = matches!(self.jobs.busy_kind(), Some(JobKind::UpdateCore));
                if self.backend.tun_owned_or_alive() && !slot_kept {
                    // Unreachable-in-practice: every abortable exclusive
                    // record was cancelled and released above, and a
                    // worker-owned record is kept out by the guard above.
                    // Stop is preemptive anyway, so this cannot reject.
                    match self.begin_exclusive(JobKind::Stop) {
                        Ok(_) => {}
                        Err(_) => unreachable!(
                            "no other exclusive record can survive into the Stop begin: \
                             `slot_kept` keeps the worker-owned ones out"
                        ),
                    }
                } else if !cancelled_operation {
                    // No exclusive record existed for the release to clear,
                    // but the GUI marks Stop optimistically after send.
                    self.emit(CoreEvt::Operation(None));
                }
                self.pending_restart = None;
                self.pending_transition.clear();
                if !update_landing {
                    self.core_update.clear();
                }
                if self.backend.tun_owned_or_alive() {
                    self.exit_policy.begin_stop(Instant::now());
                    self.kill_backend().await;
                } else {
                    self.exit_policy.finish();
                    self.backend.force_release();
                    if !matches!(self.phase, CorePhase::Stopped) {
                        self.set_phase(CorePhase::Stopped);
                    }
                    if !update_landing {
                        self.release_exclusive();
                    }
                }
            }
            CoreCmd::Restart => {
                match self.begin_exclusive(JobKind::Restart) {
                    Ok(_) => {}
                    Err(Busy { active }) => {
                        // Whitelist-era void arm: log-only, no terminal.
                        self.app_log(Self::busy_reject_text(active));
                        return;
                    }
                }
                self.pending_restart = None;
                if self.backend.tun_owned_or_alive() {
                    self.exit_policy.begin_restart(Instant::now());
                    self.kill_backend().await;
                } else {
                    self.start_backend().await;
                }
            }
            CoreCmd::ApplyConfig(value) => self.dispatch_apply(value, false, None).await,
            CoreCmd::ApplyConfigWithTunMode {
                value,
                tun_mode,
                start_after_commit,
            } => {
                self.dispatch_apply(value, start_after_commit, Some(tun_mode))
                    .await
            }
            CoreCmd::ApplyConfigAndStart(value) => self.dispatch_apply(value, true, None).await,
            CoreCmd::TestConfig { config, reply } => {
                if self.exit_policy.stopping() {
                    // The runtime is tearing down and will not run the
                    // validation; reject on the request's own channel and
                    // poke the repaint so the requester's poll wakes
                    // (mirror the reply commands' stopping terminal).
                    if reply.send(Err(seat::runtime_stopping())).is_err() {
                        // Receiver vanished; nothing further is delivered.
                    }
                    self.repaint.request_repaint();
                    return;
                }
                match self.begin_exclusive(JobKind::TestConfig) {
                    Ok(_) => self.begin_test_work(config, reply).await,
                    Err(Busy { active }) => {
                        // Whitelist-era sync reject: the rejection is the
                        // terminal result — send it on the request's own
                        // channel and poke the repaint so the requester's
                        // poll wakes.
                        let output = Self::busy_reject_text(active);
                        self.app_log(output.clone());
                        if reply.send(Err(DiagError::from(output))).is_err() {
                            // Receiver vanished; nothing further is delivered.
                        }
                        self.repaint.request_repaint();
                    }
                }
            }
            CoreCmd::ValidateProfiles { request, reply } => {
                if self.exit_policy.stopping() {
                    // The runtime is tearing down and will not run the
                    // validation; reject on the request's own channel and
                    // poke the repaint so the requester's poll wakes
                    // (mirror the reply commands' stopping terminal).
                    if reply.send(Err(seat::runtime_stopping())).is_err() {
                        // Receiver vanished; nothing further is delivered.
                    }
                    self.repaint.request_repaint();
                    return;
                }
                match self.begin_exclusive(JobKind::ValidateProfiles) {
                    Ok(_) => self.begin_profile_validation_work(*request, reply),
                    Err(Busy { active }) => {
                        // The rejection is the terminal result — send it on
                        // the request's own channel and poke the repaint so
                        // the requester's poll wakes.
                        let output = Self::busy_reject_text(active);
                        self.app_log(output.clone());
                        if reply.send(Err(DiagError::from(output))).is_err() {
                            // Receiver vanished; nothing further is delivered.
                        }
                        self.repaint.request_repaint();
                    }
                }
            }
            CoreCmd::UpdateCore => self.update_core(CoreUpdateSource::PinnedDownload),
            CoreCmd::ImportCoreArchive(path) => {
                self.update_core(CoreUpdateSource::LocalArchive(path))
            }
            CoreCmd::CheckUpdate => self.check_update(),
            CoreCmd::SetTunMode(on) => {
                // Whitelist-era guard: the command is rejected while any
                // exclusive job holds the window, whether or not this toggle
                // would restart the core.
                if let Some(occupant) = self.jobs.busy_kind() {
                    self.app_log(Self::busy_reject_text(occupant));
                    return;
                }
                if on == self.requested_tun_mode {
                    return;
                }
                let active = self.backend.tun_owned_or_alive()
                    || matches!(
                        self.phase,
                        CorePhase::Starting | CorePhase::Running | CorePhase::Backoff { .. }
                    );
                if active {
                    // Cannot reject: the guard above ran in the same
                    // synchronous section, so the window is still empty.
                    match self.begin_exclusive(JobKind::Restart) {
                        Ok(_) => {}
                        Err(_) => unreachable!(
                            "SetTunMode begin raced no mutation: the busy guard above \
                             already confirmed an empty window"
                        ),
                    }
                }
                if active {
                    self.app_log(Diag::new(Key::RtLogTransportChangeRestart));
                    self.pending_restart = None;
                    if self.backend.tun_owned_or_alive() {
                        self.exit_policy.begin_restart(Instant::now());
                        // `kill_backend` consults current ownership. Do not flip
                        // the requested next mode until TUN close was attempted.
                        self.kill_backend().await;
                        self.requested_tun_mode = on;
                    } else {
                        self.requested_tun_mode = on;
                        self.start_backend().await;
                    }
                } else {
                    self.requested_tun_mode = on;
                }
                self.app_log(if on {
                    Diag::new(Key::RtLogTunModeOn)
                } else {
                    Diag::new(Key::RtLogTunModeOff)
                });
            }
            CoreCmd::SetObservatory { enabled, tags } => {
                self.obs_enabled = enabled;
                self.obs_tags = tags;
            }
            CoreCmd::TestRoute { reply, request } => {
                // The shared runner owns the reply guard, conflict check,
                // spawn and terminal send; the seat owns the pinned
                // whitelist-era ordering (busy window before availability).
                self.run_query(seat::RouteTestSeat { request }, reply).await;
            }
            CoreCmd::ProbeLatency {
                profiles,
                probe_url,
                tun_outbound_interface,
                tun_adapter_name,
            } => {
                match self.begin_exclusive(JobKind::LatencyProbe) {
                    Ok(_) => self.begin_probe_work(
                        profiles,
                        probe_url,
                        tun_outbound_interface,
                        tun_adapter_name,
                    ),
                    Err(Busy { active }) => {
                        // Whitelist-era reject: log the line and deliver the
                        // headline-only failure event with the request's own
                        // tags (no release — the owner rejects it).
                        let output = Self::busy_reject_text(active);
                        self.app_log(output.clone());
                        let tags = profiles.iter().map(|profile| profile.tag()).collect();
                        self.emit(CoreEvt::LatencyProbe(LatencyProbeResult {
                            tags,
                            result: Err(ProbeFailure::plain(output)),
                        }));
                    }
                }
            }
            CoreCmd::GetBalancerInfo {
                reply,
                balancer_tag,
            } => {
                self.run_query(
                    seat::BalancerInfoSeat {
                        balancer_tag: balancer_tag.trim().to_string(),
                    },
                    reply,
                )
                .await;
            }
            CoreCmd::SetBalancerOverride {
                reply,
                balancer_tag,
                target,
            } => {
                self.run_query(
                    seat::SetBalancerOverrideSeat {
                        balancer_tag: balancer_tag.trim().to_string(),
                        target: target.trim().to_string(),
                    },
                    reply,
                )
                .await;
            }
            CoreCmd::ClearBalancerOverride {
                reply,
                balancer_tag,
            } => {
                self.run_query(
                    seat::ClearBalancerOverrideSeat {
                        balancer_tag: balancer_tag.trim().to_string(),
                    },
                    reply,
                )
                .await;
            }
            CoreCmd::RestartLogger { reply } => {
                self.run_query(seat::RestartLoggerSeat, reply).await;
            }
            CoreCmd::AddTrialRule { reply, rule } => {
                self.run_query(seat::AddTrialRuleSeat { rule: *rule }, reply)
                    .await;
            }
            CoreCmd::RemoveTrialRule { reply, rule_tag } => {
                self.run_query(seat::RemoveTrialRuleSeat { rule_tag }, reply)
                    .await;
            }
            CoreCmd::ListTrialRules { reply } => {
                self.run_query(seat::ListTrialRulesSeat, reply).await;
            }
            CoreCmd::ListRuntimeState { reply } => {
                self.run_query(seat::ListRuntimeStateSeat, reply).await;
            }
            CoreCmd::Shutdown => {
                self.cancel_exclusive(&Diag::new(Key::RtReasonShutdownRequested));
                self.jobs.abort_all();
                self.pending_restart = None;
                self.pending_transition.clear();
                self.core_update.clear();
                self.exit_policy.finish();
                self.shutting_down = true;
            }
        }
    }

    /// Validate-and-commit dispatch shared by the three apply commands.
    /// The busy-window reject carries the whitelist-era terminal text; the
    /// work below runs with the exclusive record already held.
    async fn dispatch_apply(
        &mut self,
        value: serde_json::Value,
        start_after_commit: bool,
        tun_mode: Option<bool>,
    ) {
        match self.begin_exclusive(JobKind::ApplyConfig) {
            Ok(_) => {
                self.begin_apply_work(value, start_after_commit, tun_mode)
                    .await
            }
            Err(Busy { active }) => {
                // Whitelist-era reject: log the line and settle the GUI's
                // pending revision with the failure result.
                let output = Self::busy_reject_text(active);
                self.app_log(output.clone());
                self.emit(CoreEvt::ApplyResult {
                    ok: false,
                    output: ApplyOutput::Message(AppMessage::from(output)),
                });
            }
        }
    }

    async fn begin_apply_work(
        &mut self,
        value: serde_json::Value,
        start_after_commit: bool,
        tun_mode: Option<bool>,
    ) {
        // The control-plane port is ephemeral and lives only in the
        // emitted config; derive it from the candidate the runtime will run so
        // the gRPC client polls exactly the committed listener.
        let api_port = match apply::api_port_from_value(&value) {
            Ok(port) => port,
            Err(error) => {
                self.emit(CoreEvt::ApplyResult {
                    ok: false,
                    output: ApplyOutput::Message(AppMessage::from(
                        DiagError::new(Diag::new(Key::RtFrameApplyRejected)).caused_by(error),
                    )),
                });
                self.release_exclusive();
                return;
            }
        };
        // The candidate write is a create/write/fsync leg, so it runs on the
        // blocking pool. The exclusive record stays held across the await, and
        // a write failure still settles the operation right here — no
        // validation task ever starts.
        let path = match apply::write_candidate_offloaded(value).await {
            Ok(path) => path,
            Err(error) => {
                self.emit(CoreEvt::ApplyResult {
                    ok: false,
                    output: ApplyOutput::Message(AppMessage::from(
                        DiagError::new(Diag::new(Key::RtFrameCandidateWriteFailed))
                            .caused_by(error),
                    )),
                });
                self.release_exclusive();
                return;
            }
        };
        let task = tokio::spawn(async move {
            let (ok, output) = apply::validate(&path).await;
            ExclusiveOutcome::ApplyValidated {
                ok,
                output,
                start_after_commit,
                tun_mode,
                api_port,
            }
        });
        self.jobs.attach_exclusive_task(task);
    }

    /// Validation work of an accepted TestConfig command (the record was
    /// begun by the arm; a write failure releases it with a pre-spawn
    /// reject).
    async fn begin_test_work(
        &mut self,
        value: serde_json::Value,
        reply: oneshot::Sender<TestConfigReply>,
    ) {
        // The candidate write is a create/write/fsync leg, so it runs on the
        // blocking pool. The exclusive record stays held across the await.
        let path = match apply::write_candidate_offloaded(value).await {
            Ok(path) => path,
            Err(error) => {
                // Pre-spawn reject: the task never began, so the rejection is
                // the terminal result — send it on the request's own channel
                // and poke the repaint so the requester's poll wakes.
                let rejection =
                    DiagError::new(Diag::new(Key::RtFrameCandidateWriteFailed)).caused_by(error);
                if reply.send(Err(rejection)).is_err() {
                    // Receiver vanished; nothing further is delivered.
                }
                self.repaint.request_repaint();
                self.release_exclusive();
                return;
            }
        };
        // Park the sidecar before the spawn: a completion racing the spawn
        // must find the pairing (current-thread executor: guard + park +
        // spawn are atomic with respect to the select loop).
        self.jobs
            .set_exclusive_sidecar(ExclusiveSidecar::TestReply(reply));
        let task = tokio::spawn(async move {
            let (ok, output) = apply::validate(&path).await;
            ExclusiveOutcome::TestValidated { ok, output }
        });
        self.jobs.attach_exclusive_task(task);
    }

    /// Validation work of an accepted ValidateProfiles command (the record
    /// was begun by the arm). The worker walks the profiles on the runtime's
    /// own executor, so the scratch write, the guard and the `xray -test`
    /// child all live with the record: cancelling is cooperative (the worker
    /// observes the record's cancel flag between profiles), and the exit path
    /// waits for its exactly-one terminal.
    fn begin_profile_validation_work(
        &mut self,
        request: ProfileValidationRequest,
        reply: oneshot::Sender<ProfileValidationReply>,
    ) {
        // Park the sidecar before the spawn: a completion racing the spawn
        // must find the pairing (current-thread executor: guard + park +
        // spawn are atomic with respect to the select loop).
        self.jobs
            .set_exclusive_sidecar(ExclusiveSidecar::ProfileReply(reply));
        let cancel = self
            .jobs
            .exclusive_cancel_flag()
            .expect("the record begun by the dispatch arm still occupies");
        let task = tokio::spawn(async move {
            ExclusiveOutcome::ProfileValidation(profiles::validate(request, &cancel).await)
        });
        self.jobs.attach_exclusive_task(task);
    }

    /// Probe work of an accepted ProbeLatency command (the record was begun
    /// by the arm). The tags are cloned into the sidecar BEFORE the spawn so
    /// a cancel/join-error terminal can always report them.
    fn begin_probe_work(
        &mut self,
        profiles: Vec<crate::model::ServerProfile>,
        probe_url: String,
        tun_outbound_interface: Option<String>,
        tun_adapter_name: Option<String>,
    ) {
        let tags: Vec<String> = profiles.iter().map(|profile| profile.tag()).collect();
        if tags.is_empty() {
            let failure = ProbeFailure::plain(Diag::new(Key::ProbeNoProfiles));
            self.log(&failure.full(Language::En));
            self.emit(CoreEvt::LatencyProbe(LatencyProbeResult {
                tags,
                result: Err(failure),
            }));
            self.release_exclusive();
            return;
        }
        self.jobs
            .set_exclusive_sidecar(ExclusiveSidecar::LatencyTags(tags.clone()));
        // The probe dials bypass the TUN only while the main core
        // is Running and owns it; with the core down or TUN off there is no
        // capture to bypass, and binding would let a stale adapter name fail
        // a probe nothing would have polluted.
        let tun_active = matches!(self.phase, CorePhase::Running) && self.backend.is_tun_owned();
        let log = self.log_sink();
        let task = tokio::spawn(async move {
            let result = latency::run(
                profiles.clone(),
                probe_url,
                tun_outbound_interface,
                tun_adapter_name,
                tun_active,
                &log,
            )
            .await;
            ExclusiveOutcome::LatencyProbe {
                tags,
                profiles,
                result,
            }
        });
        self.jobs.attach_exclusive_task(task);
    }

    /// Per-kind completion dispatch for a task outcome the select loop
    /// consumed. Release timing is per-kind: task-terminal kinds release at
    /// their terminal; an apply that restarts the core and a successful
    /// core update keep the record through readiness (deferred release).
    async fn complete_exclusive(&mut self, outcome: ExclusiveOutcome) {
        match outcome {
            ExclusiveOutcome::HelperConnected(result) => {
                let mut pipe = match result {
                    Ok(pipe) => pipe,
                    Err(error) => {
                        // A connect aborted by the shared cancel flag is not a
                        // failure: Stop/Shutdown already owns terminal state,
                        // and the launch must never turn into an Error phase.
                        let Some(error) = error.error() else {
                            self.release_exclusive();
                            return;
                        };
                        self.set_phase(CorePhase::Error(PhaseError::new(
                            DiagError::new(Diag::new(Key::RtPhaseHelperUnavailable))
                                .caused_by(error),
                        )));
                        self.release_exclusive();
                        return;
                    }
                };
                let events = pipe.take_events();
                let Some(config_bytes) = self.helper_config_bytes.as_deref() else {
                    self.set_phase(CorePhase::Error(PhaseError::new(Diag::new(
                        Key::RtPhaseHelperConfigLost,
                    ))));
                    self.release_exclusive();
                    return;
                };
                if let Err(error) = pipe.start(self.api_port, config_bytes) {
                    self.set_phase(CorePhase::Error(PhaseError::new(
                        DiagError::new(Diag::new(Key::RtPhaseHelperStartFailed)).caused_by(error),
                    )));
                    self.release_exclusive();
                    return;
                }
                self.backend.attach_tun(pipe, events);
                self.backend.mark_tun_started();
                // The TUN adapter is up; drop stale resolver answers cached
                // before it existed.
                self.flush_dns_cache();
                self.defer_readiness_deadline();
                self.emit_active_config();
                self.set_phase(CorePhase::Starting);
                self.app_log(Diag::new(Key::RtLogCoreStartedHelper));
            }
            ExclusiveOutcome::ApplyValidated {
                ok,
                output,
                start_after_commit,
                tun_mode,
                api_port,
            } => {
                self.complete_apply_validation(ok, output, start_after_commit, tun_mode, api_port)
                    .await;
            }
            ExclusiveOutcome::TestValidated { ok, output } => {
                // Invariant: the terminal can only arrive while a TestConfig
                // task is in flight, which parked the reply sidecar.
                let sidecar = self.jobs.take_exclusive_sidecar();
                seat::deliver_test_reply(self, sidecar, Ok((ok, output)));
                self.release_exclusive();
            }
            ExclusiveOutcome::ProfileValidation(reply) => {
                // Invariant: the terminal can only arrive while a profile
                // validation task is in flight, which parked the reply
                // sidecar. The worker's own terminal (a completed verdict or
                // its cooperative-cancel terminal) is the exactly-one
                // terminal, and it is what releases the busy window.
                let sidecar = self.jobs.take_exclusive_sidecar();
                seat::deliver_profile_reply(self, sidecar, reply);
                self.release_exclusive();
            }
            ExclusiveOutcome::LatencyProbe {
                tags,
                profiles,
                result,
            } => {
                match &result {
                    Err(failure) => self.log(&failure.full(Language::En)),
                    Ok(statuses) if statuses.iter().any(|status| !status.alive) => {
                        self.log(&crate::probe_verdict::warn_summary(
                            crate::model::settings::Language::En,
                            &profiles,
                            statuses,
                        ));
                    }
                    _ => {}
                }
                // The full diagnostics wall rides the verdict to
                // the UI — the failure path is not hot, and dropping the
                // payload here is what kept root causes invisible (each
                // failure needed a manual reproduction). The UI formatters
                // and the log both compose from the same `ProbeFailure`, so
                // their text cannot drift.
                self.emit(CoreEvt::LatencyProbe(LatencyProbeResult { tags, result }));
                self.release_exclusive();
            }
            ExclusiveOutcome::Download { state, kind } => {
                let succeeded = matches!(state, DownloadState::Done(_));
                self.emit(CoreEvt::Download(state));
                // When Stop/Shutdown cancelled the update but the
                // install could not be aborted (`spawn_blocking`), the swap
                // has now landed (or failed) and the disk is consistent.
                // Deliver the terminal event and release the record; the
                // health-gate start below is skipped because cancellation
                // meant exactly that — no automatic restart. The durable
                // swap marker still protects the next explicit Start.
                let cancelled = self.jobs.is_cancel_requested();
                if succeeded && kind == OperationKind::UpdateCore && !cancelled {
                    // The filesystem swap completed. Keep the record owner
                    // through the health-gate startup so no second update can
                    // race the candidate before it is acknowledged or rolled
                    // back. This work still runs entirely off the UI thread.
                    self.core_update.commit_candidate();
                    // The gate proves the installed binary with the app-owned
                    // configuration; it starts on the next housekeeping tick.
                    self.update_gate_start = true;
                    self.set_phase(CorePhase::Stopped);
                    self.pending_restart = Some(Instant::now());
                    return;
                }
                if succeeded && cancelled {
                    self.app_log(Diag::new(Key::RtLogUpdateFinishedAfterStop));
                }
                self.release_exclusive();
            }
        }
    }

    async fn complete_apply_validation(
        &mut self,
        ok: bool,
        output: ApplyOutput,
        start_after_commit: bool,
        tun_mode: Option<bool>,
        api_port: u16,
    ) {
        if !ok {
            self.emit(CoreEvt::ApplyResult { ok: false, output });
            self.release_exclusive();
            return;
        }
        // Capture the exact candidate bytes the apply gate validated BEFORE
        // the commit rename, so any helper start later stages precisely what
        // xray -test accepted — never a re-read of the user-writable active
        // path at elevated time. A candidate
        // that cannot be captured cannot be committed: fail closed instead
        // of promoting bytes the runtime could not bind to the start. The
        // capture read and the commit rename are filesystem legs, so both run
        // on the blocking pool (see the `apply` module).
        let validated_bytes = match apply::read_candidate_offloaded().await {
            Ok(bytes) => bytes,
            Err(error) => {
                self.emit(CoreEvt::ApplyResult {
                    ok: false,
                    output: ApplyOutput::Message(AppMessage::from(
                        DiagError::new(Diag::new(Key::RtFrameApplyCaptureFailed)).caused_by(error),
                    )),
                });
                self.release_exclusive();
                return;
            }
        };
        if let Err(error) = apply::commit_offloaded().await {
            self.emit(CoreEvt::ApplyResult {
                ok: false,
                output: ApplyOutput::Message(AppMessage::from(
                    DiagError::new(Diag::new(Key::RtFrameApplyCommitFailed)).caused_by(error),
                )),
            });
            self.release_exclusive();
            return;
        }
        self.helper_config_bytes = Some(validated_bytes);
        self.emit(CoreEvt::ApplyResult { ok: true, output });
        self.app_log(Diag::new(Key::RtLogConfigApplied));
        self.pending_transition.commit_candidate();
        self.candidate_boot_retries = 0;
        let active = self.backend.tun_owned_or_alive()
            || matches!(
                self.phase,
                CorePhase::Starting | CorePhase::Running | CorePhase::Backoff { .. }
            );
        if active {
            self.pending_restart = None;
            if self.backend.tun_owned_or_alive() {
                self.exit_policy.begin_restart(Instant::now());
                // Cleanup and stop polling still use the old API endpoint and
                // old TUN ownership. Commit next-backend state only after the
                // graceful close request has been issued.
                self.kill_backend().await;
            }
            self.commit_requested_backend(tun_mode, api_port);
            if !self.backend.tun_owned_or_alive() {
                // Do not recurse through the async start/rollback graph.
                // Housekeeping owns the replacement after confirmed exit;
                // inactive Backoff starts on its next tick.
                if self.exit_policy.stopping() {
                    self.exit_policy.begin_restart(Instant::now());
                } else {
                    self.pending_restart = Some(Instant::now());
                }
            }
        } else if start_after_commit {
            self.commit_requested_backend(tun_mode, api_port);
            self.pending_restart = Some(Instant::now());
        } else {
            self.commit_requested_backend(tun_mode, api_port);
            // The next explicit Start still carries the unproven candidate,
            // but applying while stopped has completed as an operation.
            self.release_exclusive();
        }
    }

    fn commit_requested_backend(&mut self, tun_mode: Option<bool>, api_port: u16) {
        if let Some(tun_mode) = tun_mode {
            self.requested_tun_mode = tun_mode;
        }
        self.api_port = api_port;
        self.grpc = GrpcClient::new(api_port);
        self.app_log(Diag::new(Key::RtLogApiEndpointCommitted).arg(api_port));
    }

    // -- backend lifecycle ---------------------------------------------------

    /// Which configuration this start runs, consuming the one-shot flags that
    /// arm the gate and the post-rollback replay. A freshly committed
    /// candidate supersedes the gate: the user's own start then carries the
    /// update's verdict (the gate flag is consumed either way).
    fn take_spawn_config_source(&mut self) -> SpawnConfigSource {
        let gate = std::mem::take(&mut self.update_gate_start);
        let replay = std::mem::take(&mut self.replay_after_rollback);
        if self.pending_transition.is_candidate_pending() {
            return SpawnConfigSource::Committed;
        }
        if gate {
            return SpawnConfigSource::CoreGate;
        }
        if replay {
            return SpawnConfigSource::RolledBackReplay;
        }
        SpawnConfigSource::SavedState
    }

    /// Whether this start runs behind the elevated helper. TUN sessions do;
    /// the health gate never does: it proves the installed binary with an
    /// app-owned direct configuration (no tun inbound), so it needs neither
    /// the elevation ceremony nor the consent prompt a user's TUN session
    /// justifies.
    fn uses_elevated_helper(&self) -> bool {
        self.requested_tun_mode && !self.gate_backend_alive
    }

    /// Land a failure to produce the spawn's configuration — the app's own
    /// generation refusal, an unreadable state file, an unwritable artefact.
    /// The core was never spawned, so this class never blames the installed
    /// payload: a pending update ends as installed and the finding is the
    /// terminal phase.
    fn settle_spawn_config_failure(&mut self, error: DiagError) {
        self.settle_config_failure(PhaseError::new(AppMessage::from(error)));
    }

    /// Land one configuration-class failure. While an update candidate is
    /// unproven the payload hashes have already verified the installed tree,
    /// so the update ends as installed — the durable marker and the retained
    /// last-good tree are consumed — and the configuration finding is what
    /// the user must see. Never a core rollback: replaying a tree cannot
    /// repair a configuration.
    fn settle_config_failure(&mut self, failure: PhaseError) {
        // Read before the ACK consumes it: only a pending update candidate
        // makes this failure keep the installed, hash-verified core, and the
        // line must say so before the phase error is read.
        let kept_installed_core = self.core_update.is_candidate_pending();
        // A no-op when no update candidate is unproven (`ack_ready` checks).
        if let Err(error) = self.core_update.ack_ready() {
            self.app_log(error);
        }
        if kept_installed_core {
            self.app_log(
                Diag::new(Key::RtLogConfigKeptInstalledCore)
                    .arg_message(failure.message.headline().clone()),
            );
        }
        self.set_phase(CorePhase::Error(failure));
        self.release_exclusive();
    }

    async fn start_backend(&mut self) {
        // Begin a Restart record only when the window is empty: internal
        // starts (housekeeping, rollback) ride the record the caller left
        // busy (an apply-then-restart, the update health-gate) and must not
        // re-enter the registry.
        if self.jobs.busy_kind().is_none()
            && let Err(Busy { active }) = self.begin_exclusive(JobKind::Restart)
        {
            // Cannot reject: the gate above ran in the same synchronous
            // section, so the window is still empty.
            unreachable!("internal Restart begin raced no mutation: {active:?} holds the window")
        }
        if self.backend.is_alive() {
            self.app_log(Diag::new(Key::RtLogInternalStartRejected));
            self.release_exclusive();
            return;
        }
        if self.backend.is_tun_owned() {
            // This should only be reachable after an abnormal transport loss.
            // Attempt cleanup, release the owner, and refuse replacement:
            // without a confirmed exit, spawning on the same ports is unsafe.
            self.cleanup_tun().await;
            self.backend.force_release();
            self.set_phase(CorePhase::Error(PhaseError::new(Diag::new(
                Key::RtPhaseBackendReplacementCancelled,
            ))));
            self.release_exclusive();
            return;
        }
        if let Err(error) = crate::sys::core_dl::recover_installation() {
            self.set_phase(CorePhase::Error(PhaseError::new(
                DiagError::new(Diag::new(Key::RtPhaseUpdateRecoveryFailed)).caused_by(error),
            )));
            self.release_exclusive();
            return;
        }
        // An update with no prior core has no durable `core.bak` marker, but
        // it still needs this session's first readiness verdict. Preserve the
        // in-memory candidate set by the completed install while also adopting
        // any durable pending swap recovered at startup.
        let update_pending_before = self.core_update.is_candidate_pending();
        self.core_update
            .adopt_durable_marker(crate::sys::core_dl::update_pending_health());
        if !update_pending_before && self.core_update.is_candidate_pending() {
            // A swap landed but was never proven: the first start of the
            // session is its health gate, with the app-owned configuration.
            self.update_gate_start = true;
        }

        // Every spawn runs a configuration this build produced. A stored
        // artefact is never replayed across builds: the runtime regenerates
        // from the saved state, the gate writes its own app-owned
        // configuration, and the one deliberate replay (the restored
        // last-known-good after a rolled-back candidate) is stamp-checked.
        let source = self.take_spawn_config_source();
        // Which configuration this start runs: one line at the decision,
        // before any spawn (direct or behind the elevated helper).
        self.app_log(source.notice());
        // The gate's proof process is the one backend whose readiness does not
        // become the user's session; its first readiness ends it.
        self.gate_backend_alive = matches!(source, SpawnConfigSource::CoreGate);
        let (api_port, generated_bytes) = match source {
            SpawnConfigSource::Committed => {
                // A fresh apply this session wrote and validated the
                // artefact; its bytes are what runs, and its own candidate
                // carries the start's verdict.
                match apply::active_api_port() {
                    Ok(port) => (port, None),
                    Err(error) => {
                        self.settle_spawn_config_failure(
                            DiagError::new(Diag::new(Key::RtPhaseApiListenerReadFailed))
                                .caused_by(error),
                        );
                        return;
                    }
                }
            }
            SpawnConfigSource::CoreGate => match apply::write_core_gate_offloaded().await {
                Ok(config) => (config.api_port, Some(config.bytes)),
                Err(error) => {
                    self.settle_spawn_config_failure(error);
                    return;
                }
            },
            SpawnConfigSource::RolledBackReplay => {
                match apply::replay_rolled_back_offloaded().await {
                    Ok(config) => (config.api_port, Some(config.bytes)),
                    Err(error) => {
                        self.settle_spawn_config_failure(error);
                        return;
                    }
                }
            }
            SpawnConfigSource::SavedState => match apply::regenerate_offloaded().await {
                Ok(config) => (config.api_port, Some(config.bytes)),
                Err(error) => {
                    self.settle_spawn_config_failure(error);
                    return;
                }
            },
        };
        if api_port != self.api_port {
            self.api_port = api_port;
            self.grpc = GrpcClient::new(api_port);
            // The listen address comes from the artefact this start wrote or
            // committed, never from Settings: the fresh candidate's own
            // `api.listen` is the endpoint the app must poll.
            self.app_log(Diag::new(Key::RtLogApiEndpointCommitted).arg(api_port));
        }
        self.backoff.reset_since();
        self.core_update.clear_last_error();
        self.prev_traffic.clear();
        self.prev_inbound_traffic.clear();
        // The previous core's listener died with it: a start never inherits a
        // pending add. Only the TUN branch below arms one, from the config
        // that core will run — a direct child never owns the adapter whose
        // gateway the listener binds.
        self.dns_in_listener = None;
        self.dns_in_attempts = 0;

        // TUN always runs behind the authenticated helper, even when the GUI
        // itself happens to be elevated. That independent owner observes pipe
        // EOF and closes the inbound before its Job fallback on GUI death.
        // The health gate is the one exception: its app-owned configuration
        // carries no tun inbound, so it spawns directly even when the user's
        // session is TUN — the proof needs no elevation and must never prompt.
        if self.uses_elevated_helper() {
            // The bytes this start generated are the ones the helper stages,
            // captured before the UAC launch below; the elevated helper never
            // re-reads the user-writable active path, so a same-user swap
            // after this point cannot reach the stage. A fresh apply in this
            // session already captured the committed candidate's exact
            // validated bytes; only a start without one falls back to the
            // active file.
            if let Some(bytes) = generated_bytes {
                self.helper_config_bytes = Some(bytes);
            } else if self.helper_config_bytes.is_none() {
                self.helper_config_bytes = Some(match std::fs::read(apply::active_path()) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        self.settle_spawn_config_failure(
                            DiagError::new(Diag::new(Key::RtPhaseConfigReadFailed))
                                .caused_by(error),
                        );
                        return;
                    }
                });
            }
            // Arm the in-tun DNS listener from the exact bytes the helper
            // stages: the listener binds the address this config pins as the
            // tun adapter's DNS, so the two can never drift.
            self.dns_in_listener = self
                .helper_config_bytes
                .as_deref()
                .and_then(dns_in::listener_for_bytes);
            self.start_via_helper();
            return;
        }

        // A stopped helper is still an elevated process. Close its authenticated
        // pipe before replacing the backend with a direct child.
        self.backend.release_pipe();
        // Every source above promoted its artefact to the active path, so the
        // child the runtime spawns is exactly the configuration this start
        // produced. The release-pin verify runs on the blocking pool; the
        // spawn resumes on the executor with the verified payload locks held.
        let log = self.log_sink();
        match supervisor::spawn(&apply::active_path(), &log).await {
            Ok(mut child) => {
                let pid = child.pid();
                let evt = self.evt.clone();
                let repaint = self.repaint.clone();
                let ring = Arc::clone(&self.output_ring);
                let gate = Arc::clone(&self.log_gate);
                child.pump_output(Box::new(move |line, _is_stderr| {
                    if let Ok(mut ring) = ring.lock() {
                        if ring.len() >= OUTPUT_RING {
                            ring.pop_front();
                        }
                        ring.push_back(line.clone());
                    }
                    // The error-surface ring above keeps every line (bounded
                    // at OUTPUT_RING); the GUI channel is gated so a flooding
                    // core cannot grow the event queue.
                    let queued = match gate.lock() {
                        Ok(mut gate) => gate.forward(line, &evt),
                        Err(_) => false,
                    };
                    if queued {
                        repaint.request_repaint();
                    }
                }));
                self.backend.spawn_direct(Box::new(child));
                self.arm_readiness_deadline();
                self.emit_active_config();
                self.set_phase(CorePhase::Starting);
                self.app_log(Diag::new(Key::RtLogCoreStartedDirect).arg(pid));
            }
            Err(error) => {
                if self.core_update.is_candidate_pending() {
                    self.core_update.clear_candidate();
                    match crate::sys::core_dl::rollback_unhealthy_update() {
                        Ok(true) => {
                            self.emit(CoreEvt::Download(DownloadState::Failed(AppMessage::from(
                                DiagError::new(Diag::new(Key::RtFrameUpdatedCoreSpawnRestored))
                                    .caused_by(error),
                            ))));
                            self.pending_restart = Some(Instant::now());
                        }
                        Ok(false) => {
                            self.emit(CoreEvt::Download(DownloadState::Failed(AppMessage::from(
                                DiagError::new(Diag::new(Key::RtFrameUpdatedCoreSpawnNoLastGood))
                                    .caused_by(error),
                            ))));
                            self.set_phase(CorePhase::Stopped);
                            self.release_exclusive();
                        }
                        Err(rollback_error) => {
                            let rollback_message = rollback_error.diag().clone();
                            self.emit(CoreEvt::Download(DownloadState::Failed(AppMessage::from(
                                DiagError::new(
                                    Diag::new(Key::RtFrameUpdatedCoreSpawnRollbackFailed)
                                        .arg_message(rollback_message),
                                )
                                .caused_by(error),
                            ))));
                            self.set_phase(CorePhase::Stopped);
                            self.release_exclusive();
                        }
                    }
                } else {
                    self.set_phase(CorePhase::Error(PhaseError::new(
                        DiagError::new(Diag::new(Key::RtPhaseCoreSpawnFailed)).caused_by(error),
                    )));
                    self.release_exclusive();
                }
            }
        }
    }

    fn start_via_helper(&mut self) {
        if let Some(Backend::Pipe(pipe)) = self.backend.as_backend() {
            // `start_backend` guaranteed the captured bytes before this
            // restart branch; a missing
            // capture is an invariant break and must fail loudly, never
            // fall back to a file re-read.
            let Some(config_bytes) = self.helper_config_bytes.as_deref() else {
                self.set_phase(CorePhase::Error(PhaseError::new(Diag::new(
                    Key::RtPhaseHelperConfigLost,
                ))));
                self.release_exclusive();
                return;
            };
            match pipe.start(self.api_port, config_bytes) {
                Ok(()) => {
                    self.backend.mark_tun_started();
                    // The TUN adapter is up; drop stale resolver answers
                    // cached before it existed.
                    self.flush_dns_cache();
                    self.defer_readiness_deadline();
                    self.emit_active_config();
                    self.set_phase(CorePhase::Starting);
                    self.app_log(Diag::new(Key::RtLogCoreStartedHelper));
                }
                Err(error) => {
                    self.set_phase(CorePhase::Error(PhaseError::new(
                        DiagError::new(Diag::new(Key::RtPhaseHelperStartFailed)).caused_by(error),
                    )));
                    self.release_exclusive();
                }
            }
            return;
        }

        let pipe_id = uuid::Uuid::new_v4().simple().to_string();
        let token = uuid::Uuid::new_v4().simple().to_string();
        // The shared cancel flag of the exclusive record: the blocking
        // connector owns a clone and polls it between bounded pipe attempts
        // (the flag flips on Stop/Shutdown/exit cancels, exactly as the
        // ceremony's per-operation flag did).
        let cancel = match self.jobs.exclusive_cancel_flag() {
            Some(flag) => flag,
            None => unreachable!("helper startup owns a lifecycle operation"),
        };
        let task_cancel = Arc::clone(&cancel);
        let task = tokio::task::spawn_blocking(move || {
            if task_cancel.load(Ordering::Acquire) {
                return cancelled_helper_connect();
            }
            // `_credentials` must stay alive through the connect attempt: the
            // elevated child reads the ProgramData token file at its startup,
            // so the GUI deletes it only after the handshake has resolved
            // (the child has read it, or it can never read it).
            let _credentials = match crate::sys::elevation::launch_core_helper(&pipe_id, &token) {
                Ok(guard) => guard,
                Err(error) => {
                    return ExclusiveOutcome::HelperConnected(Err(HelperConnectFailure::Failed(
                        DiagError::new(Diag::new(Key::RtPhaseHelperLaunchFailed))
                            .caused_by(DiagError::new(error.diag()))
                            .into(),
                    )));
                }
            };
            // ShellExecuteW is not cancellable while the consent UI is open.
            // Once it returns, cancellation wins before we can open/auth the
            // pipe. A late helper then sees its watched parent close (or its
            // bounded unauthenticated pipe timeout) and cannot receive Start.
            match connect_after_helper_launch(&task_cancel, || {
                helper::HelperPipe::connect_cancellable(&pipe_id, &token, &task_cancel)
            }) {
                // A connect that resolved after Stop/Shutdown raised the flag
                // is cancelled: the pipe (when one was opened) is dropped
                // here, and the helper sees its watched parent close.
                Some(_) if task_cancel.load(Ordering::Acquire) => cancelled_helper_connect(),
                Some(result) => ExclusiveOutcome::HelperConnected(
                    result.map_err(|error| HelperConnectFailure::Failed(error.into())),
                ),
                None => cancelled_helper_connect(),
            }
        });
        self.jobs.attach_exclusive_task(task);
        self.set_phase(CorePhase::Starting);
        self.app_log(Diag::new(Key::RtLogHelperLaunchWait));
    }

    fn arm_readiness_deadline(&mut self) {
        // The clock choice carries the TUN restart rule: a TUN start never
        // takes the short applied-candidate clock, because its wintun adapter
        // create legitimately waits out the previous session's teardown and
        // killing a core stuck mid-create wedges PnP device creation for
        // every wintun user.
        self.readiness_deadline = Some(
            Instant::now()
                + readiness_timeout(
                    self.pending_transition.is_candidate_pending(),
                    self.backend.is_tun_owned(),
                ),
        );
    }

    /// A TUN start must not start the readiness clock at `pipe.start()` write
    /// time: the elevated helper may still be staging, validating (up to
    /// `CONFIG_TEST_TIMEOUT`) and copying payloads before the xray child
    /// exists. Disarm the clock so `ready_poll` ignores any stale deadline
    /// until the helper confirms the spawn.
    fn defer_readiness_deadline(&mut self) {
        self.readiness_deadline = None;
    }

    /// The elevated helper reports `starting` immediately after the xray child
    /// was spawned and attached to its kill-on-close job. That is the spawn
    /// confirmation the readiness clock may start from; other states are
    /// informational — readiness itself comes from the gRPC poll. The reported
    /// PID is the spawned child, recorded for the owning-PID readiness check;
    /// an unknown (0) PID never records.
    fn on_helper_state(&mut self, state: &str, pid: u32) {
        if state == "starting" || state == "running" {
            self.backend.set_child_pid(pid);
        }
        if helper_state_arms_readiness(state, self.readiness_deadline.is_some()) {
            self.arm_readiness_deadline();
        }
    }

    /// Returns whether the graceful close succeeded (or was not applicable:
    /// the backend does not own a TUN).
    async fn cleanup_tun(&mut self) -> bool {
        if !self.backend.is_tun_owned() {
            return true;
        }
        // Xray's Windows TUN cleanup lives in the inbound handler's Close.
        // HandlerService.RemoveInbound is synchronous, and GrpcClient applies
        // both a request deadline and an outer cancellation deadline.
        match tokio::time::timeout(
            TUN_CLOSE_DEADLINE,
            self.grpc.remove_inbound(TUN_INBOUND_TAG),
        )
        .await
        {
            Ok(Ok(())) => {
                self.app_log(Diag::new(Key::RtLogTunInboundClosed));
                true
            }
            Ok(Err(error)) => {
                self.app_log(Diag::new(Key::RtLogTunGracefulCloseFailed).arg(error));
                false
            }
            Err(_) => {
                self.app_log(Diag::new(Key::RtLogTunCloseTimeout));
                false
            }
        }
    }

    /// Wait until the backend's child reports exit. Returns whether an exit
    /// was observed before the caller's timeout.
    async fn wait_backend_exit(&mut self) -> bool {
        if let Some(child) = self.backend.child_mut() {
            child.wait().await.is_ok()
        } else if self.backend.is_pipe()
            && let Some(events) = self.backend.events_mut()
        {
            while let Some(event) = events.recv().await {
                if matches!(event, helper::HelperEvent::Exit(_)) {
                    return true;
                }
            }
            false
        } else {
            false
        }
    }

    async fn kill_backend(&mut self) {
        // The in-tun DNS listener dies with the core it was added to; the
        // next start arms its own from the config that core runs.
        self.dns_in_listener = None;
        // Ownership, not the requested next mode, controls cleanup. This call
        // always precedes Direct::start_kill, helper Stop, or backend drop.
        let tun = self.backend.is_tun_owned();
        let gracefully_closed = self.cleanup_tun().await;
        // PnP wedge prevention (2026-08-28, replayed 2026-09-09): a
        // TUN core that ignored the graceful close is likely stuck inside
        // wintun's `WintunCreateAdapter` device-install wait (≤ 15 s), and
        // terminating it there wedges PnP device creation for every wintun
        // user on the machine. The create resolves by itself within the
        // window — the child either exits (create failed) or serves the API
        // again (create succeeded) — so wait it out before the kill. When the
        // child exits on its own nothing is left to stop.
        if tun && !gracefully_closed && self.backend.is_alive() {
            self.app_log(Diag::new(Key::RtLogTunCoreStopWindow));
            match tokio::time::timeout(TUN_STOP_WINDOW, self.wait_backend_exit()).await {
                Ok(true) => {
                    self.app_log(Diag::new(Key::RtLogTunCoreExited));
                    return;
                }
                Ok(false) => {}
                Err(_) => self.app_log(Diag::new(Key::RtLogTunCoreAlive)),
            }
        }
        match self.backend.as_backend_mut() {
            Some(Backend::Direct(child)) => child.start_kill(),
            Some(Backend::Pipe(pipe)) => {
                if let Err(error) = pipe.stop() {
                    self.app_log(
                        DiagError::new(Diag::new(Key::RtLogHelperStopFailed)).caused_by(error),
                    );
                }
            }
            None => {}
        }
    }

    /// Final process shutdown is explicit and bounded. In particular, wait for
    /// the elevated helper to report that Xray exited after TUN cleanup instead
    /// of relying on destructor order while the GUI process is disappearing.
    async fn shutdown_backend(&mut self) {
        self.pending_restart = None;
        self.pending_transition.clear();
        self.core_update.clear();
        self.gate_backend_alive = false;
        self.exit_policy.finish();
        if self.backend.as_backend().is_none() {
            self.backend.force_release();
            return;
        }
        self.exit_policy.begin_stop(Instant::now());
        if self.backend.tun_owned_or_alive() {
            self.kill_backend().await;
        }
        // Long-lived TUN children may still be inside the wintun create
        // window when their kill lands; give them the same TUN-aware window
        // instead of the short generic timeout (PnP wedge prevention, 08-28 /
        // 09-09). kill_backend above already waited the window when
        // the graceful close failed, so this wait normally returns instantly.
        let window = if self.backend.tun_owned_or_alive() {
            TUN_STOP_WINDOW
        } else {
            STOP_TIMEOUT
        };
        let _ = tokio::time::timeout(window, self.wait_backend_exit()).await;
        // Dropping Direct closes the kill-on-close job. Dropping Pipe closes
        // the watchdog channel; the helper performs its own bounded TUN close
        // before terminating its job.
        self.backend.force_release();
        self.exit_policy.finish();
    }

    // -- exit handling -------------------------------------------------------

    /// Best-effort OS resolver-cache flush on TUN up/down transitions
    /// (`ipconfig /flushdns` — DnsFlushResolverCache). The Windows cache
    /// keeps pre-TUN ISP answers alive; after a route change they would be
    /// served stale (sing-box flushes on Start/Close; Xray does not).
    /// Failure is non-fatal: the cache ages out on its own, so errors are
    /// logged, not surfaced.
    fn flush_dns_cache(&mut self) {
        // `ipconfig` is a console-subsystem child; created through
        // [`crate::sys::hidden_command`] (`CREATE_NO_WINDOW`) so it cannot
        // pop a console window from the GUI-subsystem app (user report: a
        // console window appeared when TUN was enabled — the flush runs on
        // every TUN up/down transition).
        match crate::sys::hidden_command("ipconfig")
            .arg("/flushdns")
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(_) => self.app_log(Diag::new(Key::RtLogDnsFlushExit)),
            Err(error) => self.app_log(Diag::new(Key::RtLogDnsFlushFailed).arg(error)),
        }
    }

    fn on_unconfirmed_backend_loss(&mut self) {
        // Same invariant as on_core_exit: a foreign in-flight user operation
        // must not be silently dropped when the helper transport dies.
        self.cancel_exclusive_for_exit(&Diag::new(Key::RtReasonHelperDisconnected));
        self.gate_backend_alive = false;
        let explicit_stop = self.exit_policy.is_explicit_stop();
        let was_tun = self.backend.is_tun_owned();
        self.backend.force_release();
        if was_tun {
            // Helper died while owning the TUN; the adapter is gone too.
            self.flush_dns_cache();
        }
        self.exit_policy.finish();

        if let Some(reason) = self.pending_transition.drain_failure() {
            let output = AppMessage::from(
                Diag::new(Key::RtFrameConfigRollbackCancelled).arg_message(reason),
            );
            self.app_log(output.clone());
            self.emit(CoreEvt::RollbackResult { ok: false, output });
        }

        if let Some(reason) = self.core_update.drain_failure() {
            let output =
                AppMessage::from(Diag::new(Key::RtFrameCoreRollbackCancelled).arg_message(reason));
            self.app_log(output.clone());
            self.emit(CoreEvt::Download(DownloadState::Failed(output)));
        }

        if !self.shutting_down {
            if explicit_stop {
                self.set_phase(CorePhase::Stopped);
            } else {
                self.set_phase(CorePhase::Error(PhaseError::new(Diag::new(
                    Key::RtPhaseHelperExitUnconfirmed,
                ))));
            }
            self.release_exclusive();
        }
    }

    async fn on_core_exit(&mut self, code: Option<i32>) {
        // Settle any foreign in-flight user operation before this handler's
        // early-return branches own the lifecycle. Without this, the backoff/
        // restart path would leave the operation to `start_backend`'s foreign
        // child, whose readiness would drop the JoinHandle and its result.
        self.cancel_exclusive_for_exit(&Diag::new(Key::RtReasonCoreExitedUnexpectedly));
        self.gate_backend_alive = false;
        let was_tun = self.backend.is_tun_owned();
        self.backend.confirm_exit();
        if was_tun {
            // The TUN adapter is gone; the next boot would otherwise serve
            // stale cached answers from before the switch.
            self.flush_dns_cache();
        }
        self.prev_traffic.clear();
        self.prev_inbound_traffic.clear();
        let tail = self.output_tail(START_FAILURE_EXCERPT_LINES);

        // The classifier owns the branch precedence; every arm below keeps
        // the side effects it had when the chain was inline.
        match classify_core_exit(CoreExitFacts {
            config_rollback_armed: self.pending_transition.rollback_pending().is_some(),
            update_rollback_armed: self.core_update.rollback_pending().is_some(),
            intent: self.exit_policy.kind(),
            config_candidate_pending: self.pending_transition.is_candidate_pending(),
            update_candidate_pending: self.core_update.is_candidate_pending(),
            starting: matches!(self.phase, CorePhase::Starting),
            code,
        }) {
            // A candidate timeout sets the armed rollback before requesting
            // termination; the rollback is deliberately reached only from this
            // confirmed-exit path.
            ExitBranch::ConfigRollback => {
                self.exit_policy.finish();
                self.complete_pending_rollback().await;
            }
            ExitBranch::CoreRollback => {
                self.exit_policy.finish();
                self.complete_pending_core_rollback().await;
            }
            ExitBranch::Silenced => {
                self.exit_policy.finish();
                self.release_exclusive();
            }
            ExitBranch::RestartQueued => {
                self.exit_policy.finish();
                // Exit confirmation is the sequencing barrier. Queue the
                // replacement so this handler never recursively enters the
                // start graph and the busy owner remains held.
                self.pending_restart = Some(Instant::now());
            }
            ExitBranch::StopSettled => {
                self.exit_policy.finish();
                if !self.shutting_down {
                    self.backend.force_release();
                    self.set_phase(CorePhase::Stopped);
                    self.release_exclusive();
                }
            }
            ExitBranch::CandidatePreReadiness => {
                // An empty capture fills its slot with the keyed "no core
                // output" fragment, so the value renders in the display
                // language like the frame around it.
                let no_output = tail.is_empty();
                let captured = if no_output {
                    String::new()
                } else {
                    tail.clone()
                };
                let reason = Diag::new(Key::RtFrameCandidateExited).arg(
                    code.map(|value| value.to_string())
                        .unwrap_or_else(|| "?".to_string()),
                );
                let reason = if no_output {
                    reason.arg_message(Diag::new(Key::RtFrameNoCoreOutput))
                } else {
                    reason.arg(&captured)
                };
                // Two transient TUN signatures earn an automatic retry (the
                // dns-in bind race and the adapter teardown window of a fresh
                // apply); the budget rule lives in `policy`.
                let failure = classify_pre_readiness_exit(was_tun, &captured);
                let budget = candidate_retry_budget(failure);
                if let Some(attempt) = spend_retry_attempt(&mut self.candidate_boot_retries, budget)
                {
                    let key = if matches!(failure, Some(PreReadinessFailure::DnsInBindRace)) {
                        Key::RtFrameCandidateRetryBindRace
                    } else {
                        Key::RtFrameCandidateRetryTeardownRace
                    };
                    self.app_log(Diag::new(key).arg_message(reason).arg(attempt).arg(budget));
                    self.pending_restart = Some(Instant::now() + CANDIDATE_RETRY_DELAY);
                    return;
                }
                if self.pending_transition.arm_rollback(reason) {
                    self.complete_pending_rollback().await;
                }
            }
            ExitBranch::UpdatePreReadiness => {
                let no_output = tail.is_empty();
                let captured = if no_output {
                    String::new()
                } else {
                    tail.clone()
                };
                let reason = Diag::new(Key::RtFrameUpdatedCoreExited).arg(
                    code.map(|value| value.to_string())
                        .unwrap_or_else(|| "?".to_string()),
                );
                let reason = if no_output {
                    reason.arg_message(Diag::new(Key::RtFrameNoCoreOutput))
                } else {
                    reason.arg(&captured)
                };
                if update_retries_bind_race(was_tun, &captured)
                    && let Some(attempt) = self.core_update.spend_bind_race_retry()
                {
                    self.app_log(
                        Diag::new(Key::RtFrameUpdateRetryBindRace)
                            .arg_message(reason)
                            .arg(attempt)
                            .arg(TUN_BIND_RACE_RETRIES),
                    );
                    self.pending_restart = Some(Instant::now() + CANDIDATE_RETRY_DELAY);
                    return;
                }
                // Every other pre-readiness failure rolls the update back
                // immediately: only the fresh Go-map-order roll of the race
                // can come up healthy on the next attempt.
                self.core_update.fail_before_readiness(reason);
                self.complete_pending_core_rollback().await;
            }
            ExitBranch::UpdateConfigError => {
                // The core refused its configuration while the update's
                // payload was still unproven. The configuration is not the
                // payload: the installed tree stays — the durable marker and
                // the retained last-good tree are consumed, ending the update
                // as installed — and the core's own config error is what the
                // user sees.
                let failure = PhaseError::new(Diag::new(Key::RtPhaseConfigError)).with_tail(tail);
                self.settle_config_failure(failure);
            }
            ExitBranch::ConfigError => {
                // The failure record is "headline + the captured core
                // output under the shared diagnostics wall" — the same shape as
                // probe-failure records, so connect and probe log records stay
                // uniform. The Error phase carries it: the badge renders the
                // keyed headline, and the app's LogCoreError record on the
                // phase transition composes the wall. A regenerated
                // configuration cannot be repaired by replaying an older
                // file, so the failure is terminal — the core's own message.
                let failure = PhaseError::new(Diag::new(Key::RtPhaseConfigError)).with_tail(tail);
                self.settle_config_failure(failure);
            }
            ExitBranch::Backoff => {
                // Any other unexpected exit: exponential backoff with jitter.
                let jitter_ms = self.next_rand() % 250;
                let (attempt, delay_ms) = self.backoff.next(Instant::now(), jitter_ms);
                self.app_log(
                    Diag::new(Key::RtLogCoreExitBackoff)
                        .arg(
                            code.map(|value| value.to_string())
                                .unwrap_or_else(|| "?".to_string()),
                        )
                        .arg(attempt + 1)
                        .arg(delay_ms),
                );
                self.set_phase(CorePhase::Backoff { attempt });
                self.pending_restart = Some(Instant::now() + Duration::from_millis(delay_ms));
            }
        }
    }

    async fn complete_pending_rollback(&mut self) {
        let Some(reason) = self
            .pending_transition
            .take_rollback_after_confirmed_exit(true)
        else {
            return;
        };
        // Clearing this before the filesystem operation makes the retry
        // one-shot even if the last-good replacement also fails to start.
        self.pending_transition.clear_candidate();
        match apply::rollback_offloaded().await {
            Ok(()) => {
                let output =
                    AppMessage::from(Diag::new(Key::RtFrameRolledBackLastGood).arg_message(reason));
                self.app_log(output.clone());
                self.emit(CoreEvt::RollbackResult { ok: true, output });
                // The next start replays the restored last-known-good
                // artefact instead of regenerating: regeneration would
                // produce the configuration the candidate just failed on.
                self.replay_after_rollback = true;
                // The active config changed under us; the next start must
                // capture the rolled-back file instead of the rejected
                // candidate's bytes.
                self.helper_config_bytes = None;
                // Queue rather than recursively awaiting the start graph.
                self.pending_restart = Some(Instant::now());
            }
            Err(error) => {
                let output = AppMessage::from(
                    DiagError::new(Diag::new(Key::RtFrameRollbackFailed).arg_message(reason))
                        .caused_by(error),
                );
                self.app_log(output.clone());
                self.emit(CoreEvt::RollbackResult { ok: false, output });
                self.set_phase(CorePhase::Stopped);
                self.release_exclusive();
            }
        }
    }

    async fn complete_pending_core_rollback(&mut self) {
        let Some(reason) = self.core_update.take_rollback_after_confirmed_exit(true) else {
            return;
        };
        self.core_update.clear_candidate();

        // `Backend::Direct` retains deny-write/delete handles for every
        // verified payload until its `Child` is dropped. Drop that owner only
        // after the exit has been confirmed, before renaming the managed core
        // directory back to its retained last-good sibling.
        self.backend.force_release();

        let (output, restart) = match crate::sys::core_dl::rollback_unhealthy_update() {
            Ok(true) => (
                AppMessage::from(Diag::new(Key::RtFrameCoreRestored).arg_message(reason)),
                true,
            ),
            Ok(false) => (
                AppMessage::from(Diag::new(Key::RtFrameCoreNoLastGood).arg_message(reason)),
                false,
            ),
            Err(error) => (
                AppMessage::from(
                    DiagError::new(Diag::new(Key::RtFrameCoreRollbackFailed).arg_message(reason))
                        .caused_by(error),
                ),
                false,
            ),
        };
        self.app_log(output.clone());
        self.emit(CoreEvt::Download(DownloadState::Failed(output)));

        // The update transaction is terminal as soon as its candidate has
        // either been restored or reported irrecoverable. Recovery startup is
        // deliberately a separate lifecycle operation, so Settings is never
        // left disabled while a restored core waits to reconnect.
        if restart {
            // `start_backend` will acquire its own Restart operation on the
            // next housekeeping tick. Release UpdateCore first.
            self.release_exclusive();
            self.pending_restart = Some(Instant::now());
        } else {
            self.set_phase(CorePhase::Stopped);
            self.release_exclusive();
        }
    }

    // -- periodic tasks ------------------------------------------------------

    async fn ready_poll(&mut self) {
        // The readiness clock is armed only after the backend is confirmed
        // alive: directly, right after `supervisor::spawn`; for TUN, when the
        // helper reports the xray child spawned (`HelperEvent::State
        // "starting"`). Helper staging/validation must not count against the
        // deadline, and a timeout or explicit stop may race a final successful
        // RPC; once termination is requested, the exit path owns the verdict.
        if !self.backend.is_alive() || self.exit_policy.stopping() {
            return;
        }
        let Some(deadline) = self.readiness_deadline else {
            return;
        };
        if readiness_deadline_reached(deadline, Instant::now()) {
            match readiness_timeout_verdict(
                self.pending_transition.is_candidate_pending(),
                self.core_update.is_candidate_pending(),
                self.core_update.rollback_pending().is_some(),
            ) {
                ReadinessTimeout::AppliedCandidate => {
                    let _ = self.pending_transition.arm_rollback(
                        Diag::new(Key::RtFrameCandidateReadyTimeout)
                            .arg(READY_TIMEOUT_APPLIED.as_secs()),
                    );
                    self.exit_policy.begin_stop(Instant::now());
                    self.kill_backend().await;
                }
                ReadinessTimeout::UpdatedCore => {
                    // The last readiness miss is its own keyed sentence,
                    // nested so it renders in the same language.
                    let reason = match self.core_update.last_readiness_error() {
                        Some(miss) => Diag::new(Key::RtFrameUpdatedCoreReadyTimeoutApi)
                            .arg(READY_TIMEOUT.as_secs())
                            .arg_message(miss.clone()),
                        None => Diag::new(Key::RtFrameUpdatedCoreReadyTimeout)
                            .arg(READY_TIMEOUT.as_secs()),
                    };
                    if self.core_update.arm_rollback(reason) {
                        self.exit_policy.begin_stop(Instant::now());
                        self.kill_backend().await;
                    } else {
                        self.silence_readiness_timeout().await;
                    }
                }
                ReadinessTimeout::Unclaimed => self.silence_readiness_timeout().await,
            }
            return;
        }
        match self.grpc.get_sys_stats().await {
            Ok(_) => {
                let listener_owned = self.api_listener_owned_by_child();
                self.complete_readiness_probe(listener_owned).await;
                // The in-tun DNS listener binds the TUN gateway, an address
                // the running core's adapter owns; the owning-PID check above
                // proves the responder is this child. The adapter may still
                // be coming up when readiness lands, so a failed first
                // attempt stays pending for the retry arm.
                if listener_owned && matches!(self.phase, CorePhase::Running) {
                    self.dns_in_poll().await;
                }
            }
            Err(error) => {
                self.core_update
                    .record_readiness_error(Diag::new(Key::RtFrameApiProbeFailed).arg(error));
            } // bounded miss; next tick retries
        }
    }

    /// One attempt at adding this start's in-tun DNS listener
    /// ([`dns_in`]) to the running core. Attempts are capped through the
    /// shared [`spend_retry_attempt`] rule; a success, or a spent budget,
    /// clears the pending listener so the retry arm stops firing.
    /// Best-effort, like the helper's DNS shield: a core that is serving
    /// traffic is never torn down because a listener could not be added.
    async fn dns_in_poll(&mut self) {
        let Some(listener) = self.dns_in_listener else {
            return;
        };
        match self.grpc.add_dns_in_listener(&listener).await {
            Ok(()) => {
                self.dns_in_listener = None;
                self.app_log(
                    Diag::new(Key::RtLogDnsInListenerAdded)
                        .arg(listener.address)
                        .arg(dns_in::PORT),
                );
            }
            Err(error) => {
                if spend_retry_attempt(&mut self.dns_in_attempts, DNS_IN_ADD_ATTEMPTS).is_none() {
                    self.dns_in_listener = None;
                    self.app_log(Diag::new(Key::RtLogDnsInListenerNotAdded).arg(error));
                }
            }
        }
    }

    /// Silence the exit path of a readiness timeout no candidate owns: the
    /// phase payload is the one terminal record — app-side LogCoreError,
    /// composed as the keyed headline plus the captured core output under the
    /// shared diagnostics wall, matching probe-failure records. The silenced
    /// exit policy keeps the confirmed exit from reporting a second time.
    async fn silence_readiness_timeout(&mut self) {
        self.exit_policy.begin_silenced_stop(Instant::now());
        self.kill_backend().await;
        let tail = self.output_tail(START_FAILURE_EXCERPT_LINES);
        self.set_phase(CorePhase::Error(
            PhaseError::new(Diag::new(Key::RtPhaseReadinessTimeout).arg(READY_TIMEOUT.as_secs()))
                .with_tail(tail),
        ));
    }

    /// Trust the readiness probe only when the loopback listener on
    /// the active API port is owned by the spawned core child. A same-user
    /// process could answer `get_sys_stats` on an enumerated port; only the
    /// verified responder may clear the rollback gate or ACK the core-update
    /// backup. Mismatch or unverifiable → `false` (never trust).
    fn api_listener_owned_by_child(&self) -> bool {
        let Some(pid) = self.backend.child_pid() else {
            return false;
        };
        let Some(rows) = crate::sys::net_table::tcp_table() else {
            return false;
        };
        crate::sys::net_table::loopback_api_listener_owned_by(&rows, self.api_port, pid)
    }

    /// Success branch of the readiness probe, gated on the owning-PID verdict.
    /// The gate/backup side effects run only for the verified responder.
    async fn complete_readiness_probe(&mut self, listener_owned: bool) {
        if !listener_owned {
            self.core_update
                .record_readiness_error(Diag::new(Key::RtFrameApiListenerNotOwned));
            return;
        }
        // Durable ACK must succeed before either candidate marker is cleared
        // or the update operation is released. Otherwise a failed
        // backup/marker cleanup could be misreported healthy and allow
        // another overlapping transaction.
        if let Err(message) = self.core_update.ack_ready() {
            self.app_log(message);
            return;
        }
        if self.gate_backend_alive {
            // The health gate proved the installed binary and the update is
            // installed (the ACK above consumed the marker and the retained
            // tree). Its process runs the app-owned configuration, which
            // serves no session, so the proof process is ended here and the
            // phase settles to Stopped from the confirmed exit, which also
            // releases the update operation. The user's configuration enters
            // through the next apply.
            self.app_log(Diag::new(Key::RtLogHealthGateCompleted));
            self.gate_backend_alive = false;
            self.exit_policy.begin_stop(Instant::now());
            self.kill_backend().await;
            return;
        }
        self.set_phase(CorePhase::Running);
        self.backoff.mark_ready(Instant::now());
        self.pending_transition.clear_candidate();
        self.candidate_boot_retries = 0;
        self.app_log(Diag::new(Key::RtLogCoreReady));
        self.release_exclusive();
    }

    /// Fold one `query_traffic` response into the per-tag baseline, evicting
    /// tags absent from the response so `prev_traffic` stays bounded by the
    /// live outbound set across config churn. Returns the tag-sorted
    /// per-outbound deltas and the aggregate counters.
    fn fold_traffic(
        &mut self,
        rows: Vec<(String, u64, u64)>,
    ) -> (Vec<(String, u64, u64)>, u64, u64) {
        Self::fold_into(&mut self.prev_traffic, rows)
    }

    /// Sum one raw traffic response into the cumulative aggregate totals
    /// (`total_up`/`total_down`). Called before the folds consume the rows:
    /// the totals are the core's cumulative counters summed as-is — never
    /// accumulated client-side — so a dropped tick cannot skew them.
    fn aggregate_totals(rows: &[(String, u64, u64)]) -> (u64, u64) {
        (
            rows.iter().map(|(_, up, _)| up).sum(),
            rows.iter().map(|(_, _, down)| down).sum(),
        )
    }

    /// Fold one `query_inbound_traffic` response into the inbound baseline,
    /// with the same eviction/delta semantics as [`Self::fold_traffic`].
    ///
    /// The totals ride the same fold: it writes every returned tag's counters
    /// back into the baseline, so they are one lookup per delta row — no
    /// second sweep over the response and no second sort of it. Reading them
    /// back through the deltas also pins both lists to one tag order, which
    /// is what the dashboard's parallel walk of [`StatsTick::per_inbound`]
    /// and [`StatsTick::per_inbound_totals`] requires. The query folds its
    /// response through a `BTreeMap`
    /// ([`grpc::GrpcClient::query_inbound_traffic`]), so a tag never repeats
    /// within one sweep.
    fn fold_inbound_traffic(&mut self, rows: Vec<(String, u64, u64)>) -> InboundFold {
        let (per_inbound, up, down) = Self::fold_into(&mut self.prev_inbound_traffic, rows);
        let per_inbound_totals = per_inbound
            .iter()
            .map(|(tag, _, _)| {
                let (cum_up, cum_down) =
                    self.prev_inbound_traffic.get(tag).copied().expect(
                        "the fold writes every returned tag's counters back to the baseline",
                    );
                (tag.clone(), cum_up, cum_down)
            })
            .collect();
        InboundFold {
            per_inbound,
            per_inbound_totals,
            up,
            down,
        }
    }

    /// Shared fold core: evict baselines for tags the response no longer
    /// reports; a tag that keeps appearing keeps its previous baseline, so
    /// deltas below are unchanged for live tags, and its baseline entry
    /// holds that row's cumulative counters when the fold returns. The
    /// returned list is tag-sorted; a live tag's entry is updated in place
    /// (the key already exists, so re-inserting it would re-allocate the tag
    /// for nothing).
    fn fold_into(
        baseline: &mut HashMap<String, (u64, u64)>,
        rows: Vec<(String, u64, u64)>,
    ) -> (Vec<(String, u64, u64)>, u64, u64) {
        let seen: HashSet<&str> = rows.iter().map(|(tag, _, _)| tag.as_str()).collect();
        baseline.retain(|tag, _| seen.contains(tag.as_str()));
        let mut per_tag = Vec::with_capacity(rows.len());
        let (mut up, mut down) = (0u64, 0u64);
        for (tag, cum_up, cum_down) in rows {
            let (prev_up, prev_down) = match baseline.get_mut(&tag) {
                Some(slot) => std::mem::replace(slot, (cum_up, cum_down)),
                None => {
                    baseline.insert(tag.clone(), (cum_up, cum_down));
                    (0, 0)
                }
            };
            // saturating: a counter reset (core restart) yields 0, not wraparound.
            let up_rate = cum_up.saturating_sub(prev_up);
            let down_rate = cum_down.saturating_sub(prev_down);
            up += up_rate;
            down += down_rate;
            per_tag.push((tag, up_rate, down_rate));
        }
        per_tag.sort_by(|a, b| a.0.cmp(&b.0));
        (per_tag, up, down)
    }

    async fn stats_poll(&mut self) {
        // Reset backoff after a stable minute.
        self.backoff.maybe_reset(Instant::now());

        // Both sweeps hit the same loopback channel; a failure means the core
        // is unreachable or restarting — drop the whole sample (the exit
        // watch handles state).
        let Ok(rows) = self.grpc.query_traffic().await else {
            return;
        };
        // The outbound sweep feeds only the per-outbound views; its
        // aggregate is deliberately not surfaced (see below).
        let (per_outbound, _, _) = self.fold_traffic(rows);

        let Ok(inbound_rows) = self.grpc.query_inbound_traffic().await else {
            return;
        };
        // Aggregate rates and totals come from the same inbound (listener)
        // response the dashboard table renders, so the session totals line
        // and the aggregate rates match the table by construction:
        // the aggregated line is the aggregate of the per-inbound totals.
        // The outbound family is not used for the dashboard
        // aggregates: it measures wire bytes (TLS/protocol overhead,
        // core-internal DNS), and Xray 26.x drops per-connection chunks from
        // its outbound uplink counters, so outbound-derived figures diverge
        // from the table.
        let (total_up, total_down) = Self::aggregate_totals(&inbound_rows);
        let InboundFold {
            per_inbound,
            per_inbound_totals,
            up,
            down,
        } = self.fold_inbound_traffic(inbound_rows);

        let sys = self
            .grpc
            .get_sys_stats()
            .await
            .map(|r| SysStatsSnapshot {
                uptime_secs: u64::from(r.uptime),
                goroutines: u64::from(r.num_goroutine),
                alloc_bytes: r.alloc,
                sys_bytes: r.sys,
                live_objects: r.live_objects,
                num_gc: u64::from(r.num_gc),
            })
            .unwrap_or_default();

        self.emit(CoreEvt::Stats(StatsTick {
            up,
            down,
            per_outbound,
            per_inbound,
            total_up,
            total_down,
            per_inbound_totals,
            uptime_secs: sys.uptime_secs,
            goroutines: sys.goroutines,
            alloc_bytes: sys.alloc_bytes,
            sys_bytes: sys.sys_bytes,
            live_objects: sys.live_objects,
            num_gc: sys.num_gc,
        }));
    }

    async fn obs_poll(&mut self) {
        let Ok(statuses) = self.grpc.outbound_statuses().await else {
            return;
        };
        let statuses = if self.obs_tags.is_empty() {
            statuses
        } else {
            statuses
                .into_iter()
                .filter(|s| self.obs_tags.contains(&s.tag))
                .collect()
        };
        self.emit(CoreEvt::Observatory(statuses));
    }

    async fn housekeeping(&mut self) {
        if let Some(at) = self.pending_restart
            && Instant::now() >= at
            && !self.exit_policy.stopping()
            && !self.backend.is_alive()
        {
            self.pending_restart = None;
            self.start_backend().await;
        }
        if !self.exit_policy.stopping()
            || !self.exit_policy.stop_timed_out(
                Instant::now(),
                if self.backend.tun_owned_or_alive() {
                    TUN_STOP_WINDOW
                } else {
                    STOP_TIMEOUT
                },
            )
        {
            return;
        }

        self.app_log(Diag::new(Key::RtLogExitNotReported));
        if self.backend.is_direct() {
            let status = {
                let child = match self.backend.child_mut() {
                    Some(child) => child,
                    None => unreachable!(),
                };
                child.start_kill();
                tokio::time::timeout(Duration::from_secs(1), child.wait()).await
            };
            if let Ok(Ok(status)) = status {
                self.on_core_exit(status.code()).await;
                return;
            }
        }

        // Cleanup was already attempted before the first kill. Dropping the
        // owning Job/pipe is the final fallback, but it does not prove the old
        // child exited. A pending rollback/restart is therefore cancelled
        // instead of spawning against possibly occupied ports.
        self.backend.force_release();
        let wanted_restart = self.exit_policy.finish();
        if let Some(reason) = self.pending_transition.drain_rollback() {
            let output = AppMessage::from(
                Diag::new(Key::RtFrameConfigRollbackCancelled).arg_message(reason),
            );
            self.app_log(output.clone());
            self.emit(CoreEvt::RollbackResult { ok: false, output });
            self.set_phase(CorePhase::Stopped);
            self.release_exclusive();
        } else if let Some(reason) = self.core_update.drain_rollback() {
            let output =
                AppMessage::from(Diag::new(Key::RtFrameCoreRollbackCancelled).arg_message(reason));
            self.app_log(output.clone());
            self.emit(CoreEvt::Download(DownloadState::Failed(output)));
            self.set_phase(CorePhase::Stopped);
            self.release_exclusive();
        } else if wanted_restart {
            self.set_phase(CorePhase::Error(PhaseError::new(Diag::new(
                Key::RtPhaseRestartCancelled,
            ))));
            self.release_exclusive();
        } else if !self.shutting_down {
            self.set_phase(CorePhase::Stopped);
            self.release_exclusive();
        }
    }

    // -- apply / verified core sources ---------------------------------------

    /// Start the single core-update operation: download the pinned release
    /// (or install a user-selected pinned archive). The terminal result is
    /// delivered as exactly one `CoreEvt::Download` followed by
    /// `CoreEvt::Operation(None)`.
    ///
    /// Cancellation: the install swap runs in `spawn_blocking`,
    /// which `abort()` cannot interrupt — it only detaches the closure, so
    /// aborting would let the update land after the UI saw "cancelled" and
    /// would free the operation slot for a second, overlapping install.
    /// Stop/Shutdown therefore never abort this task: the slot stays held
    /// until the swap's terminal result arrives. On Stop the landing is
    /// reported as a `Download` event and only then is the slot released,
    /// with the health-gate auto-restart suppressed (the durable swap marker
    /// still protects the next explicit Start). On Shutdown the worker is
    /// dropped with the runtime and the detached swap completes on disk; the
    /// marker-first swap plus `recover_interrupted_swap` keep the managed
    /// core directory consistent for the next launch.
    fn update_core(&mut self, source: CoreUpdateSource) {
        if !matches!(self.phase, CorePhase::Stopped | CorePhase::Error(_))
            || self.backend.is_alive()
        {
            self.emit(CoreEvt::Download(DownloadState::Failed(AppMessage::from(
                Diag::new(Key::RtFrameUpdateStopCoreFirst),
            ))));
            // Rejected commands do not acquire an operation, but a prior UI
            // click may optimistically show an update state until this reply
            // lands. Always settle that view state; a stale busy indicator
            // must not leave Settings disabled after a synchronous rejection.
            self.emit(CoreEvt::Operation(None));
            return;
        }
        if crate::sys::core_dl::update_pending_health() {
            self.emit(CoreEvt::Download(DownloadState::Failed(AppMessage::from(
                Diag::new(Key::RtFrameUpdateHealthCheckPending),
            ))));
            self.emit(CoreEvt::Operation(None));
            return;
        }
        match self.begin_exclusive(JobKind::UpdateCore) {
            Ok(_) => {}
            Err(Busy { active }) => {
                // Whitelist-era reject: log the line, settle the optimistic
                // update state with the failure, then re-emit the occupant's
                // bookend so the GUI settles its local view without releasing
                // the operation that rejected this command.
                let output = Self::busy_reject_text(active);
                self.app_log(output.clone());
                self.emit(CoreEvt::Download(DownloadState::Failed(AppMessage::from(
                    output,
                ))));
                self.emit(CoreEvt::Operation(Some(
                    active
                        .exclusive_operation_kind()
                        .expect("busy occupants are exclusive kinds; queries never occupy"),
                )));
                return;
            }
        }
        let initial_stage = match &source {
            CoreUpdateSource::PinnedDownload => Diag::new(Key::RtFrameStageCheckingRelease),
            CoreUpdateSource::LocalArchive(_) => Diag::new(Key::RtFrameStageVerifyingArchive),
        };
        self.emit(CoreEvt::Download(DownloadState::Working {
            stage: initial_stage,
            done: 0,
            total: 0,
        }));
        let evt = self.evt.clone();
        let repaint = self.repaint.clone();
        let client = if matches!(&source, CoreUpdateSource::PinnedDownload) {
            Some(self.http.get_or_insert_with(reqwest::Client::new).clone())
        } else {
            None
        };
        let task = tokio::spawn(async move {
            let result = match source {
                CoreUpdateSource::PinnedDownload => {
                    let client = client.expect("pinned download source has an HTTP client");
                    // The callback is handed to `download_core` by shared
                    // reference, so it must be `Sync`; the throttle mark is
                    // therefore an atomic rather than a lock — one calling
                    // task, no poison path, no contention.
                    let started = Instant::now();
                    let last_progress = AtomicU64::new(NO_PROGRESS_EMITTED);
                    let progress = move |done: u64, total: u64, stage: &Diag| {
                        let should_emit = should_emit_download_progress(
                            &last_progress,
                            started.elapsed(),
                            done,
                            total,
                        );
                        if should_emit {
                            // Progress is volatile: a full channel
                            // drops it without blocking the runtime thread the
                            // task runs on; the next snapshot or the terminal
                            // event follows.
                            let _ = evt.try_send(CoreEvt::Download(DownloadState::Working {
                                stage: stage.clone(),
                                done,
                                total,
                            }));
                            repaint.request_repaint();
                        }
                    };
                    crate::sys::core_dl::download_core(&client, progress).await
                }
                CoreUpdateSource::LocalArchive(path) => {
                    match tokio::task::spawn_blocking(move || {
                        crate::sys::core_dl::install_pinned_core_archive(&path)
                    })
                    .await
                    {
                        Ok(result) => result,
                        Err(error) => {
                            Err(DiagError::new(Diag::new(Key::RtFrameArchiveWorkerFailed))
                                .caused_by(error))
                        }
                    }
                }
            };
            let state = match result {
                Ok(version) => DownloadState::Done(version),
                Err(error) => DownloadState::Failed(AppMessage::from(error)),
            };
            ExclusiveOutcome::Download {
                state,
                kind: OperationKind::UpdateCore,
            }
        });
        self.jobs.attach_exclusive_task(task);
    }

    /// Runs one on-demand update check off the UI thread and
    /// emits exactly one terminal `CoreEvt::UpdateCheck`. Not an operation:
    /// the check touches neither the core nor the mutually-exclusive
    /// operation slot, so it can run while lifecycle work is busy. The HTTP
    /// client is shared with the core downloader.
    fn check_update(&mut self) {
        if !self.accept_update_check() {
            return;
        }
        let client = self.http.get_or_insert_with(reqwest::Client::new).clone();
        let evt = self.evt.clone();
        let repaint = self.repaint.clone();
        let busy = Arc::clone(&self.update_check_busy);
        tokio::spawn(async move {
            let state = match crate::sys::selfupd::check_for_update(&client).await {
                Ok(remote) => crate::sys::selfupd::check_outcome(remote),
                Err(_) => UpdateCheckState::Failed,
            };
            queue_event(CoreEvt::UpdateCheck(state), &evt);
            // Release the gate only after the terminal event is queued, so a
            // retry click cannot interleave a second check ahead of it.
            busy.store(false, Ordering::SeqCst);
            repaint.request_repaint();
        });
    }

    /// Accept the on-demand update check: flips the UI to `Checking` and
    /// reserves the in-flight slot, or rejects the command when a check is
    /// already running. Unit-testable without network.
    fn accept_update_check(&mut self) -> bool {
        if self.update_check_busy.swap(true, Ordering::SeqCst) {
            return false;
        }
        self.emit(CoreEvt::UpdateCheck(UpdateCheckState::Checking));
        true
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use super::{
        CoreCmd, CoreEvt, CoreTransport, DOWNLOAD_PROGRESS_INTERVAL, ExclusiveOutcome,
        LatencyProbeResult, NO_PROGRESS_EMITTED, OperationKind, OutboundStatusView, PhaseError,
        ProbeFailure, ProfileValidationOrigin, ProfileValidationRequest, READY_TIMEOUT,
        READY_TIMEOUT_APPLIED, Runtime, STOP_TIMEOUT, TUN_BIND_RACE_RETRIES, TUN_STOP_WINDOW,
        connect_after_helper_launch, policy::DNS_IN_ADD_ATTEMPTS, policy::DNS_IN_BIND_RACE_LINE,
        should_emit_download_progress, spawn_runtime, state::BackendState,
    };
    use crate::diag::{Diag, DiagError};
    use crate::i18n::{Key, t};
    use crate::model::settings::Language;
    use crate::model::{OutboundModel, Protocol, ProtocolSettings, ServerProfile};
    use crate::rt::jobs::{ExclusiveSidecar, JobKind};
    use crate::sys::appdata::{APPDATA_ENV_LOCK, AppDataRedirect, with_appdata_async};

    /// The TUN stop window must keep a kill out of wintun's create stall.
    /// `WintunCreateAdapter`'s device-interface wait is 15 000 ms, so the
    /// TUN window must exceed it; the generic 5 s STOP_TIMEOUT does not —
    /// that 10 s gap is where a mid-create TUN core got terminated and
    /// wedged PnP device creation machine-wide (2026-08-28 and
    /// the 2026-09-09 reconnect outage).
    #[test]
    fn tun_stop_window_covers_wintun_create_stall() {
        assert_eq!(TUN_STOP_WINDOW, Duration::from_secs(20));
        assert!(TUN_STOP_WINDOW > Duration::from_secs(15));
        assert!(STOP_TIMEOUT < Duration::from_secs(15));
    }

    /// Deliver any busy-window bookends the registry sink queued during a
    /// direct `handle_cmd`/state call into the GUI event channel — exactly
    /// what the select loop's bookend arm does on its next pass in the real
    /// runtime. Tests that drive the runtime methods directly must flush
    /// before asserting on the collected events.
    fn flush_bookends(runtime: &mut Runtime) {
        runtime.drain_pending_bookends();
    }

    /// Begin an exclusive job on the runtime's registry (the direct-call
    /// mirror of what a dispatch arm's `try_begin` does). Task-bearing
    /// tests additionally attach a controllable task with
    /// [`park_pending_task`].
    fn occupy_exclusive(runtime: &mut Runtime, kind: JobKind) {
        runtime
            .jobs
            .try_begin(kind)
            .expect("test occupies an empty registry window");
    }

    /// Park an abortable, never-resolving task on the exclusive record, as
    /// the dispatch arms do after spawning a task-bearing job.
    fn park_pending_task(runtime: &mut Runtime) {
        runtime.jobs.attach_exclusive_task(tokio::spawn(async {
            std::future::pending::<ExclusiveOutcome>().await
        }));
    }

    #[test]
    fn tun_close_deadline_is_bound_plus_margin() {
        // The outer give-up wrap must leave the RPC's own deadline room to
        // fire first (graceful-close ordering), so the margin is strictly
        // positive and the total derives from bound + margin — never an
        // independent literal that could drift.
        assert!(super::TUN_CLOSE_MARGIN > Duration::ZERO);
        assert_eq!(
            super::TUN_CLOSE_DEADLINE,
            super::TUN_RPC_TIMEOUT + super::TUN_CLOSE_MARGIN
        );
    }

    #[test]
    fn tls_provider_installed_before_reqwest_client() {
        super::ensure_tls_provider();
        assert!(
            rustls::crypto::CryptoProvider::get_default().is_some(),
            "the aws-lc-rs provider must be installed as the process default"
        );
        // Regression: reqwest 0.12's -no-provider TLS backend panics with
        // "No provider set" at Client::new() when no provider is installed
        // (feature unification alone does not install one).
        let _client = reqwest::Client::new();
    }

    fn runtime_with_events() -> (Runtime, std::sync::mpsc::Receiver<CoreEvt>) {
        let (_command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (event_sender, event_receiver) =
            std::sync::mpsc::sync_channel(super::EVT_CHANNEL_CAPACITY);
        (
            Runtime::new(
                command_receiver,
                event_sender,
                egui::Context::default(),
                crate::metrics::MetricsHandle::new(),
            ),
            event_receiver,
        )
    }

    fn runtime() -> Runtime {
        runtime_with_events().0
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prev_traffic_evicts_stale_tags_across_polls() {
        let mut runtime = runtime();
        // Seed baselines for 50 outbounds, then poll a response reporting only
        // 5: the baseline map must shrink to the live set, not keep growing.
        for i in 0..50u64 {
            runtime
                .prev_traffic
                .insert(format!("tag-{i}"), (100 + i, 200 + i));
        }
        let live: Vec<(String, u64, u64)> = (0..5u64)
            .map(|i| (format!("tag-{i}"), 110 + i, 220 + i))
            .collect();
        let (per_outbound, up, down) = runtime.fold_traffic(live);
        assert_eq!(runtime.prev_traffic.len(), 5, "stale tags must be evicted");
        for i in 0..5u64 {
            let tag = format!("tag-{i}");
            assert_eq!(
                runtime.prev_traffic.get(&tag).copied(),
                Some((110 + i, 220 + i)),
                "live tag baseline must advance"
            );
        }
        assert!(!runtime.prev_traffic.contains_key("tag-5"));
        assert!(!runtime.prev_traffic.contains_key("tag-49"));
        // Live tags keep their delta semantics (10 up / 20 down each).
        assert_eq!(up, 5 * 10);
        assert_eq!(down, 5 * 20);
        assert_eq!(
            per_outbound,
            (0..5u64)
                .map(|i| (format!("tag-{i}"), 10, 20))
                .collect::<Vec<_>>()
        );
        // A follow-up poll over the same tags keeps deltas and stays bounded.
        let again: Vec<(String, u64, u64)> = (0..5u64)
            .map(|i| (format!("tag-{i}"), 130 + i, 240 + i))
            .collect();
        let (_, up, down) = runtime.fold_traffic(again);
        assert_eq!(runtime.prev_traffic.len(), 5);
        assert_eq!(up, 5 * 20);
        assert_eq!(down, 5 * 20);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prev_traffic_stable_response_keeps_baseline_deltas() {
        let mut runtime = runtime();
        runtime.prev_traffic.insert("a".to_string(), (1000, 2000));
        runtime.prev_traffic.insert("b".to_string(), (3000, 4000));
        let rows = vec![("a".to_string(), 1010, 2020), ("b".to_string(), 3030, 4030)];
        let (per_outbound, up, down) = runtime.fold_traffic(rows);
        assert_eq!(runtime.prev_traffic.len(), 2, "stable set is a no-op");
        assert_eq!(up, 10 + 30);
        assert_eq!(down, 20 + 30);
        assert_eq!(
            per_outbound,
            vec![("a".to_string(), 10, 20), ("b".to_string(), 30, 30)]
        );
        // One more identical-set poll: deltas stay incremental from the new
        // baselines, still no eviction.
        let rows = vec![("a".to_string(), 1030, 2060), ("b".to_string(), 3050, 4070)];
        let (_, up, down) = runtime.fold_traffic(rows);
        assert_eq!(runtime.prev_traffic.len(), 2);
        assert_eq!(up, 20 + 20);
        assert_eq!(down, 40 + 40);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inbound_fold_uses_its_own_baseline_and_evicts_stale_tags() {
        let mut runtime = runtime();
        runtime
            .prev_inbound_traffic
            .insert("socks".to_string(), (1000, 2000));
        let rows = vec![
            ("socks".to_string(), 1010, 2020),
            ("tun".to_string(), 500, 600),
        ];
        let fold = runtime.fold_inbound_traffic(rows);

        assert_eq!(
            fold.per_inbound,
            vec![("socks".to_string(), 10, 20), ("tun".to_string(), 500, 600)]
        );
        assert_eq!(
            fold.per_inbound_totals,
            vec![
                ("socks".to_string(), 1010, 2020),
                ("tun".to_string(), 500, 600)
            ],
            "totals carry the sweep's cumulative counters, in the deltas' order"
        );
        assert_eq!(fold.up, 510);
        assert_eq!(fold.down, 620);
        assert_eq!(runtime.prev_inbound_traffic.len(), 2);
        // The outbound baseline is untouched by the inbound sweep.
        assert!(runtime.prev_traffic.is_empty());

        // One more poll reporting only "tun": "socks" is evicted, and the
        // totals follow the surviving tag set.
        let rows = vec![("tun".to_string(), 600, 700)];
        let fold = runtime.fold_inbound_traffic(rows);
        assert_eq!(fold.per_inbound, vec![("tun".to_string(), 100, 100)]);
        assert_eq!(fold.per_inbound_totals, vec![("tun".to_string(), 600, 700)]);
        assert_eq!(fold.up, 100);
        assert_eq!(fold.down, 100);
        assert_eq!(runtime.prev_inbound_traffic.len(), 1);
        assert!(!runtime.prev_inbound_traffic.contains_key("socks"));
    }

    /// The cumulative totals (`total_up`/`total_down`, `per_inbound_totals`)
    /// carry cumulative values — never deltas — for exactly the tags the fold
    /// reports. Because they are core-side counters, not client-accumulated
    /// figures, a dropped tick can never skew them: the totals always equal
    /// the raw rows of the sweep they were read from.
    #[tokio::test(flavor = "current_thread")]
    async fn cumulative_totals_come_from_raw_rows_not_deltas() {
        let mut runtime = runtime();
        // Seed inbound baselines so the fold reports small deltas while the
        // totals must still carry the full cumulative counters. The response
        // rows arrive tag-sorted from the query; keep one deliberately
        // unsorted sweep to prove both lists still land in tag order.
        runtime
            .prev_inbound_traffic
            .insert("socks".to_string(), (1_000, 2_000));
        let rows = vec![
            ("tun".to_string(), 600, 700),
            ("socks".to_string(), 1_010, 2_020),
        ];
        let fold = runtime.fold_inbound_traffic(rows);
        assert_eq!(
            fold.per_inbound,
            vec![("socks".to_string(), 10, 20), ("tun".to_string(), 600, 700)],
            "deltas stay incremental from the seeded baselines"
        );
        assert_eq!(
            fold.per_inbound_totals,
            vec![
                ("socks".to_string(), 1_010, 2_020),
                ("tun".to_string(), 600, 700),
            ],
            "totals carry the raw cumulative values, sorted by tag"
        );
        // The totals cover exactly the tag set the fold emitted deltas for,
        // in the deltas' order: the dashboard walks the two lists in
        // lockstep.
        assert_eq!(
            fold.per_inbound_totals
                .iter()
                .map(|(tag, _, _)| tag)
                .collect::<Vec<_>>(),
            fold.per_inbound
                .iter()
                .map(|(tag, _, _)| tag)
                .collect::<Vec<_>>()
        );

        // Outbound aggregate totals: the raw cumulative sum, regardless of
        // seeded baselines. A dropped tick (a failed sweep skips the whole
        // sample) cannot skew the next tick — nothing is accumulated
        // client-side, so the totals are a pure function of the sweep they
        // were read from: re-deriving them from the same raw rows yields
        // identical values.
        let rows = vec![("a".to_string(), 1010, 2020), ("b".to_string(), 3030, 4030)];
        let (total_up, total_down) = Runtime::aggregate_totals(&rows);
        assert_eq!((total_up, total_down), (4040, 6050));
        let (again_up, again_down) = Runtime::aggregate_totals(&rows);
        assert_eq!((again_up, again_down), (total_up, total_down));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn aggregate_totals_equal_the_inbound_totals_sum() {
        // The dashboard's session totals line and the inbound traffic table
        // must never diverge: `stats_poll` derives both from the same raw
        // inbound response: the aggregated line is the aggregate of the
        // per-inbound totals. Regression for "totals not match
        // inbound traffic": the totals used to come from the outbound sweep.
        let mut runtime = runtime();
        let rows = vec![("a".to_string(), 1010, 2020), ("b".to_string(), 3030, 4030)];
        let (total_up, total_down) = Runtime::aggregate_totals(&rows);
        let fold = runtime.fold_inbound_traffic(rows);
        let (sum_up, sum_down) = fold
            .per_inbound_totals
            .iter()
            .fold((0u64, 0u64), |(u, d), (_, uu, dd)| (u + uu, d + dd));
        assert_eq!((total_up, total_down), (sum_up, sum_down));
        assert_eq!((sum_up, sum_down), (4040, 6050));
    }

    #[test]
    fn download_progress_is_coalesced_but_completion_is_never_hidden() {
        let last = AtomicU64::new(NO_PROGRESS_EMITTED);
        assert!(should_emit_download_progress(
            &last,
            Duration::ZERO,
            0,
            1_000
        ));
        assert!(!should_emit_download_progress(
            &last,
            DOWNLOAD_PROGRESS_INTERVAL / 2,
            500,
            1_000
        ));
        assert!(should_emit_download_progress(
            &last,
            DOWNLOAD_PROGRESS_INTERVAL / 2,
            1_000,
            1_000
        ));
        assert!(should_emit_download_progress(
            &last,
            DOWNLOAD_PROGRESS_INTERVAL * 2,
            1_001,
            2_000
        ));
    }
    /// A flooding core must not grow the GUI queue; lines beyond
    /// channel capacity are counted and later coalesced into one summary.
    #[test]
    fn log_gate_coalesces_lines_when_channel_is_full() {
        use super::{LogGate, suppressed_summary};

        let (sender, receiver) = std::sync::mpsc::sync_channel(2);
        let mut gate = LogGate::new();
        let mut queued = 0;
        for _ in 0..5 {
            if gate.forward("line".to_string(), &sender) {
                queued += 1;
            }
        }
        // Capacity 2: exactly two lines fit; the rest were counted, not queued.
        assert_eq!(queued, 2);

        // The GUI catches up (drains the queue); the next line emits the
        // summary of the 3 suppressed lines followed by the line itself.
        while receiver.try_recv().is_ok() {}
        assert!(gate.forward("fresh".to_string(), &sender));
        let mut drained = Vec::new();
        while let Ok(evt) = receiver.try_recv() {
            drained.push(evt);
        }
        assert_eq!(drained.len(), 2, "summary plus the fresh line");
        match &drained[0] {
            CoreEvt::AppLog(message) => assert_eq!(
                message.text(Language::En),
                suppressed_summary(3).text(Language::En),
                "the summary must state how many core lines were dropped"
            ),
            other => panic!("expected suppression summary, got {other:?}"),
        }
        match &drained[1] {
            CoreEvt::Log {
                line,
                from_core: true,
            } => assert_eq!(line, "fresh"),
            other => panic!("expected fresh line, got {other:?}"),
        }
        assert!(
            matches!(
                receiver.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "no further events queued"
        );
    }

    /// A lifecycle event must never be dropped while the GUI is
    /// draining — the bounded fallback waits (well within EVENT_SEND_BOUND)
    /// for the next drain cycle to free a slot.
    #[test]
    fn lifecycle_events_are_never_dropped_when_channel_is_full() {
        use super::queue_event;

        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        sender.send(CoreEvt::Operation(None)).expect("fill slot");
        let full_sender = sender.clone();
        let blocker = std::thread::spawn(move || {
            queue_event(CoreEvt::State(super::CorePhase::Running), &full_sender);
        });
        // Free the slot; the waiting lifecycle event arrives next.
        assert!(matches!(receiver.recv(), Ok(CoreEvt::Operation(None))));
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(1)),
            Ok(CoreEvt::State(super::CorePhase::Running))
        ));
        blocker.join().expect("blocked send completes");
    }

    /// When the GUI has stopped draining, the full-channel fallback
    /// must return within the bounded window instead of blocking the runtime
    /// thread forever; the lifecycle event is dropped only in that case.
    #[test]
    fn full_channel_lifecycle_event_waits_bounded_window_then_drops() {
        use super::queue_event;

        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        sender.send(CoreEvt::Operation(None)).expect("fill slot");
        let full_sender = sender.clone();
        let started = Instant::now();
        let blocker = std::thread::spawn(move || {
            queue_event(CoreEvt::State(super::CorePhase::Running), &full_sender);
        });
        blocker.join().expect("bounded fallback must return");
        let waited = started.elapsed();
        assert!(
            waited >= super::EVENT_SEND_BOUND / 2,
            "the bounded window must actually wait for a drain cycle, got {waited:?}"
        );
        // Only the filler remains; the lifecycle event was dropped after the
        // bound because the GUI never drained.
        assert!(matches!(receiver.try_recv(), Ok(CoreEvt::Operation(None))));
        assert!(
            matches!(
                receiver.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "the lifecycle event is dropped only when the GUI never drains"
        );
    }

    /// Volatile events (telemetry, progress, diagnostics) never
    /// block the runtime thread — a full channel drops them immediately.
    #[test]
    fn volatile_events_never_block_when_channel_is_full() {
        use super::queue_event;

        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        sender.send(CoreEvt::Operation(None)).expect("fill slot");
        let started = Instant::now();
        queue_event(CoreEvt::Stats(Default::default()), &sender);
        queue_event(
            CoreEvt::Log {
                line: "diagnostic".into(),
                from_core: false,
            },
            &sender,
        );
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "volatile events must be dropped without waiting"
        );
        assert!(matches!(receiver.try_recv(), Ok(CoreEvt::Operation(None))));
        assert!(
            matches!(
                receiver.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "no volatile event may be queued"
        );
    }

    /// Dropping the runtime handle with a full event channel and a
    /// GUI that has stopped draining must complete within a bounded time.
    /// This is the shutdown deadlock regression: the runtime thread blocking
    /// in a send while the GUI thread waits on the worker join.
    #[test]
    fn drop_with_full_event_channel_completes_within_bounded_time() {
        let (event_sender, event_receiver) =
            std::sync::mpsc::sync_channel(super::EVT_CHANNEL_CAPACITY);
        let handle = spawn_runtime(
            event_sender.clone(),
            egui::Context::default(),
            crate::metrics::MetricsHandle::new(),
        );
        assert!(matches!(
            event_receiver.recv_timeout(Duration::from_secs(1)),
            Ok(super::CoreEvt::State(super::CorePhase::Stopped))
        ));

        // The GUI stops draining: fill the channel so every later event hits
        // the full-channel fallback.
        for _ in 0..super::EVT_CHANNEL_CAPACITY {
            event_sender
                .send(super::CoreEvt::Stats(Default::default()))
                .expect("fill the GUI event channel");
        }

        // A lifecycle-class event is queued behind the full channel while the
        // GUI thread is inside drop(RuntimeHandle). GetBalancerInfo used to
        // ride the event ceremony, but it now answers on a per-request
        // reply channel (no event) — `CoreCmd::Stop` from the fresh Stopped
        // phase emits exactly one lifecycle `Operation(None)` event through
        // the same bounded-wait path, so the class under test is unchanged.
        handle
            .cmd
            .send(CoreCmd::Stop)
            .expect("queue a lifecycle-class event");

        let started = Instant::now();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let dropper = std::thread::spawn(move || {
            drop(handle);
            let _ = done_tx.send(());
        });
        assert!(
            done_rx.recv_timeout(Duration::from_secs(5)).is_ok(),
            "RuntimeHandle::drop must not deadlock on a full event channel"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "drop must complete within the bounded window"
        );
        // The dropper thread is deliberately not joined: in the regression
        // (blocking fallback) it would be stuck inside drop() forever, and
        // the assertion above already reported the deadlock.
        drop(dropper);
    }

    /// An unauthenticated `get_sys_stats` answer from a
    /// responder that is not the spawned core child must never clear the
    /// rollback gate or ACK (delete) the core-update backup. A fabricated
    /// listener/pid mismatch keeps both candidates pending and the phase
    /// pre-Running — no side-effect calls at all.
    #[tokio::test(flavor = "current_thread")]
    async fn unverified_responder_never_clears_gates_or_acks_backup() {
        let mut runtime = runtime();
        runtime.backend = BackendState::for_test(true, false);
        runtime.backend.set_child_pid(4242);
        runtime.pending_transition.commit_candidate();
        runtime.core_update.commit_candidate();

        runtime.complete_readiness_probe(false).await;

        assert!(
            runtime.pending_transition.is_candidate_pending(),
            "a spoofed responder must not clear the config-rollback gate"
        );
        assert!(
            runtime.core_update.is_candidate_pending(),
            "a spoofed responder must not ACK (delete) the core-update backup"
        );
        assert!(
            !matches!(runtime.phase, super::CorePhase::Running),
            "readiness must not be trusted without owning-PID verification"
        );
    }

    /// The verified responder (owning PID matches the spawned child) may clear
    /// the rollback gate and reach Running. `core_update` is deliberately not
    /// committed here so `ack_ready` stays a no-op and never touches disk.
    #[tokio::test(flavor = "current_thread")]
    async fn verified_listener_clears_the_rollback_gate() {
        let mut runtime = runtime();
        runtime.backend = BackendState::for_test(true, false);
        runtime.backend.set_child_pid(4242);
        runtime.pending_transition.commit_candidate();

        runtime.complete_readiness_probe(true).await;

        assert!(!runtime.pending_transition.is_candidate_pending());
        assert!(matches!(runtime.phase, super::CorePhase::Running));
        assert!(
            !runtime.core_update.is_candidate_pending(),
            "a no-op ack must stay a no-op"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tun_readiness_deadline_arms_only_after_helper_confirms_spawn() {
        let mut runtime = runtime();
        runtime.pending_transition.commit_candidate();
        runtime.requested_tun_mode = true;
        runtime.backend = BackendState::for_test(true, true);

        // `pipe.start()` has been accepted, but the elevated helper is still
        // staging/validating (up to CONFIG_TEST_TIMEOUT plus the payload copy)
        // — the xray child does not exist yet, so no deadline may be armed.
        runtime.defer_readiness_deadline();
        assert!(
            runtime.readiness_deadline.is_none(),
            "TUN staging must not arm the readiness clock before spawn confirmation"
        );

        // The helper reports the child spawned; the clock starts here, never
        // earlier than the confirmation instant.
        let confirmation = Instant::now();
        runtime.on_helper_state("starting", 4242);
        assert!(runtime.readiness_deadline.is_some());
        let ahead = runtime
            .readiness_deadline
            .expect("armed deadline")
            .saturating_duration_since(confirmation);
        assert!(
            ahead >= READY_TIMEOUT,
            "applied-candidate TUN start must arm the cold-start clock, never \
             the 3 s applied clock: the wintun create legitimately waits out \
             the previous teardown (~3 s observed), and killing a core stuck \
             mid-create wedges PnP for every wintun user"
        );
        assert!(
            ahead <= READY_TIMEOUT + Duration::from_secs(2),
            "deadline must start no earlier than spawn confirmation"
        );

        // A later informational state must not re-arm (or extend) the clock.
        let armed = runtime.readiness_deadline;
        runtime.on_helper_state("running", 4242);
        assert_eq!(runtime.readiness_deadline, armed);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tun_plain_start_arms_deadline_with_cold_start_timeout() {
        let mut runtime = runtime();
        runtime.requested_tun_mode = true;
        runtime.backend = BackendState::for_test(true, false);

        runtime.defer_readiness_deadline();
        let confirmation = Instant::now();
        runtime.on_helper_state("starting", 4242);
        assert!(runtime.readiness_deadline.is_some());
        let ahead = runtime
            .readiness_deadline
            .expect("armed deadline")
            .saturating_duration_since(confirmation);
        assert!(
            ahead >= READY_TIMEOUT,
            "plain TUN start must arm with READY_TIMEOUT"
        );
        assert!(ahead <= READY_TIMEOUT + Duration::from_secs(2));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn slow_tun_staging_never_triggers_candidate_rollback() {
        let mut runtime = runtime();
        runtime.pending_transition.commit_candidate();
        runtime.requested_tun_mode = true;
        runtime.backend = BackendState::for_test(true, false);
        runtime.defer_readiness_deadline();

        // While the readiness clock is unarmed (helper still staging), ready_poll
        // must no-op: no rollback, the candidate stays pending, no stop begun.
        runtime.ready_poll().await;

        assert!(
            runtime.pending_transition.rollback_pending().is_none(),
            "slow staging must not queue a candidate rollback"
        );
        assert!(
            runtime.pending_transition.is_candidate_pending(),
            "the applied candidate must stay pending while staging"
        );
        assert!(!runtime.exit_policy.stopping());

        // The helper finally confirms the spawn: the clock starts now, and a
        // genuine post-confirmation timeout still queues exactly one rollback.
        runtime.on_helper_state("starting", 4242);
        assert!(runtime.readiness_deadline.is_some());
        runtime.readiness_deadline = Some(Instant::now() - Duration::from_millis(1));
        runtime.ready_poll().await;
        assert!(
            runtime.pending_transition.rollback_pending().is_some(),
            "a genuine readiness timeout after spawn confirmation must roll back"
        );
        assert!(!runtime.pending_transition.is_candidate_pending());
        assert!(runtime.exit_policy.stopping());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn direct_start_arms_readiness_deadline_immediately() {
        let mut runtime = runtime();
        runtime.pending_transition.commit_candidate();
        // The direct path arms right after `supervisor::spawn` succeeds; the
        // clock must be live immediately, before any ready poll.
        runtime.arm_readiness_deadline();
        assert!(runtime.readiness_deadline.is_some());
        let remaining = runtime
            .readiness_deadline
            .expect("armed deadline")
            .saturating_duration_since(Instant::now());
        assert!(
            remaining <= READY_TIMEOUT_APPLIED,
            "direct applied-candidate start must arm with READY_TIMEOUT_APPLIED"
        );
    }

    /// The install swap runs in `spawn_blocking`, which `abort()`
    /// cannot interrupt. Stop must therefore NOT release the operation slot
    /// while the worker is still running — releasing it would let the update
    /// land after the UI saw "cancelled" and would let a second install
    /// overlap the orphaned first one.
    #[tokio::test(flavor = "current_thread")]
    async fn stop_holds_update_slot_while_the_install_cannot_be_aborted() {
        // The busy-reject path gates on `update_pending_health()`, which reads
        // the real %APPDATA% root. Isolate so a concurrent test's redirected
        // env (or a genuine mid-update state on the user machine) cannot
        // replace the expected busy-reject event with the health-check text.
        with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            occupy_exclusive(&mut runtime, JobKind::UpdateCore);
            park_pending_task(&mut runtime);

            tokio::time::timeout(
                Duration::from_millis(100),
                runtime.handle_cmd(CoreCmd::Stop),
            )
            .await
            .expect("Stop must not wait for the stalled install worker");
            assert_eq!(
                runtime.jobs.busy_kind(),
                Some(JobKind::UpdateCore),
                "the update record must stay held until the install worker's terminal result"
            );
            assert!(
                runtime.jobs.is_cancel_requested(),
                "the held record must record the cancellation"
            );
            assert!(!runtime.backend.is_alive());

            // A second update while the first install still owns the slot
            // must be rejected: the single in-flight install invariant
            // survives cancel.
            runtime.handle_cmd(CoreCmd::UpdateCore).await;
            assert!(runtime.jobs.busy_kind().is_some());
            flush_bookends(&mut runtime);
            let emitted: Vec<_> = events.try_iter().collect();
            assert!(emitted.iter().any(|event| matches!(
                event,
                CoreEvt::Download(super::DownloadState::Failed(error))
                    if error.text(Language::En) == busy_reject_text(JobKind::UpdateCore)
            )));
            assert!(
                !emitted
                    .iter()
                    .any(|event| matches!(event, CoreEvt::Operation(None))),
                "no Operation(None) may be emitted while the install is still running"
            );
        })
        .await;
    }

    /// End to end through the real select loop: Stop during an
    /// in-flight install keeps the slot held; the worker's terminal
    /// `Download` event is delivered first, `Operation(None)` only after, and
    /// a second update issued mid-install is rejected (no overlap). The
    /// cancelled path must not arm the health-gate auto-restart.
    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_update_lands_then_releases_slot_through_the_select_loop() {
        // The rejected second update gates on `update_pending_health()`,
        // which reads the real %APPDATA% root; isolate (same rationale as
        // `stop_holds_update_slot_while_the_install_cannot_be_aborted`).
        with_appdata_async(async {
            let (command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
            let (event_sender, event_receiver) =
                std::sync::mpsc::sync_channel(super::EVT_CHANNEL_CAPACITY);
            let mut runtime = Runtime::new(
                command_receiver,
                event_sender,
                egui::Context::default(),
                crate::metrics::MetricsHandle::new(),
            );
            runtime
                .jobs
                .try_begin(JobKind::UpdateCore)
                .expect("begin the install job");
            runtime.jobs.attach_exclusive_task(tokio::spawn(async {
                // The swap takes a moment, like the real spawn_blocking install.
                tokio::time::sleep(Duration::from_millis(150)).await;
                ExclusiveOutcome::Download {
                    state: super::DownloadState::Done("26.7.28".into()),
                    kind: OperationKind::UpdateCore,
                }
            }));
            let run = tokio::spawn(runtime.run());

            // The GUI-initiated stop and a second update arrive while the swap
            // is still running.
            command_sender.send(CoreCmd::Stop).expect("send Stop");
            command_sender
                .send(CoreCmd::UpdateCore)
                .expect("send second update");

            let (mut seen_done, mut seen_none, mut seen_conflict) = (false, false, false);
            tokio::time::timeout(Duration::from_secs(5), async {
                while !(seen_done && seen_none) {
                    tokio::task::yield_now().await;
                    let Ok(event) = event_receiver.try_recv() else {
                        continue;
                    };
                    match event {
                        super::CoreEvt::Download(super::DownloadState::Done(_)) => {
                            assert!(!seen_done, "exactly one terminal Download");
                            assert!(!seen_none, "Download(Done) must precede Operation(None)");
                            seen_done = true;
                        }
                        super::CoreEvt::Download(super::DownloadState::Failed(error)) => {
                            assert!(
                                error.text(Language::En) == busy_reject_text(JobKind::UpdateCore),
                                "second update must be rejected while the slot is held, got: {error}"
                            );
                            seen_conflict = true;
                        }
                        super::CoreEvt::Operation(None) => {
                            assert!(
                                seen_done,
                                "Operation(None) may be emitted only after the swap lands"
                            );
                            seen_none = true;
                        }
                        super::CoreEvt::Operation(Some(_))
                        | super::CoreEvt::State(_)
                        | super::CoreEvt::Log { .. }
                        | super::CoreEvt::AppLog(..) => {}
                        other => panic!("unexpected event: {other:?}"),
                    }
                }
            })
            .await
            .expect("terminal update result must arrive within the bound");
            assert!(
                seen_conflict,
                "the overlapping second update must be rejected"
            );

            command_sender
                .send(CoreCmd::Shutdown)
                .expect("send Shutdown");
            run.await.expect("runtime run() must complete cleanly");

            // The cancelled path must not arm the health-gate auto-restart:
            // after the terminal result no further lifecycle event may appear.
            assert!(
                event_receiver
                    .recv_timeout(Duration::from_millis(200))
                    .is_err(),
                "no health-gate restart may follow a cancelled update"
            );
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn installed_update_stays_busy_until_readiness() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::UpdateCore);

        runtime
            .complete_exclusive(ExclusiveOutcome::Download {
                state: super::DownloadState::Done("26.7.28".into()),
                kind: OperationKind::UpdateCore,
            })
            .await;

        assert!(runtime.core_update.is_candidate_pending());
        assert_eq!(runtime.jobs.busy_kind(), Some(JobKind::UpdateCore));
        assert!(runtime.pending_restart.is_some());
        flush_bookends(&mut runtime);
        assert!(
            !events
                .try_iter()
                .any(|event| matches!(event, CoreEvt::Operation(None)))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejected_update_emits_a_terminal_operation_event() {
        let (mut runtime, events) = runtime_with_events();
        runtime.phase = super::CorePhase::Running;
        runtime.backend = BackendState::for_test(true, false);

        runtime.handle_cmd(CoreCmd::UpdateCore).await;

        let emitted: Vec<_> = events.try_iter().collect();
        assert!(emitted.iter().any(|event| matches!(
            event,
            CoreEvt::Download(super::DownloadState::Failed(error))
                if error.text(Language::En) == t(Language::En, Key::RtFrameUpdateStopCoreFirst)
        )));
        assert!(
            emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::Operation(None)))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejected_import_emits_a_terminal_operation_event() {
        let (mut runtime, events) = runtime_with_events();
        runtime.phase = super::CorePhase::Running;
        runtime.backend = BackendState::for_test(true, false);

        runtime
            .handle_cmd(CoreCmd::ImportCoreArchive("selected.zip".into()))
            .await;

        let emitted: Vec<_> = events.try_iter().collect();
        assert!(emitted.iter().any(|event| matches!(
            event,
            CoreEvt::Download(super::DownloadState::Failed(error))
                if error.text(Language::En) == t(Language::En, Key::RtFrameUpdateStopCoreFirst)
        )));
        assert!(
            emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::Operation(None)))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn conflicting_import_preserves_the_active_operation_owner() {
        // `ImportCoreArchive` funnels into `update_core`, whose busy-reject
        // path gates on `update_pending_health()` before the registry check;
        // isolate from the real %APPDATA% root (same rationale as
        // `stop_holds_update_slot_while_the_install_cannot_be_aborted`).
        with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            occupy_exclusive(&mut runtime, JobKind::Start);

            runtime
                .handle_cmd(CoreCmd::ImportCoreArchive("selected.zip".into()))
                .await;

            assert_eq!(runtime.jobs.busy_kind(), Some(JobKind::Start));
            flush_bookends(&mut runtime);
            let emitted: Vec<_> = events.try_iter().collect();
            assert!(emitted.iter().any(|event| matches!(
                event,
                CoreEvt::Download(super::DownloadState::Failed(error))
                    if error.text(Language::En) == busy_reject_text(JobKind::Start)
            )));
            assert!(
                emitted
                    .iter()
                    .any(|event| matches!(event, CoreEvt::Operation(Some(OperationKind::Start))))
            );
            assert!(
                !emitted
                    .iter()
                    .any(|event| matches!(event, CoreEvt::Operation(None)))
            );
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn conflicting_update_preserves_the_active_operation_owner() {
        // The busy-reject path gates on `update_pending_health()` before the
        // registry check; isolate from the real %APPDATA% root (same
        // rationale as `stop_holds_update_slot_while_the_install_cannot_be_aborted`).
        with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            occupy_exclusive(&mut runtime, JobKind::Start);

            runtime.handle_cmd(CoreCmd::UpdateCore).await;

            assert_eq!(runtime.jobs.busy_kind(), Some(JobKind::Start));
            flush_bookends(&mut runtime);
            let emitted: Vec<_> = events.try_iter().collect();
            assert!(emitted.iter().any(|event| matches!(
                event,
                CoreEvt::Download(super::DownloadState::Failed(error))
                    if error.text(Language::En) == busy_reject_text(JobKind::Start)
            )));
            assert!(
                emitted
                    .iter()
                    .any(|event| matches!(event, CoreEvt::Operation(Some(OperationKind::Start))))
            );
            assert!(
                !emitted
                    .iter()
                    .any(|event| matches!(event, CoreEvt::Operation(None)))
            );
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn core_rollback_failure_releases_update_operation() {
        // The rollback leg renames whatever core tree the current root holds,
        // so isolate it: a concurrent test's redirected env must never decide
        // what this test rolls back (and this test must never touch the real
        // config directory). With no pending swap here the rollback reports
        // the no-last-good failure the assertions below pin.
        with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            occupy_exclusive(&mut runtime, JobKind::UpdateCore);
            runtime.core_update.commit_candidate();
            runtime.core_update.arm_rollback(rollback_reason());

            runtime.complete_pending_core_rollback().await;

            assert!(runtime.jobs.busy_kind().is_none());
            assert!(matches!(runtime.phase, super::CorePhase::Stopped));
            flush_bookends(&mut runtime);
            let emitted: Vec<_> = events.try_iter().collect();
            assert!(emitted.iter().any(|event| matches!(
                event,
                CoreEvt::Download(super::DownloadState::Failed(message))
                    if message.text(Language::En).contains(&rollback_reason().text(Language::En))
            )));
            assert!(
                emitted
                    .iter()
                    .any(|event| matches!(event, CoreEvt::Operation(None)))
            );
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn second_update_check_is_rejected_while_one_is_in_flight() {
        let (mut runtime, events) = runtime_with_events();
        assert!(
            runtime.accept_update_check(),
            "first check must be accepted"
        );
        assert!(
            !runtime.accept_update_check(),
            "a second check must be rejected while one is in flight"
        );
        assert!(matches!(
            events.try_recv(),
            Ok(CoreEvt::UpdateCheck(
                crate::sys::selfupd::UpdateCheckState::Checking
            ))
        ));
        assert!(
            events.try_recv().is_err(),
            "accepted check must emit exactly one Checking event"
        );
        // The fetch task clears the gate after the terminal event; simulate
        // the terminal state so a retry click is accepted again.
        runtime.update_check_busy.store(false, Ordering::SeqCst);
        assert!(
            runtime.accept_update_check(),
            "a retry after the terminal state must be accepted"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn core_rollback_restoration_releases_update_before_restart() {
        let (mut runtime, events) = runtime_with_events();
        // APPDATA is process-global, not thread-local: serialize against tests
        // that read `%APPDATA%\broccoli` paths so this redirect cannot race them.
        let _appdata_lock = APPDATA_ENV_LOCK.lock().await;
        let temporary = tempfile::tempdir().expect("temporary AppData root");
        let _appdata = AppDataRedirect::to(temporary.path());
        std::fs::create_dir_all(temporary.path().join("broccoli/core")).expect("create candidate");
        std::fs::create_dir_all(temporary.path().join("broccoli/core.bak")).expect("create backup");
        std::fs::write(
            temporary.path().join("broccoli/.core-update.pending"),
            b"broccoli-core-swap-v1\n",
        )
        .expect("write update marker");
        occupy_exclusive(&mut runtime, JobKind::UpdateCore);
        runtime.core_update.commit_candidate();
        runtime.core_update.arm_rollback(rollback_reason());

        runtime.complete_pending_core_rollback().await;

        assert!(runtime.jobs.busy_kind().is_none());
        assert!(runtime.pending_restart.is_some());
        flush_bookends(&mut runtime);
        let emitted: Vec<_> = events.try_iter().collect();
        assert!(
            emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::Operation(None)))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stalled_api_deadline_keeps_stop_dispatch_responsive() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stalling API");
        listener
            .set_nonblocking(true)
            .expect("make stalling API nonblocking");
        let port = listener.local_addr().expect("stall address").port();
        let stop_server = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop_server);
        let server = std::thread::spawn(move || {
            let mut accepted = None;
            while !thread_stop.load(Ordering::Acquire) {
                if accepted.is_none() {
                    match listener.accept() {
                        Ok((stream, _)) => accepted = Some(stream),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => panic!("stall accept failed: {error}"),
                    }
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        });

        let mut runtime = runtime();
        runtime.grpc = crate::rt::grpc::GrpcClient::new(port);
        runtime.phase = super::CorePhase::Running;
        runtime.backend = BackendState::for_test(true, false);
        let started = Instant::now();
        runtime.stats_poll().await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "poll deadline did not bound the stalled API"
        );
        tokio::time::timeout(
            Duration::from_millis(100),
            runtime.handle_cmd(CoreCmd::Stop),
        )
        .await
        .expect("Stop dispatch must remain responsive after a stalled API");
        stop_server.store(true, Ordering::Release);
        server.join().expect("join stalling API");
    }

    #[test]
    fn core_transport_tracks_backend_tun_ownership() {
        assert_eq!(
            CoreTransport::from_backend_tun_owned(false),
            CoreTransport::Direct
        );
        assert_eq!(
            CoreTransport::from_backend_tun_owned(true),
            CoreTransport::Tun
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn requested_tun_mode_never_rewrites_current_backend_ownership() {
        let mut runtime = runtime();
        runtime.backend = BackendState::for_test(true, true);
        runtime.requested_tun_mode = false;
        assert!(runtime.backend.is_tun_owned());
        runtime.requested_tun_mode = true;
        assert!(runtime.backend.is_tun_owned());
        runtime.requested_tun_mode = false;
        assert!(runtime.backend.is_tun_owned());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn conflicting_route_controls_reject_through_reply_channel() {
        // TestRoute answers on the request's own oneshot channel.
        // The busy-window reject (TestRoute's registry rule blocks it) must
        // deliver the same rejection text it used to emit as an event — now
        // straight into the requester's channel (no event, no bus).
        let (mut runtime, _events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::UpdateCore);
        let (reply, result) = tokio::sync::oneshot::channel();

        runtime
            .handle_cmd(CoreCmd::TestRoute {
                reply,
                request: crate::model::routing::RouteTestRequest {
                    target_domain: "example.com".into(),
                    ..Default::default()
                },
            })
            .await;

        assert_eq!(
            reply_reject_text(result.await),
            busy_reject_text(JobKind::UpdateCore),
            "the busy-window reject must arrive on the request's reply channel"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn conflicting_test_config_rejects_through_reply_channel() {
        // TestConfig answers on the request's own oneshot channel.
        // The busy-window reject (TestConfig's registry rule blocks it) must
        // deliver the same rejection text it used to emit as an event — now
        // straight into the requester's channel (no event, no bus).
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::UpdateCore);
        let (reply, result) = tokio::sync::oneshot::channel();

        runtime
            .handle_cmd(CoreCmd::TestConfig {
                config: serde_json::json!({}),
                reply,
            })
            .await;

        assert_eq!(
            reply_reject_text(result.await),
            busy_reject_text(JobKind::UpdateCore),
            "the busy-window reject must arrive on the request's reply channel"
        );
        assert!(
            events
                .try_iter()
                .all(|event| !matches!(event, CoreEvt::Operation(None) | CoreEvt::LatencyProbe(_))),
            "the sync reject must not release the busy owner nor emit a probe result"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn conflicting_latency_probe_emits_one_error_without_releasing_owner() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::UpdateCore);
        let profile = crate::model::ServerProfile::new(
            "probe",
            crate::model::OutboundModel::new(crate::model::Protocol::Freedom),
        );

        runtime
            .handle_cmd(CoreCmd::ProbeLatency {
                profiles: vec![profile],
                probe_url: "http://127.0.0.1:1".into(),
                tun_outbound_interface: None,
                tun_adapter_name: None,
            })
            .await;

        assert_eq!(runtime.jobs.busy_kind(), Some(JobKind::UpdateCore));
        flush_bookends(&mut runtime);
        let emitted: Vec<_> = events.try_iter().collect();
        let results: Vec<_> = emitted
            .iter()
            .filter_map(|event| match event {
                CoreEvt::LatencyProbe(result) => Some(result),
                _ => None,
            })
            .collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tags.len(), 1);
        assert!(matches!(
            &results[0].result,
            Err(error) if error.headline.key() == Key::RtFrameCommandRejectedBusy
        ));
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::Operation(None)))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn logger_restart_rejects_with_core_not_running_through_reply_channel() {
        // The pilot families answer on the request's own oneshot
        // channel. A fresh runtime is Stopped, so the guard pre-check must
        // deliver the same rejection text it used to emit as an event —
        // now straight into the requester's channel (no event, no bus).
        let (mut runtime, _events) = runtime_with_events();
        let (reply, result) = tokio::sync::oneshot::channel();

        runtime.handle_cmd(CoreCmd::RestartLogger { reply }).await;

        assert_eq!(
            reply_reject_text(result.await),
            t(Language::En, Key::SeatCoreNotRunning),
            "the sync reject must arrive on the request's reply channel"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn runtime_state_rejects_with_core_not_running_through_reply_channel() {
        let (mut runtime, _events) = runtime_with_events();
        let (reply, result) = tokio::sync::oneshot::channel();

        runtime
            .handle_cmd(CoreCmd::ListRuntimeState { reply })
            .await;

        assert_eq!(
            reply_reject_text(result.await),
            t(Language::En, Key::SeatCoreNotRunning),
            "the sync reject must arrive on the request's reply channel"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn route_test_rejects_with_core_not_running_through_reply_channel() {
        // TestRoute answers on the request's own oneshot channel.
        // A fresh runtime is Stopped, so the arm's pre-check must deliver
        // the same rejection text it used to emit as an event — now straight
        // into the requester's channel (no event, no bus).
        let (mut runtime, _events) = runtime_with_events();
        let (reply, result) = tokio::sync::oneshot::channel();

        runtime
            .handle_cmd(CoreCmd::TestRoute {
                reply,
                request: crate::model::routing::RouteTestRequest {
                    target_domain: "example.com".into(),
                    ..Default::default()
                },
            })
            .await;

        assert_eq!(
            reply_reject_text(result.await),
            t(Language::En, Key::SeatCoreNotRunning),
            "the sync reject must arrive on the request's reply channel"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn balancer_info_rejects_with_core_not_running_through_reply_channel() {
        // GetBalancerInfo answers on the request's own oneshot
        // channel. A fresh runtime is Stopped, so the unavailable ladder
        // must deliver the same rejection text it used to emit as an event.
        let (mut runtime, _events) = runtime_with_events();
        let (reply, result) = tokio::sync::oneshot::channel();

        runtime
            .handle_cmd(CoreCmd::GetBalancerInfo {
                reply,
                balancer_tag: "edge".into(),
            })
            .await;

        assert_eq!(
            reply_reject_text(result.await),
            t(Language::En, Key::SeatCoreNotRunning),
            "the sync reject must arrive on the request's reply channel"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn trial_rules_list_rejects_with_core_not_running_through_reply_channel() {
        // ListTrialRules answers on the request's own oneshot
        // channel. A fresh runtime is Stopped, so the arm's pre-check must
        // deliver the same rejection text it used to emit as an event.
        let (mut runtime, _events) = runtime_with_events();
        let (reply, result) = tokio::sync::oneshot::channel();

        runtime.handle_cmd(CoreCmd::ListTrialRules { reply }).await;

        assert_eq!(
            reply_reject_text(result.await),
            t(Language::En, Key::SeatCoreNotRunning),
            "the sync reject must arrive on the request's reply channel"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stopping_latency_probe_emits_cancellation_before_release() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::LatencyProbe);
        runtime
            .jobs
            .set_exclusive_sidecar(ExclusiveSidecar::LatencyTags(vec!["srv-probe".into()]));
        park_pending_task(&mut runtime);

        runtime.handle_cmd(CoreCmd::Stop).await;

        assert!(runtime.jobs.busy_kind().is_none());
        flush_bookends(&mut runtime);
        let emitted: Vec<_> = events.try_iter().collect();
        let latency_indices: Vec<usize> = emitted
            .iter()
            .enumerate()
            .filter_map(|(index, event)| matches!(event, CoreEvt::LatencyProbe(_)).then_some(index))
            .collect();
        let none_indices: Vec<usize> = emitted
            .iter()
            .enumerate()
            .filter_map(|(index, event)| matches!(event, CoreEvt::Operation(None)).then_some(index))
            .collect();
        assert_eq!(latency_indices.len(), 1);
        assert_eq!(none_indices.len(), 1);
        assert!(latency_indices[0] < none_indices[0]);
        assert!(matches!(
            &emitted[latency_indices[0]],
            CoreEvt::LatencyProbe(result)
                if result.tags == ["srv-probe"]
                    && matches!(&result.result, Err(error)
                        if error.headline.key() == Key::ProbeCancelled)
        ));
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::State(_)))
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stopping_test_config_delivers_terminal_cancellation_on_reply() {
        // Stop during an in-flight test now delivers a terminal
        // to the settings screen where the verdict used to be silently
        // dropped. APPDATA is redirected so the test command's candidate
        // write stays in the temp root (same seam as the rollback tests).
        let (runtime, events) = with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            let (reply, result) = tokio::sync::oneshot::channel();
            runtime
                .handle_cmd(CoreCmd::TestConfig {
                    config: serde_json::json!({ "log": { "loglevel": "info" } }),
                    reply,
                })
                .await;
            assert_eq!(
                runtime.jobs.busy_kind(),
                Some(JobKind::TestConfig),
                "the accepted test must occupy the busy window"
            );

            runtime.handle_cmd(CoreCmd::Stop).await;

            assert!(runtime.jobs.busy_kind().is_none());
            assert_eq!(
                reply_reject_text(result.await),
                test_cancelled_text(Key::RtReasonStopRequested),
                "the stop cancellation must deliver the terminal on the request's reply"
            );
            flush_bookends(&mut runtime);
            let emitted: Vec<_> = events.try_iter().collect();
            assert_eq!(
                emitted
                    .iter()
                    .filter(|event| matches!(event, CoreEvt::Operation(None)))
                    .count(),
                1,
                "stop cancellation releases the busy slot exactly once"
            );
            assert!(
                !emitted
                    .iter()
                    .any(|event| matches!(event, CoreEvt::LatencyProbe(_)))
            );
            assert!(
                !emitted
                    .iter()
                    .any(|event| matches!(event, CoreEvt::State(_)))
            );
            (runtime, events)
        })
        .await;
        let _ = (runtime, events);
    }

    /// Stop cancels an in-flight apply with its exactly-one terminal result
    /// (`apply cancelled: stop requested`) and releases the busy slot — the
    /// apply cell of the stop-cancel uniformity matrix.
    #[tokio::test(flavor = "current_thread")]
    async fn stopping_apply_emits_cancellation_before_release() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::ApplyConfig);
        park_pending_task(&mut runtime);

        runtime.handle_cmd(CoreCmd::Stop).await;

        assert!(runtime.jobs.busy_kind().is_none());
        flush_bookends(&mut runtime);
        let emitted: Vec<_> = events.try_iter().collect();
        let apply_indices: Vec<usize> = emitted
            .iter()
            .enumerate()
            .filter_map(|(index, event)| {
                matches!(event, CoreEvt::ApplyResult { .. }).then_some(index)
            })
            .collect();
        let none_indices: Vec<usize> = emitted
            .iter()
            .enumerate()
            .filter_map(|(index, event)| matches!(event, CoreEvt::Operation(None)).then_some(index))
            .collect();
        assert_eq!(
            apply_indices.len(),
            1,
            "one apply result settles one GUI revision"
        );
        assert_eq!(none_indices.len(), 1);
        assert!(apply_indices[0] < none_indices[0]);
        assert!(matches!(
            &emitted[apply_indices[0]],
            CoreEvt::ApplyResult { ok: false, output }
                if output.text(Language::En)
                    == apply_cancelled_text(Key::RtReasonStopRequested)
        ));
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::State(_)))
        );
    }

    /// Shutdown cancels an in-flight apply with its exactly-one terminal
    /// result (`apply cancelled: shutdown requested`) and releases the busy
    /// slot — the shutdown cell of the uniformity matrix for ApplyConfig.
    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_cancels_inflight_apply_with_terminal_result() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::ApplyConfig);
        park_pending_task(&mut runtime);

        runtime.handle_cmd(CoreCmd::Shutdown).await;

        assert!(runtime.jobs.busy_kind().is_none());
        assert!(runtime.shutting_down);
        flush_bookends(&mut runtime);
        let emitted: Vec<_> = events.try_iter().collect();
        let apply_indices: Vec<usize> = emitted
            .iter()
            .enumerate()
            .filter_map(|(index, event)| {
                matches!(event, CoreEvt::ApplyResult { .. }).then_some(index)
            })
            .collect();
        let none_indices: Vec<usize> = emitted
            .iter()
            .enumerate()
            .filter_map(|(index, event)| matches!(event, CoreEvt::Operation(None)).then_some(index))
            .collect();
        assert_eq!(
            apply_indices.len(),
            1,
            "one apply result settles one GUI revision"
        );
        assert_eq!(
            none_indices.len(),
            1,
            "shutdown cancellation releases the busy slot exactly once"
        );
        assert!(apply_indices[0] < none_indices[0]);
        assert!(matches!(
            &emitted[apply_indices[0]],
            CoreEvt::ApplyResult { ok: false, output }
                if output.text(Language::En)
                    == apply_cancelled_text(Key::RtReasonShutdownRequested)
        ));
    }

    /// Shutdown cancels an in-flight TestConfig validation with the
    /// exactly-one terminal on the request's reply (`config test cancelled:
    /// shutdown requested`) and releases the busy slot — the shutdown cell
    /// of the uniformity matrix for TestConfig. APPDATA is redirected so
    /// the accepted command's candidate write stays in the temp root.
    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_cancels_inflight_test_with_terminal_result() {
        let (runtime, events) = with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            let (reply, result) = tokio::sync::oneshot::channel();
            runtime
                .handle_cmd(CoreCmd::TestConfig {
                    config: serde_json::json!({ "log": { "loglevel": "info" } }),
                    reply,
                })
                .await;
            assert_eq!(
                runtime.jobs.busy_kind(),
                Some(JobKind::TestConfig),
                "the accepted test must occupy the busy window"
            );

            runtime.handle_cmd(CoreCmd::Shutdown).await;

            assert!(runtime.jobs.busy_kind().is_none());
            assert_eq!(
                reply_reject_text(result.await),
                test_cancelled_text(Key::RtReasonShutdownRequested),
                "the shutdown cancellation must deliver the terminal on the request's reply"
            );
            flush_bookends(&mut runtime);
            let emitted: Vec<_> = events.try_iter().collect();
            assert_eq!(
                emitted
                    .iter()
                    .filter(|event| matches!(event, CoreEvt::Operation(None)))
                    .count(),
                1,
                "shutdown cancellation releases the busy slot exactly once"
            );
            assert!(
                !emitted
                    .iter()
                    .any(|event| matches!(event, CoreEvt::ApplyResult { .. }))
            );
            (runtime, events)
        })
        .await;
        let _ = (runtime, events);
    }

    /// Shutdown cancels an in-flight latency probe with the exactly-one
    /// failure event carrying the sidecar tags (`latency probe cancelled:
    /// shutdown requested`) and releases the busy slot — the shutdown cell
    /// of the uniformity matrix for LatencyProbe.
    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_cancels_inflight_latency_probe_with_terminal_result() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::LatencyProbe);
        runtime
            .jobs
            .set_exclusive_sidecar(ExclusiveSidecar::LatencyTags(vec!["srv-probe".into()]));
        park_pending_task(&mut runtime);

        runtime.handle_cmd(CoreCmd::Shutdown).await;

        assert!(runtime.jobs.busy_kind().is_none());
        assert!(runtime.shutting_down);
        flush_bookends(&mut runtime);
        let emitted: Vec<_> = events.try_iter().collect();
        let probe_indices: Vec<usize> = emitted
            .iter()
            .enumerate()
            .filter_map(|(index, event)| matches!(event, CoreEvt::LatencyProbe(_)).then_some(index))
            .collect();
        let none_indices: Vec<usize> = emitted
            .iter()
            .enumerate()
            .filter_map(|(index, event)| matches!(event, CoreEvt::Operation(None)).then_some(index))
            .collect();
        assert_eq!(probe_indices.len(), 1);
        assert_eq!(
            none_indices.len(),
            1,
            "shutdown cancellation releases the busy slot exactly once"
        );
        assert!(probe_indices[0] < none_indices[0]);
        assert!(matches!(
            &emitted[probe_indices[0]],
            CoreEvt::LatencyProbe(result)
                if result.tags == ["srv-probe"]
                    && matches!(&result.result, Err(error)
                        if error.headline.key() == Key::ProbeCancelled)
        ));
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::State(_)))
        );
    }

    // ---------- CoreCmd::ValidateProfiles (profile validation verb) ----------

    /// One accepting `ValidateProfiles` request of `origin` over `profiles`,
    /// staged against an empty servers file with default scratch settings.
    fn validation_request(
        origin: ProfileValidationOrigin,
        profiles: Vec<ServerProfile>,
    ) -> Box<ProfileValidationRequest> {
        Box::new(ProfileValidationRequest {
            origin,
            lang: crate::model::settings::Language::En,
            profiles,
            draft_target: None,
            import_source: None,
            servers: crate::model::ServersFile::default(),
            settings: crate::model::Settings::default(),
        })
    }

    /// A freedom profile: the cheapest outbound for a validation run.
    fn freedom_profile(name: &str) -> ServerProfile {
        ServerProfile::new(name, OutboundModel::new(Protocol::Freedom))
    }

    /// Scratch validation configs still in the (redirected) config dir.
    /// Deliberately prefix-based: it must also catch a writer that stopped
    /// matching the sweep's exact naming contract.
    fn scratch_configs_in_config_dir() -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(crate::sys::paths::config_dir()) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with("profile-test-"))
            .collect();
        names.sort();
        names
    }

    /// Drive the exclusive record's in-flight task to its terminal the way
    /// the select loop's task arm does, then run the per-kind completion
    /// handler.
    async fn complete_parked_exclusive(runtime: &mut Runtime) {
        let outcome = runtime
            .jobs
            .exclusive_task_mut()
            .expect("the record still carries its in-flight task")
            .await
            .expect("the worker completes without panicking");
        runtime.jobs.clear_exclusive_task();
        runtime.complete_exclusive(outcome).await;
    }

    /// The busy-window reject the verb answers when another occupying
    /// operation holds the window (and, symmetrically, the one that
    /// operation gets while a validation runs).
    #[tokio::test(flavor = "current_thread")]
    async fn validate_profiles_rejects_while_another_occupying_operation_runs() {
        with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            occupy_exclusive(&mut runtime, JobKind::UpdateCore);
            let (reply, result) = tokio::sync::oneshot::channel();

            runtime
                .handle_cmd(CoreCmd::ValidateProfiles {
                    request: validation_request(
                        ProfileValidationOrigin::Import,
                        vec![freedom_profile("rejected")],
                    ),
                    reply,
                })
                .await;

            let verdict = result
                .await
                .expect("the reject answers on the reply channel");
            assert_eq!(
                verdict.as_ref().err().map(|error| error.text(Language::En)),
                Some(busy_reject_text(JobKind::UpdateCore)),
                "the busy-window reject must arrive on the request's reply channel"
            );
            assert_eq!(
                runtime.jobs.busy_kind(),
                Some(JobKind::UpdateCore),
                "a rejected validation must not touch the occupant"
            );
            assert!(
                scratch_configs_in_config_dir().is_empty(),
                "a rejected validation must not write a scratch config"
            );
            assert!(
                events
                    .try_iter()
                    .all(|event| !matches!(event, CoreEvt::Operation(None))),
                "the sync reject must not release the busy owner"
            );
        })
        .await;
    }

    /// The accepted validation occupies the busy window: another occupying
    /// command rejects while it runs, and the GUI sees its bookend.
    #[tokio::test(flavor = "current_thread")]
    async fn occupying_operations_reject_while_a_validation_runs() {
        with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            let (reply, mut result) = tokio::sync::oneshot::channel();
            runtime
                .handle_cmd(CoreCmd::ValidateProfiles {
                    request: validation_request(
                        ProfileValidationOrigin::Import,
                        vec![freedom_profile("holding")],
                    ),
                    reply,
                })
                .await;
            assert_eq!(runtime.jobs.busy_kind(), Some(JobKind::ValidateProfiles));
            flush_bookends(&mut runtime);
            let emitted: Vec<_> = events.try_iter().collect();
            assert!(
                emitted.iter().any(|event| matches!(
                    event,
                    CoreEvt::Operation(Some(OperationKind::ValidateProfiles))
                )),
                "the accepted validation must open the busy window for the UI gates"
            );

            let (test_reply, test_result) = tokio::sync::oneshot::channel();
            runtime
                .handle_cmd(CoreCmd::TestConfig {
                    config: serde_json::json!({}),
                    reply: test_reply,
                })
                .await;
            assert_eq!(
                test_result
                    .await
                    .expect("the reject answers on the reply channel")
                    .as_ref()
                    .err()
                    .map(|error| error.text(Language::En)),
                Some(busy_reject_text(JobKind::ValidateProfiles)),
                "a second occupying command must reject while the validation runs"
            );

            // The worker's own terminal releases the window exactly once.
            runtime.handle_cmd(CoreCmd::Shutdown).await;
            assert!(
                result.try_recv().is_err(),
                "the cooperative cancel must not deliver the terminal itself"
            );
            complete_parked_exclusive(&mut runtime).await;
            let verdict = result
                .await
                .expect("the worker's terminal must be delivered");
            assert_eq!(
                verdict.as_ref().err().map(|error| error.text(Language::En)),
                Some(crate::rt::profiles::validation_cancelled().text(Language::En)),
                "the cancelled worker delivers its own exactly-one terminal"
            );
            assert_released_once(&mut runtime, &events);
        })
        .await;
    }

    /// Stop cancels a validation cooperatively: the child that owns the
    /// scratch config is never hard-aborted, the record stays held until the
    /// worker's own terminal, and nothing is left on disk.
    #[tokio::test(flavor = "current_thread")]
    async fn stop_keeps_the_validation_slot_and_leaves_no_scratch_config() {
        with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            let (reply, result) = tokio::sync::oneshot::channel();
            runtime
                .handle_cmd(CoreCmd::ValidateProfiles {
                    request: validation_request(
                        ProfileValidationOrigin::Import,
                        vec![freedom_profile("stopped")],
                    ),
                    reply,
                })
                .await;

            runtime.handle_cmd(CoreCmd::Stop).await;

            assert_eq!(
                runtime.jobs.busy_kind(),
                Some(JobKind::ValidateProfiles),
                "Stop must not preempt the worker that owns the scratch config"
            );
            assert!(
                runtime.jobs.exclusive_task_active(),
                "the worker task must still be running after Stop"
            );
            assert!(
                runtime
                    .jobs
                    .exclusive_cancel_flag()
                    .expect("the record still occupies")
                    .load(Ordering::SeqCst),
                "Stop must raise the worker's cooperative cancel flag"
            );
            flush_bookends(&mut runtime);
            assert!(
                events
                    .try_iter()
                    .all(|event| !matches!(event, CoreEvt::Operation(None))),
                "no release may be emitted before the worker's terminal"
            );

            complete_parked_exclusive(&mut runtime).await;

            let verdict = result
                .await
                .expect("the worker's terminal must be delivered");
            assert_eq!(
                verdict.as_ref().err().map(|error| error.text(Language::En)),
                Some(crate::rt::profiles::validation_cancelled().text(Language::En)),
                "the cancelled worker delivers its exactly-one terminal"
            );
            assert_eq!(runtime.jobs.busy_kind(), None);
            assert_released_once(&mut runtime, &events);
            assert!(
                scratch_configs_in_config_dir().is_empty(),
                "a cancelled validation must leave no scratch config behind"
            );
        })
        .await;
    }

    /// A completed run reports its verdict on the request's reply, releases
    /// the window exactly once and leaves no scratch config behind (the
    /// worker's guard removed every per-profile file).
    #[tokio::test(flavor = "current_thread")]
    async fn completed_validation_reports_the_verdict_and_removes_every_scratch_config() {
        with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            let (reply, result) = tokio::sync::oneshot::channel();
            runtime
                .handle_cmd(CoreCmd::ValidateProfiles {
                    // The draft flow skips the import-only share-link check,
                    // so both profiles reach the scratch write and the
                    // validation child.
                    request: validation_request(
                        ProfileValidationOrigin::Draft,
                        vec![freedom_profile("first"), freedom_profile("second")],
                    ),
                    reply,
                })
                .await;

            complete_parked_exclusive(&mut runtime).await;

            let verdict = result
                .await
                .expect("the accepted command delivers exactly one terminal")
                .expect("a completed run reports a verdict");
            assert!(
                verdict.accepted.is_empty(),
                "the managed core is absent under the redirected root: nothing may validate"
            );
            assert_eq!(
                verdict.rejected.len(),
                2,
                "every profile of the request must be accounted for"
            );
            assert!(
                verdict
                    .rejected
                    .iter()
                    .all(|(name, output)| !name.is_empty() && !output.trim().is_empty()),
                "each rejection carries its label and a diagnostic, got {:?}",
                verdict.rejected
            );
            // Both rejections come from the validation stage (the managed
            // core is absent), which runs *after* the per-profile scratch
            // write: the empty config dir below therefore proves the guard
            // removed files the worker really wrote, not merely that the run
            // never got that far.
            let verify_sentence = t(Language::En, Key::ApplyCoreVerifyFailed);
            assert!(
                verdict
                    .rejected
                    .iter()
                    .all(|(_, output)| output.starts_with(verify_sentence)),
                "the run must reach the validation stage for every profile, got {:?}",
                verdict.rejected
            );
            assert_eq!(runtime.jobs.busy_kind(), None);
            assert_released_once(&mut runtime, &events);
            assert!(
                scratch_configs_in_config_dir().is_empty(),
                "the guard must remove every scratch config the run wrote"
            );
        })
        .await;
    }

    /// A panicking validation worker settles the request with the join-error
    /// terminal on its reply, exactly once, and releases the busy slot.
    #[tokio::test(flavor = "current_thread")]
    async fn validation_join_error_delivers_terminal_failure_on_reply() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::ValidateProfiles);
        let (reply, result) = tokio::sync::oneshot::channel();
        runtime
            .jobs
            .set_exclusive_sidecar(ExclusiveSidecar::ProfileReply(reply));
        let task = tokio::spawn(async {
            panic!("validation worker panic");
        });
        let error = task.await.expect_err("worker panic must become JoinError");

        runtime.complete_exclusive_join_error(JobKind::ValidateProfiles, error);
        flush_bookends(&mut runtime);

        let verdict = result
            .await
            .expect("the join-error terminal must be delivered");
        let message = verdict.expect_err("a panicking worker never reports a verdict");
        assert!(
            message
                .text(Language::En)
                .starts_with(background_failed_sentence()),
            "the join-error terminal must carry the failure text, got {message:?}"
        );
        assert_eq!(runtime.jobs.busy_kind(), None);
        assert_released_once(&mut runtime, &events);
    }

    /// Shutdown waits for an in-flight validation's own terminal: the runtime
    /// keeps its select loop alive until the worker (which owns an open
    /// scratch config through its child) reports, so the reply is delivered
    /// rather than dropped by a torn-down runtime.
    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_waits_for_the_validation_terminal_before_teardown() {
        let (command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (event_sender, event_receiver) =
            std::sync::mpsc::sync_channel(super::EVT_CHANNEL_CAPACITY);
        let mut runtime = Runtime::new(
            command_receiver,
            event_sender,
            egui::Context::default(),
            crate::metrics::MetricsHandle::new(),
        );
        runtime
            .jobs
            .try_begin(JobKind::ValidateProfiles)
            .expect("begin the validation job");
        let (reply, result) = tokio::sync::oneshot::channel();
        runtime
            .jobs
            .set_exclusive_sidecar(ExclusiveSidecar::ProfileReply(reply));
        let cancel = runtime
            .jobs
            .exclusive_cancel_flag()
            .expect("the begun record still occupies");
        runtime.jobs.attach_exclusive_task(tokio::spawn(async move {
            // A worker past its validation child: it ends only on the
            // cooperative cancel, exactly like a real run observing the flag
            // at its next profile boundary.
            while !cancel.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            ExclusiveOutcome::ProfileValidation(Err(crate::rt::profiles::validation_cancelled()))
        }));
        let run = tokio::spawn(runtime.run());

        command_sender
            .send(CoreCmd::Shutdown)
            .expect("send Shutdown");
        // The handle's drop closes the channel right after the command, like
        // the real runtime teardown.
        drop(command_sender);

        let verdict = tokio::time::timeout(Duration::from_secs(5), result)
            .await
            .expect("the shutdown wait must end with the worker's terminal")
            .expect("the runtime must deliver the terminal, not drop the channel");
        assert_eq!(
            verdict.as_ref().err().map(|error| error.text(Language::En)),
            Some(crate::rt::profiles::validation_cancelled().text(Language::En)),
            "the worker's own terminal must be the one delivered"
        );
        tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("the runtime must finish tearing down after the terminal")
            .expect("runtime run() must complete cleanly");
        let emitted: Vec<_> = event_receiver.try_iter().collect();
        assert_eq!(
            emitted
                .iter()
                .filter(|event| matches!(event, CoreEvt::Operation(None)))
                .count(),
            1,
            "the terminal releases the window exactly once before teardown"
        );
    }

    /// The terminal under test released the busy window exactly once.
    fn assert_released_once(runtime: &mut Runtime, events: &std::sync::mpsc::Receiver<CoreEvt>) {
        flush_bookends(runtime);
        let emitted: Vec<_> = events.try_iter().collect();
        assert_eq!(
            emitted
                .iter()
                .filter(|event| matches!(event, CoreEvt::Operation(None)))
                .count(),
            1,
            "one terminal releases one busy window"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unexpected_exit_cancels_inflight_apply_with_terminal_result() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::ApplyConfig);
        park_pending_task(&mut runtime);

        runtime.on_core_exit(None).await;

        assert!(
            runtime.jobs.busy_kind().is_none(),
            "exit must clear the foreign in-flight apply"
        );
        assert!(
            runtime.pending_restart.is_some(),
            "backoff restart must still be scheduled"
        );
        flush_bookends(&mut runtime);
        let emitted: Vec<_> = events.try_iter().collect();
        let apply_results: Vec<_> = emitted
            .iter()
            .filter_map(|event| match event {
                CoreEvt::ApplyResult { ok, output } => Some((ok, output)),
                _ => None,
            })
            .collect();
        assert_eq!(
            apply_results.len(),
            1,
            "one apply result settles one GUI revision"
        );
        assert!(!apply_results[0].0);
        assert!(
            apply_results[0]
                .1
                .text(Language::En)
                .contains(t(Language::En, Key::RtReasonCoreExitedUnexpectedly)),
            "terminal apply result must mention the reason, got: {}",
            apply_results[0].1.text(Language::En)
        );
        assert_eq!(
            emitted
                .iter()
                .filter(|event| matches!(event, CoreEvt::Operation(None)))
                .count(),
            1,
            "exit cancellation releases the busy slot exactly once"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unexpected_exit_cancels_inflight_test_with_terminal_result() {
        // The test verdict travels the request's own reply
        // channel; an unexpected core exit must settle it there, exactly
        // once, instead of an event. APPDATA is
        // redirected so the test command's candidate write stays in the
        // temp root (same seam as the rollback tests).
        let (runtime, events) = with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            let (reply, result) = tokio::sync::oneshot::channel();
            runtime
                .handle_cmd(CoreCmd::TestConfig {
                    config: serde_json::json!({ "log": { "loglevel": "info" } }),
                    reply,
                })
                .await;
            assert_eq!(
                runtime.jobs.busy_kind(),
                Some(JobKind::TestConfig),
                "the accepted test must occupy the busy window"
            );

            runtime.on_core_exit(None).await;

            assert!(runtime.jobs.busy_kind().is_none());
            match result.await {
                Ok(Err(error)) => assert_eq!(
                    error.text(Language::En),
                    test_cancelled_text(Key::RtReasonCoreExitedUnexpectedly),
                    "terminal must name the exit reason"
                ),
                other => panic!("expected a cancellation terminal, got {other:?}"),
            }
            flush_bookends(&mut runtime);
            assert_eq!(
                events
                    .try_iter()
                    .filter(|event| matches!(event, CoreEvt::Operation(None)))
                    .count(),
                1,
                "exit cancellation releases the busy slot exactly once"
            );
            (runtime, events)
        })
        .await;
        let _ = (runtime, events);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unexpected_exit_cancels_inflight_latency_probe_with_terminal_result() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::LatencyProbe);
        runtime
            .jobs
            .set_exclusive_sidecar(ExclusiveSidecar::LatencyTags(vec!["srv-probe".into()]));
        park_pending_task(&mut runtime);

        runtime.on_core_exit(None).await;

        assert!(
            runtime.jobs.busy_kind().is_none(),
            "exit must clear the foreign in-flight probe"
        );
        flush_bookends(&mut runtime);
        let emitted: Vec<_> = events.try_iter().collect();
        let results: Vec<_> = emitted
            .iter()
            .filter_map(|event| match event {
                CoreEvt::LatencyProbe(result) => Some(result),
                _ => None,
            })
            .collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tags, ["srv-probe"]);
        assert!(matches!(
            &results[0].result,
            Err(error)
                if error
                    .headline
                    .text(Language::En)
                    .contains(t(Language::En, Key::RtReasonCoreExitedUnexpectedly))
        ));
        assert_eq!(
            emitted
                .iter()
                .filter(|event| matches!(event, CoreEvt::Operation(None)))
                .count(),
            1,
            "exit cancellation releases the busy slot exactly once"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unexpected_exit_preserves_lifecycle_busy_owner() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::Restart);

        runtime.on_core_exit(None).await;

        assert_eq!(
            runtime.jobs.busy_kind(),
            Some(JobKind::Restart),
            "task-less lifecycle spans stay owned by the exit/readiness path"
        );
        let emitted: Vec<_> = events.try_iter().collect();
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::Operation(None)))
        );
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::ApplyResult { .. }))
        );
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::LatencyProbe(_)))
        );
    }

    /// A silenced exit (the readiness-timeout error path already reported the
    /// phase) must finish the exit policy and release the operation without
    /// emitting a second record.
    #[tokio::test(flavor = "current_thread")]
    async fn silenced_exit_releases_without_reporting_again() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::Restart);
        let reported = Diag::new(Key::RtPhaseRestartCancelled);
        runtime.phase = super::CorePhase::Error(PhaseError::new(reported.clone()));
        runtime.exit_policy.begin_silenced_stop(Instant::now());

        runtime.on_core_exit(None).await;

        assert!(!runtime.exit_policy.stopping());
        assert!(
            runtime.jobs.busy_kind().is_none(),
            "the silenced exit owns the operation release"
        );
        assert!(
            matches!(
                &runtime.phase,
                super::CorePhase::Error(error) if *phase_message(error) == reported
            ),
            "the reported phase payload stays the one record"
        );
        let emitted: Vec<_> = events.try_iter().collect();
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::State(_))),
            "a silenced exit must not emit a second phase record"
        );
    }

    /// A requested restart queues the replacement only once the old child's
    /// exit is confirmed, and the busy owner stays held for that replacement.
    #[tokio::test(flavor = "current_thread")]
    async fn restart_queues_replacement_after_confirmed_exit() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::Restart);
        runtime.exit_policy.begin_restart(Instant::now());

        runtime.on_core_exit(None).await;

        assert!(!runtime.exit_policy.stopping());
        assert!(
            runtime.pending_restart.is_some(),
            "the confirmed exit queues the replacement"
        );
        assert_eq!(
            runtime.jobs.busy_kind(),
            Some(JobKind::Restart),
            "the replacement rides the held owner"
        );
        let emitted: Vec<_> = events.try_iter().collect();
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::Operation(None))),
            "a restart must not release the operation before the exit is handled"
        );
    }

    /// A plain stop settles into Stopped once the child's exit is confirmed
    /// and releases the lifecycle operation without scheduling a restart.
    #[tokio::test(flavor = "current_thread")]
    async fn plain_stop_settles_stopped_after_confirmed_exit() {
        let (mut runtime, _events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::Stop);
        runtime.exit_policy.begin_stop(Instant::now());

        runtime.on_core_exit(None).await;

        assert!(!runtime.exit_policy.stopping());
        assert!(matches!(runtime.phase, super::CorePhase::Stopped));
        assert!(runtime.jobs.busy_kind().is_none());
        assert!(
            runtime.pending_restart.is_none(),
            "a plain stop never restarts"
        );
    }

    /// A plain start that misses its readiness deadline (no candidate owns
    /// it) reports exactly one Error record and silences the exit path.
    #[tokio::test(flavor = "current_thread")]
    async fn plain_readiness_timeout_reports_one_error_and_silences_the_exit() {
        let (mut runtime, events) = runtime_with_events();
        runtime.backend = BackendState::for_test(true, false);
        runtime.phase = super::CorePhase::Starting;
        runtime.readiness_deadline = Some(Instant::now() - Duration::from_millis(1));

        runtime.ready_poll().await;

        assert!(runtime.exit_policy.stopping());
        assert!(
            matches!(
                &runtime.phase,
                super::CorePhase::Error(error)
                    if phase_message(error).key() == Key::RtPhaseReadinessTimeout
            ),
            "the timeout must report its keyed terminal record, got {:?}",
            runtime.phase
        );
        let emitted: Vec<_> = events.try_iter().collect();
        assert_eq!(
            emitted
                .iter()
                .filter(|event| matches!(event, CoreEvt::State(_)))
                .count(),
            1,
            "the timeout must report exactly one phase record"
        );

        // The child's confirmed exit is silenced: the phase payload remains
        // the one record and the exit policy finishes.
        runtime.on_core_exit(None).await;
        assert!(!runtime.exit_policy.stopping());
        assert!(matches!(runtime.phase, super::CorePhase::Error(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tun_candidate_retries_once_before_rollback() {
        // A candidate that died pre-readiness without a recognizable
        // signature (this test captures no output at all) still gets the
        // single retry past the adapter teardown window; only the dns-in
        // bind race draws on a larger budget.
        let (mut runtime, events) = runtime_with_events();
        runtime.backend = BackendState::for_test(false, true);
        runtime.pending_transition.commit_candidate();

        runtime.on_core_exit(Some(-1)).await;

        assert!(
            runtime.pending_transition.is_candidate_pending(),
            "the retry must keep the candidate armed"
        );
        assert!(
            runtime.pending_transition.rollback_pending().is_none(),
            "the first failure must not arm a rollback"
        );
        assert_eq!(runtime.candidate_boot_retries, 1, "retry budget spent");
        let retry_at = runtime.pending_restart.expect("retry must be scheduled");
        assert!(
            retry_at > Instant::now(),
            "the retry must wait out the teardown window"
        );
        let emitted: Vec<_> = events.try_iter().collect();
        assert!(
            app_log_texts(&emitted)
                .iter()
                .any(|text| text.contains(&retry_suffix(
                    Key::RtFrameCandidateRetryTeardownRace,
                    1,
                    1
                ))),
            "the retry decision must be logged"
        );
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::RollbackResult { .. })),
            "no rollback may be attempted on the first failure"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tun_candidate_second_failure_rolls_back() {
        // Once the retry budget is spent, a second pre-readiness exit must
        // roll back exactly as before the retry was introduced. APPDATA is
        // redirected to a temp dir so the rollback path can never touch the
        // real config directory; with no last-good there it fails closed.
        let (runtime, events) = with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            runtime.backend = BackendState::for_test(false, true);
            runtime.pending_transition.commit_candidate();
            runtime.candidate_boot_retries = 1; // budget spent by the first exit

            runtime.on_core_exit(Some(-1)).await;

            assert!(
                !runtime.pending_transition.is_candidate_pending(),
                "the second failure must arm the rollback (candidate cleared)"
            );
            assert!(
                runtime.pending_transition.rollback_pending().is_none(),
                "the rollback must be consumed by the completion path"
            );
            assert_eq!(runtime.candidate_boot_retries, 1);
            assert!(
                matches!(runtime.phase, super::CorePhase::Stopped),
                "rollback without a last-good in the temp dir must fail closed"
            );
            let emitted: Vec<_> = events.try_iter().collect();
            let rollbacks: Vec<_> = emitted
                .iter()
                .filter_map(|event| match event {
                    CoreEvt::RollbackResult { ok, output } => Some((ok, output)),
                    _ => None,
                })
                .collect();
            assert_eq!(rollbacks.len(), 1, "exactly one rollback verdict");
            assert!(!rollbacks[0].0);
            assert!(
                rollbacks[0]
                    .1
                    .text(Language::En)
                    .contains(frame_suffix(Key::RtFrameRollbackFailed)),
                "the verdict must explain the failed rollback, got: {}",
                rollbacks[0].1
            );
            (runtime, events)
        })
        .await;
        let _ = (runtime, events);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tun_bind_race_exit_gets_its_own_retry_budget() {
        // The dns-in bind race is a fresh Go-map-order roll in every
        // process, so the candidate draws on `TUN_BIND_RACE_RETRIES` attempts
        // instead of the single teardown retry — this is what keeps a
        // ~1/8-per-roll race off the user-visible surface.
        let (mut runtime, events) = runtime_with_events();
        runtime.backend = BackendState::for_test(false, true);
        runtime.pending_transition.commit_candidate();
        runtime.push_ring(DNS_IN_BIND_RACE_LINE);

        runtime.on_core_exit(Some(-1)).await;

        assert!(runtime.pending_transition.is_candidate_pending());
        assert!(runtime.pending_transition.rollback_pending().is_none());
        assert_eq!(runtime.candidate_boot_retries, 1);
        let emitted: Vec<_> = events.try_iter().collect();
        assert!(
            app_log_texts(&emitted)
                .iter()
                .any(|text| text.contains(&retry_suffix(
                    Key::RtFrameCandidateRetryBindRace,
                    1,
                    TUN_BIND_RACE_RETRIES
                ))),
            "the race retry must be logged with its budget"
        );

        for expected in 2..=TUN_BIND_RACE_RETRIES {
            // Each retry restarts through the helper, which re-establishes
            // TUN ownership before the child can exit.
            runtime.backend = BackendState::for_test(true, true);
            runtime.on_core_exit(Some(-1)).await;
            assert_eq!(
                runtime.candidate_boot_retries, expected,
                "every race exit inside the budget must retry"
            );
            assert!(runtime.pending_transition.is_candidate_pending());
            assert!(runtime.pending_transition.rollback_pending().is_none());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tun_bind_race_budget_exhaustion_rolls_back() {
        // Past the race budget the failure stops being treated as transient
        // and the rollback path runs exactly as for any other pre-readiness
        // exit. APPDATA is redirected so the rollback cannot touch the real
        // config directory; with no last-good there it fails closed.
        let (runtime, events) = with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            runtime.backend = BackendState::for_test(false, true);
            runtime.pending_transition.commit_candidate();
            runtime.candidate_boot_retries = TUN_BIND_RACE_RETRIES;
            runtime.push_ring(DNS_IN_BIND_RACE_LINE);

            runtime.on_core_exit(Some(-1)).await;

            assert_eq!(runtime.candidate_boot_retries, TUN_BIND_RACE_RETRIES);
            assert!(
                !runtime.pending_transition.is_candidate_pending(),
                "an exhausted race budget must arm the rollback"
            );
            let rollbacks: Vec<_> = events
                .try_iter()
                .filter_map(|event| match event {
                    CoreEvt::RollbackResult { ok, output } => Some((ok, output)),
                    _ => None,
                })
                .collect();
            assert_eq!(rollbacks.len(), 1, "exactly one rollback verdict");
            assert!(!rollbacks[0].0);
            assert!(
                rollbacks[0]
                    .1
                    .text(Language::En)
                    .contains(frame_suffix(Key::RtFrameRollbackFailed)),
                "the verdict must explain the failed rollback, got: {}",
                rollbacks[0].1
            );
            (runtime, events)
        })
        .await;
        let _ = (runtime, events);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn core_update_dns_in_bind_race_retries_before_rolling_back() {
        // The same Go-map-order race can kill an updated core's health-gate
        // start while TUN is on; a fresh attempt re-rolls the order, so the
        // update draws on the race budget instead of spuriously rolling a
        // healthy update back.
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::UpdateCore);
        runtime.core_update.commit_candidate();
        runtime.phase = super::CorePhase::Starting;
        runtime.backend = BackendState::for_test(false, true);
        runtime.push_ring(DNS_IN_BIND_RACE_LINE);

        runtime.on_core_exit(Some(-1)).await;

        assert!(
            runtime.core_update.is_candidate_pending(),
            "the retry must keep the update candidate armed"
        );
        assert!(
            runtime.core_update.rollback_pending().is_none(),
            "no rollback may be armed on a race retry"
        );
        assert!(
            runtime.pending_restart.is_some(),
            "the retry must reschedule the candidate boot"
        );
        assert_eq!(
            runtime.jobs.busy_kind(),
            Some(JobKind::UpdateCore),
            "the update operation must stay busy across the retry"
        );
        let emitted: Vec<_> = events.try_iter().collect();
        assert!(
            app_log_texts(&emitted)
                .iter()
                .any(|text| text.contains(&retry_suffix(
                    Key::RtFrameUpdateRetryBindRace,
                    1,
                    TUN_BIND_RACE_RETRIES
                ))),
            "the update retry decision must be logged with its budget"
        );
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::Download(super::DownloadState::Failed(_)))),
            "no rollback verdict may be emitted on a race retry"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn core_update_direct_mode_race_line_still_rolls_back() {
        // The retry is TUN-gated like the apply path's: outside a TUN boot the
        // same listener text can only come from a user-configured inbound on
        // port 53, where retrying merely delays the correct rollback. APPDATA
        // is redirected so the restore cannot touch the real core directory.
        with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            occupy_exclusive(&mut runtime, JobKind::UpdateCore);
            runtime.core_update.commit_candidate();
            runtime.phase = super::CorePhase::Starting;
            runtime.backend = BackendState::for_test(false, false);
            runtime.push_ring(DNS_IN_BIND_RACE_LINE);

            runtime.on_core_exit(Some(-1)).await;

            assert!(
                !runtime.core_update.is_candidate_pending(),
                "a direct-mode candidate must roll straight back"
            );
            assert!(
                events.try_iter().any(|event| matches!(
                    event,
                    CoreEvt::Download(super::DownloadState::Failed(_))
                )),
                "the rollback must emit its verdict"
            );
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn core_update_race_budget_exhaustion_rolls_back() {
        // Past the budget the update candidate is rolled back exactly as any
        // other pre-readiness failure. APPDATA is redirected so the restore
        // cannot touch the real core directory; with no retained last-good
        // there it reports the failure and stops.
        with_appdata_async(async {
            let (mut runtime, events) = runtime_with_events();
            occupy_exclusive(&mut runtime, JobKind::UpdateCore);
            runtime.core_update.commit_candidate();
            runtime.phase = super::CorePhase::Starting;
            runtime.backend = BackendState::for_test(false, true);
            runtime.push_ring(DNS_IN_BIND_RACE_LINE);
            for expected in 1..=TUN_BIND_RACE_RETRIES {
                assert_eq!(
                    runtime.core_update.spend_bind_race_retry(),
                    Some(expected),
                    "every attempt inside the budget must be granted"
                );
            }
            assert_eq!(
                runtime.core_update.spend_bind_race_retry(),
                None,
                "the budget must stay capped"
            );

            runtime.on_core_exit(Some(-1)).await;

            assert!(
                !runtime.core_update.is_candidate_pending(),
                "an exhausted race budget must arm the update rollback"
            );
            assert!(
                runtime.jobs.busy_kind().is_none(),
                "the terminal verdict must release the update slot"
            );
            let failures: Vec<_> = events
                .try_iter()
                .filter_map(|event| match event {
                    CoreEvt::Download(super::DownloadState::Failed(output)) => Some(output),
                    _ => None,
                })
                .collect();
            assert_eq!(failures.len(), 1, "exactly one update verdict");
            assert!(
                failures[0].text(Language::En).contains(
                    t(Language::En, Key::RtFrameUpdatedCoreExited)
                        .split_once("(code")
                        .unwrap()
                        .0
                        .trim_end()
                ),
                "the verdict must carry the exit, got: {}",
                failures[0]
            );

            // A fresh install arms a new transaction with a full budget.
            runtime.core_update.commit_candidate();
            assert_eq!(
                runtime.core_update.spend_bind_race_retry(),
                Some(1),
                "a new install must start with a fresh race budget"
            );
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn candidate_retry_budget_resets_on_readiness() {
        let mut runtime = runtime();
        runtime.pending_transition.commit_candidate();
        runtime.candidate_boot_retries = 1;

        runtime.complete_readiness_probe(true).await;

        assert_eq!(
            runtime.candidate_boot_retries, 0,
            "first readiness must restore the retry budget for the next apply"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dns_in_listener_add_spends_its_budget_then_gives_up() {
        // Every attempt fails against a dead API port — the same failure
        // shape a still-coming-up wintun adapter produces — so this drives
        // the retry budget, the quiet in-budget attempts, and the give-up
        // record.
        let dead_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ephemeral port");
            listener.local_addr().expect("local addr").port()
        };
        let (mut runtime, events) = runtime_with_events();
        runtime.grpc = crate::rt::grpc::GrpcClient::new(dead_port);
        runtime.phase = super::CorePhase::Running;
        runtime.dns_in_listener = Some(super::dns_in::Listener {
            address: std::net::Ipv4Addr::new(10, 255, 0, 1),
        });

        for _ in 0..DNS_IN_ADD_ATTEMPTS {
            runtime.dns_in_poll().await;
        }
        assert_eq!(
            runtime.dns_in_attempts, DNS_IN_ADD_ATTEMPTS,
            "every attempt inside the budget must be spent"
        );
        assert!(
            runtime.dns_in_listener.is_some(),
            "inside the budget the listener stays pending for the retry arm"
        );
        assert!(
            !app_log_texts(&events.try_iter().collect::<Vec<_>>())
                .iter()
                .any(|text| text.contains(frame_prefix(Key::RtLogDnsInListenerNotAdded))),
            "in-budget attempts stay quiet — a retry is expected while the adapter comes up"
        );

        runtime.dns_in_poll().await;
        assert!(
            runtime.dns_in_listener.is_none(),
            "a spent budget clears the pending listener"
        );
        let emitted: Vec<_> = events.try_iter().collect();
        assert!(
            app_log_texts(&emitted)
                .iter()
                .any(|text| text.contains(frame_prefix(Key::RtLogDnsInListenerNotAdded))),
            "the give-up must leave one record"
        );

        runtime.dns_in_poll().await;
        assert_eq!(
            runtime.dns_in_attempts, DNS_IN_ADD_ATTEMPTS,
            "with nothing pending the poll must be a no-op"
        );
    }

    fn vless_profile(name: &str, address: &str, port: u16) -> ServerProfile {
        let mut profile = ServerProfile::new(name, OutboundModel::new(Protocol::Vless));
        let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
            unreachable!("Vless is the default protocol");
        };
        settings.address = address.into();
        settings.port = port;
        profile
    }

    fn log_lines(events: &[CoreEvt]) -> Vec<&str> {
        events
            .iter()
            .filter_map(|event| match event {
                CoreEvt::Log { line, .. } => Some(line.as_str()),
                _ => None,
            })
            .collect()
    }

    /// The runtime-authored messages the events carry, rendered in English
    /// the way the app's drain renders them.
    fn app_log_texts(events: &[CoreEvt]) -> Vec<String> {
        events
            .iter()
            .filter_map(|event| match event {
                CoreEvt::AppLog(message) => Some(message.text(Language::En)),
                _ => None,
            })
            .collect()
    }

    /// The sentence half of the join-error terminal, taken from the key so the
    /// tests never re-pin the wording: the terminal text is this sentence
    /// followed by the worker's `JoinError`.
    fn background_failed_sentence() -> &'static str {
        t(Language::En, Key::RtFrameBackgroundFailed)
            .split_once("{}")
            .expect("the join-error sentence carries one placeholder")
            .0
    }

    /// The busy-window rejection for `kind`, rendered like the reply
    /// channels do.
    fn busy_reject_text(kind: JobKind) -> String {
        Diag::new(Key::RtFrameCommandRejectedBusy)
            .arg_message(super::seat::operation_name(kind))
            .text(Language::En)
    }

    /// The rejection delivered on a request's own reply channel, rendered for
    /// comparison.
    fn reply_reject_text<T: std::fmt::Debug>(
        result: Result<Result<T, crate::diag::DiagError>, tokio::sync::oneshot::error::RecvError>,
    ) -> String {
        result
            .expect("the reply channel stays open")
            .expect_err("the request must be rejected")
            .text(Language::En)
    }

    /// The apply-cancel terminal for `reason`, rendered like the event does.
    fn apply_cancelled_text(reason: Key) -> String {
        Diag::new(Key::RtFrameApplyCancelled)
            .arg_message(Diag::new(reason))
            .text(Language::En)
    }

    /// The config-test-cancel terminal for `reason`, rendered like the reply
    /// channel does.
    fn test_cancelled_text(reason: Key) -> String {
        Diag::new(Key::RtFrameConfigTestCancelled)
            .arg_message(Diag::new(reason))
            .text(Language::En)
    }

    /// The part of a `{}`-leading frame after its message slot, taken from the
    /// key so the tests never re-pin the wording.
    fn frame_suffix(key: Key) -> &'static str {
        t(Language::En, key)
            .split_once("{}")
            .expect("the frame leads with a message slot")
            .1
            .trim_start()
    }

    /// The sentence before a frame's first `{}` slot, taken from the key so
    /// the tests never re-pin the wording.
    fn frame_prefix(key: Key) -> &'static str {
        t(Language::En, key)
            .split_once("{}")
            .expect("the frame carries a message slot")
            .0
            .trim_end()
    }

    /// The retry sentence of `key` for one attempt, taken from the key.
    fn retry_suffix(key: Key, attempt: u8, budget: u8) -> String {
        frame_suffix(key)
            .replacen("{}", &attempt.to_string(), 1)
            .replacen("{}", &budget.to_string(), 1)
    }

    /// The keyed sentence of a phase failure (tests assert on keys, never on
    /// rendered text).
    fn phase_message(error: &PhaseError) -> &Diag {
        match &error.message {
            super::AppMessage::Message(message) => message,
            super::AppMessage::Error(_) => panic!("a keyed phase failure was expected"),
        }
    }

    /// A rollback reason fixture carrying the candidate-timeout sentence.
    fn rollback_reason() -> Diag {
        Diag::new(Key::RtFrameCandidateReadyTimeout).arg(1)
    }

    /// The busy rejection names the occupying operation through its shared
    /// key for every kind that can occupy the window, and the nested name
    /// renders in the frame's own language.
    #[test]
    fn busy_rejection_names_every_occupying_kind() {
        let occupying = [
            JobKind::Start,
            JobKind::Stop,
            JobKind::Restart,
            JobKind::ApplyConfig,
            JobKind::TestConfig,
            JobKind::UpdateCore,
            JobKind::LatencyProbe,
            JobKind::ValidateProfiles,
        ];
        for kind in occupying {
            let frame = Runtime::busy_reject_text(kind);
            assert_eq!(frame.key(), Key::RtFrameCommandRejectedBusy);
            let rendered = frame.text(Language::En);
            let name = super::seat::operation_name(kind).text(Language::En);
            assert!(
                rendered.contains(&name),
                "the busy frame must name the operation, got: {rendered}"
            );
            assert!(
                !rendered.contains(&format!("{kind:?}")),
                "the busy frame must never fall back to the Rust identifier: {rendered}"
            );
        }
    }

    /// A decoded helper record splits by shape: a keyed record lands as a
    /// runtime message the app renders at the drain, an unknown shape stays a
    /// raw passthrough line.
    #[tokio::test(flavor = "current_thread")]
    async fn helper_records_route_by_shape() {
        let (mut runtime, events) = runtime_with_events();
        runtime.emit_helper_log(super::helper::HelperLog::Message(DiagError::from(
            Diag::new(Key::RtLogHelperDisconnected),
        )));
        runtime.emit_helper_log(super::helper::HelperLog::Raw("helper: raw tail".into()));

        let emitted: Vec<_> = events.try_iter().collect();
        assert_eq!(
            app_log_texts(&emitted),
            vec![t(Language::En, Key::RtLogHelperDisconnected).to_string()],
            "a keyed helper record must land as a runtime message"
        );
        assert_eq!(
            log_lines(&emitted),
            vec!["helper: raw tail"],
            "an unknown helper shape must stay a raw passthrough line"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn latency_probe_failure_is_logged_with_full_diagnostics() {
        let (mut runtime, events) = runtime_with_events();
        let failure = ProbeFailure {
            headline: Diag::new(Key::ProbeExitStatus).arg(1),
            tail: "[stderr] boom".into(),
        };
        let expected = failure.full(Language::En);
        runtime
            .complete_exclusive(ExclusiveOutcome::LatencyProbe {
                tags: vec!["srv-a".into()],
                profiles: vec![],
                result: Err(failure),
            })
            .await;

        let emitted: Vec<_> = events.try_iter().collect();
        let lines = log_lines(&emitted);
        assert!(
            lines
                .iter()
                .any(|line| *line == format!("[broccoli] {expected}")),
            "the failure must reach the log through the [broccoli] path with its tail, got: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("[stderr] boom")),
            "the diagnostics tail must ride along in the log"
        );
        assert!(
            emitted.iter().any(|event| matches!(
                event,
                CoreEvt::LatencyProbe(result)
                    if result.tags == ["srv-a"]
                        && matches!(&result.result, Err(failure)
                            if failure.headline.key() == Key::ProbeExitStatus
                                && failure.tail == "[stderr] boom")
            )),
            "the emitted failure must carry the keyed headline and the captured tail"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn latency_probe_busy_reject_is_logged() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::LatencyProbe);

        runtime
            .handle_cmd(CoreCmd::ProbeLatency {
                profiles: vec![],
                probe_url: "https://example.com/generate_204".into(),
                tun_outbound_interface: None,
                tun_adapter_name: None,
            })
            .await;

        let emitted: Vec<_> = events.try_iter().collect();
        let expected = busy_reject_text(JobKind::LatencyProbe);
        assert!(
            app_log_texts(&emitted).contains(&expected),
            "the busy rejection must reach the log as a keyed app message, got: {emitted:?}"
        );
        assert!(
            emitted.iter().any(|event| matches!(
                event,
                CoreEvt::LatencyProbe(result)
                    if result.tags.is_empty()
                        && matches!(&result.result, Err(failure)
                            if failure.headline.key() == Key::RtFrameCommandRejectedBusy)
            )),
            "the busy rejection must still reach the UI as a terminal result"
        );
        assert!(
            !emitted
                .iter()
                .any(|event| matches!(event, CoreEvt::Operation(None))),
            "the reject must not release the occupying probe owner"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn latency_probe_no_profiles_reject_is_logged() {
        let (mut runtime, events) = runtime_with_events();
        runtime
            .handle_cmd(CoreCmd::ProbeLatency {
                profiles: vec![],
                probe_url: "https://example.com/generate_204".into(),
                tun_outbound_interface: None,
                tun_adapter_name: None,
            })
            .await;

        flush_bookends(&mut runtime);
        let emitted: Vec<_> = events.try_iter().collect();
        let expected = format!("[broccoli] {}", t(Language::En, Key::ProbeNoProfiles));
        assert!(
            log_lines(&emitted).iter().any(|line| *line == expected),
            "the no-profiles rejection must reach the log through the [broccoli] path, got: {emitted:?}"
        );
        assert!(
            emitted.iter().any(|event| matches!(
                event,
                CoreEvt::LatencyProbe(result)
                    if result.tags.is_empty()
                        && matches!(&result.result, Err(failure)
                            if failure.headline.key() == Key::ProbeNoProfiles)
            )),
            "the no-profiles rejection must still reach the UI as a terminal result"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn latency_probe_dead_rows_log_warn_line_with_verdicts() {
        let (mut runtime, events) = runtime_with_events();
        let tokyo = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let osaka = vless_profile("Osaka", "10.0.0.2", 443);
        let statuses = vec![
            OutboundStatusView {
                health_ping: None,
                tag: tokyo.tag(),
                alive: true,
                delay_ms: 10,
                last_error: None,
                diagnostics: None,
            },
            OutboundStatusView {
                health_ping: None,
                tag: osaka.tag(),
                alive: false,
                delay_ms: 0,
                last_error: Some("connection refused".into()),
                diagnostics: None,
            },
        ];
        let expected = crate::probe_verdict::warn_summary(
            Language::En,
            &[tokyo.clone(), osaka.clone()],
            &statuses,
        );
        runtime
            .complete_exclusive(ExclusiveOutcome::LatencyProbe {
                tags: vec![tokyo.tag(), osaka.tag()],
                profiles: vec![tokyo.clone(), osaka.clone()],
                result: Ok(statuses),
            })
            .await;

        let emitted: Vec<_> = events.try_iter().collect();
        let lines = log_lines(&emitted);
        assert!(
            lines
                .iter()
                .any(|line| *line == format!("[broccoli] {expected}")),
            "the warn line must name the dead server's verdict, got: {lines:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dead_rows_with_diagnostics_log_the_wall_after_the_verdicts() {
        let (mut runtime, events) = runtime_with_events();
        let tokyo = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let osaka = vless_profile("Osaka", "10.0.0.2", 443);
        let statuses = vec![
            OutboundStatusView {
                health_ping: None,
                tag: tokyo.tag(),
                alive: false,
                delay_ms: 0,
                last_error: Some("connection refused".into()),
                // One probe run is one child: both dead rows carry
                // the run's shared tail (as the completion path
                // stamps them).
                diagnostics: Some("[stderr] tls handshake failed".into()),
            },
            OutboundStatusView {
                health_ping: None,
                tag: osaka.tag(),
                alive: false,
                delay_ms: 0,
                last_error: Some("timeout".into()),
                diagnostics: Some("[stderr] tls handshake failed".into()),
            },
        ];
        let expected = crate::probe_verdict::warn_summary(
            Language::En,
            &[tokyo.clone(), osaka.clone()],
            &statuses,
        );
        runtime
            .complete_exclusive(ExclusiveOutcome::LatencyProbe {
                tags: vec![tokyo.tag(), osaka.tag()],
                profiles: vec![tokyo.clone(), osaka.clone()],
                result: Ok(statuses),
            })
            .await;

        let emitted: Vec<_> = events.try_iter().collect();
        let lines = log_lines(&emitted);
        assert!(
            expected.ends_with(&format!(
                "\n{}\n[stderr] tls handshake failed",
                t(Language::En, Key::ProbeDiagnosticsWall)
            )) && expected
                .matches(t(Language::En, Key::ProbeDiagnosticsWall))
                .count()
                == 1,
            "premise: the summary appends the wall exactly once, got: {expected}"
        );
        assert!(
            lines
                .iter()
                .any(|line| *line == format!("[broccoli] {expected}")),
            "the warn line must append the run's diagnostics wall once, got: {lines:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dead_rows_without_diagnostics_log_no_wall() {
        // Rows without a tail (output-less runs, live observatory rows)
        // degrade to the headline-only warn line.
        let (mut runtime, events) = runtime_with_events();
        let tokyo = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let statuses = vec![OutboundStatusView {
            health_ping: None,
            tag: tokyo.tag(),
            alive: false,
            delay_ms: 0,
            last_error: Some("connection refused".into()),
            diagnostics: None,
        }];
        let expected = crate::probe_verdict::warn_summary(
            Language::En,
            std::slice::from_ref(&tokyo),
            &statuses,
        );
        runtime
            .complete_exclusive(ExclusiveOutcome::LatencyProbe {
                tags: vec![tokyo.tag()],
                profiles: vec![tokyo.clone()],
                result: Ok(statuses),
            })
            .await;

        let emitted: Vec<_> = events.try_iter().collect();
        let lines = log_lines(&emitted);
        assert!(
            lines
                .iter()
                .any(|line| *line == format!("[broccoli] {expected}")),
            "the warn line must name the dead server's verdict, got: {lines:?}"
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.contains(t(Language::En, Key::ProbeDiagnosticsWall))),
            "a run without captured diagnostics must not fabricate a wall"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn single_probe_dead_verdict_logs_warn_line() {
        let (mut runtime, events) = runtime_with_events();
        let tokyo = vless_profile("Tokyo edge", "1.2.3.4", 443);
        let statuses = vec![OutboundStatusView {
            health_ping: None,
            tag: tokyo.tag(),
            alive: false,
            delay_ms: 0,
            last_error: Some("connection refused".into()),
            diagnostics: None,
        }];
        let expected = crate::probe_verdict::warn_summary(
            Language::En,
            std::slice::from_ref(&tokyo),
            &statuses,
        );
        runtime
            .complete_exclusive(ExclusiveOutcome::LatencyProbe {
                tags: vec![tokyo.tag()],
                profiles: vec![tokyo.clone()],
                result: Ok(statuses),
            })
            .await;

        let emitted: Vec<_> = events.try_iter().collect();
        let lines = log_lines(&emitted);
        assert!(
            lines
                .iter()
                .any(|line| *line == format!("[broccoli] {expected}")),
            "a single-probe dead verdict must log the same warn line shape, got: {lines:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn latency_probe_full_success_logs_nothing() {
        let (mut runtime, events) = runtime_with_events();
        let tokyo = vless_profile("Tokyo edge", "1.2.3.4", 443);
        runtime
            .complete_exclusive(ExclusiveOutcome::LatencyProbe {
                tags: vec![tokyo.tag()],
                profiles: vec![tokyo],
                result: Ok(vec![OutboundStatusView {
                    health_ping: None,
                    tag: "srv-x".into(),
                    alive: true,
                    delay_ms: 23,
                    last_error: None,
                    diagnostics: None,
                }]),
            })
            .await;

        let emitted: Vec<_> = events.try_iter().collect();
        assert!(
            log_lines(&emitted).is_empty(),
            "a fully-successful probe must not write log lines"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exit_23_terminal_carries_the_diagnostics_wall_and_logs_once() {
        // Connect scope: a core-start config error (xray exit 23)
        // lands in CorePhase::Error carrying the keyed headline plus the
        // captured core output; the app's LogCoreError record on that phase
        // renders the two as one terminal record, so the runtime must not log
        // a duplicate alongside it. A regenerated configuration cannot be
        // repaired by replaying an older file, so no retry arm exists.
        let (mut runtime, events) = runtime_with_events();
        runtime.push_ring("[stdout] 2026/09/05 failed to parse config");
        runtime.push_ring("[stdout] invalid field 'routing'");
        runtime.on_core_exit(Some(23)).await;

        let tail = "[stdout] 2026/09/05 failed to parse config\n[stdout] invalid field 'routing'";
        let super::CorePhase::Error(error) = &runtime.phase else {
            panic!(
                "the exit-23 branch must land in the Error phase, got {:?}",
                runtime.phase
            );
        };
        assert_eq!(phase_message(error).key(), Key::RtPhaseConfigError);
        assert_eq!(error.tail, tail);
        assert_eq!(
            error.record(Language::En),
            format!(
                "{}\n{}\n{tail}",
                t(Language::En, Key::RtPhaseConfigError),
                t(Language::En, Key::ProbeDiagnosticsWall),
            ),
            "the record must be the headline, the wall header, and the captured tail"
        );
        let emitted: Vec<_> = events.try_iter().collect();
        assert!(
            emitted.iter().any(|event| matches!(
                event,
                CoreEvt::State(super::CorePhase::Error(error))
                    if phase_message(error).key() == Key::RtPhaseConfigError && error.tail == tail
            )),
            "the phase event must carry the keyed headline plus the tail, got: {emitted:?}"
        );
        assert!(
            log_lines(&emitted).is_empty(),
            "the terminal branch must not log a duplicate record — the app's \
             LogCoreError on the phase transition is the one failure record, got: {:?}",
            log_lines(&emitted)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exit_23_without_captured_output_degrades_to_headline() {
        // No core output captured: the wall must not be fabricated and the
        // payload is exactly the keyed headline.
        let (mut runtime, events) = runtime_with_events();
        runtime.on_core_exit(Some(23)).await;

        let super::CorePhase::Error(error) = &runtime.phase else {
            panic!(
                "the exit-23 branch must land in the Error phase, got {:?}",
                runtime.phase
            );
        };
        assert!(
            error.tail.is_empty(),
            "no captured output must leave the tail empty, got {:?}",
            error.tail
        );
        assert_eq!(
            error.record(Language::En),
            t(Language::En, Key::RtPhaseConfigError),
            "an output-less exit-23 failure must degrade to the headline"
        );
        let emitted: Vec<_> = events.try_iter().collect();
        assert!(
            emitted.iter().any(|event| matches!(
                event,
                CoreEvt::State(super::CorePhase::Error(error))
                    if phase_message(error).key() == Key::RtPhaseConfigError
            )),
            "the phase event must carry the keyed headline, got: {emitted:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn helper_loss_cancels_inflight_apply() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::ApplyConfig);
        park_pending_task(&mut runtime);

        runtime.on_unconfirmed_backend_loss();

        assert!(
            runtime.jobs.busy_kind().is_none(),
            "helper loss must clear the foreign in-flight apply"
        );
        flush_bookends(&mut runtime);
        let emitted: Vec<_> = events.try_iter().collect();
        let apply_results: Vec<_> = emitted
            .iter()
            .filter_map(|event| match event {
                CoreEvt::ApplyResult { ok, output } => Some((ok, output)),
                _ => None,
            })
            .collect();
        assert_eq!(apply_results.len(), 1);
        assert!(!apply_results[0].0);
        assert!(
            apply_results[0]
                .1
                .text(Language::En)
                .contains(t(Language::En, Key::RtReasonHelperDisconnected)),
            "terminal apply result must mention the reason, got: {}",
            apply_results[0].1.text(Language::En)
        );
        assert_eq!(
            emitted
                .iter()
                .filter(|event| matches!(event, CoreEvt::Operation(None)))
                .count(),
            1,
            "helper loss releases the busy slot exactly once"
        );
    }

    #[test]
    fn latency_probe_results_carry_tags_without_correlation_id() {
        // The probe is single-flight, so its outcome pairs back
        // to the request structurally — the payload carries tags only, no
        // correlation id (the bus and its id allocator are gone).
        let probe = LatencyProbeResult {
            tags: vec!["edge".into()],
            result: Err(ProbeFailure::plain(Diag::new(Key::ProbeNoProfiles))),
        };
        assert_eq!(probe.tags, vec!["edge".to_string()]);
    }

    #[test]
    fn runtime_handle_drop_waits_for_worker_shutdown() {
        let (event_sender, event_receiver) =
            std::sync::mpsc::sync_channel(super::EVT_CHANNEL_CAPACITY);
        let handle = spawn_runtime(
            event_sender,
            egui::Context::default(),
            crate::metrics::MetricsHandle::new(),
        );
        assert!(matches!(
            event_receiver.recv_timeout(Duration::from_secs(1)),
            Ok(super::CoreEvt::State(super::CorePhase::Stopped))
        ));

        let started = Instant::now();
        drop(handle);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "idle runtime shutdown should join promptly"
        );
        assert!(
            event_receiver
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "joined runtime must close its final event sender"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ready_tick_records_duration_while_other_arms_stay_gated() {
        let (command_sender, command_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (event_sender, _event_receiver) =
            std::sync::mpsc::sync_channel(super::EVT_CHANNEL_CAPACITY);
        let metrics = crate::metrics::MetricsHandle::new();
        let mut runtime = Runtime::new(
            command_receiver,
            event_sender,
            egui::Context::default(),
            metrics.clone(),
        );
        // The ready arm is gated on Starting; the stats/obs arms are gated on
        // Running. With no backend, ready_poll returns immediately, so each
        // interval tick still records its (near-zero) duration.
        runtime.phase = super::CorePhase::Starting;
        let run = tokio::spawn(runtime.run());

        // READY_POLL is 250 ms and tokio's first interval tick fires
        // immediately, so 600 ms of real time guarantees at least two
        // completed ticks.
        tokio::time::sleep(Duration::from_millis(600)).await;
        let _ = command_sender.send(super::CoreCmd::Shutdown);
        run.await.expect("runtime run() must complete cleanly");

        let snapshot = metrics.snapshot();
        assert!(
            snapshot.ready_ticks >= 2,
            "ready ticks must accumulate while Starting, got {}",
            snapshot.ready_ticks
        );
        assert!(
            snapshot.ready_tick_ns_total > 0,
            "ready tick durations must accumulate"
        );
        assert_eq!(snapshot.stats_ticks, 0, "stats arm is gated on Running");
        assert_eq!(snapshot.stats_tick_ns_total, 0);
        assert_eq!(snapshot.obs_ticks, 0, "obs arm is gated on Running");
        assert_eq!(snapshot.obs_tick_ns_total, 0);
    }

    /// Every run-loop ticker is built by [`super::ticker`], which pins
    /// `MissedTickBehavior::Delay` at construction — the acceptance seam. A
    /// wedged core overruns stats polls; Burst would then
    /// fire the next tick instantly and chain zero-gap timeout cycles on the
    /// single runtime thread, while Delay costs one poll per period. Fails
    /// the moment any constructed ticker loses its explicit Delay.
    #[test]
    fn ticker_factory_delays_missed_ticks() {
        // `tokio::time::interval` requires a live timer driver (it panics
        // outside a runtime), so construct the tickers inside a throwaway
        // current-thread runtime.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime builds");
        rt.block_on(async {
            for period in [
                super::READY_POLL,
                Duration::from_secs(1),
                Duration::from_secs(5),
                Duration::from_millis(500),
            ] {
                assert_eq!(
                    super::ticker(period).missed_tick_behavior(),
                    tokio::time::MissedTickBehavior::Delay,
                    "ticker({period:?}) must never fall back to Burst"
                );
            }
        });
    }

    #[test]
    fn cancellation_after_uac_returns_never_opens_helper_pipe() {
        let cancelled = AtomicBool::new(false);
        // This is the interleaving after ShellExecuteW returns but before the
        // connector could open/auth the per-launch pipe.
        cancelled.store(true, Ordering::Release);
        let connector_called = AtomicBool::new(false);
        let result = connect_after_helper_launch(&cancelled, || {
            connector_called.store(true, Ordering::Release);
        });
        assert!(result.is_none());
        assert!(
            !connector_called.load(Ordering::Acquire),
            "a cancelled helper launch must not authenticate or send Start"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn confirmed_core_rollback_clears_direct_backend_before_filesystem_swap() {
        let mut runtime = runtime();
        runtime.core_update.commit_candidate();
        runtime.core_update.arm_rollback(rollback_reason());
        // The direct child owns deny-write/delete payload handles. The
        // rollback path must release that backend before it touches core/.
        assert!(runtime.backend.as_backend().is_none());
        assert!(runtime.core_update.is_candidate_pending());
        assert!(runtime.core_update.rollback_pending().is_some());
        assert!(
            runtime
                .core_update
                .take_rollback_after_confirmed_exit(true)
                .is_some()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn apply_join_error_emits_exactly_one_failure_result() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::ApplyConfig);
        let task = tokio::spawn(async { panic!("deliberate apply worker failure") });
        let error = task.await.expect_err("worker panic must become JoinError");
        runtime.complete_exclusive_join_error(JobKind::ApplyConfig, error);
        flush_bookends(&mut runtime);

        let apply_results: Vec<_> = events
            .try_iter()
            .filter_map(|event| match event {
                CoreEvt::ApplyResult { ok, output } => Some((ok, output)),
                _ => None,
            })
            .collect();
        assert_eq!(
            apply_results.len(),
            1,
            "one apply result settles one revision"
        );
        assert!(!apply_results[0].0);
        assert!(
            apply_results[0]
                .1
                .text(Language::En)
                .contains(background_failed_sentence())
        );
        assert!(runtime.jobs.busy_kind().is_none());
    }

    /// A panicking TestConfig worker settles the request with the join-error
    /// terminal (`background operation failed: ...`) on its reply, exactly
    /// once, and releases the busy slot — the join-error cell of the
    /// uniformity matrix for TestConfig.
    #[tokio::test(flavor = "current_thread")]
    async fn test_join_error_delivers_terminal_failure_on_reply() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::TestConfig);
        let (reply, result) = tokio::sync::oneshot::channel();
        runtime
            .jobs
            .set_exclusive_sidecar(ExclusiveSidecar::TestReply(reply));
        let task = tokio::spawn(async { panic!("deliberate test worker failure") });
        let error = task.await.expect_err("worker panic must become JoinError");
        runtime.complete_exclusive_join_error(JobKind::TestConfig, error);
        flush_bookends(&mut runtime);

        match result.await {
            Ok(Err(error)) => assert!(
                error
                    .text(Language::En)
                    .contains(background_failed_sentence()),
                "terminal must name the join failure, got: {error}"
            ),
            other => panic!("expected a join-error terminal, got {other:?}"),
        }
        assert!(
            runtime.jobs.busy_kind().is_none(),
            "join error releases the busy slot"
        );
        assert_eq!(
            events
                .try_iter()
                .filter(|event| matches!(event, CoreEvt::Operation(None)))
                .count(),
            1,
            "join error releases the busy slot exactly once"
        );
    }

    /// A panicking latency-probe worker emits the join-error failure event
    /// (`background operation failed: ...`) with the sidecar tags, exactly
    /// once, and releases the busy slot — the join-error cell of the
    /// uniformity matrix for LatencyProbe.
    #[tokio::test(flavor = "current_thread")]
    async fn latency_probe_join_error_emits_failure_with_sidecar_tags() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::LatencyProbe);
        runtime
            .jobs
            .set_exclusive_sidecar(ExclusiveSidecar::LatencyTags(vec!["srv-probe".into()]));
        let task = tokio::spawn(async { panic!("deliberate probe worker failure") });
        let error = task.await.expect_err("worker panic must become JoinError");
        runtime.complete_exclusive_join_error(JobKind::LatencyProbe, error);
        flush_bookends(&mut runtime);

        let emitted: Vec<_> = events.try_iter().collect();
        let probe_indices: Vec<usize> = emitted
            .iter()
            .enumerate()
            .filter_map(|(index, event)| matches!(event, CoreEvt::LatencyProbe(_)).then_some(index))
            .collect();
        let none_indices: Vec<usize> = emitted
            .iter()
            .enumerate()
            .filter_map(|(index, event)| matches!(event, CoreEvt::Operation(None)).then_some(index))
            .collect();
        assert_eq!(probe_indices.len(), 1);
        assert_eq!(
            none_indices.len(),
            1,
            "join error releases the busy slot exactly once"
        );
        assert!(probe_indices[0] < none_indices[0]);
        assert!(matches!(
            &emitted[probe_indices[0]],
            CoreEvt::LatencyProbe(result)
                if result.tags == ["srv-probe"]
                    && matches!(&result.result, Err(error)
                        if error.headline.key() == Key::RtFrameBackgroundFailed)
        ));
        assert!(runtime.jobs.busy_kind().is_none());
    }

    /// A panicking UpdateCore worker settles the install with the
    /// join-error terminal `Download(Failed, "background operation failed:
    /// ...")`, exactly once, and releases the busy slot — the join-error cell
    /// of the uniformity matrix for UpdateCore.
    #[tokio::test(flavor = "current_thread")]
    async fn update_join_error_emits_exactly_one_failure_download() {
        let (mut runtime, events) = runtime_with_events();
        occupy_exclusive(&mut runtime, JobKind::UpdateCore);
        let task = tokio::spawn(async { panic!("deliberate update worker failure") });
        let error = task.await.expect_err("worker panic must become JoinError");
        runtime.complete_exclusive_join_error(JobKind::UpdateCore, error);
        flush_bookends(&mut runtime);

        let emitted: Vec<_> = events.try_iter().collect();
        let failed_indices: Vec<(usize, &super::AppMessage)> = emitted
            .iter()
            .enumerate()
            .filter_map(|(index, event)| match event {
                CoreEvt::Download(super::DownloadState::Failed(text)) => Some((index, text)),
                _ => None,
            })
            .collect();
        let none_indices: Vec<usize> = emitted
            .iter()
            .enumerate()
            .filter_map(|(index, event)| matches!(event, CoreEvt::Operation(None)).then_some(index))
            .collect();
        assert_eq!(
            failed_indices.len(),
            1,
            "one join-error download settles one install"
        );
        assert_eq!(
            none_indices.len(),
            1,
            "join error releases the busy slot exactly once"
        );
        assert!(failed_indices[0].0 < none_indices[0]);
        assert!(
            failed_indices[0]
                .1
                .text(Language::En)
                .contains(background_failed_sentence()),
            "terminal must name the join failure, got: {}",
            failed_indices[0].1
        );
        assert!(runtime.jobs.busy_kind().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_landed_install_gate_start_writes_the_app_owned_configuration() {
        with_appdata_async(async {
            let (mut runtime, _events) = runtime_with_events();
            occupy_exclusive(&mut runtime, JobKind::UpdateCore);
            runtime
                .complete_exclusive(ExclusiveOutcome::Download {
                    state: super::DownloadState::Done("26.9.9".into()),
                    kind: OperationKind::UpdateCore,
                })
                .await;
            // The completed install arms the health gate. Its start writes
            // and runs the app-owned configuration, so it needs no stored
            // configuration.
            runtime.housekeeping().await;

            let active: serde_json::Value = serde_json::from_slice(
                &std::fs::read(super::apply::active_path())
                    .expect("the gate start must write the runtime artefact"),
            )
            .expect("the gate configuration parses");
            assert!(
                active.get("inbounds").is_none(),
                "the gate serves no inbound: {active}"
            );
            assert!(super::apply::stamp_is_current());
        })
        .await;
    }

    /// The health gate proves the installed binary with an app-owned direct
    /// configuration, so it never takes the elevated helper — a TUN session's
    /// proof must not depend on an elevation ceremony or a consent prompt for
    /// a configuration that carries no tun inbound.
    #[tokio::test(flavor = "current_thread")]
    async fn the_health_gate_never_uses_the_elevated_helper() {
        let mut runtime = runtime();
        assert!(
            !runtime.uses_elevated_helper(),
            "a direct session never uses the helper"
        );
        runtime.requested_tun_mode = true;
        assert!(
            runtime.uses_elevated_helper(),
            "a TUN session runs behind the helper"
        );
        runtime.gate_backend_alive = true;
        assert!(
            !runtime.uses_elevated_helper(),
            "the gate's proof process is always a direct child"
        );
        runtime.gate_backend_alive = false;
        assert!(runtime.uses_elevated_helper());
    }

    /// Seed the state a landed but unproven core update leaves: the installed
    /// tree, the retained last-good tree, and the durable health marker.
    fn seed_pending_swap(installed: &[u8], retained: &[u8]) {
        let root = crate::sys::paths::broccoli_root();
        let core = root.join("core");
        let backup = root.join("core.bak");
        std::fs::create_dir_all(&core).expect("create installed core dir");
        std::fs::create_dir_all(&backup).expect("create retained core dir");
        std::fs::write(core.join("xray.exe"), installed).expect("write installed payload");
        std::fs::write(backup.join("xray.exe"), retained).expect("write retained payload");
        std::fs::write(
            root.join(".core-update.pending"),
            b"broccoli-core-swap-v1\n",
        )
        .expect("write the durable swap marker");
    }

    /// A digest over every file name and byte of one tree: "the installed
    /// payload is byte-identical" as a single value.
    fn tree_hash(root: &std::path::Path) -> u64 {
        use std::hash::{Hash as _, Hasher as _};
        let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(root)
            .expect("read tree dir")
            .map(|entry| {
                let entry = entry.expect("tree entry");
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    std::fs::read(entry.path()).expect("read tree file"),
                )
            })
            .collect();
        files.sort();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for (name, bytes) in files {
            name.hash(&mut hasher);
            bytes.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Every configuration source names its own line: the log must say which
    /// configuration the start runs, and no two sources may share a line.
    #[test]
    fn every_spawn_config_source_names_its_own_line() {
        let keys = [
            super::SpawnConfigSource::Committed,
            super::SpawnConfigSource::CoreGate,
            super::SpawnConfigSource::RolledBackReplay,
            super::SpawnConfigSource::SavedState,
        ]
        .map(|source| source.notice().key());
        assert_eq!(
            keys,
            [
                Key::RtLogSpawnConfigCommitted,
                Key::RtLogSpawnConfigGate,
                Key::RtLogSpawnConfigReplay,
                Key::RtLogSpawnConfigRegenerated,
            ]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn gate_start_config_error_keeps_the_installed_core() {
        with_appdata_async(async {
            seed_pending_swap(b"installed-v26.9.9", b"retained-v26.7.28");
            let installed_before = tree_hash(&crate::sys::paths::core_dir());

            let (mut runtime, events) = runtime_with_events();
            runtime.core_update.commit_candidate();
            runtime.set_phase(super::CorePhase::Starting);
            runtime.push_ring("[stdout] 2026/09/18 failed to parse config");
            runtime.on_core_exit(Some(23)).await;

            assert_eq!(
                tree_hash(&crate::sys::paths::core_dir()),
                installed_before,
                "a config-class failure must not touch the verified payload"
            );
            assert!(
                !crate::sys::core_dl::update_pending_health(),
                "the update must end as installed"
            );
            assert!(
                !crate::sys::paths::broccoli_root().join("core.bak").exists(),
                "ending the update as installed consumes the retained tree"
            );
            assert!(!runtime.core_update.is_candidate_pending());
            let super::CorePhase::Error(error) = &runtime.phase else {
                panic!(
                    "expected the config-class Error phase, got {:?}",
                    runtime.phase
                );
            };
            assert_eq!(phase_message(error).key(), Key::RtPhaseConfigError);
            assert!(error.tail.contains("failed to parse config"));
            let emitted: Vec<_> = events.try_iter().collect();
            assert!(
                !emitted
                    .iter()
                    .any(|event| matches!(event, CoreEvt::Download(_))),
                "no rollback report may reach the GUI, got: {emitted:?}"
            );
            let logs = app_log_texts(&emitted);
            let kept: Vec<&String> = logs
                .iter()
                .filter(|line| line.starts_with(frame_prefix(Key::RtLogConfigKeptInstalledCore)))
                .collect();
            assert_eq!(
                kept.len(),
                1,
                "the config-class finding must reach the log once, got: {logs:?}"
            );
            assert!(
                kept[0].contains(t(Language::En, Key::RtPhaseConfigError)),
                "the kept-core line must carry the core's config error, got: {kept:?}"
            );
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn healthy_gate_start_completes_the_update_then_ends_the_proof_process() {
        with_appdata_async(async {
            seed_pending_swap(b"installed-v26.9.9", b"retained-v26.7.28");

            let (mut runtime, events) = runtime_with_events();
            runtime.core_update.commit_candidate();
            runtime.set_phase(super::CorePhase::Starting);
            // The start that proved the binary ran the app-owned
            // configuration; its readiness ACKs the update and ends it.
            runtime.gate_backend_alive = true;
            runtime.complete_readiness_probe(true).await;

            assert!(
                !crate::sys::core_dl::update_pending_health(),
                "first readiness completes the update"
            );
            assert!(
                !crate::sys::paths::broccoli_root().join("core.bak").exists(),
                "a completed update consumes the retained tree"
            );
            assert!(!runtime.core_update.is_candidate_pending());
            assert!(
                runtime.exit_policy.stopping(),
                "the gate's proof process must be ended, not left serving the app-owned config"
            );
            assert!(!runtime.gate_backend_alive);
            assert!(
                !matches!(runtime.phase, super::CorePhase::Running),
                "a gate start must never become the running session, got {:?}",
                runtime.phase
            );
            let emitted: Vec<_> = events.try_iter().collect();
            assert!(
                !emitted
                    .iter()
                    .any(|event| matches!(event, CoreEvt::Download(_))),
                "a healthy gate is no rollback, got: {emitted:?}"
            );
            assert!(
                app_log_texts(&emitted)
                    .contains(&t(Language::En, Key::RtLogHealthGateCompleted).to_string()),
                "the completed gate must say the update is acknowledged and its core stopped, \
                 got: {emitted:?}"
            );

            // The confirmed exit settles the phase and releases the update
            // operation.
            runtime.on_core_exit(Some(0)).await;
            assert!(matches!(runtime.phase, super::CorePhase::Stopped));
            assert!(runtime.jobs.busy_kind().is_none());
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_generation_refusal_during_a_pending_update_keeps_the_installed_core() {
        with_appdata_async(async {
            seed_pending_swap(b"installed-v26.9.9", b"retained-v26.7.28");
            let installed_before = tree_hash(&crate::sys::paths::core_dir());
            // The saved profiles still carry the retired spelling the pinned
            // core refuses (infra/conf/xray.go:262), so the app's own
            // generation refuses before any spawn.
            let mut profile = ServerProfile {
                id: "0123456789abcdef".into(),
                name: "Stale edge".into(),
                outbound: OutboundModel::new(Protocol::Freedom),
                ..ServerProfile::new("Stale edge", OutboundModel::new(Protocol::Freedom))
            };
            profile.outbound.retired_proxy_settings = Some(serde_json::json!({"tag": "direct"}));
            let servers = crate::model::ServersFile {
                profiles: vec![profile.clone()],
                active: Some(profile.id.clone()),
                ..crate::model::ServersFile::default()
            };
            servers.save().expect("save the marked profile set");

            let (mut runtime, events) = runtime_with_events();
            runtime.core_update.commit_candidate();
            runtime.start_backend().await;

            let emitted: Vec<_> = events.try_iter().collect();
            let logs = app_log_texts(&emitted);
            let kept: Vec<&String> = logs
                .iter()
                .filter(|line| line.starts_with(frame_prefix(Key::RtLogConfigKeptInstalledCore)))
                .collect();
            assert_eq!(
                kept.len(),
                1,
                "the config-class finding must reach the log once, got: {logs:?}"
            );
            assert!(
                kept[0].contains(frame_prefix(Key::GenerationFailed)),
                "the kept-core line must carry the failure that kept it, got: {kept:?}"
            );
            assert_eq!(
                tree_hash(&crate::sys::paths::core_dir()),
                installed_before,
                "a generation refusal must not touch the verified payload"
            );
            assert!(
                !crate::sys::core_dl::update_pending_health(),
                "the update must end as installed"
            );
            assert!(
                !crate::sys::paths::broccoli_root().join("core.bak").exists(),
                "ending the update as installed consumes the retained tree"
            );
            assert!(!runtime.core_update.is_candidate_pending());
            let super::CorePhase::Error(error) = &runtime.phase else {
                panic!(
                    "expected the configuration-finding Error phase, got {:?}",
                    runtime.phase
                );
            };
            let text = error.message.text(Language::En);
            assert!(
                text.contains("proxySettings")
                    && text.contains("streamSettings.sockopt.dialerProxy"),
                "the app's own finding must reach the user, got: {text}"
            );
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_start_regenerates_from_the_saved_state_over_a_stored_artefact() {
        with_appdata_async(async {
            let profile = ServerProfile {
                id: "0123456789abcdef".into(),
                name: "Saved edge".into(),
                outbound: OutboundModel::new(Protocol::Freedom),
                ..ServerProfile::new("Saved edge", OutboundModel::new(Protocol::Freedom))
            };
            let servers = crate::model::ServersFile {
                profiles: vec![profile.clone()],
                active: Some(profile.id.clone()),
                ..crate::model::ServersFile::default()
            };
            servers.save().expect("save the server list");
            crate::model::Settings::default()
                .save()
                .expect("save the settings");
            // The artefact a previous build left behind, stamp included.
            std::fs::create_dir_all(crate::sys::paths::config_dir()).expect("config dir");
            std::fs::write(
                super::apply::active_path(),
                br#"{"log":{"loglevel":"debug"},"previousBuild":true}"#,
            )
            .expect("write the stored artefact");
            std::fs::write(
                super::apply::meta_path(),
                br#"{"appVersion":"0.0.1","corePin":"v1.0.0"}"#,
            )
            .expect("write the foreign stamp");

            let (mut runtime, events) = runtime_with_events();
            runtime.start_backend().await;

            let emitted: Vec<_> = events.try_iter().collect();
            assert!(
                app_log_texts(&emitted)
                    .contains(&t(Language::En, Key::RtLogSpawnConfigRegenerated).to_string()),
                "the start must name the configuration it runs, got: {emitted:?}"
            );

            let active: serde_json::Value = serde_json::from_slice(
                &std::fs::read(super::apply::active_path()).expect("read the regenerated artefact"),
            )
            .expect("the regenerated artefact parses");
            assert!(
                active.get("previousBuild").is_none(),
                "the stored artefact must not be replayed: {active}"
            );
            let tag = profile.tag();
            assert!(
                active["outbounds"]
                    .as_array()
                    .expect("generated outbounds")
                    .iter()
                    .any(|outbound| outbound["tag"] == serde_json::json!(tag)),
                "the configuration must come from the saved server list: {active}"
            );
            assert!(super::apply::stamp_is_current());
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_gate_start_runs_the_app_owned_configuration_not_the_users_profiles() {
        with_appdata_async(async {
            let profile = ServerProfile {
                id: "0123456789abcdef".into(),
                name: "Tokyo edge".into(),
                outbound: OutboundModel::new(Protocol::Freedom),
                ..ServerProfile::new("Tokyo edge", OutboundModel::new(Protocol::Freedom))
            };
            let servers = crate::model::ServersFile {
                profiles: vec![profile.clone()],
                active: Some(profile.id.clone()),
                ..crate::model::ServersFile::default()
            };
            servers.save().expect("save the server list");

            let (mut runtime, events) = runtime_with_events();
            runtime.core_update.commit_candidate();
            runtime.update_gate_start = true;
            runtime.start_backend().await;

            let emitted: Vec<_> = events.try_iter().collect();
            assert!(
                app_log_texts(&emitted)
                    .contains(&t(Language::En, Key::RtLogSpawnConfigGate).to_string()),
                "the gate start must name the app-owned configuration, got: {emitted:?}"
            );

            let active_text = std::fs::read_to_string(super::apply::active_path())
                .expect("the gate start must write the runtime artefact");
            let active: serde_json::Value =
                serde_json::from_str(&active_text).expect("the gate configuration parses");
            let mut tags: Vec<&str> = active["outbounds"]
                .as_array()
                .expect("gate outbounds")
                .iter()
                .filter_map(|outbound| outbound["tag"].as_str())
                .collect();
            tags.sort_unstable();
            assert_eq!(
                tags,
                ["block", "direct"],
                "a direct outbound and nothing else"
            );
            assert!(
                active.get("inbounds").is_none(),
                "the gate serves no inbound: {active}"
            );
            assert!(
                !active_text.contains(&profile.tag()),
                "no user profile may reach the gate configuration"
            );
            assert!(super::apply::stamp_is_current());
        })
        .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_rolled_back_artefact_is_replayed_only_under_this_builds_stamp() {
        with_appdata_async(async {
            let servers = crate::model::ServersFile::default();
            servers.save().expect("save the server list");
            crate::model::Settings::default()
                .save()
                .expect("save the settings");
            std::fs::create_dir_all(crate::sys::paths::config_dir()).expect("config dir");

            // A foreign-stamped artefact is regenerated, never replayed.
            std::fs::write(
                super::apply::active_path(),
                br#"{"log":{"loglevel":"debug"},"foreignArtefact":true}"#,
            )
            .expect("write the foreign artefact");
            std::fs::write(
                super::apply::meta_path(),
                br#"{"appVersion":"0.0.1","corePin":"v1.0.0"}"#,
            )
            .expect("write the foreign stamp");
            let (mut runtime, _events) = runtime_with_events();
            runtime.replay_after_rollback = true;
            runtime.start_backend().await;
            let regenerated = std::fs::read_to_string(super::apply::active_path())
                .expect("read the regenerated artefact");
            assert!(
                !regenerated.contains("foreignArtefact"),
                "a foreign-stamped artefact must not be replayed: {regenerated}"
            );
            assert!(super::apply::stamp_is_current());

            // This build's stamp replays the stored artefact byte for byte.
            let stored = br#"{"api":{"tag":"api","listen":"127.0.0.1:45999","services":["StatsService"]},"replayedArtefact":true}"#;
            std::fs::write(super::apply::active_path(), stored).expect("write the stored artefact");
            let stamp = format!(
                r#"{{"appVersion":"{}","corePin":"{}","configSha256":"{}"}}"#,
                env!("CARGO_PKG_VERSION"),
                crate::sys::core_dl::pinned_release_version(),
                super::apply::sha256_hex(stored)
            );
            std::fs::write(super::apply::meta_path(), stamp).expect("write this build's stamp");
            assert!(
                super::apply::stamp_is_current(),
                "a stamp describing the stored bytes must match"
            );
            runtime.replay_after_rollback = true;
            runtime.start_backend().await;
            assert_eq!(
                std::fs::read(super::apply::active_path()).expect("read the replayed artefact"),
                stored,
                "the deliberate rollback replay runs the stored artefact unchanged"
            );
        })
        .await;
    }
}
