//! One seat per runtime job kind: the per-kind declaration the shared
//! ceremony reads.
//!
//! Every accepted query command — route test, the balancer family, logger
//! restart, the trial-rule family, runtime state — runs through
//! [`Runtime::run_query`], which owns the ceremony the dispatch arms used to
//! repeat: the reply guard with its terminal, the conflict check, the
//! busy-window reject, the `grpc`/`repaint` clones, the spawn, the terminal
//! send, and the abort registration. A seat declares only its own content:
//! the job kind, the conflict rule, the availability gate, the RPC call with
//! its error text, and the busy-reject flavor.
//!
//! The exclusive kinds keep their bespoke workers in `rt/mod.rs` (sidecars,
//! outcomes, bookend timing, preemption) — the profile validation's worker
//! and the scratch-config contract it owns live in `rt/profiles.rs`.
//! Declared here are the facts every shared path reads for them: the
//! conflict rule, the busy-reject flavour the begin runner emits for a held
//! window, the user-facing operation name the busy window is reported
//! through, whether a hard abort must
//! leave the task to its own terminal, whether an unexpected exit cancels
//! the in-flight task, and where the exactly-one terminal travels when the
//! worker's own outcome cannot arrive.

use std::future::Future;

use tokio::sync::oneshot;

use super::grpc::pb::xray::app::router as router_cfg;
use super::grpc::pb::xray::app::router::command as router_cmd;
use super::grpc::{
    GrpcClient, add_rule_outcome, balancer_status_diag, routing_context, trial_rule_to_pb,
};
use super::jobs::{Busy, ExclusiveSidecar, JobKind, KindRule, ReplyGuard, TestConfigReply};
use super::{
    AppMessage, ApplyOutput, CoreEvt, CorePhase, DownloadState, LatencyProbeResult, PhaseError,
    ProbeFailure, Runtime, RuntimeStateView, TrialRuleAddOutcome,
};
use crate::diag::{Diag, DiagError};
use crate::i18n::Key;
use crate::model::routing::{RouteTestRequest, Rule};

/// The user-facing name of one job kind: the shared `Operation*` keys the
/// runtime busy frames and the seat's busy reject nest as a message, so a
/// blocked user reads the same operation name wherever it appears. Query
/// kinds never occupy the busy window and have no operation name.
pub(crate) fn operation_name(kind: JobKind) -> Option<Diag> {
    let key = match kind {
        JobKind::Start => Key::OperationConnect,
        JobKind::Stop => Key::OperationDisconnect,
        JobKind::Restart => Key::OperationRestart,
        JobKind::ApplyConfig => Key::OperationApplyConfig,
        JobKind::TestConfig => Key::OperationTestConfig,
        JobKind::UpdateCore => Key::OperationUpdateCore,
        JobKind::LatencyProbe => Key::OperationLatencyProbe,
        JobKind::ValidateProfiles => Key::OperationValidateProfiles,
        JobKind::TestRoute
        | JobKind::Balancer
        | JobKind::LoggerRestart
        | JobKind::TrialRules
        | JobKind::RuntimeState => return None,
    };
    Some(Diag::new(key))
}

/// The user-facing name of the kind holding the busy window, for the texts
/// that report the occupant (the busy rejection, the cancel log). The window
/// is held by an occupying kind — the registry begins nothing else — and every
/// occupying kind names itself ([`operation_name`]).
pub(crate) fn occupant_name(kind: JobKind) -> Diag {
    kind.operation_name()
        .expect("a held window is an occupying kind, and every occupying kind names itself")
}

/// Terminal a query job's reply guard delivers when the job dies without a
/// result (cancel, abort, exit), and the message the reply commands are
/// answered with while the runtime is tearing down: one definition, so every
/// request channel carries the same message.
pub(crate) fn runtime_stopping() -> DiagError {
    DiagError::from(Diag::new(Key::SeatRuntimeStopping))
}

/// Where a seat's availability gate runs relative to the conflict check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateOrder {
    /// The conflict check runs first: the record is begun before the gate,
    /// and a gate rejection finishes it again. This is the route test's
    /// interception order — a busy window outranks "core is not running".
    BusyFirst,
    /// Availability rejects before any record exists; the conflict check
    /// follows the begin (the balancer/logger/trial-rules order).
    AvailabilityFirst,
}

/// How the shared runner answers the registry's busy-window reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BusyReject {
    /// Log the shared busy line and send it on the reply channel (the route
    /// test's whitelist-era flavor).
    Logged,
    /// Send `runtime is busy with {active:?}` without logging (the balancer
    /// family and logger restart).
    Text,
    /// The kind's conflict rule never checks the busy window, so the
    /// registry cannot reject it; a reject is a declaration error.
    Impossible,
}

/// How the runtime's exclusive begin runner answers a held busy window for
/// one kind: where the rejected command's terminal lands (or that the kind
/// preempts instead of rejecting). A flavour is a kind fact, declared with
/// the kind's rule and never chosen by a dispatch arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExclusiveReject {
    /// Log the shared busy line; the command owns no terminal of its own.
    Logged,
    /// The rule's `preemptive`: the occupant is cancelled — its own terminal
    /// and its release — before this kind's begin, so the begin has no
    /// occupant left to reject with. A reject reaching the runner is a wiring
    /// error.
    Preempting,
    /// Answer on the request's own reply channel.
    Reply,
    /// Answer as the probe's failure event, tagged with the request's
    /// profiles.
    ProbeEvent,
    /// Answer as the apply verdict of the rejected command.
    ApplyVerdict,
    /// Log the shared line, settle the update's optimistic view with the
    /// failure, and re-emit the occupant's bookend so the GUI keeps its
    /// owner.
    UpdateSettled,
}

/// One accepted query job's seat: the request payload plus its per-kind
/// content. Everything channel-shaped lives in [`Runtime::run_query`].
pub(crate) trait QuerySeat: Send + 'static {
    /// Success payload of the request's reply channel.
    type Payload: Send + 'static;
    /// Validated input the gate hands to the RPC call (`()` for seats whose
    /// call needs nothing beyond the payload).
    type Prepared: Send + 'static;

    /// The kind this seat begins as.
    const KIND: JobKind;
    /// Where the availability gate runs relative to the conflict check.
    const GATE: GateOrder;
    /// The registry-reject flavor.
    const BUSY: BusyReject;
    /// Whether this seat's task must run to its own terminal even under the
    /// Stop/Shutdown drain. The trial-rule mutations write to the core and
    /// then read the rule list back: an abort between the two RPCs would
    /// report "cancelled" for a rule that is already live (and an
    /// append-mode retry would add a duplicate). Such a record still gets
    /// the drain's cancel flag; each RPC carries its own local deadline
    /// ([`GrpcClient`] bounds every call), so the task always ends promptly
    /// on its own and its reply guard delivers the true verdict.
    const RUNS_TO_OWN_TERMINAL: bool = false;

    /// Availability and validation, run at the point [`QuerySeat::GATE`]
    /// declares; `Err` is the rejection text delivered on the reply channel.
    fn gate(&self, runtime: &Runtime) -> Result<Self::Prepared, DiagError>;

    /// The RPC call, run on the runtime's executor; the error text is the
    /// terminal verdict.
    fn call(
        self,
        grpc: &GrpcClient,
        prepared: Self::Prepared,
    ) -> impl Future<Output = Result<Self::Payload, DiagError>> + Send;
}

/// Occupies the busy window (exclusive job). At most one such record.
const OCCUPIES: bool = true;
/// Does not occupy the busy window (concurrent query).
const DOES_NOT_OCCUPY: bool = false;
/// Preempts the exclusive occupant by cancelling it before beginning.
const PREEMPTIVE: bool = true;
/// Never preempts; rejects while an exclusive job holds the window.
const NON_PREEMPTIVE: bool = false;
/// Rejects while an exclusive job holds the window.
const BLOCKED_BY_EXCLUSIVE: bool = true;
/// Runs regardless of the busy window.
const NOT_BLOCKED_BY_EXCLUSIVE: bool = false;

/// Exclusive kinds: occupying, non-preemptive, rejecting while busy.
const OCCUPYING: KindRule = KindRule::new(OCCUPIES, NON_PREEMPTIVE, BLOCKED_BY_EXCLUSIVE);
/// `Stop`: occupying and preemptive (cancels the occupant before beginning).
const PREEMPTIVE_KIND: KindRule = KindRule::new(OCCUPIES, PREEMPTIVE, BLOCKED_BY_EXCLUSIVE);
/// Query kinds that reject while an exclusive job holds the window.
const BLOCKED_QUERY: KindRule =
    KindRule::new(DOES_NOT_OCCUPY, NON_PREEMPTIVE, BLOCKED_BY_EXCLUSIVE);
/// Query kinds that run regardless of the busy window (trial rules, runtime
/// state): they never reject, so a registry reject would be a rule error.
const FREE_QUERY: KindRule =
    KindRule::new(DOES_NOT_OCCUPY, NON_PREEMPTIVE, NOT_BLOCKED_BY_EXCLUSIVE);

/// The conflict rule of each kind, read by [`JobKind::rule`]. The conflict
/// rules are per kind, not per command, so the table lives here with the
/// shared shapes — a seat declares its kind, gate order and busy flavor, and
/// never a rule that a sibling command's seat could contradict.
pub(crate) fn rule(kind: JobKind) -> KindRule {
    match kind {
        // Exclusive kinds.
        JobKind::Start => OCCUPYING,
        JobKind::Stop => PREEMPTIVE_KIND,
        JobKind::Restart => OCCUPYING,
        JobKind::ApplyConfig => OCCUPYING,
        JobKind::TestConfig => OCCUPYING,
        JobKind::UpdateCore => OCCUPYING,
        JobKind::LatencyProbe => OCCUPYING,
        JobKind::ValidateProfiles => OCCUPYING,
        // Queries.
        JobKind::TestRoute | JobKind::Balancer | JobKind::LoggerRestart => BLOCKED_QUERY,
        JobKind::TrialRules | JobKind::RuntimeState => FREE_QUERY,
    }
}

/// The busy-reject flavour of each exclusive kind, read by the runtime's
/// begin runner: what the runner emits when that kind meets a held busy
/// window. Declared with [`rule`] for the same reason the rules are — a
/// command's rejection is a per-kind fact, so a dispatch arm never carries a
/// copy that could drift from its siblings.
pub(crate) fn exclusive_reject(kind: JobKind) -> ExclusiveReject {
    match kind {
        // Lifecycle spans: no terminal of their own to answer with.
        JobKind::Start | JobKind::Restart => ExclusiveReject::Logged,
        JobKind::Stop => ExclusiveReject::Preempting,
        // The two request/reply kinds answer their requester directly.
        JobKind::TestConfig | JobKind::ValidateProfiles => ExclusiveReject::Reply,
        // The probe's verdict rides its event, tagged by the request.
        JobKind::LatencyProbe => ExclusiveReject::ProbeEvent,
        JobKind::ApplyConfig => ExclusiveReject::ApplyVerdict,
        // The GUI marks the update optimistically, so its reject must settle
        // that view without releasing the owner that rejected it.
        JobKind::UpdateCore => ExclusiveReject::UpdateSettled,
        kind => unreachable!("query kinds never occupy the busy window: {kind:?}"),
    }
}

/// Whether this kind's in-flight task must be left to its own terminal:
/// the worker owns on-disk work that a hard abort would strand — the
/// core-update install runs past the abortable point, and the profile
/// validation's `xray -test` child holds its scratch config open, so Windows
/// cannot delete it under a live reader. Read by the registry's preemptive
/// begin, its lifecycle releases (`JobRegistry::exclusive_runs_to_terminal`),
/// and the runtime's shutdown wait: none of them may end such a task.
pub(crate) const fn runs_to_own_terminal(kind: JobKind) -> bool {
    matches!(kind, JobKind::UpdateCore | JobKind::ValidateProfiles)
}

/// Whether this kind's worker polls its record's cancel flag between units
/// of work, so a cooperative cancel must raise it: the profile validation
/// checks it before the first profile and between profiles. A worker without
/// such a boundary (the core-update install) finishes on its own; its landing
/// reads the keep-slot flag instead.
pub(crate) const fn worker_polls_cancel_flag(kind: JobKind) -> bool {
    matches!(kind, JobKind::ValidateProfiles)
}

/// The log record a cooperative (flag-only) cancel leaves behind: the worker
/// observes the flag between units of work and its own terminal releases the
/// record. The busy window stays held until then — never a hard abort, which
/// would strand the artifact the worker owns.
pub(crate) fn cooperative_cancel_log(kind: JobKind, reason: &Diag) -> Diag {
    let key = match kind {
        JobKind::UpdateCore => Key::RtLogUpdateCancelRequested,
        JobKind::ValidateProfiles => Key::RtLogValidationCancelRequested,
        kind => unreachable!(
            "only the kinds that run to their own terminal cancel cooperatively: {kind:?}"
        ),
    };
    Diag::new(key).arg_message(reason.clone())
}

/// Deliver the profile-validation reply terminal (the sidecar parked at
/// begin). Exactly one terminal path may take the sidecar, so a missing or
/// mismatched one is a declaration error.
pub(crate) fn deliver_profile_reply(
    runtime: &mut Runtime,
    sidecar: Option<ExclusiveSidecar>,
    reply: super::ProfileValidationReply,
) {
    match sidecar {
        Some(ExclusiveSidecar::ProfileReply(sender)) => {
            if sender.send(reply).is_err() {
                // Receiver vanished; nothing further is delivered.
            }
            runtime.repaint.request_repaint();
        }
        sidecar => unreachable!(
            "a profile-validation terminal must carry its parked reply sidecar, got {sidecar:?}"
        ),
    }
}

/// Whether an unexpected core exit (or TUN helper transport loss) must
/// cancel this kind's in-flight task and settle its terminal — the three
/// user operations whose result would otherwise be silently dropped.
/// Task-less busy slots (lifecycle spans, a deferred apply-restart, a
/// completed update awaiting readiness) are owned by the normal
/// exit/readiness path, and a profile validation is deliberately absent: its
/// child is independent of the core, and only the worker's own terminal may
/// end its scratch-config lifetime.
pub(crate) const fn cancelled_on_exit(kind: JobKind) -> bool {
    matches!(
        kind,
        JobKind::ApplyConfig | JobKind::TestConfig | JobKind::LatencyProbe
    )
}

/// Deliver the config-test reply terminal (the sidecar parked at begin).
/// Exactly one terminal path may take the sidecar, so a missing or
/// mismatched one is a declaration error.
pub(crate) fn deliver_test_reply(
    runtime: &mut Runtime,
    sidecar: Option<ExclusiveSidecar>,
    verdict: TestConfigReply,
) {
    match sidecar {
        Some(ExclusiveSidecar::TestReply(reply)) => {
            if reply.send(verdict).is_err() {
                // Receiver vanished; nothing further is delivered.
            }
            runtime.repaint.request_repaint();
        }
        sidecar => unreachable!(
            "a config-test terminal must carry its parked reply sidecar, got {sidecar:?}"
        ),
    }
}

/// Deliver one apply failure: exactly one `ApplyResult` settles the config
/// revision the in-flight command carried (parked where its begin put it).
fn deliver_apply_failure(runtime: &mut Runtime, output: ApplyOutput) {
    let revision = runtime.apply_revision;
    runtime.emit(CoreEvt::ApplyResult {
        ok: false,
        output,
        revision,
    });
}

/// Deliver a latency-probe failure with the sidecar's tags (probe:
/// single-flight, so tags pair the terminal back to its request).
fn deliver_probe_failure(
    runtime: &mut Runtime,
    sidecar: Option<ExclusiveSidecar>,
    failure: ProbeFailure,
) {
    match sidecar {
        Some(ExclusiveSidecar::LatencyTags(tags)) => {
            runtime.emit(CoreEvt::LatencyProbe(LatencyProbeResult {
                tags,
                result: Err(failure),
            }));
        }
        sidecar => unreachable!(
            "a latency-probe terminal must carry its parked tags sidecar, got {sidecar:?}"
        ),
    }
}

/// Deliver a core-update failure on the download channel.
fn deliver_update_failure(runtime: &mut Runtime, message: AppMessage) {
    runtime.emit(CoreEvt::Download(DownloadState::Failed(message)));
}

/// Deliver the exactly-one terminal of an exclusive task the runtime just
/// cancelled. The kind's wording and routing are declared here; the caller
/// has already taken the sidecar and stopped the worker. The reason stays a
/// [`Diag`] so the screen renders it in the active language.
pub(crate) fn deliver_cancel_terminal(
    kind: JobKind,
    runtime: &mut Runtime,
    sidecar: Option<ExclusiveSidecar>,
    reason: &Diag,
) {
    match kind {
        JobKind::ApplyConfig => {
            deliver_apply_failure(
                runtime,
                ApplyOutput::Message(AppMessage::from(
                    Diag::new(Key::RtFrameApplyCancelled).arg_message(reason.clone()),
                )),
            );
        }
        JobKind::TestConfig => deliver_test_reply(
            runtime,
            sidecar,
            Err(DiagError::from(
                Diag::new(Key::RtFrameConfigTestCancelled).arg_message(reason.clone()),
            )),
        ),
        JobKind::LatencyProbe => deliver_probe_failure(
            runtime,
            sidecar,
            ProbeFailure::plain(Diag::new(Key::ProbeCancelled).arg_message(reason.clone())),
        ),
        // Defensive: an active validation is cancelled cooperatively (its
        // worker polls the cancel flag) and is outside the exit-cancel set,
        // so no path reaches this arm today. The terminal is kept so a
        // future wiring change degrades to a delivered verdict rather than a
        // panic in the select loop.
        JobKind::ValidateProfiles => deliver_profile_reply(
            runtime,
            sidecar,
            Err(DiagError::from(
                Diag::new(Key::RtFrameProfileValidationCancelled).arg_message(reason.clone()),
            )),
        ),
        // Lifecycle spans cancel to log + release only: their terminal would
        // have ridden the worker's outcome, which the cancel owns.
        JobKind::Start | JobKind::Restart | JobKind::Stop => {}
        // A keep-slot core-update install is never aborted by a cancel path
        // (the flag-only path returns before this point).
        JobKind::UpdateCore => unreachable!(
            "an in-flight core update keeps its slot and never takes the cancel terminal"
        ),
        kind => unreachable!("query kinds never reach the exclusive cancel terminal: {kind:?}"),
    }
}

/// Deliver the exactly-one terminal of an exclusive worker that died
/// without a result (panic or join failure).
pub(crate) fn deliver_join_error_terminal(
    kind: JobKind,
    runtime: &mut Runtime,
    sidecar: Option<ExclusiveSidecar>,
    message: Diag,
) {
    match kind {
        JobKind::TestConfig => deliver_test_reply(runtime, sidecar, Err(DiagError::from(message))),
        JobKind::ValidateProfiles => {
            deliver_profile_reply(runtime, sidecar, Err(DiagError::from(message)))
        }
        JobKind::UpdateCore => deliver_update_failure(runtime, AppMessage::from(message)),
        JobKind::ApplyConfig => {
            deliver_apply_failure(runtime, ApplyOutput::Message(AppMessage::from(message)));
        }
        JobKind::LatencyProbe => {
            deliver_probe_failure(runtime, sidecar, ProbeFailure::plain(message));
        }
        JobKind::Start | JobKind::Restart => {
            runtime.set_phase(CorePhase::Error(PhaseError::new(message)))
        }
        JobKind::Stop => {}
        kind => unreachable!("query kinds never reach the exclusive task branch: {kind:?}"),
    }
}

/// `CoreCmd::TestRoute`: the running core's verdict for one routing context.
pub(crate) struct RouteTestSeat {
    pub(crate) request: RouteTestRequest,
}

impl QuerySeat for RouteTestSeat {
    type Payload = String;
    type Prepared = router_cmd::RoutingContext;

    const KIND: JobKind = JobKind::TestRoute;
    const GATE: GateOrder = GateOrder::BusyFirst;
    const BUSY: BusyReject = BusyReject::Logged;

    fn gate(&self, runtime: &Runtime) -> Result<router_cmd::RoutingContext, DiagError> {
        if !matches!(runtime.phase, CorePhase::Running) {
            return Err(DiagError::from(Diag::new(Key::SeatCoreNotRunning)));
        }
        routing_context(&self.request)
            .map_err(|error| DiagError::new(Diag::new(Key::SeatInvalidRouteTest)).caused_by(error))
    }

    async fn call(
        self,
        grpc: &GrpcClient,
        context: router_cmd::RoutingContext,
    ) -> Result<String, DiagError> {
        grpc.test_route(context)
            .await
            .map_err(|error| DiagError::new(Diag::new(Key::GrpcTestRouteFailed)).caused_by(error))
    }
}

/// `CoreCmd::GetBalancerInfo`: one balancer's live ephemeral state.
pub(crate) struct BalancerInfoSeat {
    pub(crate) balancer_tag: String,
}

impl QuerySeat for BalancerInfoSeat {
    type Payload = super::BalancerInfoView;
    type Prepared = ();

    const KIND: JobKind = JobKind::Balancer;
    const GATE: GateOrder = GateOrder::AvailabilityFirst;
    const BUSY: BusyReject = BusyReject::Text;

    fn gate(&self, runtime: &Runtime) -> Result<(), DiagError> {
        if !matches!(runtime.phase, CorePhase::Running) {
            return Err(DiagError::from(Diag::new(Key::SeatCoreNotRunning)));
        }
        if self.balancer_tag.is_empty() {
            return Err(DiagError::from(Diag::new(Key::SeatBalancerTagRequired)));
        }
        Ok(())
    }

    async fn call(
        self,
        grpc: &GrpcClient,
        _prepared: (),
    ) -> Result<super::BalancerInfoView, DiagError> {
        grpc.get_balancer_info(&self.balancer_tag).await
    }
}

/// `CoreCmd::SetBalancerOverride`: pin one balancer to an exact outbound tag.
pub(crate) struct SetBalancerOverrideSeat {
    pub(crate) balancer_tag: String,
    pub(crate) target: String,
}

impl QuerySeat for SetBalancerOverrideSeat {
    type Payload = ();
    type Prepared = ();

    const KIND: JobKind = JobKind::Balancer;
    const GATE: GateOrder = GateOrder::AvailabilityFirst;
    const BUSY: BusyReject = BusyReject::Text;

    fn gate(&self, runtime: &Runtime) -> Result<(), DiagError> {
        if !matches!(runtime.phase, CorePhase::Running) {
            return Err(DiagError::from(Diag::new(Key::SeatCoreNotRunning)));
        }
        if self.balancer_tag.is_empty() {
            return Err(DiagError::from(Diag::new(Key::SeatBalancerTagRequired)));
        }
        if self.target.is_empty() {
            return Err(DiagError::from(Diag::new(Key::SeatOverrideTargetRequired)));
        }
        Ok(())
    }

    async fn call(self, grpc: &GrpcClient, _prepared: ()) -> Result<(), DiagError> {
        grpc.override_balancer_target(&self.balancer_tag, &self.target)
            .await
            .map_err(|error| {
                balancer_status_diag(Key::GrpcBalancerOverrideFailed, &self.balancer_tag, error)
            })
    }
}

/// `CoreCmd::ClearBalancerOverride`: let the balancer's strategy choose again.
pub(crate) struct ClearBalancerOverrideSeat {
    pub(crate) balancer_tag: String,
}

impl QuerySeat for ClearBalancerOverrideSeat {
    type Payload = ();
    type Prepared = ();

    const KIND: JobKind = JobKind::Balancer;
    const GATE: GateOrder = GateOrder::AvailabilityFirst;
    const BUSY: BusyReject = BusyReject::Text;

    fn gate(&self, runtime: &Runtime) -> Result<(), DiagError> {
        if !matches!(runtime.phase, CorePhase::Running) {
            return Err(DiagError::from(Diag::new(Key::SeatCoreNotRunning)));
        }
        if self.balancer_tag.is_empty() {
            return Err(DiagError::from(Diag::new(Key::SeatBalancerTagRequired)));
        }
        Ok(())
    }

    async fn call(self, grpc: &GrpcClient, _prepared: ()) -> Result<(), DiagError> {
        grpc.override_balancer_target(&self.balancer_tag, "")
            .await
            .map_err(|error| {
                balancer_status_diag(
                    Key::GrpcBalancerOverrideClearFailed,
                    &self.balancer_tag,
                    error,
                )
            })
    }
}

/// `CoreCmd::RestartLogger`: reopen the core's configured log outputs.
pub(crate) struct RestartLoggerSeat;

impl QuerySeat for RestartLoggerSeat {
    type Payload = ();
    type Prepared = ();

    const KIND: JobKind = JobKind::LoggerRestart;
    const GATE: GateOrder = GateOrder::AvailabilityFirst;
    const BUSY: BusyReject = BusyReject::Text;

    fn gate(&self, runtime: &Runtime) -> Result<(), DiagError> {
        if !matches!(runtime.phase, CorePhase::Running) {
            return Err(DiagError::from(Diag::new(Key::SeatCoreNotRunning)));
        }
        Ok(())
    }

    async fn call(self, grpc: &GrpcClient, _prepared: ()) -> Result<(), DiagError> {
        grpc.restart_logger().await.map_err(|error| {
            DiagError::new(Diag::new(Key::GrpcRestartLoggerFailed)).caused_by(error)
        })
    }
}

/// `CoreCmd::AddTrialRule`: inject one ephemeral rule and report the
/// read-back verdict on the live rule inventory.
pub(crate) struct AddTrialRuleSeat {
    pub(crate) rule: Rule,
}

impl QuerySeat for AddTrialRuleSeat {
    type Payload = TrialRuleAddOutcome;
    type Prepared = router_cfg::RoutingRule;

    const KIND: JobKind = JobKind::TrialRules;
    const GATE: GateOrder = GateOrder::AvailabilityFirst;
    const BUSY: BusyReject = BusyReject::Impossible;
    // The add is append-mode, and the read-back after it is the only
    // authority on what the core holds: aborting that read-back would report
    // a cancelled add for a rule the core may already have, and make a retry
    // duplicate it. The task therefore always runs to its own terminal.
    const RUNS_TO_OWN_TERMINAL: bool = true;

    fn gate(&self, runtime: &Runtime) -> Result<router_cfg::RoutingRule, DiagError> {
        if !matches!(runtime.phase, CorePhase::Running) {
            return Err(DiagError::from(Diag::new(Key::SeatCoreNotRunning)));
        }
        trial_rule_to_pb(&self.rule)
            .map_err(|error| DiagError::new(Diag::new(Key::SeatInvalidTrialRule)).caused_by(error))
    }

    async fn call(
        self,
        grpc: &GrpcClient,
        rule_pb: router_cfg::RoutingRule,
    ) -> Result<TrialRuleAddOutcome, DiagError> {
        // The prepared payload carries this same tag; the seat's own copy
        // survives the move into the request.
        let rule_tag = self.rule.rule_tag;
        let add = grpc
            .add_rule(
                router_cfg::Config {
                    rule: vec![rule_pb],
                    ..Default::default()
                },
                true,
            )
            .await;
        // Issued even after a failed add: the core may have applied the rule
        // before the reply was lost, and the read-back settles which.
        let list = grpc.list_rules().await;
        add_rule_outcome(&rule_tag, add, list)
    }
}

/// `CoreCmd::RemoveTrialRule`: drop every live rule with one tag and report
/// the refreshed live rule list.
pub(crate) struct RemoveTrialRuleSeat {
    pub(crate) rule_tag: String,
}

impl QuerySeat for RemoveTrialRuleSeat {
    type Payload = Vec<(String, String)>;
    type Prepared = ();

    const KIND: JobKind = JobKind::TrialRules;
    const GATE: GateOrder = GateOrder::AvailabilityFirst;
    const BUSY: BusyReject = BusyReject::Impossible;
    // The removal is already live server-side once `remove_rule` returns;
    // aborting the following `list_rules` read-back would report a
    // cancelled removal for a rule that is gone.
    const RUNS_TO_OWN_TERMINAL: bool = true;

    fn gate(&self, runtime: &Runtime) -> Result<(), DiagError> {
        if !matches!(runtime.phase, CorePhase::Running) {
            return Err(DiagError::from(Diag::new(Key::SeatCoreNotRunning)));
        }
        if self.rule_tag.is_empty() {
            return Err(DiagError::from(Diag::new(Key::SeatRuleTagRequired)));
        }
        Ok(())
    }

    async fn call(
        self,
        grpc: &GrpcClient,
        _prepared: (),
    ) -> Result<Vec<(String, String)>, DiagError> {
        async {
            grpc.remove_rule(&self.rule_tag).await?;
            grpc.list_rules().await
        }
        .await
        .map_err(|error| DiagError::new(Diag::new(Key::GrpcRemoveRuleFailed)).caused_by(error))
    }
}

/// `CoreCmd::ListTrialRules`: refresh the live rule inventory.
pub(crate) struct ListTrialRulesSeat;

impl QuerySeat for ListTrialRulesSeat {
    type Payload = Vec<(String, String)>;
    type Prepared = ();

    const KIND: JobKind = JobKind::TrialRules;
    const GATE: GateOrder = GateOrder::AvailabilityFirst;
    const BUSY: BusyReject = BusyReject::Impossible;

    fn gate(&self, runtime: &Runtime) -> Result<(), DiagError> {
        if !matches!(runtime.phase, CorePhase::Running) {
            return Err(DiagError::from(Diag::new(Key::SeatCoreNotRunning)));
        }
        Ok(())
    }

    async fn call(
        self,
        grpc: &GrpcClient,
        _prepared: (),
    ) -> Result<Vec<(String, String)>, DiagError> {
        grpc.list_rules()
            .await
            .map_err(|error| DiagError::new(Diag::new(Key::GrpcListRulesFailed)).caused_by(error))
    }
}

/// `CoreCmd::ListRuntimeState`: the running core's live inbounds/outbounds.
pub(crate) struct ListRuntimeStateSeat;

impl QuerySeat for ListRuntimeStateSeat {
    type Payload = RuntimeStateView;
    type Prepared = ();

    const KIND: JobKind = JobKind::RuntimeState;
    const GATE: GateOrder = GateOrder::AvailabilityFirst;
    const BUSY: BusyReject = BusyReject::Impossible;

    fn gate(&self, runtime: &Runtime) -> Result<(), DiagError> {
        if !matches!(runtime.phase, CorePhase::Running) {
            return Err(DiagError::from(Diag::new(Key::SeatCoreNotRunning)));
        }
        Ok(())
    }

    async fn call(self, grpc: &GrpcClient, _prepared: ()) -> Result<RuntimeStateView, DiagError> {
        async {
            let inbounds = grpc.list_inbounds().await?;
            let outbounds = grpc.list_outbounds().await?;
            Ok::<RuntimeStateView, tonic::Status>(RuntimeStateView {
                inbounds,
                outbounds,
            })
        }
        .await
        .map_err(|error| DiagError::new(Diag::new(Key::GrpcRuntimeStateFailed)).caused_by(error))
    }
}

impl Runtime {
    /// Run one accepted query job: the reply guard (exactly-one terminal on
    /// every death path), the conflict check with its seat-declared reject
    /// flavor, the availability gate, the `grpc`/`repaint` clones, the spawn,
    /// the terminal send, and the abort registration. A seat that declares
    /// [`QuerySeat::RUNS_TO_OWN_TERMINAL`] registers its task so completion
    /// is still provable to the lazy sweep, but no cancel path aborts it.
    pub(crate) async fn run_query<Seat: QuerySeat>(
        &mut self,
        seat: Seat,
        reply: oneshot::Sender<Result<Seat::Payload, DiagError>>,
    ) {
        let guard = ReplyGuard::new(reply, Err(runtime_stopping()));

        // Availability-first seats reject before a record exists. The
        // busy-first seat checks the window first and runs its gate after
        // the begin below, where a gate rejection finishes the record again.
        let prepared = if Seat::GATE == GateOrder::AvailabilityFirst {
            match seat.gate(self) {
                Ok(prepared) => Some(prepared),
                Err(error) => return self.reject_query::<Seat>(guard, error),
            }
        } else {
            None
        };

        let id = match self.jobs.try_begin(Seat::KIND) {
            Ok(id) => id,
            Err(Busy { active }) => return self.reject_query_busy::<Seat>(guard, active),
        };

        let prepared = match prepared {
            Some(prepared) => prepared,
            // Busy-first: the gate runs after the begin, so a rejection
            // finishes the record again before answering.
            None => match seat.gate(self) {
                Ok(prepared) => prepared,
                Err(error) => {
                    // A query id addresses a concurrent record, so the
                    // concurrent release is the only correct one here.
                    self.jobs.finish_concurrent(id);
                    return self.reject_query::<Seat>(guard, error);
                }
            },
        };

        let grpc = self.grpc.clone();
        let repaint = self.repaint.clone();
        let task = tokio::spawn(async move {
            let result = seat.call(&grpc, prepared).await;
            let _ = guard.send(result);
            repaint.request_repaint();
        });
        if Seat::RUNS_TO_OWN_TERMINAL {
            self.jobs.set_abort_keep_running(id, task.abort_handle());
        } else {
            self.jobs.set_abort(id, task.abort_handle());
        }
    }

    /// Answer a query rejection on its reply channel and wake the requester.
    fn reject_query<Seat: QuerySeat>(
        &mut self,
        guard: ReplyGuard<Result<Seat::Payload, DiagError>>,
        error: DiagError,
    ) {
        let _ = guard.send(Err(error));
        self.repaint.request_repaint();
    }

    /// Answer the registry's busy-window reject with the seat's declared
    /// flavor: the route test logs the shared busy line, the ceremony-ladder
    /// queries stay silent, and a kind whose rule never checks the window
    /// fails loudly rather than dropping the request.
    fn reject_query_busy<Seat: QuerySeat>(
        &mut self,
        guard: ReplyGuard<Result<Seat::Payload, DiagError>>,
        active: JobKind,
    ) {
        let error = match Seat::BUSY {
            BusyReject::Logged => {
                let output = Self::busy_reject_text(active);
                self.app_log(output.clone());
                DiagError::from(output)
            }
            BusyReject::Text => DiagError::from(
                Diag::new(Key::SeatBusyWithOperation).arg_message(occupant_name(active)),
            ),
            BusyReject::Impossible => unreachable!(
                "{:?} never checks the busy window (rule table); the registry cannot reject it",
                Seat::KIND
            ),
        };
        self.reject_query::<Seat>(guard, error);
    }
}
