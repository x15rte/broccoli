//! Pure decision rules of the core lifecycle.
//!
//! Every function here maps observed facts — exit codes and captured output,
//! TUN ownership, elapsed instants, attempt counters — to one decision of the
//! readiness / retry / rollback machine. None of them reads a clock, spawns a
//! process, touches the filesystem, or holds hidden state: the call sites in
//! [`super`] and [`super::state`] own every side effect and hand the facts
//! in. The one exception is the attempt counter [`spend_retry_attempt`] takes
//! as an explicit in/out parameter. That split is what lets the boundary
//! cases — deadline hit or not, retry budget spent or not, bind race
//! classified or not, rollback armable or not — be exercised with plain
//! values, without a real child and without real time.
//!
//! These rules are the single home for decisions the exit, readiness and
//! retry paths used to spell inline at each call site.

use std::time::{Duration, Instant};

/// Cold-start readiness deadline.
pub(super) const READY_TIMEOUT: Duration = Duration::from_secs(10);
/// Readiness deadline for a start that carries a freshly applied config.
pub(super) const READY_TIMEOUT_APPLIED: Duration = Duration::from_secs(3);
/// Delay before an automatic retry of a pre-readiness candidate (a freshly
/// applied config, or an updated core under its health-gate start). A fresh
/// apply restarts the core while the previous wintun adapter (and its
/// gateway address) is still tearing down, so the retry waits the teardown
/// window out; the dns-in bind race draws on the same delay for each of its
/// extra attempts ([`TUN_BIND_RACE_RETRIES`]) — the update candidate retries
/// on that race signature only.
pub(super) const CANDIDATE_RETRY_DELAY: Duration = Duration::from_millis(2000);
/// Extra automatic retries for the TUN dns-in bind race. Xray starts tagged
/// inbounds in Go map order, so in a fraction of cold TUN starts the dns-in
/// dokodemo (listening on the TUN gateway, port 53) is started before the
/// tun inbound assigned the gateway address, and the core dies pre-readiness
/// ("failed to listen TCP on 53 … The requested address is not valid in its
/// context"; measured on the pinned core: 7/72 launches across two probe
/// shapes). The order re-rolls in every fresh process, so three extra
/// attempts cut the user-visible rate to roughly `(1/8)^4`.
pub(super) const TUN_BIND_RACE_RETRIES: u8 = 3;

/// Automatic add attempts for the in-tun DNS listener a running TUN core
/// needs ([`super::dns_in`]): the listener binds the TUN gateway, an address
/// the core's tun inbound assigns while its start is still in flight, so
/// early attempts may race the adapter create. At the listener's retry
/// cadence the budget spans roughly ten seconds; the add is best-effort, so
/// a spent budget logs and leaves the core running.
pub(super) const DNS_IN_ADD_ATTEMPTS: u8 = 20;

/// Xray's process exit code for a config-load failure.
const CONFIG_ERROR_EXIT_CODE: i32 = 23;

/// True when the captured pre-readiness output carries the dns-in bind-race
/// signature: the dokodemo's port-53 listener failed because the TUN gateway
/// address did not exist yet. The ` > ` before the wrapped cause is Xray's
/// error-chain separator; if a future core changes it, the signature
/// degrades to the single generic retry — never to a wrong retry.
fn dns_in_bind_race(captured: &str) -> bool {
    captured.contains("failed to listen TCP on 53 >")
}

/// Pre-readiness failure kinds of a TUN-owned boot that are transient enough
/// to earn an automatic retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PreReadinessFailure {
    /// The dns-in dokodemo's port-53 listener started before the tun inbound
    /// assigned the TUN gateway address. Xray starts tagged inbounds in Go
    /// map order, so the order re-rolls in every fresh process and a
    /// multi-attempt budget is worth spending ([`TUN_BIND_RACE_RETRIES`]).
    DnsInBindRace,
    /// Any other pre-readiness exit of a TUN-owned boot: the adapter teardown
    /// window of a fresh apply. One retry past the window; a second non-race
    /// failure is a real config fault.
    AdapterTeardown,
}

/// Classify one pre-readiness candidate exit from the facts the exit path
/// already holds: the TUN ownership of the backend that just exited and its
/// captured output excerpt. A direct (non-TUN) exit never classifies — the
/// same port-53 listener text there can only come from a user-configured
/// inbound on port 53, and retrying it would merely delay the correct
/// rollback.
pub(super) fn classify_pre_readiness_exit(
    tun_owned: bool,
    captured: &str,
) -> Option<PreReadinessFailure> {
    if !tun_owned {
        return None;
    }
    Some(if dns_in_bind_race(captured) {
        PreReadinessFailure::DnsInBindRace
    } else {
        PreReadinessFailure::AdapterTeardown
    })
}

/// Automatic retry budget for a config-apply candidate that exited before
/// readiness, given the classified failure: none without a TUN-owned boot
/// (a direct start has no adapter teardown window to wait out), one for the
/// adapter teardown window, and the full race budget for the dns-in bind
/// race.
pub(super) fn candidate_retry_budget(failure: Option<PreReadinessFailure>) -> u8 {
    match failure {
        Some(PreReadinessFailure::DnsInBindRace) => TUN_BIND_RACE_RETRIES,
        Some(PreReadinessFailure::AdapterTeardown) => 1,
        None => 0,
    }
}

/// Whether an updated-core health-gate exit may draw on the bind-race retry
/// budget. Only the dns-in bind race on a TUN-owned boot qualifies — the
/// order re-rolls per process, so a fresh attempt can come up healthy; every
/// other pre-readiness failure rolls the update back immediately.
pub(super) fn update_retries_bind_race(tun_owned: bool, captured: &str) -> bool {
    matches!(
        classify_pre_readiness_exit(tun_owned, captured),
        Some(PreReadinessFailure::DnsInBindRace)
    )
}

/// Spend one attempt from a retry budget, returning the attempt number while
/// inside it. Both pre-readiness candidate paths cap through this single
/// rule so their counters cannot drift apart.
pub(super) fn spend_retry_attempt(spent: &mut u8, budget: u8) -> Option<u8> {
    if *spent >= budget {
        return None;
    }
    *spent += 1;
    Some(*spent)
}

/// Whether an exit-23 startup failure may retry once from the last known-good
/// config: only while the one-shot retry is unspent and a last-good config
/// exists.
pub(super) fn config_error_retry_eligible(retry_spent: bool, lastgood_present: bool) -> bool {
    !retry_spent && lastgood_present
}

/// Rollback-arming gate shared by the config-apply and core-update groups:
/// only an unproven candidate may arm a rollback, and only while none is
/// armed already (a second pre-readiness exit must not replace the retained
/// reason). What each group then does to its candidate marker stays with its
/// own state type.
pub(super) fn rollback_armable(candidate_pending: bool, rollback_armed: bool) -> bool {
    candidate_pending && !rollback_armed
}

/// Which readiness clock a start arms. A direct start carrying a freshly
/// applied candidate uses the short applied clock; every other start uses the
/// cold-start clock. A TUN start never takes the short clock: its wintun
/// adapter create legitimately waits out the previous session's teardown
/// (observed ~3 s stall), and killing a core stuck mid-create wedges PnP
/// device creation for every wintun user.
pub(super) fn readiness_timeout(applied_candidate_pending: bool, tun_owned: bool) -> Duration {
    if applied_candidate_pending && !tun_owned {
        READY_TIMEOUT_APPLIED
    } else {
        READY_TIMEOUT
    }
}

/// Whether one helper state report may start the readiness clock. `starting`
/// is the spawn confirmation (the xray child was spawned and attached to its
/// kill-on-close job); it arms only an unarmed clock. Every other state is
/// informational — readiness itself comes from the gRPC poll.
pub(super) fn helper_state_arms_readiness(state: &str, deadline_armed: bool) -> bool {
    state == "starting" && !deadline_armed
}

/// Whether an armed readiness deadline has fired. The boundary counts as
/// fired: the poll compares `now >= deadline`.
pub(super) fn readiness_deadline_reached(deadline: Instant, now: Instant) -> bool {
    now >= deadline
}

/// Which handler owns an armed readiness deadline that fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadinessTimeout {
    /// A freshly applied candidate never became ready: arm its rollback and
    /// stop the child.
    AppliedCandidate,
    /// An updated-core health gate never became ready: arm its rollback and
    /// stop the child.
    UpdatedCore,
    /// No candidate owns the deadline: a plain start timed out. The phase
    /// reports the terminal record and the exit path is silenced.
    Unclaimed,
}

/// Classify a fired readiness deadline by the candidate it belongs to. The
/// config-apply candidate wins first; an update candidate owns the timeout
/// only while none of its rollbacks is armed — once armed, the confirmed
/// exit path already owns the verdict.
pub(super) fn readiness_timeout_verdict(
    applied_candidate_pending: bool,
    update_candidate_pending: bool,
    update_rollback_armed: bool,
) -> ReadinessTimeout {
    if applied_candidate_pending {
        ReadinessTimeout::AppliedCandidate
    } else if update_candidate_pending && !update_rollback_armed {
        ReadinessTimeout::UpdatedCore
    } else {
        ReadinessTimeout::Unclaimed
    }
}

/// The recorded intent for the in-flight expected exit, as observed by the
/// exit classifier: the policy's variant without its recorded instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExitIntent {
    /// No expected exit: this exit is unexpected.
    Idle,
    /// A plain stop was requested.
    Stop,
    /// A restart was requested (implies a stop).
    Restart,
    /// A stop whose phase record was already reported by the error path.
    Silenced,
}

/// Which branch of the confirmed-exit handler owns one exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExitBranch {
    /// An armed config-apply rollback: complete it.
    ConfigRollback,
    /// An armed core-update rollback: complete it.
    CoreRollback,
    /// A silenced stop: finish the policy and release the operation.
    Silenced,
    /// A requested restart: queue the replacement now the exit is confirmed.
    RestartQueued,
    /// A requested plain stop: settle into the stopped state.
    StopSettled,
    /// A pending config-apply candidate exited before readiness: retry or
    /// roll back per the pre-readiness rules.
    CandidatePreReadiness,
    /// A pending core-update candidate exited before readiness.
    UpdatePreReadiness,
    /// Exit 23 outside both candidate paths: the startup config error.
    ConfigError,
    /// Any other unexpected exit: exponential backoff with jitter.
    Backoff,
}

/// The observed facts of one confirmed core exit, exactly what the exit
/// classifier reads. Every field is a value the exit handler already holds
/// when the old child's exit is confirmed.
#[derive(Debug, Clone, Copy)]
pub(super) struct CoreExitFacts {
    /// A config-apply rollback is armed.
    pub(super) config_rollback_armed: bool,
    /// A core-update rollback is armed.
    pub(super) update_rollback_armed: bool,
    /// The recorded intent for this expected exit.
    pub(super) intent: ExitIntent,
    /// A freshly applied config candidate is unproven.
    pub(super) config_candidate_pending: bool,
    /// An updated-core health-gate candidate is unproven.
    pub(super) update_candidate_pending: bool,
    /// The runtime is in its starting phase.
    pub(super) starting: bool,
    /// The exit code the platform reported, if any.
    pub(super) code: Option<i32>,
}

/// Classify one confirmed exit into the handler branch that owns it. The
/// precedence is the rollback/retry machine's rule: armed rollbacks first
/// (config, then update), then a silenced stop, then a requested
/// restart/stop, then the two pre-readiness candidates, then the exit-23
/// config error, and finally the backoff restart.
pub(super) fn classify_core_exit(facts: CoreExitFacts) -> ExitBranch {
    if facts.config_rollback_armed {
        return ExitBranch::ConfigRollback;
    }
    if facts.update_rollback_armed {
        return ExitBranch::CoreRollback;
    }
    match facts.intent {
        ExitIntent::Silenced => return ExitBranch::Silenced,
        ExitIntent::Restart => return ExitBranch::RestartQueued,
        ExitIntent::Stop => return ExitBranch::StopSettled,
        ExitIntent::Idle => {}
    }
    if facts.config_candidate_pending {
        return ExitBranch::CandidatePreReadiness;
    }
    if facts.update_candidate_pending && facts.starting {
        return ExitBranch::UpdatePreReadiness;
    }
    if facts.code == Some(CONFIG_ERROR_EXIT_CODE) {
        return ExitBranch::ConfigError;
    }
    ExitBranch::Backoff
}

/// Verbatim pre-readiness output of the pinned core when the dns-in
/// dokodemo's port-53 listener started before the tun inbound had assigned
/// the TUN gateway address (Go map-order start; see
/// [`TUN_BIND_RACE_RETRIES`]). Shared with the runtime's in-module tests so
/// the recorded race signature has one home.
#[cfg(test)]
pub(super) const DNS_IN_BIND_RACE_LINE: &str = "Failed to start: app/proxyman/inbound: failed to listen TCP on 53 > \
transport/internet: failed to listen on address: 10.255.0.1:53 > transport/internet/tcp: failed to listen TCP on \
10.255.0.1:53 > listen tcp 10.255.0.1:53: bind: The requested address is not valid in its context.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_in_bind_race_signature_is_exact() {
        assert!(dns_in_bind_race(DNS_IN_BIND_RACE_LINE));
        assert!(!dns_in_bind_race(""));
        assert!(!dns_in_bind_race("no core output captured"));
        assert!(
            !dns_in_bind_race("failed to listen TCP on 5353 > transport/internet: boom"),
            "another port must not match the race signature"
        );
        assert!(
            !dns_in_bind_race("failed to listen TCP on 10808 > transport/internet: boom"),
            "listener conflicts elsewhere keep the single generic retry"
        );
    }

    #[test]
    fn pre_readiness_classification_is_tun_gated() {
        assert_eq!(
            classify_pre_readiness_exit(true, DNS_IN_BIND_RACE_LINE),
            Some(PreReadinessFailure::DnsInBindRace)
        );
        assert_eq!(
            classify_pre_readiness_exit(true, "panic: boom"),
            Some(PreReadinessFailure::AdapterTeardown)
        );
        assert_eq!(
            classify_pre_readiness_exit(true, ""),
            Some(PreReadinessFailure::AdapterTeardown),
            "an output-less TUN exit still gets the teardown retry"
        );
        assert_eq!(
            classify_pre_readiness_exit(false, DNS_IN_BIND_RACE_LINE),
            None,
            "a direct mode listener conflict never classifies as the race"
        );
        assert_eq!(classify_pre_readiness_exit(false, ""), None);
    }

    #[test]
    fn retry_budgets_match_the_classified_failure() {
        assert_eq!(candidate_retry_budget(None), 0);
        assert_eq!(
            candidate_retry_budget(Some(PreReadinessFailure::AdapterTeardown)),
            1
        );
        assert_eq!(
            candidate_retry_budget(Some(PreReadinessFailure::DnsInBindRace)),
            TUN_BIND_RACE_RETRIES
        );
        let race_budget = candidate_retry_budget(Some(PreReadinessFailure::DnsInBindRace));
        let teardown_budget = candidate_retry_budget(Some(PreReadinessFailure::AdapterTeardown));
        assert!(
            race_budget > teardown_budget,
            "the race budget must exceed the generic retry, or a fresh Go-map-order roll would not be drawn"
        );
    }

    #[test]
    fn retry_attempt_spend_is_bounded_and_never_overdraws() {
        let mut spent = 0;
        assert_eq!(spend_retry_attempt(&mut spent, 0), None);
        assert_eq!(spent, 0, "a zero budget must not spend an attempt");
        assert_eq!(spend_retry_attempt(&mut spent, 1), Some(1));
        assert_eq!(spend_retry_attempt(&mut spent, 1), None);
        assert_eq!(spent, 1, "an exhausted budget must stay put");

        let mut spent = TUN_BIND_RACE_RETRIES - 1;
        assert_eq!(
            spend_retry_attempt(&mut spent, TUN_BIND_RACE_RETRIES),
            Some(TUN_BIND_RACE_RETRIES)
        );
        assert_eq!(spend_retry_attempt(&mut spent, TUN_BIND_RACE_RETRIES), None);
        assert_eq!(spent, TUN_BIND_RACE_RETRIES);
    }

    #[test]
    fn update_retry_is_the_bind_race_on_tun_only() {
        assert!(update_retries_bind_race(true, DNS_IN_BIND_RACE_LINE));
        assert!(!update_retries_bind_race(true, "panic: boom"));
        assert!(!update_retries_bind_race(true, ""));
        assert!(
            !update_retries_bind_race(false, DNS_IN_BIND_RACE_LINE),
            "the retry is TUN-gated on both candidate paths"
        );
    }

    #[test]
    fn one_shot_config_error_retry_needs_a_lastgood() {
        assert!(config_error_retry_eligible(false, true));
        assert!(
            !config_error_retry_eligible(true, true),
            "the last-good retry is one-shot"
        );
        assert!(!config_error_retry_eligible(false, false));
        assert!(!config_error_retry_eligible(true, false));
    }

    #[test]
    fn rollback_armable_needs_a_candidate_and_an_empty_gate() {
        assert!(rollback_armable(true, false));
        assert!(
            !rollback_armable(true, true),
            "an armed rollback must reject a second arm"
        );
        assert!(!rollback_armable(false, false), "nothing to roll back");
        assert!(!rollback_armable(false, true));
    }

    #[test]
    fn readiness_clock_depends_on_candidate_and_transport() {
        assert_eq!(readiness_timeout(true, false), READY_TIMEOUT_APPLIED);
        assert_eq!(readiness_timeout(false, false), READY_TIMEOUT);
        assert_eq!(
            readiness_timeout(true, true),
            READY_TIMEOUT,
            "a TUN applied start must keep the cold-start clock"
        );
        assert_eq!(readiness_timeout(false, true), READY_TIMEOUT);
        assert!(READY_TIMEOUT > READY_TIMEOUT_APPLIED);
    }

    #[test]
    fn readiness_deadline_fires_at_the_boundary() {
        let deadline = Instant::now();
        assert!(!readiness_deadline_reached(
            deadline,
            deadline - Duration::from_millis(1)
        ));
        assert!(readiness_deadline_reached(deadline, deadline));
        assert!(readiness_deadline_reached(
            deadline,
            deadline + Duration::from_millis(1)
        ));
    }

    #[test]
    fn helper_state_arms_only_starting_and_only_unarmed() {
        assert!(helper_state_arms_readiness("starting", false));
        assert!(
            !helper_state_arms_readiness("starting", true),
            "a repeated report must not re-arm the clock"
        );
        assert!(!helper_state_arms_readiness("running", false));
        assert!(!helper_state_arms_readiness("stopped", false));
    }

    #[test]
    fn readiness_timeout_verdict_prefers_the_applied_candidate() {
        assert_eq!(
            readiness_timeout_verdict(true, false, false),
            ReadinessTimeout::AppliedCandidate
        );
        assert_eq!(
            readiness_timeout_verdict(true, true, false),
            ReadinessTimeout::AppliedCandidate
        );
        assert_eq!(
            readiness_timeout_verdict(true, true, true),
            ReadinessTimeout::AppliedCandidate
        );
        assert_eq!(
            readiness_timeout_verdict(false, true, false),
            ReadinessTimeout::UpdatedCore
        );
        assert_eq!(
            readiness_timeout_verdict(false, true, true),
            ReadinessTimeout::Unclaimed,
            "an armed rollback already owns the exit verdict"
        );
        assert_eq!(
            readiness_timeout_verdict(false, false, false),
            ReadinessTimeout::Unclaimed
        );
    }

    /// Facts with every flag clear; each test overrides only the field it
    /// exercises.
    fn facts() -> CoreExitFacts {
        CoreExitFacts {
            config_rollback_armed: false,
            update_rollback_armed: false,
            intent: ExitIntent::Idle,
            config_candidate_pending: false,
            update_candidate_pending: false,
            starting: false,
            code: None,
        }
    }

    #[test]
    fn armed_rollbacks_win_over_every_later_branch() {
        let mut f = facts();
        f.config_rollback_armed = true;
        f.update_rollback_armed = true;
        f.intent = ExitIntent::Silenced;
        f.config_candidate_pending = true;
        f.update_candidate_pending = true;
        f.starting = true;
        f.code = Some(CONFIG_ERROR_EXIT_CODE);
        assert_eq!(classify_core_exit(f), ExitBranch::ConfigRollback);
        f.config_rollback_armed = false;
        assert_eq!(classify_core_exit(f), ExitBranch::CoreRollback);
    }

    #[test]
    fn exit_intent_owns_the_branch_before_any_candidate() {
        let mut f = facts();
        f.intent = ExitIntent::Silenced;
        f.config_candidate_pending = true;
        assert_eq!(
            classify_core_exit(f),
            ExitBranch::Silenced,
            "a silenced stop already reported its phase"
        );
        f.intent = ExitIntent::Restart;
        assert_eq!(classify_core_exit(f), ExitBranch::RestartQueued);
        f.intent = ExitIntent::Stop;
        assert_eq!(classify_core_exit(f), ExitBranch::StopSettled);
    }

    #[test]
    fn pre_readiness_candidates_outrank_the_config_error_code() {
        let mut f = facts();
        f.code = Some(CONFIG_ERROR_EXIT_CODE);
        f.config_candidate_pending = true;
        assert_eq!(classify_core_exit(f), ExitBranch::CandidatePreReadiness);
        f.config_candidate_pending = false;
        f.update_candidate_pending = true;
        f.starting = true;
        assert_eq!(classify_core_exit(f), ExitBranch::UpdatePreReadiness);
    }

    #[test]
    fn update_candidate_needs_the_starting_phase() {
        let mut f = facts();
        f.update_candidate_pending = true;
        assert_eq!(
            classify_core_exit(f),
            ExitBranch::Backoff,
            "a non-starting update candidate is no health-gate exit"
        );
        f.code = Some(CONFIG_ERROR_EXIT_CODE);
        assert_eq!(classify_core_exit(f), ExitBranch::ConfigError);
    }

    #[test]
    fn config_error_and_backoff_split_on_the_exit_code() {
        assert_eq!(classify_core_exit(facts()), ExitBranch::Backoff);
        let mut f = facts();
        f.code = Some(CONFIG_ERROR_EXIT_CODE);
        assert_eq!(classify_core_exit(f), ExitBranch::ConfigError);
        f.code = Some(1);
        assert_eq!(classify_core_exit(f), ExitBranch::Backoff);
        f.code = None;
        assert_eq!(classify_core_exit(f), ExitBranch::Backoff);
    }
}
