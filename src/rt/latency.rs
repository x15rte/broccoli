use std::collections::{HashMap, VecDeque};
use std::net::TcpListener;
use std::path::Path;
use std::process::ExitStatus;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::diag::Diag;
use crate::r#gen;
use crate::i18n::Key;
use crate::model::ServerProfile;
use crate::model::settings::Language;
use crate::sys;
use crate::sys::netif::ProbeUplink;

use super::grpc::GrpcClient;
use super::supervisor;
use super::{AppLogSink, OutboundStatusView, ProbeFailure};

const POLL_INTERVAL: Duration = Duration::from_millis(250);
const PROBE_DEADLINE: Duration = Duration::from_secs(15);
const CHILD_KILL_WAIT: Duration = Duration::from_secs(2);
const DIAGNOSTIC_TAIL_LINES: usize = 80;
const DIAGNOSTIC_LINE_CHARS: usize = 512;
/// Prefix of every probe scratch directory name — the exact bytes the
/// creator ([`run`]) hands `tempfile` — shared with the startup sweep
/// ([`sweep_stale_probe_dirs`]) so the sweep can never grow a looser idea of
/// what it may delete.
const PROBE_TEMP_PREFIX: &str = "broccoli-latency-probe-";
/// Age bound of the startup probe-scratch sweep: a probe run is bounded to
/// [`PROBE_DEADLINE`] plus its child teardown, so anything a full day old is
/// necessarily a crash or kill leftover. The day-scale mirrors the
/// scratch-config sweep in `rt::profiles`; it stays far above any
/// legitimately live directory, so a parallel probe can never lose its temp
/// dir.
const PROBE_TEMP_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug)]
enum PollOutcome {
    Exited(std::io::Result<ExitStatus>),
    Status(Result<Vec<OutboundStatusView>, tonic::Status>),
}

/// Return a completed snapshot only when every requested tag has an exact row.
/// Observatory selectors are prefix-based, so exact matching is required to
/// prevent a longer selected tag from satisfying a shorter requested tag.
///
/// The response is indexed once per poll rather than rescanned per requested
/// tag, and the rows are returned borrowed: the caller clones them once, at
/// the success site, instead of every poll paying a clone. A repeated tag
/// (which the runtime does not produce) resolves to its first row, exactly
/// the row the previous per-tag `find` returned.
pub(crate) fn complete_statuses<'a>(
    statuses: &'a [OutboundStatusView],
    requested_tags: &[String],
) -> Option<Vec<&'a OutboundStatusView>> {
    let by_tag = rows_by_tag(statuses);
    requested_tags
        .iter()
        .map(|tag| by_tag.get(tag.as_str()).copied())
        .collect()
}

/// Index a snapshot by tag, the first row for a repeated tag winning. The
/// probe's arrival bookkeeping and the completion check share this one rule.
fn rows_by_tag(statuses: &[OutboundStatusView]) -> HashMap<&str, &OutboundStatusView> {
    let mut by_tag: HashMap<&str, &OutboundStatusView> = HashMap::with_capacity(statuses.len());
    for status in statuses {
        by_tag.entry(status.tag.as_str()).or_insert(status);
    }
    by_tag
}

/// Stamp the probe run's captured diagnostics tail onto the dead
/// rows of a completed snapshot. The wall is run-level (one probe run, one
/// child), and only dead rows can surface it — alive rows never carry or
/// render a wall, and an empty tail leaves every row untouched, degrading
/// verdict text to the headline-only shape.
fn with_run_diagnostics(
    mut completed: Vec<OutboundStatusView>,
    tail: &str,
) -> Vec<OutboundStatusView> {
    if !tail.is_empty() {
        for status in completed.iter_mut().filter(|status| !status.alive) {
            status.diagnostics = Some(tail.to_owned());
        }
    }
    completed
}

fn push_diagnostic(tail: &Arc<Mutex<VecDeque<String>>>, line: String, is_stderr: bool) {
    let mut line = line;
    // The byte length bounds the char count from above, so this only walks
    // the string when truncation is actually possible — the common short
    // line never pays a full char scan.
    if line.len() > DIAGNOSTIC_LINE_CHARS
        && let Some((cut, _)) = line.char_indices().nth(DIAGNOSTIC_LINE_CHARS)
    {
        // `cut` is a char boundary after exactly `DIAGNOSTIC_LINE_CHARS`
        // chars, so the prefix is the same text `chars().take(n)` produced,
        // built once into its final allocation.
        let mut truncated = String::with_capacity(cut + 3);
        truncated.push_str(&line[..cut]);
        truncated.push_str("...");
        line = truncated;
    }
    let stream = if is_stderr { "stderr" } else { "stdout" };
    if let Ok(mut tail) = tail.lock() {
        if tail.len() >= DIAGNOSTIC_TAIL_LINES {
            tail.pop_front();
        }
        tail.push_back(format!("[{stream}] {line}"));
    }
}

fn diagnostic_tail(tail: &Arc<Mutex<VecDeque<String>>>) -> String {
    tail.lock()
        .map(|tail| tail.iter().cloned().collect::<Vec<_>>().join("\n"))
        .unwrap_or_default()
}

/// Shape a probe failure: the keyed headline plus the run's captured
/// diagnostics tail, which [`ProbeFailure::full`] renders under the shared
/// wall.
fn probe_failure(headline: Diag, tail: &Arc<Mutex<VecDeque<String>>>) -> ProbeFailure {
    ProbeFailure {
        headline,
        tail: diagnostic_tail(tail),
    }
}

fn exit_description(status: &std::io::Result<ExitStatus>) -> Diag {
    match status {
        Ok(status) => match status.code() {
            Some(code) => Diag::new(Key::ProbeExitStatus).arg(code),
            None => Diag::new(Key::ProbeExitNoStatus),
        },
        Err(error) => Diag::new(Key::ProbeWaitFailed).arg(error),
    }
}

async fn next_poll(
    child: &mut supervisor::Child,
    grpc: &GrpcClient,
    delay: Duration,
) -> PollOutcome {
    let sleeper = tokio::time::sleep(delay);
    tokio::pin!(sleeper);
    tokio::select! {
        exit = child.wait() => PollOutcome::Exited(exit),
        _ = &mut sleeper => {
            tokio::select! {
                exit = child.wait() => PollOutcome::Exited(exit),
                statuses = grpc.outbound_statuses() => PollOutcome::Status(statuses),
            }
        }
    }
}

/// Kill the probe child and wait — bounded by [`CHILD_KILL_WAIT`] — for it to
/// be reaped. Returns whether the exit was confirmed, which is what makes the
/// output pumps safe to join ([`supervisor::Child::drain_output`]): the pipes
/// reach EOF only once the process is gone, so a kill whose reap timed out
/// must not be followed by a drain.
async fn stop_child(child: &mut supervisor::Child) -> bool {
    child.start_kill();
    matches!(
        tokio::time::timeout(CHILD_KILL_WAIT, child.wait()).await,
        Ok(Ok(_))
    )
}

/// Resolve the interface the probe child binds its dials to: the shared TUN
/// uplink rule ([`sys::netif::resolve_probe_uplink`]) rendered as the probe's
/// binding or a loud failure. The TUN adapter's index comes from matching
/// its configured wire name against the enumeration — the match must stay
/// live, since a rename that breaks it silently disables the exclusion. The
/// auto branch reads live OS state.
pub(crate) fn resolve_probe_interface(
    setting: Option<&str>,
    tun_active: bool,
    tun_adapter_name: Option<&str>,
    ifaces: &[sys::netif::NetIf],
) -> Result<Option<String>, ProbeFailure> {
    let tun_self_index = tun_adapter_name
        .and_then(|name| ifaces.iter().find(|iface| iface.name == name))
        .map(|iface| iface.index);
    match sys::netif::resolve_probe_uplink(setting, tun_active, tun_self_index, ifaces) {
        // A Bind NIC request carries an interface while TUN mode is on, but
        // without a live capture it and Native are the same OS path. Falling
        // back to no bind is therefore not a silent route change.
        ProbeUplink::Unbound => Ok(None),
        ProbeUplink::Interface(name) => Ok(Some(name.to_owned())),
        ProbeUplink::TunSelf { name } => Err(ProbeFailure::plain(
            Diag::new(Key::ProbeInterfaceTunSelf).arg(name),
        )),
        ProbeUplink::Down { name } => Err(ProbeFailure::plain(
            Diag::new(Key::ProbeInterfaceDown).arg(name),
        )),
        ProbeUplink::Missing { name } => Err(ProbeFailure::plain(
            Diag::new(Key::ProbeInterfaceMissing).arg(name),
        )),
    }
}

/// Tracks which requested tags the probe has reported, so each arrival is
/// delivered exactly once and a terminal count is available for the strip.
struct ProbeDelivery<F> {
    requested: Vec<String>,
    answered: Vec<bool>,
    done: usize,
    on_status: F,
}

impl<F> ProbeDelivery<F>
where
    F: FnMut(Vec<OutboundStatusView>, usize),
{
    fn new(requested: Vec<String>, on_status: F) -> Self {
        let answered = vec![false; requested.len()];
        Self {
            requested,
            answered,
            done: 0,
            on_status,
        }
    }

    /// Deliver every requested tag that now has an exact row and was not
    /// delivered before, keeping requested order.
    fn offer(&mut self, statuses: &[OutboundStatusView]) {
        // One index per poll instead of a scan per requested tag: the shared
        // first-row-for-a-repeated-tag rule lives in `rows_by_tag`.
        let by_tag = rows_by_tag(statuses);
        let mut fresh = Vec::new();
        for (index, tag) in self.requested.iter().enumerate() {
            if self.answered[index] {
                continue;
            }
            if let Some(status) = by_tag.get(tag.as_str()) {
                self.answered[index] = true;
                fresh.push((*status).clone());
            }
        }
        if !fresh.is_empty() {
            self.done = self.answered.iter().filter(|answered| **answered).count();
            (self.on_status)(fresh, self.done);
        }
    }

    fn all_answered(&self) -> bool {
        self.done == self.requested.len()
    }

    /// Fill every tag that never answered with a dead verdict carrying the
    /// run's failure text: a timeout or an early exit keeps the arrivals and
    /// still says the rest are dead.
    fn report_dead_missing(&mut self, failure: &ProbeFailure) {
        let message = failure.headline.text(Language::En);
        let missing: Vec<OutboundStatusView> = self
            .requested
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.answered[*index])
            .map(|(_, tag)| OutboundStatusView {
                tag: tag.clone(),
                alive: false,
                delay_ms: 0,
                last_error: Some(message.clone()),
                diagnostics: None,
                health_ping: None,
            })
            .collect();
        if !missing.is_empty() {
            self.answered.fill(true);
            self.done = self.requested.len();
            (self.on_status)(missing, self.done);
        }
    }

    /// Requested tags that have not answered yet, in requested order.
    fn unanswered(&self) -> Vec<String> {
        self.requested
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.answered[*index])
            .map(|(_, tag)| tag.clone())
            .collect()
    }
}

/// Run one isolated probe and report each requested tag's status as its row
/// appears. The run keeps going until every tag answered or the deadline
/// expires; any tag the run cannot report — a timeout, an early exit, or a
/// startup failure — is delivered as a dead verdict carrying the run's error,
/// so the caller's write rule always settles every requested profile.
pub(crate) async fn run<F>(
    profiles: &[ServerProfile],
    probe_url: String,
    tun_outbound_interface: Option<String>,
    tun_adapter_name: Option<String>,
    tun_active: bool,
    log: &AppLogSink,
    on_status: F,
) -> Result<Vec<OutboundStatusView>, ProbeFailure>
where
    F: FnMut(Vec<OutboundStatusView>, usize),
{
    let requested: Vec<String> = profiles.iter().map(ServerProfile::tag).collect();
    let mut delivery = ProbeDelivery::new(requested, on_status);
    let result = run_inner(
        profiles,
        probe_url,
        tun_outbound_interface,
        tun_adapter_name,
        tun_active,
        log,
        &mut delivery,
    )
    .await;
    if let Err(failure) = &result {
        delivery.report_dead_missing(failure);
    }
    result
}

async fn run_inner<F>(
    profiles: &[ServerProfile],
    probe_url: String,
    tun_outbound_interface: Option<String>,
    tun_adapter_name: Option<String>,
    tun_active: bool,
    log: &AppLogSink,
    delivery: &mut ProbeDelivery<F>,
) -> Result<Vec<OutboundStatusView>, ProbeFailure>
where
    F: FnMut(Vec<OutboundStatusView>, usize),
{
    // Resolve the TUN outbound interface from a fresh enumeration
    // at probe time, so the binding is current even after an adapter rename.
    // Only binds while the main core is Running and owns the TUN; a fixed
    // name missing from the enumeration fails the probe loudly.
    let interface = resolve_probe_interface(
        tun_outbound_interface.as_deref(),
        tun_active,
        tun_adapter_name.as_deref(),
        &sys::netif::list_all(),
    )?;

    // Defense-in-depth: re-check the probe target before any
    // socket is created or the child is spawned. Config generation validates
    // too, but the execution path must not depend on it.
    if let Some(class) = r#gen::blocked_latency_probe_host_class(&probe_url) {
        return Err(ProbeFailure::plain(
            Diag::new(Key::ProbeHostBlocked).arg(class),
        ));
    }

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| ProbeFailure::plain(Diag::new(Key::ProbePortAllocateFailed).arg(error)))?;
    let api_port = listener
        .local_addr()
        .map_err(|error| ProbeFailure::plain(Diag::new(Key::ProbePortReadFailed).arg(error)))?
        .port();
    drop(listener);

    let config =
        r#gen::generate_latency_probe(profiles, &probe_url, api_port, interface.as_deref())
            .map_err(|error| ProbeFailure::plain(Diag::new(Key::ProbeConfigRejected).arg(error)))?;
    // `TempDir`'s drop removes this directory — and the config with every
    // probed profile's credentials — on every path a run can take
    // (completion, failure, cooperative cancellation), while a crash or kill
    // leaves it for the startup sweep (`sweep_stale_probe_dirs`).
    let tempdir = tempfile::Builder::new()
        .prefix(PROBE_TEMP_PREFIX)
        .tempdir()
        .map_err(|error| ProbeFailure::plain(Diag::new(Key::ProbeTempDirFailed).arg(error)))?;
    let config_path = tempdir.path().join("config.json");
    let config_bytes = serde_json::to_vec_pretty(&config).map_err(|error| {
        ProbeFailure::plain(Diag::new(Key::ProbeConfigSerializeFailed).arg(error))
    })?;
    std::fs::write(&config_path, config_bytes)
        .map_err(|error| ProbeFailure::plain(Diag::new(Key::ProbeConfigWriteFailed).arg(error)))?;

    // The probe child executes only xray.exe from the outbound-only config
    // above (no TUN/wintun, no geodata-referencing routing — see the config
    // shape test in this module), so the exe-only spawn verify is used; the
    // full four-payload verify runs on every main-core spawn instead.
    let mut child = supervisor::spawn_probe(&config_path, log)
        .await
        .map_err(|error| {
            ProbeFailure::plain(Diag::new(Key::ProbeChildLaunchFailed).arg(format!("{error:#}")))
        })?;
    let diagnostics = Arc::new(Mutex::new(VecDeque::with_capacity(DIAGNOSTIC_TAIL_LINES)));
    let diagnostics_for_child = Arc::clone(&diagnostics);
    child.pump_output(Box::new(move |line, is_stderr| {
        push_diagnostic(&diagnostics_for_child, line, is_stderr);
    }));

    let grpc = GrpcClient::new(api_port);
    let deadline = Instant::now() + PROBE_DEADLINE;
    let mut delay = Duration::ZERO;
    let mut last_api_error = None;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let outcome =
            match tokio::time::timeout(remaining, next_poll(&mut child, &grpc, delay)).await {
                Ok(outcome) => outcome,
                Err(_) => break,
            };
        match outcome {
            PollOutcome::Exited(status) => {
                // A resolved `wait` means the child is gone, so its pipes
                // reach EOF and the pumps end: join them before composing
                // the wall, so the child's final writes are part of it. A
                // failed wait leaves the exit unconfirmed (the process may
                // still hold its pipes open), so that path composes the wall
                // without a drain.
                if status.is_ok() {
                    child.drain_output().await;
                }
                return Err(probe_failure(exit_description(&status), &diagnostics));
            }
            PollOutcome::Status(Ok(statuses)) => {
                delivery.offer(&statuses);
                if delivery.all_answered() {
                    // The count is cumulative, but the final snapshot must
                    // carry every requested tag itself: a poll that omits a
                    // tag reported earlier is not the closing one, so keep
                    // polling instead of panicking on the mismatch.
                    if let Some(completed) = complete_statuses(&statuses, &delivery.requested) {
                        if stop_child(&mut child).await {
                            child.drain_output().await;
                        }
                        // The dead rows of a completed run ride to the
                        // log and UI with the child's captured diagnostics
                        // tail (run-level: one probe, one child).
                        let tail = diagnostic_tail(&diagnostics);
                        let completed: Vec<OutboundStatusView> =
                            completed.into_iter().cloned().collect();
                        return Ok(with_run_diagnostics(completed, &tail));
                    }
                }
                last_api_error = None;
                delay = POLL_INTERVAL;
            }
            PollOutcome::Status(Err(error)) => {
                last_api_error = Some(error.to_string());
                delay = POLL_INTERVAL;
            }
        }
    }

    let missing = delivery.unanswered();
    // Stop the child and, once the exit is confirmed (its pipes then reach
    // EOF), join the output pumps so the failure wall carries everything the
    // child wrote before the deadline fired.
    if stop_child(&mut child).await {
        child.drain_output().await;
    }
    // One key per combination of the two optional details (the missing
    // outbound tags and the last API error), so no sentence is spliced from
    // two placeholders.
    let seconds = PROBE_DEADLINE.as_secs();
    let timeout = match (missing.is_empty(), last_api_error) {
        (true, None) => Diag::new(Key::ProbeTimedOut).arg(seconds),
        (false, None) => Diag::new(Key::ProbeTimedOutMissing)
            .arg(seconds)
            .arg(missing.join(", ")),
        (true, Some(error)) => Diag::new(Key::ProbeTimedOutApiError)
            .arg(seconds)
            .arg(error),
        (false, Some(error)) => Diag::new(Key::ProbeTimedOutMissingApiError)
            .arg(seconds)
            .arg(missing.join(", "))
            .arg(error),
    };
    Err(probe_failure(timeout, &diagnostics))
}

/// Remove probe scratch directories (`%TEMP%\broccoli-latency-probe-*`)
/// stranded by a crash or kill. Such a directory holds the probe's config —
/// every probed profile's credentials — and is removed by
/// [`tempfile::TempDir`]'s drop on every path a run can take; a hard kill
/// bypasses that, and this sweep is the next-launch backstop (the shell's
/// boot sweep calls it).
///
/// Best-effort, age-bounded ([`PROBE_TEMP_MAX_AGE`]) and prefix-matched
/// exactly: only directories directly inside the temp dir whose name starts
/// with [`PROBE_TEMP_PREFIX`] and whose mtime is at least that old are
/// removed, so a probe running right now — or a future-stamped entry, for
/// clock skew — survives, and nothing below an unmatched entry is ever
/// examined. Returns the number of directories removed; a missing temp dir
/// is not an error.
pub fn sweep_stale_probe_dirs() -> std::io::Result<usize> {
    cleanup_stale_probe_dirs(
        &std::env::temp_dir(),
        std::time::SystemTime::now(),
        PROBE_TEMP_MAX_AGE,
    )
}

/// The sweep body behind [`sweep_stale_probe_dirs`], with the base directory,
/// the clock and the age bound injected so the naming contract and the age
/// comparison are unit-testable. The rules themselves are the shared
/// [`sweep`](super::sweep::sweep) ones; this binds the caller's own naming
/// contract and directory kind.
fn cleanup_stale_probe_dirs(
    dir: &Path,
    now: std::time::SystemTime,
    max_age: Duration,
) -> std::io::Result<usize> {
    super::sweep::sweep(
        dir,
        now,
        max_age,
        // The probe's temp dirs carry no filename suffix: the prefix is the
        // whole naming contract.
        super::sweep::Matcher::directories(PROBE_TEMP_PREFIX, ""),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        OutboundStatusView, PROBE_TEMP_MAX_AGE, PROBE_TEMP_PREFIX, ProbeDelivery,
        cleanup_stale_probe_dirs, complete_statuses, probe_failure, resolve_probe_interface, run,
        with_run_diagnostics,
    };
    use crate::diag::Diag;
    use crate::i18n::{Key, t};
    use crate::model::settings::Language;
    use crate::model::{OutboundModel, Protocol, ServerProfile};
    use crate::sys::netif::NetIf;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A log handle for `run` whose channel no test drains: the probe path
    /// only writes the release-verification line to it.
    fn log_sink() -> super::AppLogSink {
        let (evt, _rx) = std::sync::mpsc::sync_channel(1);
        super::super::events::EventStream::new(evt, egui::Context::default()).sink()
    }

    #[test]
    fn with_run_diagnostics_stamps_only_dead_rows() {
        let tail = "[stderr] rejected: unknown SNI";
        let rows = with_run_diagnostics(
            vec![
                status("alive", true, 12, None),
                status("dead", false, 0, Some("refused")),
                status("dead2", false, 0, Some("timeout")),
            ],
            tail,
        );
        assert_eq!(rows[0].diagnostics, None, "alive rows never carry a wall");
        assert_eq!(
            rows[1].diagnostics.as_deref(),
            Some(tail),
            "dead rows carry the run's diagnostics tail"
        );
        assert_eq!(rows[2].diagnostics.as_deref(), Some(tail));
        assert_eq!(
            rows[1].last_error.as_deref(),
            Some("refused"),
            "other fields untouched"
        );
    }

    #[test]
    fn with_run_diagnostics_without_tail_leaves_rows_untouched() {
        let rows = with_run_diagnostics(vec![status("dead", false, 0, Some("refused"))], "");
        assert_eq!(rows[0].diagnostics, None);
        assert_eq!(rows[0].last_error.as_deref(), Some("refused"));
    }

    #[test]
    fn probe_failure_splits_headline_from_diagnostics_tail() {
        let tail = Arc::new(Mutex::new(VecDeque::from([
            "[stdout] connecting".to_string(),
            "[stderr] boom".to_string(),
        ])));
        let failure = probe_failure(Diag::new(Key::ProbeExitNoStatus), &tail);
        assert_eq!(failure.headline.key(), Key::ProbeExitNoStatus);
        assert_eq!(
            failure.full(Language::En),
            format!(
                "{}\n{}\n[stdout] connecting\n[stderr] boom",
                t(Language::En, Key::ProbeExitNoStatus),
                t(Language::En, Key::ProbeDiagnosticsWall),
            )
        );
    }

    #[test]
    fn probe_failure_without_tail_keeps_full_equal_to_headline() {
        let tail = Arc::new(Mutex::new(VecDeque::new()));
        let failure = probe_failure(Diag::new(Key::ProbeConfigRejected).arg("x"), &tail);
        assert_eq!(failure.headline.key(), Key::ProbeConfigRejected);
        assert_eq!(
            failure.full(Language::En),
            failure.headline.text(Language::En)
        );
    }

    /// Each requested tag is delivered once, in requested order, with the
    /// running count the strip prints — an unrelated row in the snapshot is
    /// not a target.
    #[test]
    fn delivery_reports_each_requested_tag_once_in_requested_order() {
        let mut seen: Vec<(Vec<String>, usize)> = Vec::new();
        let mut delivery = ProbeDelivery::new(
            vec!["a".to_string(), "b".to_string()],
            |statuses: Vec<OutboundStatusView>, done: usize| {
                seen.push((
                    statuses.iter().map(|status| status.tag.clone()).collect(),
                    done,
                ));
            },
        );
        delivery.offer(&[status("a", true, 12, None), status("zzz", true, 5, None)]);
        delivery.offer(&[status("a", true, 12, None), status("b", true, 30, None)]);
        delivery.offer(&[status("a", true, 12, None), status("b", true, 30, None)]);
        assert!(delivery.all_answered());
        drop(delivery);
        assert_eq!(
            seen,
            [
                (["a".to_string()].to_vec(), 1),
                (["b".to_string()].to_vec(), 2)
            ]
        );
    }

    /// A run that ends early keeps every arrival and says only the unanswered
    /// tags are dead, carrying the run's sentence.
    #[test]
    fn delivery_dead_fills_only_the_tags_that_never_answered() {
        let mut seen: Vec<Vec<OutboundStatusView>> = Vec::new();
        let mut delivery = ProbeDelivery::new(
            vec!["a".to_string(), "b".to_string()],
            |statuses: Vec<OutboundStatusView>, _done: usize| seen.push(statuses),
        );
        delivery.offer(&[status("a", true, 12, None)]);
        let failure = probe_failure(
            Diag::new(Key::ProbeExitNoStatus),
            &Arc::new(Mutex::new(VecDeque::new())),
        );
        delivery.report_dead_missing(&failure);
        assert!(delivery.all_answered());
        drop(delivery);
        assert_eq!(seen.len(), 2, "the arrived row is not re-delivered");
        assert_eq!(seen[1].len(), 1, "only the unanswered tag is filled");
        assert_eq!(seen[1][0].tag, "b");
        assert!(!seen[1][0].alive);
        assert_eq!(
            seen[1][0].last_error.as_deref(),
            Some(t(Language::En, Key::ProbeExitNoStatus)),
            "the dead fill carries the run's sentence"
        );
    }

    /// Premise guard: the config the probe child runs against
    /// references no wintun/geodata payloads, so the probe spawn only needs
    /// xray.exe release-verified (`supervisor::spawn_probe`). If a future
    /// change adds a TUN inbound, routing-rule geo conditions, or a geodata
    /// block to this config, this test fails and the probe spawn must go
    /// back to the full four-payload verify.
    #[test]
    fn probe_config_references_no_wintun_or_geodata_payloads() {
        let profiles = vec![ServerProfile {
            id: "0123456789abcdef".into(),
            ..ServerProfile::new("probe", OutboundModel::new(Protocol::Freedom))
        }];
        let config = crate::r#gen::generate_latency_probe(
            &profiles,
            "https://probe.example/health",
            45678,
            None,
        )
        .expect("generate isolated latency config");
        // The non-exe payloads are only reachable through these sections; a
        // probe config must carry none of them.
        for section in ["routing", "inbounds", "dns", "fakeDns", "geodata"] {
            assert!(
                config.get(section).is_none(),
                "probe config must not carry a {section} section"
            );
        }
        let wire = serde_json::to_string(&config).expect("serialize probe config");
        let wire = wire.to_ascii_lowercase();
        for token in ["wintun", "geoip", "geosite"] {
            assert!(
                !wire.contains(token),
                "probe config must not reference {token}: {wire}"
            );
        }
    }
    fn status(
        tag: &str,
        alive: bool,
        delay_ms: i64,
        last_error: Option<&str>,
    ) -> OutboundStatusView {
        OutboundStatusView {
            health_ping: None,
            tag: tag.into(),
            alive,
            delay_ms,
            last_error: last_error.map(str::to_owned),
            diagnostics: None,
        }
    }

    #[test]
    fn incomplete_snapshot_does_not_finish_probe() {
        let requested = vec!["srv-a".into(), "srv-b".into()];
        let statuses = vec![status("srv-a", true, 12, None)];
        assert!(complete_statuses(&statuses, &requested).is_none());
        assert!(complete_statuses(&[], &requested).is_none());
    }

    #[test]
    fn completed_snapshot_preserves_requested_order() {
        let requested = vec!["srv-b".into(), "srv-a".into()];
        let statuses = vec![
            status("srv-a", true, 18, None),
            status("srv-b", true, 9, None),
        ];
        let completed = complete_statuses(&statuses, &requested).expect("all tags present");
        assert_eq!(
            completed
                .iter()
                .map(|status| status.tag.as_str())
                .collect::<Vec<_>>(),
            ["srv-b", "srv-a"]
        );
    }

    #[test]
    fn alive_failure_is_a_completed_row_with_its_error() {
        let requested = vec!["srv-dead".into()];
        let statuses = vec![status("srv-dead", false, 0, Some("connection refused"))];
        let completed = complete_statuses(&statuses, &requested).expect("dead row is terminal");
        assert!(!completed[0].alive);
        assert_eq!(
            completed[0].last_error.as_deref(),
            Some("connection refused")
        );
    }

    #[test]
    fn prefix_matches_do_not_satisfy_a_missing_exact_tag() {
        let requested = vec!["srv-a".into()];
        let statuses = vec![status("srv-a-longer", true, 3, None)];
        assert!(complete_statuses(&statuses, &requested).is_none());
    }

    /// The execution path re-checks the probe target before any
    /// socket is bound or child spawned; a blocked literal host fails fast.
    #[tokio::test(flavor = "current_thread")]
    async fn run_rejects_blocked_probe_url_before_any_connection() {
        let profiles = vec![ServerProfile {
            id: "0123456789abcdef".into(),
            ..ServerProfile::new("probe", OutboundModel::new(Protocol::Freedom))
        }];
        let mut delivered = Vec::new();
        let error = run(
            &profiles,
            "http://127.0.0.1:9/health".into(),
            None,
            None,
            false,
            &log_sink(),
            |statuses, done| delivered.push((statuses, done)),
        )
        .await
        .expect_err("loopback probe must be rejected");
        assert_eq!(
            delivered.len(),
            1,
            "a probe that cannot start must still deliver a verdict for every target"
        );
        assert_eq!(delivered[0].1, 1);
        assert_eq!(delivered[0].0[0].tag, profiles[0].tag());
        assert!(!delivered[0].0[0].alive);
        assert!(
            delivered[0].0[0]
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("loopback")),
            "the startup error must ride the dead verdict: {:?}",
            delivered[0].0[0]
        );
        assert_eq!(
            error.headline.key(),
            Key::ProbeHostBlocked,
            "the loopback host must be rejected by the keyed host-block sentence"
        );
        assert!(
            error.headline.text(Language::En).contains("loopback"),
            "the host class must ride the sentence: {error:?}"
        );
        assert!(
            !error
                .headline
                .text(Language::En)
                .contains("config rejected"),
            "rejection must fire before config generation: {error:?}"
        );
        assert_eq!(
            error.full(Language::En),
            error.headline.text(Language::En),
            "a pre-child failure has no diagnostics tail"
        );
    }

    /// A fixture adapter with a stable, nonzero index per name: real
    /// adapters always report one, and the TUN-adapter identification keys
    /// on it.
    fn iface(name: &str, ips: &[&str], up: bool) -> NetIf {
        let index = match name {
            "Ethernet" => 2,
            "Wi-Fi" => 17,
            "wired" => 26,
            "broccoli0" => 9,
            other => panic!("fixture adapter {other:?} needs an index"),
        };
        crate::sys::netif::test_iface(name, index, name == "Wi-Fi", up, ips)
    }

    /// Adapter fixture for the fixed-name branches. The auto branch reads
    /// the live route table and then intersects it with the view it is
    /// given, so a fixture can only ever narrow that reading.
    fn candidates() -> Vec<NetIf> {
        vec![
            iface("Ethernet", &["192.168.1.5"], true),
            iface("Wi-Fi", &["10.0.0.5"], true),
        ]
    }

    #[test]
    fn fixed_present_interface_wins_over_the_heuristic() {
        let resolved = resolve_probe_interface(Some("Ethernet"), true, None, &candidates())
            .expect("present fixed name resolves");
        assert_eq!(resolved.as_deref(), Some("Ethernet"));
    }

    #[test]
    fn fixed_absent_interface_fails_loudly_with_the_name() {
        let error = resolve_probe_interface(Some("ghost"), true, None, &candidates())
            .expect_err("absent fixed name must fail");
        assert_eq!(error.headline.key(), Key::ProbeInterfaceMissing);
        assert!(
            error.headline.text(Language::En).contains("ghost"),
            "the missing name must ride the sentence: {error:?}"
        );
        assert_eq!(
            error.full(Language::En),
            error.headline.text(Language::En),
            "no diagnostics tail pre-child"
        );
    }

    #[test]
    fn fixed_down_interface_fails_loudly_with_the_name() {
        // Binding to a down adapter kills the dial with an unreachable-host
        // error (Xray's fixed-name branch has no FlagUp filter) — the probe
        // must reject it up front instead of timing out on a dead bind.
        let ifaces = vec![
            iface("Ethernet", &["10.0.0.1"], true),
            iface("wired", &[], false),
            iface("Wi-Fi", &["10.0.0.5"], true),
        ];
        let error = resolve_probe_interface(Some("wired"), true, None, &ifaces)
            .expect_err("down fixed name must fail");
        assert_eq!(error.headline.key(), Key::ProbeInterfaceDown);
        assert!(
            error.headline.text(Language::En).contains("wired"),
            "the down interface's name must ride the sentence: {error:?}"
        );
    }

    #[test]
    fn inactive_tun_with_a_requested_interface_stays_unbound() {
        let resolved = resolve_probe_interface(Some("ghost"), false, None, &[])
            .expect("without a live capture Bind NIC and Native are the same path");
        assert_eq!(resolved, None);
    }

    #[test]
    fn inactive_tun_without_a_requested_interface_stays_unbound() {
        let resolved = resolve_probe_interface(None, false, None, &[])
            .expect("Native has no interface to bind");
        assert_eq!(resolved, None);
    }

    #[test]
    fn live_tun_without_a_candidate_stays_unbound() {
        let resolved = resolve_probe_interface(Some("auto"), true, None, &[])
            .expect("a live TUN with no auto candidate keeps the unbound fallback");
        assert_eq!(resolved, None);
    }

    #[test]
    fn fixed_name_equal_to_the_tun_adapter_fails_loudly() {
        // Binding to the TUN's own interface would send the dial back into
        // the tunnel: reject it with the reason, not a silent fallback.
        let ifaces = vec![
            iface("broccoli0", &["10.255.0.1"], true),
            iface("Ethernet", &["10.0.0.1"], true),
        ];
        let error = resolve_probe_interface(Some("broccoli0"), true, Some("broccoli0"), &ifaces)
            .expect_err("the TUN adapter itself must be rejected as a fixed target");
        assert_eq!(error.headline.key(), Key::ProbeInterfaceTunSelf);
    }

    // ---------- stale probe-directory sweep ----------

    #[test]
    fn stale_probe_sweep_removes_only_aged_prefixed_directories() {
        let base = std::env::temp_dir().join(format!(
            "broccoli-probe-sweep-test-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let now = std::time::SystemTime::now();

        // A probe may be running right now: its directory, an unrelated
        // directory, a file wearing the prefix, and a directory nested below
        // an unmatched entry all survive the sweep.
        let live = base.join(format!("{PROBE_TEMP_PREFIX}live"));
        std::fs::create_dir_all(&live).unwrap();
        let unrelated = base.join("another-tool-dir");
        std::fs::create_dir_all(&unrelated).unwrap();
        let prefixed_file = base.join(format!("{PROBE_TEMP_PREFIX}file"));
        std::fs::write(&prefixed_file, b"{}").unwrap();
        let nested = base.join("nested").join(format!("{PROBE_TEMP_PREFIX}deep"));
        std::fs::create_dir_all(&nested).unwrap();

        assert_eq!(
            cleanup_stale_probe_dirs(&base, now, PROBE_TEMP_MAX_AGE).expect("sweep succeeds"),
            0,
            "nothing is old enough to sweep"
        );
        for kept in [&live, &unrelated, &prefixed_file, &nested] {
            assert!(kept.exists(), "{} must survive the sweep", kept.display());
        }

        // The age bound is the discriminator: `now` is a sweep input, so a
        // future one puts the same directory past it (Windows hands out no
        // directory handle that could backdate the fixture instead). The
        // config inside — profile credentials — goes with it.
        std::fs::write(live.join("config.json"), b"{\"password\":\"secret\"}").unwrap();
        let aged = now + PROBE_TEMP_MAX_AGE + Duration::from_secs(1);
        assert_eq!(
            cleanup_stale_probe_dirs(&base, aged, PROBE_TEMP_MAX_AGE).expect("sweep succeeds"),
            1,
            "the aged probe directory is the only removable entry"
        );
        assert!(
            !live.exists(),
            "the aged directory and its config must be gone"
        );
        for kept in [&unrelated, &prefixed_file, &nested] {
            assert!(kept.exists(), "{} must never be swept", kept.display());
        }

        // A missing base is a no-op, not an error.
        assert_eq!(
            cleanup_stale_probe_dirs(&base.join("missing"), aged, PROBE_TEMP_MAX_AGE)
                .expect("a missing temp base is not an error"),
            0
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
