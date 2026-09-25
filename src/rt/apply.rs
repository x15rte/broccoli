//! Candidate-config validation, atomic-ish commit/rollback, and the
//! per-spawn configuration the runtime artefacts carry. Layout under
//! Broccoli's mutable config directory:
//! - `config.json`             — the active config the core runs;
//! - `config.candidate.json`   — validated candidate, atomically replaces active;
//! - `config.lastgood.json`    — previous active config, atomically replaced;
//! - `config.rollback.json`    — transient rollback copy;
//! - `config.meta.json`        — sidecar stamp of the active config (app
//!   version + compiled core pin); a stored config is never replayed on a
//!   stamp that names another build.

use std::collections::VecDeque;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use crate::diag::{Diag, DiagError, DiagResult};
use crate::r#gen::keys;
use crate::i18n::Key;
use crate::model::{ServersFile, Settings};
use tokio::process::Command;
use windows::Win32::Foundation::HANDLE;

use super::{AppMessage, ApplyOutput};
use crate::rt::supervisor::{CREATE_NO_WINDOW, Job, OutputSink, pump_stream};
use crate::sys::paths::{config_dir, core_dir};

/// Sidecar stamp written with the active configuration it describes.
const META_NAME: &str = "config.meta.json";
/// Stamp of the candidate, promoted over the active stamp by [`commit`].
const META_CANDIDATE_NAME: &str = "config.meta.candidate.json";
/// Stamp of the config [`commit`] retires to `config.lastgood.json`.
const META_LASTGOOD_NAME: &str = "config.lastgood.meta.json";

/// Bound on one `xray run -test` validation run before the child is killed
/// and the run reported as timed out. The runtime's shutdown wait for an
/// in-flight profile validation ([`super::RUNTIME_JOIN_BOUND`]) inherits this
/// bound: the child owns its scratch config, so nothing may tear down while
/// it runs.
pub(crate) const VALIDATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long the timeout path may take to reap the killed validation child
/// before giving up. `TerminateProcess` lands in milliseconds, so this bound
/// only guards a pathological kernel stall; the child's `kill_on_drop` and
/// the kill-on-close job still back the kill up on drop.
const VALIDATE_KILL_WAIT: std::time::Duration = std::time::Duration::from_secs(2);
/// Byte budget of the rolling tail of xray's `-test` output retained for the
/// GUI message. Output streams in per-line capped (see
/// `supervisor::MAX_LINE_BYTES`); this ring drops whole oldest lines so the
/// retained tail — the only part ever surfaced — never exceeds the budget
/// plus one line.
const OUTPUT_TAIL: usize = 4096;

pub fn active_path() -> PathBuf {
    config_dir().join("config.json")
}

/// Sidecar stamp of [`active_path`].
pub fn meta_path() -> PathBuf {
    config_dir().join(META_NAME)
}

fn meta_candidate_path() -> PathBuf {
    config_dir().join(META_CANDIDATE_NAME)
}

fn meta_lastgood_path() -> PathBuf {
    config_dir().join(META_LASTGOOD_NAME)
}

/// The build identity a stored configuration carries: the app version, the
/// compiled core pin, and the digest of the exact configuration bytes the
/// stamp was written for. Recorded in its sidecar stamp so a start can tell
/// this build's artefact from one another build wrote — or from any file the
/// stamp did not produce.
#[derive(serde::Serialize, serde::Deserialize)]
struct ConfigStamp {
    #[serde(rename = "appVersion")]
    app_version: String,
    #[serde(rename = "corePin")]
    core_pin: String,
    /// Lowercase hex SHA-256 of the configuration the stamp describes. Without
    /// it a stamp's build identity could vouch for a file it never produced
    /// (a retired pair, a hand-edited artefact, a crash window).
    #[serde(rename = "configSha256")]
    config_sha256: String,
}

fn current_stamp(config_sha256: String) -> ConfigStamp {
    ConfigStamp {
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        core_pin: crate::sys::core_dl::pinned_release_version().to_string(),
        config_sha256,
    }
}

/// Lowercase hex SHA-256 of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    // digest 0.11 no longer formats its output through `LowerHex`, so the
    // bytes are written out explicitly (same rendering as the core payload
    // verification).
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// True when `meta` is a stamp that names this build *and* describes `config`'s
/// exact bytes. A missing/unreadable stamp, an unreadable configuration, or a
/// digest that does not describe the file never matches: a consumer regenerates
/// instead of replaying a file no stamp vouches for.
fn stamp_describes(meta: &Path, config: &Path) -> bool {
    let (Ok(stamp_bytes), Ok(config_bytes)) = (std::fs::read(meta), std::fs::read(config)) else {
        return false;
    };
    let Ok(stamp) = serde_json::from_slice::<ConfigStamp>(&stamp_bytes) else {
        return false;
    };
    let current = current_stamp(sha256_hex(&config_bytes));
    stamp.app_version == current.app_version
        && stamp.core_pin == current.core_pin
        && stamp.config_sha256 == current.config_sha256
}

/// True when the active artefact's sidecar stamp describes this build and these
/// exact bytes — the one gate a stored configuration must pass before it is
/// replayed.
pub fn stamp_is_current() -> bool {
    stamp_describes(&meta_path(), &active_path())
}

/// One spawn's configuration: the artefact's exact bytes — what the elevated
/// helper stages, when the start runs behind it — and the control-plane port
/// its `api.listen` pins.
pub struct SpawnConfig {
    pub bytes: Vec<u8>,
    pub api_port: u16,
}

/// Generate the runtime configuration from the saved server list and
/// settings, write it through the candidate path, promote it with its stamp,
/// and return what the spawn must run.
///
/// Every start without a fresh apply — cold boot, backoff retry, transport
/// switch — goes through here, so a configuration another build wrote is
/// never replayed. The generation is the only validation: the core's own
/// config load is what the start proves.
pub fn regenerate() -> Result<SpawnConfig, DiagError> {
    let state_failure = |error: crate::model::StateLoadError| {
        DiagError::new(Diag::new(Key::GenerationFailed).arg(error.to_string()))
    };
    let servers = ServersFile::load().map_err(state_failure)?;
    let settings = Settings::load().map_err(state_failure)?;
    let value = crate::r#gen::generate(&servers, &settings).map_err(generation_failure)?;
    let api_port = api_port_from_value(&value)?;
    let bytes = write_candidate_bytes(&value)?;
    commit()?;
    Ok(SpawnConfig { bytes, api_port })
}

/// Write and promote the app-owned configuration a core update's health gate
/// starts: a direct outbound and the control-plane listener, generated for
/// this start alone. Never the user's profiles or settings — a user's state
/// must not decide whether an install is accepted.
pub fn write_core_gate() -> Result<SpawnConfig, DiagError> {
    let api_port = crate::r#gen::pick_ephemeral_api_port().map_err(generation_failure)?;
    let value = crate::r#gen::generate_core_gate(api_port).map_err(generation_failure)?;
    let bytes = write_candidate_bytes(&value)?;
    commit()?;
    Ok(SpawnConfig { bytes, api_port })
}

/// The configuration for a start that follows a deliberate rollback of a
/// failed candidate: the restored last-known-good artefact, because
/// regeneration would reproduce the rejected configuration. Replayed only
/// while its stamp names this build — a foreign-stamped (or unstamped)
/// artefact is regenerated from the saved state instead.
pub fn replay_rolled_back() -> Result<SpawnConfig, DiagError> {
    if !stamp_is_current() {
        return regenerate();
    }
    let path = active_path();
    let bytes = std::fs::read(&path).diag(Key::ApplyActiveReadFailed)?;
    let api_port = api_port_from_path(&path)?;
    Ok(SpawnConfig { bytes, api_port })
}

/// [`regenerate`], off the executor (see [`on_blocking_pool`]).
pub async fn regenerate_offloaded() -> Result<SpawnConfig, DiagError> {
    on_blocking_pool(regenerate).await
}

/// [`write_core_gate`], off the executor (see [`on_blocking_pool`]).
pub async fn write_core_gate_offloaded() -> Result<SpawnConfig, DiagError> {
    on_blocking_pool(write_core_gate).await
}

/// [`replay_rolled_back`], off the executor (see [`on_blocking_pool`]).
pub async fn replay_rolled_back_offloaded() -> Result<SpawnConfig, DiagError> {
    on_blocking_pool(replay_rolled_back).await
}

/// One generation refusal as the runtime's user-visible finding: the same
/// sentence the GUI's own generation failure carries.
fn generation_failure(error: crate::r#gen::GenerateError) -> DiagError {
    // English in the argument: the display boundary re-renders the outer
    // sentence in the active language, and the generator's own finding is
    // app-authored text with no locale of its own here.
    DiagError::new(
        Diag::new(Key::GenerationFailed).arg(error.text(crate::model::settings::Language::En)),
    )
}

pub fn read_active_contents() -> Result<String, DiagError> {
    std::fs::read_to_string(active_path()).diag(Key::ApplyActiveReadFailed)
}

/// True when a launched configuration carries an outbound-health extension:
/// the `observatory` or the `burstObservatory` block. The GUI's status read
/// follows this fact rather than the settings, because the core may run a
/// config the settings no longer describe — a raw override, or a candidate
/// that failed readiness and was replaced by the last known-good config.
/// A snapshot that does not parse starts no read.
pub fn carries_health_extension(config_text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(config_text).is_ok_and(|config| {
        config.get(keys::OBSERVATORY).is_some() || config.get(keys::BURST_OBSERVATORY).is_some()
    })
}

pub fn candidate_path() -> PathBuf {
    config_dir().join("config.candidate.json")
}

/// `config.lastgood.json` — the artefact a candidate replaced. Replayed only
/// after a deliberate rollback, and only while its sidecar stamp names this
/// build; otherwise it stays diagnostic history.
fn lastgood_path() -> PathBuf {
    config_dir().join("config.lastgood.json")
}

/// Read the API listener from the exact active config a backend will run.
/// The GUI setting may have been reset after a prior session while
/// `config.json` still owns a different listener. Starting against the latter
/// must poll the latter, not time out on the newly chosen default port.
pub fn active_api_port() -> Result<u16, DiagError> {
    api_port_from_path(&active_path())
}

/// Derive the API listener port from an emitted config value (the candidate
/// the runtime will commit). `api.listen` must be a non-zero loopback address,
/// the same invariant [`active_api_port`] enforces on the active config — this
/// is the single seam the runtime uses to learn the ephemeral port.
pub fn api_port_from_value(config: &serde_json::Value) -> Result<u16, DiagError> {
    let listen = config
        .get(keys::API)
        .and_then(serde_json::Value::as_object)
        .and_then(|api| api.get(keys::LISTEN))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| DiagError::new(Diag::new(Key::ApplyListenMissing)))?;
    let address: std::net::SocketAddr = listen
        .parse()
        .map_err(|_| DiagError::new(Diag::new(Key::ApplyListenInvalid).arg(listen)))?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(DiagError::new(
            Diag::new(Key::ApplyListenNotLoopback).arg(listen),
        ));
    }
    Ok(address.port())
}

fn api_port_from_path(path: &Path) -> Result<u16, DiagError> {
    let bytes =
        std::fs::read(path).diag_with(Diag::new(Key::ApplyFileReadFailed).arg(path.display()))?;
    let config: serde_json::Value = serde_json::from_slice(&bytes)
        .diag_with(Diag::new(Key::ApplyFileParseFailed).arg(path.display()))?;
    api_port_from_value(&config)
}

/// The candidate config is the config that would run, so its own emitted
/// `geodata` block decides whether the verification DAT pins are suspended
/// for the `-test` gate: a candidate that configured the core's geo data
/// updater may legitimately carry a replaced pair, and the gate must accept
/// it. Delegates to the one shared core_dl predicate — never
/// re-implemented — and fails closed on an unreadable candidate.
fn candidate_dat_pins_suspended(candidate_path: &Path) -> bool {
    crate::sys::core_dl::dat_pins_suspended_at(candidate_path)
}

/// Rolling tail of the validation child's combined stdout+stderr, bounded to
/// [`OUTPUT_TAIL`] bytes so a flooding child cannot grow the memory held for
/// the UI message (CWE-400/770). Lines arrive
/// pre-capped by the supervisor reader — at most
/// `supervisor::MAX_LINE_BYTES` each, over-long lines carrying the
/// supervisor's truncation marker — and this ring drops whole oldest lines
/// once the budget is exceeded, keeping newest-lines tail semantics for the
/// message.
struct TailRing {
    budget: usize,
    bytes: usize,
    lines: VecDeque<String>,
}

impl TailRing {
    /// Empty ring retaining at most `budget` bytes of joined lines.
    fn new(budget: usize) -> Self {
        TailRing {
            budget,
            bytes: 0,
            lines: VecDeque::new(),
        }
    }

    /// Retain one captured line, evicting whole oldest lines while the
    /// budget is exceeded. The newest line is never evicted, so a single
    /// over-budget line still surfaces whole in the message (lossy decoding
    /// can inflate a kept line past the raw cap by a constant factor).
    fn push(&mut self, line: String) {
        self.bytes = self.bytes.saturating_add(line.len() + 1);
        self.lines.push_back(line);
        while self.bytes > self.budget && self.lines.len() > 1 {
            if let Some(evicted) = self.lines.pop_front() {
                self.bytes = self.bytes.saturating_sub(evicted.len() + 1);
            }
        }
    }

    /// Join the retained lines with newlines, trimmed at the edges like the
    /// byte tail it replaced was. Bounded by the budget plus one line.
    fn compose(&self) -> String {
        let mut message = String::new();
        for (index, line) in self.lines.iter().enumerate() {
            if index > 0 {
                message.push('\n');
            }
            message.push_str(line);
        }
        let trimmed = message.trim();
        trimmed.to_owned()
    }
}

/// A running validation child plus the kill-on-close Job Object that owns it
/// and the two capped output pumps draining its pipes. Mirror of
/// `supervisor::Child` for the `-test` gate: tokio `kill_on_drop` plus
/// `KILL_ON_JOB_CLOSE`, so even a GUI crash — which closes every handle the
/// process holds — terminates the validation child.
struct ValidationChild {
    /// Field order matters: killed first in `Drop`, then `_job` closes and
    /// sweeps the child (and anything it spawned).
    child: tokio::process::Child,
    _job: Job,
    stdout_pump: Option<tokio::task::JoinHandle<()>>,
    stderr_pump: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for ValidationChild {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        // `_job` drops after `child`, closing the last job handle ->
        // KILL_ON_JOB_CLOSE sweeps anything still alive.
    }
}

/// Spawn one hidden, piped, job-pinned validation child from `command`
/// (program, args, cwd and env already configured by the caller) and start
/// pumping its stdout/stderr through the supervisor's capped reader into
/// `tail`. Both pipes are drained from the moment the child exists, so a
/// flooding child can neither back up into a full pipe nor grow retained
/// memory.
async fn spawn_validation_child(
    mut command: Command,
    tail: Arc<Mutex<TailRing>>,
) -> Result<ValidationChild, DiagError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .creation_flags(CREATE_NO_WINDOW);
    let mut child = command.spawn().diag(Key::ApplyValidationSpawnFailed)?;
    let raw = child
        .raw_handle()
        .ok_or_else(|| DiagError::new(Diag::new(Key::ApplyValidationChildExited)))?;
    let job = Job::new_kill_on_close().diag(Key::ApplyValidationJobCreateFailed)?;
    job.assign(HANDLE(raw))
        .diag(Key::ApplyValidationJobAssignFailed)?;
    let sink: OutputSink = Arc::new(Mutex::new(Box::new(
        move |line: String, _is_stderr: bool| {
            if let Ok(mut ring) = tail.lock() {
                ring.push(line);
            }
        },
    )));
    let stdout_pump = child
        .stdout
        .take()
        .map(|stream| tokio::spawn(pump_stream(stream, Arc::clone(&sink), false)));
    let stderr_pump = child
        .stderr
        .take()
        .map(|stream| tokio::spawn(pump_stream(stream, sink, true)));
    Ok(ValidationChild {
        child,
        _job: job,
        stdout_pump,
        stderr_pump,
    })
}

/// Join both output pumps; each ends at EOF on its pipe, which the child's
/// exit guarantees once the pipe is drained, so after the child is gone
/// every byte it wrote lands in the ring before the message is composed.
async fn drain_output_pumps(child: &mut ValidationChild) {
    if let Some(pump) = child.stdout_pump.take() {
        let _ = pump.await;
    }
    if let Some(pump) = child.stderr_pump.take() {
        let _ = pump.await;
    }
}

fn compose_tail(tail: &Arc<Mutex<TailRing>>) -> String {
    match tail.lock() {
        Ok(ring) => ring.compose(),
        Err(poisoned) => poisoned.into_inner().compose(),
    }
}

/// Drive a spawned validation child to a verdict: wait up to `timeout` for
/// it to exit (the pumps keep draining both streams the whole time), kill
/// it when the bound fires, then join the pumps so the message carries the
/// complete bounded tail. Returns `(ok, output)` with the established
/// contracts: `ok` is the exit status on an exit verdict and `output` is
/// the rolling captured tail; the wait, timeout, and worker failures report
/// keyed messages instead.
async fn settle_validation(
    child: &mut ValidationChild,
    tail: &Arc<Mutex<TailRing>>,
    timeout: std::time::Duration,
) -> (bool, ApplyOutput) {
    match tokio::time::timeout(timeout, child.child.wait()).await {
        Ok(Ok(status)) => {
            drain_output_pumps(child).await;
            (status.success(), ApplyOutput::Text(compose_tail(tail)))
        }
        Ok(Err(error)) => (
            false,
            validation_failure(
                DiagError::new(Diag::new(Key::ApplyValidationRunFailed)).caused_by(error),
            ),
        ),
        Err(_) => {
            let _ = child.child.start_kill();
            let reaped = matches!(
                tokio::time::timeout(VALIDATE_KILL_WAIT, child.child.wait()).await,
                Ok(Ok(_))
            );
            if reaped {
                drain_output_pumps(child).await;
            }
            (
                false,
                ApplyOutput::Message(AppMessage::Message(
                    Diag::new(Key::ApplyValidationTimeout).arg(timeout.as_secs()),
                )),
            )
        }
    }
}

/// One keyed validation failure as the apply verdict carries it.
fn validation_failure(error: DiagError) -> ApplyOutput {
    ApplyOutput::Message(AppMessage::Error(Arc::new(error)))
}

/// Run `xray run -test -config <candidate_path>` (hidden, 10 s timeout).
/// Returns `(ok, output)`: `ok` is exit status 0 and `output` is the bounded
/// tail of combined stdout+stderr (xray prints config errors to stdout via
/// `fmt.Println`, so both streams matter); failures before or around the
/// child carry keyed messages instead.
///
/// The child is pinned to a kill-on-close Job Object like every other core
/// spawn: a GUI crash closes the job handle and
/// the kernel terminates the validation process. Its output streams through
/// the supervisor's capped line reader — per line at most 4 KiB, over-long
/// lines cut with the truncation marker — into a ring that retains only the
/// last [`OUTPUT_TAIL`] bytes, so a flooding `xray -test` can neither grow
/// the memory held for the message nor stall on a full pipe. Timeout
/// behavior is unchanged: the 10 s bound kills the child and reports the
/// keyed timeout message; an exit verdict surfaces the retained tail.
///
/// The release-pin verify hashes the payloads in 8 KiB blocking reads, so it
/// runs on tokio's blocking pool instead of the current-thread executor,
/// which must keep dispatching commands while a config is tested/applied.
/// The candidate's own geodata block decides the DAT-suspension
/// mode (see [`candidate_dat_pins_suspended`]); the verified deny-write
/// handles return to the executor and stay held through CreateProcess and
/// the validation run, exactly as before.
pub async fn validate(candidate_path: &Path) -> (bool, ApplyOutput) {
    let candidate = candidate_path.to_path_buf();
    let verify = tokio::task::spawn_blocking(move || {
        // The decision and the payload hashes both run off the executor; the
        // candidate file is small and the managed core tree is not.
        if candidate_dat_pins_suspended(&candidate) {
            crate::sys::core_dl::open_verified_core_user_managed_dats(&core_dir())
        } else {
            crate::sys::core_dl::open_verified_managed_core()
        }
    });
    let verified_core = match verify.await {
        Ok(Ok(verified_core)) => verified_core,
        Ok(Err(error)) => {
            return (
                false,
                validation_failure(
                    DiagError::new(Diag::new(Key::ApplyCoreVerifyFailed)).caused_by(error),
                ),
            );
        }
        Err(join) => {
            return (
                false,
                validation_failure(
                    DiagError::new(Diag::new(Key::ApplyCoreVerifyWorkerFailed))
                        .caused_by_text(join.to_string()),
                ),
            );
        }
    };
    let core = core_dir();
    let mut command = Command::new(core.join("xray.exe"));
    command
        .arg("run")
        .arg("-test")
        .arg("-config")
        .arg(candidate_path)
        .current_dir(&core)
        .env("XRAY_LOCATION_ASSET", &core);
    let tail = Arc::new(Mutex::new(TailRing::new(OUTPUT_TAIL)));
    let mut child = match spawn_validation_child(command, Arc::clone(&tail)).await {
        Ok(child) => child,
        Err(error) => {
            drop(verified_core);
            return (false, validation_failure(error));
        }
    };
    let result = settle_validation(&mut child, &tail, VALIDATE_TIMEOUT).await;
    drop(child);
    drop(verified_core);
    result
}

/// Run one blocking filesystem leg of the candidate/commit pipeline on
/// tokio's blocking pool. The control plane runs on a current-thread runtime
/// ([`super::spawn_runtime`]), which must keep polling the tasks it spawned —
/// the validation child's output pumps and `wait` included — while a config
/// is tested, committed, or rolled back; a create/write/`sync_all`/read/rename
/// sequence run inline would stall every one of them for the disk's latency.
/// A worker that panics, or that runtime shutdown cancels before it runs,
/// reports through the join error and lands on the caller's reject path.
async fn on_blocking_pool<T, F>(work: F) -> Result<T, DiagError>
where
    F: FnOnce() -> Result<T, DiagError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work).await.map_err(|join| {
        DiagError::new(Diag::new(Key::ApplyFilesystemWorkerFailed)).caused_by_text(join.to_string())
    })?
}

/// Durably serialize `v` as pretty JSON to `config.candidate.json`, and write
/// the sidecar stamp naming the build that produced it. The stamp is written
/// with the configuration it describes — never apart from it.
pub fn write_candidate(v: &serde_json::Value) -> Result<PathBuf, DiagError> {
    write_candidate_bytes(v)?;
    Ok(candidate_path())
}

/// [`write_candidate`] returning the exact bytes written, so a caller that
/// must hand the artefact to the elevated helper never re-reads the
/// user-writable path it just wrote.
fn write_candidate_bytes(v: &serde_json::Value) -> Result<Vec<u8>, DiagError> {
    let dir = config_dir();
    std::fs::create_dir_all(&dir).diag(Key::ApplyConfigDirCreateFailed)?;
    let json = serde_json::to_vec_pretty(v).diag(Key::ApplyCandidateSerializeFailed)?;
    write_synced(&candidate_path(), &json)?;
    // The stamp describes these exact bytes: its digest is the file identity
    // no later build-identity match can fake.
    let stamp = serde_json::to_vec_pretty(&current_stamp(sha256_hex(&json)))
        .diag(Key::ApplyCandidateSerializeFailed)?;
    write_synced(&meta_candidate_path(), &stamp)?;
    Ok(json)
}

/// [`write_candidate`], off the executor (see [`on_blocking_pool`]).
pub async fn write_candidate_offloaded(v: serde_json::Value) -> Result<PathBuf, DiagError> {
    on_blocking_pool(move || write_candidate(&v)).await
}

/// Create/write/flush one artefact. `sync_all` before the rename makes the
/// bytes durable before anything promotes or executes the file.
fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), DiagError> {
    let mut file =
        File::create(path).diag_with(Diag::new(Key::ApplyFileCreateFailed).arg(path.display()))?;
    file.write_all(bytes)
        .diag_with(Diag::new(Key::ApplyFileWriteFailed).arg(path.display()))?;
    file.sync_all()
        .diag_with(Diag::new(Key::ApplyFileFlushFailed).arg(path.display()))?;
    Ok(())
}

/// Promote the validated candidate without an interval where `config.json`
/// is missing. Rust's Windows `rename` uses `MoveFileExW` with
/// `MOVEFILE_REPLACE_EXISTING`.
///
/// The configuration renames first and its stamp second: a crash between the
/// two leaves the new artefact beside the stamp of the file it replaced, whose
/// digest cannot describe the new bytes — every consumer reads that pair as
/// "not this file's" and regenerates. The reverse order (stamp first) would
/// leave a stamp vouching for a file another build wrote, the one direction a
/// replay must never see.
pub fn commit() -> Result<(), DiagError> {
    let dir = config_dir();
    let active = active_path();
    let candidate = candidate_path();
    let lastgood = lastgood_path();
    let meta = meta_path();
    let meta_candidate = meta_candidate_path();
    let meta_lastgood = meta_lastgood_path();
    if active.exists() {
        let pending = dir.join("config.lastgood.pending.json");
        durable_copy(&active, &pending).diag(Key::ApplyLastgoodStageFailed)?;
        std::fs::rename(&pending, &lastgood).diag(Key::ApplyLastgoodReplaceFailed)?;
        // The retired artefact keeps its own stamp — and only while that stamp
        // really describes it. A mismatched or absent stamp is dropped, so the
        // last-good pair on disk is never a lie a replay could read as one.
        if meta.is_file() && stamp_describes(&meta, &active) {
            let pending_meta = dir.join("config.lastgood.meta.pending.json");
            durable_copy(&meta, &pending_meta).diag(Key::ApplyLastgoodStageFailed)?;
            std::fs::rename(&pending_meta, meta_lastgood).diag(Key::ApplyLastgoodReplaceFailed)?;
        } else if meta_lastgood.exists() {
            std::fs::remove_file(&meta_lastgood).diag(Key::ApplyLastgoodReplaceFailed)?;
        }
    }
    std::fs::rename(&candidate, &active).diag(Key::ApplyActiveReplaceFailed)?;
    if meta_candidate.is_file() && stamp_describes(&meta_candidate, &active) {
        std::fs::rename(&meta_candidate, &meta).diag(Key::ApplyActiveReplaceFailed)?;
    } else if meta.is_file() {
        // A promoted configuration with no stamp of its own (or one that does
        // not describe it) leaves none: the previous stamp describes the file
        // that was just replaced.
        std::fs::remove_file(&meta).diag(Key::ApplyActiveReplaceFailed)?;
    }
    Ok(())
}

/// [`commit`], off the executor (see [`on_blocking_pool`]).
pub async fn commit_offloaded() -> Result<(), DiagError> {
    on_blocking_pool(commit).await
}

/// Atomically restore `config.lastgood.json` over `config.json`, its sidecar
/// stamp travelling with it. A last-good pair written before sidecar stamps
/// existed has no stamp: the active stamp is then removed, so the restored
/// artefact never reads as one this build vouches for.
pub fn rollback() -> Result<(), DiagError> {
    let dir = config_dir();
    let active = active_path();
    let lastgood = lastgood_path();
    if !lastgood.exists() {
        return Err(DiagError::new(Diag::new(Key::ApplyRollbackMissing)));
    }
    let pending = dir.join("config.rollback.json");
    durable_copy(&lastgood, &pending).diag(Key::ApplyRollbackStageFailed)?;
    std::fs::rename(&pending, &active).diag(Key::ApplyRollbackRestoreFailed)?;
    let lastgood_meta = meta_lastgood_path();
    let meta = meta_path();
    if lastgood_meta.is_file() && stamp_describes(&lastgood_meta, &active) {
        let pending_meta = dir.join("config.rollback.meta.pending.json");
        durable_copy(&lastgood_meta, &pending_meta).diag(Key::ApplyRollbackStageFailed)?;
        std::fs::rename(&pending_meta, &meta).diag(Key::ApplyRollbackRestoreFailed)?;
    } else if meta.is_file() {
        // The restored configuration has no stamp of its own (or one that does
        // not describe it): the active stamp describes the failed candidate.
        std::fs::remove_file(&meta).diag(Key::ApplyRollbackRestoreFailed)?;
    }
    Ok(())
}

/// [`rollback`], off the executor (see [`on_blocking_pool`]).
pub async fn rollback_offloaded() -> Result<(), DiagError> {
    on_blocking_pool(rollback).await
}

/// The validated candidate's exact bytes. The apply gate captures them before
/// the commit rename so any later helper start stages precisely what
/// `xray -test` accepted — never a re-read of the user-writable active path
/// at elevated time.
fn read_candidate() -> Result<Vec<u8>, DiagError> {
    let path = candidate_path();
    std::fs::read(&path).diag_with(Diag::new(Key::ApplyFileReadFailed).arg(path.display()))
}

/// [`read_candidate`], off the executor (see [`on_blocking_pool`]).
pub async fn read_candidate_offloaded() -> Result<Vec<u8>, DiagError> {
    on_blocking_pool(read_candidate).await
}

fn durable_copy(source: &Path, destination: &Path) -> Result<(), DiagError> {
    let bytes = std::fs::read(source)
        .diag_with(Diag::new(Key::ApplyFileReadFailed).arg(source.display()))?;
    let mut file = File::create(destination)
        .diag_with(Diag::new(Key::ApplyFileCreateFailed).arg(destination.display()))?;
    file.write_all(&bytes)
        .diag_with(Diag::new(Key::ApplyFileWriteFailed).arg(destination.display()))?;
    file.sync_all()
        .diag_with(Diag::new(Key::ApplyFileFlushFailed).arg(destination.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::{
        AppMessage, ApplyOutput, META_CANDIDATE_NAME, META_LASTGOOD_NAME, OUTPUT_TAIL, TailRing,
        active_path, api_port_from_path, api_port_from_value, carries_health_extension, commit,
        lastgood_path, meta_path, rollback, settle_validation, spawn_validation_child,
        stamp_is_current, write_candidate,
    };
    use crate::i18n::{Key, t, t_fmt};
    use crate::model::settings::Language;
    use crate::rt::supervisor::{MAX_LINE_BYTES, TRUNCATED_MARKER};
    use crate::sys::paths::config_dir;
    use serde_json::json;

    /// The status read follows the launched config's own keys: either engine
    /// counts, neither means no reader, and an unparsable snapshot starts no
    /// read.
    #[test]
    fn health_extension_is_read_from_the_launched_config() {
        assert!(carries_health_extension(
            &json!({ "observatory": { "subjectSelector": ["srv-"] } }).to_string()
        ));
        assert!(carries_health_extension(
            &json!({ "burstObservatory": { "subjectSelector": ["srv-"] } }).to_string()
        ));
        assert!(!carries_health_extension(
            &json!({ "outbounds": [], "inbounds": [] }).to_string()
        ));
        assert!(!carries_health_extension("{not json"));
    }

    /// The candidate pair and the stamp are written together, and commit
    /// promotes them together: the active configuration and its stamp always
    /// describe the same build and bytes, while a retired configuration keeps
    /// the stamp that describes it (for the rollback replay).
    #[test]
    fn commit_moves_each_configuration_with_its_own_stamp() {
        crate::sys::appdata::with_appdata(|| {
            std::fs::create_dir_all(config_dir()).expect("create config dir");
            let previous = br#"{"previous":true}"#;
            std::fs::write(active_path(), previous).expect("write the previous active");
            std::fs::write(
                meta_path(),
                format!(
                    r#"{{"appVersion":"{}","corePin":"{}","configSha256":"{}"}}"#,
                    env!("CARGO_PKG_VERSION"),
                    crate::sys::core_dl::pinned_release_version(),
                    super::sha256_hex(previous)
                ),
            )
            .expect("write the previous stamp");
            write_candidate(&json!({"next": true})).expect("write the candidate pair");
            assert!(
                std::fs::read(config_dir().join(META_CANDIDATE_NAME)).is_ok(),
                "the candidate stamp is written with the candidate"
            );

            commit().expect("commit");

            assert_eq!(
                std::fs::read(active_path()).expect("read the active config"),
                serde_json::to_vec_pretty(&json!({"next": true})).expect("serialize the candidate"),
                "the committed configuration is the candidate"
            );
            assert!(
                stamp_is_current(),
                "the promoted stamp describes the file it was written for"
            );
            assert_eq!(
                std::fs::read(lastgood_path()).expect("read the retired config"),
                previous,
                "the previous configuration is retired for the rollback"
            );
            let retired_stamp = std::fs::read_to_string(config_dir().join(META_LASTGOOD_NAME))
                .expect("the retired stamp travels with the configuration it describes");
            assert!(
                retired_stamp.contains(&super::sha256_hex(previous)),
                "the retired stamp must describe the retired bytes: {retired_stamp}"
            );
        });
    }

    #[test]
    fn a_stamp_matches_only_the_build_that_wrote_it() {
        crate::sys::appdata::with_appdata(|| {
            std::fs::create_dir_all(config_dir()).expect("create config dir");
            assert!(!stamp_is_current(), "a missing stamp never matches");
            write_candidate(&json!({})).expect("write the candidate pair");
            commit().expect("commit the candidate");
            assert!(stamp_is_current());
            // Any single field naming another build breaks the match.
            for foreign in [
                r#"{"appVersion":"0.0.1","corePin":"v26.9.9"}"#,
                r#"{"appVersion":"0.1.1","corePin":"v1.0.0"}"#,
                r#"{"appVersion":"0.0.1"}"#,
                "not json",
            ] {
                std::fs::write(meta_path(), foreign).expect("write the foreign stamp");
                assert!(!stamp_is_current(), "{foreign} must not match this build");
            }
        });
    }

    /// A rollback restores the configuration and its stamp as one pair; a
    /// last-good config written before stamps existed leaves no stamp, so the
    /// restored artefact can never read as one this build vouches for.
    #[test]
    fn rollback_restores_the_stamp_pair_or_leaves_none() {
        crate::sys::appdata::with_appdata(|| {
            std::fs::create_dir_all(config_dir()).expect("create config dir");
            let lastgood_meta = config_dir().join(META_LASTGOOD_NAME);

            // A pair written by another build restores with its own stamp.
            std::fs::write(active_path(), br#"{"failed":true}"#).expect("write the failed active");
            std::fs::write(lastgood_path(), br#"{"good":true}"#).expect("write the last-good");
            std::fs::write(
                &lastgood_meta,
                br#"{"appVersion":"0.0.1","corePin":"v1.0.0"}"#,
            )
            .expect("write the last-good stamp");
            write_candidate(&json!({"failed": true})).expect("write the candidate pair");
            rollback().expect("rollback");
            assert_eq!(
                std::fs::read(active_path()).expect("read the restored config"),
                br#"{"good":true}"#
            );
            assert!(
                !stamp_is_current(),
                "a foreign last-good artefact must not read as this build's"
            );

            // A last-good config with no stamp restores without one.
            std::fs::write(meta_path(), br#"{"appVersion":"0.1.1","corePin":"v1.0.0"}"#)
                .expect("write a matching-looking active stamp");
            std::fs::remove_file(&lastgood_meta).expect("drop the last-good stamp");
            rollback().expect("rollback");
            assert!(
                !meta_path().exists(),
                "no stamp may survive without the configuration it describes"
            );
            assert!(!stamp_is_current());
        });
    }

    /// A retired configuration with no stamp of its own must not inherit the
    /// previous last-good stamp: that stamp would describe none of the retired
    /// bytes, and a rollback would replay a file no stamp vouches for.
    #[test]
    fn a_retired_configuration_never_inherits_a_stale_stamp() {
        crate::sys::appdata::with_appdata(|| {
            std::fs::create_dir_all(config_dir()).expect("create config dir");
            let lastgood_meta = config_dir().join(META_LASTGOOD_NAME);
            // A stale pair from an earlier run: a last-good stamp whose digest
            // describes bytes no longer present, beside a hand-written active
            // configuration with no stamp at all.
            std::fs::write(
                &lastgood_meta,
                format!(
                    r#"{{"appVersion":"{}","corePin":"{}","configSha256":"{}"}}"#,
                    env!("CARGO_PKG_VERSION"),
                    crate::sys::core_dl::pinned_release_version(),
                    "0".repeat(64)
                ),
            )
            .expect("write the stale stamp");
            std::fs::write(active_path(), br#"{"foreign":true}"#)
                .expect("write the foreign active config");

            write_candidate(&json!({"next": true})).expect("write the candidate pair");
            commit().expect("commit");

            assert!(
                !lastgood_meta.exists(),
                "a retired configuration with no stamp must not keep a stale one"
            );
            assert!(stamp_is_current(), "the promoted pair is this build's");

            // The foreign configuration is now the retired one; restored by a
            // rollback it can still never read as replayable.
            rollback().expect("rollback");
            assert_eq!(
                std::fs::read(active_path()).expect("read the restored config"),
                br#"{"foreign":true}"#
            );
            assert!(
                !stamp_is_current(),
                "a foreign configuration must never be replayable"
            );
        });
    }

    /// The stamp records the digest of the exact bytes it describes, so build
    /// identity alone can never vouch for a file the stamp did not produce.
    #[test]
    fn a_stamp_must_describe_the_exact_configuration_bytes() {
        crate::sys::appdata::with_appdata(|| {
            std::fs::create_dir_all(config_dir()).expect("create config dir");
            let stamp_for = |digest: &str| {
                format!(
                    r#"{{"appVersion":"{}","corePin":"{}","configSha256":"{digest}"}}"#,
                    env!("CARGO_PKG_VERSION"),
                    crate::sys::core_dl::pinned_release_version()
                )
            };
            std::fs::write(active_path(), br#"{"here":true}"#).expect("write the active config");
            std::fs::write(meta_path(), stamp_for(&"0".repeat(64)))
                .expect("write a mismatched stamp");
            assert!(
                !stamp_is_current(),
                "a stamp whose digest is not its file's must fail closed"
            );

            let digest = super::sha256_hex(br#"{"here":true}"#);
            std::fs::write(meta_path(), stamp_for(&digest)).expect("write the matching stamp");
            assert!(stamp_is_current(), "the digest of these bytes must match");

            std::fs::write(active_path(), br#"{"here":false}"#).expect("edit the active config");
            assert!(
                !stamp_is_current(),
                "an edited file must not keep the stamp that described it"
            );

            // A freshly written candidate carries the digest of its own bytes.
            write_candidate(&json!({"here": false})).expect("write the candidate pair");
            commit().expect("commit");
            assert!(stamp_is_current());
        });
    }

    #[test]
    fn api_port_comes_from_the_active_config_listener() {
        let temp = tempfile::NamedTempFile::new().expect("create config fixture");
        std::fs::write(temp.path(), r#"{"api":{"listen":"127.0.0.1:54465"}}"#)
            .expect("write config fixture");
        assert_eq!(api_port_from_path(temp.path()).unwrap(), 54465);
    }

    #[test]
    fn api_port_derives_from_a_candidate_value() {
        assert_eq!(
            api_port_from_value(&json!({"api": {"listen": "127.0.0.1:54465"}})).unwrap(),
            54465
        );
        assert!(
            api_port_from_value(&json!({"api": {"listen": "0.0.0.0:54465"}})).is_err(),
            "a non-loopback control plane must be rejected"
        );
        assert!(
            api_port_from_value(&json!({"api": {"listen": "127.0.0.1:0"}})).is_err(),
            "a zero control-plane port must be rejected"
        );
        assert!(
            api_port_from_value(&json!({"outbounds": []})).is_err(),
            "a config without api.listen must be rejected"
        );
    }

    #[test]
    fn api_listener_must_be_non_zero_loopback() {
        let temp = tempfile::NamedTempFile::new().expect("create config fixture");
        std::fs::write(temp.path(), r#"{"api":{"listen":"0.0.0.0:54465"}}"#)
            .expect("write config fixture");
        assert!(api_port_from_path(temp.path()).is_err());
    }

    #[test]
    fn candidate_dat_pins_suspension_uses_the_candidates_own_geodata_block() {
        use super::candidate_dat_pins_suspended;

        let dir = tempfile::tempdir().expect("candidate fixture dir");
        // The candidate config is the config that would run, so its own
        // geodata block — not the active config's — decides the gate's
        // DAT-suspension mode.
        let geodata = dir.path().join("config.candidate.json");
        std::fs::write(
            &geodata,
            r#"{"geodata":{"assets":[{"url":"https://example.com/geosite.dat","file":"geosite.dat"}]}}"#,
        )
        .expect("write geodata candidate");
        let plain = dir.path().join("plain.candidate.json");
        std::fs::write(&plain, r#"{"outbounds":[]}"#).expect("write plain candidate");
        assert!(candidate_dat_pins_suspended(&geodata));
        assert!(!candidate_dat_pins_suspended(&plain));
        assert!(
            !candidate_dat_pins_suspended(&dir.path().join("missing.json")),
            "an unreadable candidate fails closed toward the hard pins"
        );
    }

    // ---------------------------------------------------------------------
    // Bounded -test capture and kill-on-close job.
    // The per-line cap + truncation marker are pinned by the supervisor's
    // reader tests; here the ring, the process-level boundedness, the
    // timeout kill, and the job close are exercised.
    // ---------------------------------------------------------------------

    /// Marker env var on the re-executed flood child (see
    /// [`validation_flood_child`]); absent in a normal suite run.
    const FLOOD_ENV: &str = "BROCCOLI_VALIDATION_FLOOD_CHILD";
    /// Short final line the finite flooder prints; it must survive in the
    /// retained tail (newest-lines semantics) while older flood lines are
    /// evicted.
    const FLOOD_END_SENTINEL: &str = "BROCCOLI-FLOOD-END-SENTINEL";
    /// Length of one flood line: every line exceeds the supervisor's
    /// per-line cap, so each is truncated with the marker by the reader.
    const FLOOD_LINE_BYTES: usize = 8 * 1024;

    /// Child role for the flood tests. The parent re-executes the test
    /// binary with `--nocapture`, this test's name as filter, and
    /// [`FLOOD_ENV`] set, so a real process floods a real pipe the way a
    /// hostile or broken `xray -test` would. Without the marker this test
    /// is inert in the normal suite.
    #[test]
    fn validation_flood_child() {
        let Ok(mode) = std::env::var(FLOOD_ENV) else {
            return;
        };
        let line = "F".repeat(FLOOD_LINE_BYTES);
        let mut stdout = std::io::stdout().lock();
        match mode.as_str() {
            // Print far more than any cap, then the sentinel, then pass.
            "finite" => {
                for _ in 0..2000 {
                    if writeln!(stdout, "{line}").is_err() {
                        return;
                    }
                }
                // Test double: a closed pipe means the parent is gone —
                // dropping the write error ends this role quietly.
                let _ = writeln!(stdout, "{FLOOD_END_SENTINEL}");
            }
            // Print forever; only the parent's timeout kill ends this.
            "infinite" => loop {
                if writeln!(stdout, "{line}").is_err() {
                    return;
                }
            },
            _ => {}
        }
    }

    /// Command that re-executes the test binary as a flooding validation
    /// child in the given role.
    fn flood_command(mode: &str) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(
            std::env::current_exe().expect("test binary path for the flood child"),
        );
        command
            .args(["--nocapture", "validation_flood_child"])
            .env(FLOOD_ENV, mode);
        command
    }

    #[test]
    fn tail_ring_keeps_a_bounded_newest_tail() {
        let mut ring = TailRing::new(OUTPUT_TAIL);
        ring.push("OLD-PREFIX-UNIQUE".into());
        // Far more content than the budget, in lines well under the cap.
        for _ in 0..4000 {
            ring.push("x".repeat(MAX_LINE_BYTES / 4));
        }
        ring.push(FLOOD_END_SENTINEL.into());
        let message = ring.compose();
        assert!(
            message.ends_with(FLOOD_END_SENTINEL),
            "the newest line must survive as the tail: {message}"
        );
        assert!(
            !message.contains("OLD-PREFIX-UNIQUE"),
            "oldest lines must be evicted past the budget"
        );
        assert!(
            message.len() <= OUTPUT_TAIL,
            "retained message must not exceed the budget: {} bytes",
            message.len()
        );
    }

    #[test]
    fn tail_ring_never_drops_the_newest_line_even_when_over_budget() {
        let mut ring = TailRing::new(OUTPUT_TAIL);
        // One line at the reader's full cap (marker included) is over the
        // ring's budget once the separator is counted; it must still surface
        // whole — lossy decoding can push a kept line past the raw cap by a
        // constant factor, never past a bounded multiple.
        let keep = MAX_LINE_BYTES - TRUNCATED_MARKER.len();
        let giant = format!("{}a{TRUNCATED_MARKER}", "a".repeat(keep - 1));
        assert_eq!(giant.len(), MAX_LINE_BYTES);
        ring.push(giant.clone());
        assert_eq!(ring.compose(), giant);
        // And an empty ring composes to nothing.
        assert_eq!(TailRing::new(OUTPUT_TAIL).compose(), "");
    }

    /// A finite flooding child (over-cap lines plus a final sentinel,
    /// exiting 0) must produce a bounded message that still carries the
    /// newest output: the drain through the capped reader + ring never lets
    /// the retained tail grow, and it never loses the tail end.
    #[tokio::test(flavor = "current_thread")]
    async fn flooding_validation_child_output_stays_bounded_with_newest_tail() {
        let tail = Arc::new(Mutex::new(TailRing::new(OUTPUT_TAIL)));
        let mut child = spawn_validation_child(flood_command("finite"), Arc::clone(&tail))
            .await
            .expect("spawn flooding validation child");
        let (ok, output) = settle_validation(&mut child, &tail, Duration::from_secs(30)).await;
        drop(child);
        assert!(ok, "the finite flood child must exit 0: {output:?}");
        let ApplyOutput::Text(message) = output else {
            panic!("an exit verdict must carry the captured tail, got {output:?}");
        };
        assert!(
            message.contains(FLOOD_END_SENTINEL),
            "the newest output must reach the message tail: {message}"
        );
        assert!(
            message.len() <= OUTPUT_TAIL + MAX_LINE_BYTES + 512,
            "the retained message must stay bounded: {} bytes",
            message.len()
        );
    }

    /// An infinite flooding child must be killed when the timeout gate
    /// fires: the settle path reports the keyed timeout message and the
    /// process is gone afterwards.
    #[tokio::test(flavor = "current_thread")]
    async fn flooding_validation_child_is_killed_on_timeout() {
        let tail = Arc::new(Mutex::new(TailRing::new(OUTPUT_TAIL)));
        let mut child = spawn_validation_child(flood_command("infinite"), Arc::clone(&tail))
            .await
            .expect("spawn flooding validation child");
        assert!(
            matches!(child.child.try_wait(), Ok(None)),
            "the flooder must be alive when the gate fires"
        );
        let (ok, output) = settle_validation(&mut child, &tail, Duration::from_secs(2)).await;
        assert!(!ok, "the timeout verdict must not be a success");
        match &output {
            ApplyOutput::Message(AppMessage::Message(diag)) => {
                assert_eq!(diag.key(), Key::ApplyValidationTimeout);
            }
            other => panic!("the timeout verdict must carry a keyed message, got {other:?}"),
        }
        assert_eq!(
            output.text(Language::En),
            t_fmt(Language::En, Key::ApplyValidationTimeout, &[&2])
        );
        assert!(
            matches!(child.child.try_wait(), Ok(Some(_))),
            "the timeout path must kill the flooder"
        );
        drop(child);
    }

    /// Every converted apply error renders its keyed sentence, with the
    /// listener value kept as the argument of the invalid-address cases.
    #[test]
    fn converted_apply_errors_render_their_keys() {
        let missing = api_port_from_value(&json!({"outbounds": []}))
            .expect_err("a config without api.listen must be rejected");
        assert_eq!(missing.diag().key(), Key::ApplyListenMissing);
        assert_eq!(
            missing.text(Language::En),
            t(Language::En, Key::ApplyListenMissing)
        );

        let invalid = api_port_from_value(&json!({"api": {"listen": "not-an-address"}}))
            .expect_err("a non-address listener must be rejected");
        assert_eq!(invalid.diag().key(), Key::ApplyListenInvalid);
        assert_eq!(
            invalid.text(Language::En),
            t_fmt(Language::En, Key::ApplyListenInvalid, &[&"not-an-address"])
        );

        let not_loopback = api_port_from_value(&json!({"api": {"listen": "0.0.0.0:54465"}}))
            .expect_err("a non-loopback control plane must be rejected");
        assert_eq!(not_loopback.diag().key(), Key::ApplyListenNotLoopback);
        assert_eq!(
            not_loopback.text(Language::En),
            t_fmt(
                Language::En,
                Key::ApplyListenNotLoopback,
                &[&"0.0.0.0:54465"]
            )
        );
    }

    /// Crash-path orphaning: closing the last handle of the kill-on-close
    /// job terminates an assigned child even while the caller still owns
    /// the child handle — the exact state a GUI crash leaves behind, and
    /// the guarantee [`spawn_validation_child`] pins the `-test` child to
    /// through the shared supervisor job wrapper.
    #[test]
    fn job_close_kills_the_assigned_child() {
        use std::os::windows::io::AsRawHandle as _;
        use std::os::windows::process::CommandExt as _;
        use windows::Win32::Foundation::HANDLE;

        use crate::rt::supervisor::{CREATE_NO_WINDOW, Job};

        let mut command = std::process::Command::new("cmd");
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        command.creation_flags(CREATE_NO_WINDOW);
        let mut child = command.spawn().expect("spawn job probe child");
        let job = Job::new_kill_on_close().expect("create kill-on-close job");
        job.assign(HANDLE(child.as_raw_handle()))
            .expect("assign probe child to the job");
        assert!(
            matches!(child.try_wait(), Ok(None)),
            "the probe child must be alive inside its job"
        );
        drop(job);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Ok(None) => {
                    panic!("job close did not terminate the probe child");
                }
                Err(error) => panic!("waiting on the probe child failed: {error}"),
            }
        }
    }
}
