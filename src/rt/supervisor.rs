//! Direct (unprivileged) core process supervision: spawn `xray run` hidden,
//! pinned to a kill-on-close Job Object so no orphan xray.exe can outlive the
//! GUI.

use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use crate::diag::{Diag, DiagError, DiagResult};
use crate::i18n::Key;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufReader};
use tokio::process::Command;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows::core::PCWSTR;

use crate::sys::paths::core_dir;

/// Shared sink for one captured core-output line `(text, is_stderr)`.
pub(crate) type OutputSink = Arc<Mutex<Box<dyn Fn(String, bool) + Send>>>;
/// Cap on the bytes retained from one core output line, truncation marker
/// included. `BufReader::lines()` grows its String without bound, so a single
/// newline-less flood from a hostile or broken core would balloon memory
/// (CWE-400/770); the capped reader below stops retaining bytes at
/// this cap and consumes the rest of the over-long line without buffering it.
pub(crate) const MAX_LINE_BYTES: usize = 4 * 1024;

/// Marker appended to an over-long line so truncation stays visible in the
/// log instead of silently cutting the diagnostic.
pub(crate) const TRUNCATED_MARKER: &str = " [truncated]";

/// `CREATE_NO_WINDOW` — the core must never pop a console.
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Owned Job Object handle. `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` means closing
/// the last handle terminates every process in the job, so dropping this is a
/// guaranteed kill even if tokio's own kill_on_drop path is bypassed.
///
/// SAFETY: the wrapped `HANDLE` is an opaque kernel-object reference with value
/// semantics — no process memory is dereferenced through it, and every Win32
/// call used on it (`SetInformationJobObject`, `AssignProcessToJobObject`,
/// `CloseHandle`) carries no thread affinity; the kernel serializes access.
/// Ownership is exclusive: the handle is created by `CreateJobObjectW` and
/// closed exactly once in `Drop`, on whatever thread drops the value, so
/// moving the handle (Send) or sharing it by reference (Sync) across threads
/// cannot race a close or alias a second owner.
///
/// Shared by the apply-gate's `xray run -test` child: every
/// managed-core spawn in the crate — main core, latency probe, validation —
/// pins its child to a kill-on-close job through this one wrapper.
pub(crate) struct Job(HANDLE);
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Job {
    pub(crate) fn new_kill_on_close() -> windows::core::Result<Job> {
        // SAFETY: `None` means default security attributes and
        // `PCWSTR::null()` means an anonymous (name-less) job object, so no
        // string needs to be valid. The windows crate maps the NULL-handle
        // failure to `Err`, so `Ok(job)` is a valid job handle; ownership of
        // it moves into the `Job` wrapper, whose `Drop` closes it exactly once.
        let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }?;
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `job` is the valid job handle created above and stays open
        // for the call. `info` is fully initialized (defaulted, then
        // `LimitFlags` set) and lives on this stack frame for the duration of
        // the call; the length is exactly
        // `size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()`, so the kernel
        // reads one complete, valid structure. Failure is mapped to `Err` and
        // propagated with `?`; the handle remains valid on either path.
        unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }?;
        Ok(Job(job))
    }

    pub(crate) fn assign(&self, process: HANDLE) -> windows::core::Result<()> {
        // SAFETY: `self.0` is a valid job handle kept open for `self`'s
        // lifetime; `process` is the raw handle of the just-spawned xray
        // child, obtained from `child.raw_handle()` while the `Child` value
        // still owns the process, so it is a valid, open process handle for
        // the duration of the call. The API reports failure as an error
        // (mapped to `Err`) and never leaves partial state.
        unsafe { AssignProcessToJobObject(self.0, process) }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the handle from `CreateJobObjectW`, never
        // closed before; `Drop` runs exactly once and `Job` is the exclusive
        // owner, so the handle is closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// A running xray core child plus the Job Object that owns it.
pub struct Child {
    child: tokio::process::Child,
    /// Kept alive until drop; field order matters: `child` is killed first,
    /// then the job handle closes and sweeps anything left.
    _job: Job,
    pid: u32,
    /// One task per piped stream, started by [`Child::pump_output`] and
    /// joined by [`Child::drain_output`] once the child is known dead.
    pumps: Vec<tokio::task::JoinHandle<()>>,
}

impl Child {
    /// Take the piped stdout/stderr and stream lines into `on_line(line,
    /// is_stderr)` on the current tokio runtime. Callable once; later calls are
    /// no-ops (the pipes are taken).
    ///
    /// Lines are capped at [`MAX_LINE_BYTES`]: an over-long line from a hostile
    /// or broken core is truncated with [`TRUNCATED_MARKER`] instead of growing
    /// an unbounded buffer (CWE-400/770).
    pub fn pump_output(&mut self, on_line: Box<dyn Fn(String, bool) + Send>) {
        let cb = Arc::new(Mutex::new(on_line));
        if let Some(stdout) = self.child.stdout.take() {
            let cb = Arc::clone(&cb);
            self.pumps
                .push(tokio::spawn(pump_stream(stdout, cb, false)));
        }
        if let Some(stderr) = self.child.stderr.take() {
            let cb = Arc::clone(&cb);
            self.pumps.push(tokio::spawn(pump_stream(stderr, cb, true)));
        }
    }

    /// Join the output pumps started by [`Child::pump_output`], so every byte
    /// the child wrote has landed in the sink before the caller composes
    /// diagnostics from it. Only call once the child is known dead — its
    /// `wait` resolved, or a kill plus wait confirmed the reap — because that
    /// is what closes the pipes: each pump ends at EOF. A kill whose reap
    /// timed out leaves a live process holding the pipe open, so its caller
    /// must not drain.
    pub async fn drain_output(&mut self) {
        for pump in self.pumps.drain(..) {
            let _ = pump.await;
        }
    }

    /// Wait for process exit (cancel-safe).
    pub async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait().await
    }

    /// Ask the process to die without waiting; the job handle close on drop
    /// backs this up.
    pub fn start_kill(&mut self) {
        let _ = self.child.start_kill();
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        // `_job` drops after this and closes the handle -> KILL_ON_JOB_CLOSE.
    }
}

/// Flavor of an `xray run` child, deciding which managed-core payloads must
/// be release-pin verified before CreateProcess.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpawnFlavor {
    /// Traffic-carrying main-core child (connect, apply restart, backoff
    /// retry): full routing config, loads wintun.dll and the geodata DATs.
    MainCore,
    /// One-shot latency-probe child: outbound-only config, executes only
    /// xray.exe (config shape pinned by tests in `rt::latency`).
    LatencyProbe,
}

impl SpawnFlavor {
    /// The verify scope this flavor needs, as a pure decision so the two
    /// spawn paths are unit-testable without spawning a child.
    fn verify_scope(self) -> crate::sys::core_dl::VerifyScope {
        match self {
            SpawnFlavor::MainCore => crate::sys::core_dl::VerifyScope::Full,
            SpawnFlavor::LatencyProbe => crate::sys::core_dl::VerifyScope::XrayExeOnly,
        }
    }

    /// Whether this flavor's spawn suspends the geo data pin compare because
    /// the config it is about to run carries a `geodata` asset URL. Only the
    /// traffic-carrying main core runs a config whose user-configured
    /// updater may have replaced the DAT files; the latency-probe
    /// config never references geo data and its exe-only scope holds no DAT
    /// payload, so it never suspends. The decision reads `config_path`
    /// through the one shared core_dl predicate — never re-implemented
    /// here — and runs on the executor (the config file is small) before the
    /// payload verify moves to the blocking pool.
    fn dat_pins_suspended(self, config_path: &Path) -> bool {
        match self {
            SpawnFlavor::MainCore => crate::sys::core_dl::dat_pins_suspended_at(config_path),
            SpawnFlavor::LatencyProbe => false,
        }
    }
}

/// Spawn `xray run -config <config_path>` for the main core:
/// - hidden (`CREATE_NO_WINDOW`), cwd = core dir, `XRAY_LOCATION_ASSET` = core
///   dir so geoip.dat/geosite.dat/wintun.dll resolve;
/// - stdout/stderr piped for [`Child::pump_output`];
/// - tokio `kill_on_drop` + Job Object `KILL_ON_JOB_CLOSE` (belt and braces:
///   even a GUI crash closes the handle, and the kernel kills the core).
///
/// A traffic-carrying main-core spawn always verifies the full four-payload
/// set (xray.exe, wintun.dll, geoip.dat, geosite.dat); a config carrying a
/// `geodata` asset URL suspends only the geo data compare, which stays
/// hash-locked but user-managed ([`SpawnFlavor::dat_pins_suspended`]).
/// The one-shot latency probe uses [`spawn_probe`], which
/// verifies only xray.exe. The verify is awaited off the executor (see
/// [`spawn_for`]); the verified payload handles are then held through
/// `CreateProcess` and released right after, exactly as before.
pub async fn spawn(config_path: &Path) -> Result<Child, DiagError> {
    spawn_for(config_path, SpawnFlavor::MainCore).await
}

/// Spawn the one-shot latency-probe `xray run -config <config_path>` child.
///
/// The probe child executes only xray.exe against an outbound-only config
/// that references no wintun/geodata payload (the probe-config shape is
/// pinned by unit tests in `rt::latency`), so only xray.exe is release-pin
/// verified before CreateProcess; wintun.dll and the geodata DATs are
/// re-hashed by the next main-core [`spawn`] instead. Main-core starts must
/// keep using [`spawn`]: the integrity guarantee that matters is on the core
/// that carries traffic. The verify is awaited off the executor (see
/// [`spawn_for`]).
pub async fn spawn_probe(config_path: &Path) -> Result<Child, DiagError> {
    spawn_for(config_path, SpawnFlavor::LatencyProbe).await
}

/// Shared spawn implementation; `flavor` picks the release-pin verify scope
/// (see [`SpawnFlavor::verify_scope`]), and a `MainCore` spawn additionally
/// suspends the geo data compare when the config at hand carries a
/// `geodata` asset URL (see [`SpawnFlavor::dat_pins_suspended`]).
///
/// Release verification hashes the pinned payloads in 8 KiB blocking reads
/// (tens to hundreds of MB at the full scope), so it runs on tokio's blocking
/// pool: the current-thread runtime executor must keep dispatching commands,
/// draining the helper hop, and watching the child while bytes are checked.
/// `VerifiedCore` is handles plus metadata — `Send` — so the
/// deny-write locks cross back to the executor, where they are held only
/// through `CreateProcess` and released right after, the same window a
/// synchronous verify had.
async fn spawn_for(config_path: &Path, flavor: SpawnFlavor) -> Result<Child, DiagError> {
    let core = core_dir();
    // Hold the verified payload handles only through CreateProcess: dropping
    // them earlier would leave a replacement race before CreateProcess opens
    // xray.exe by path, and holding them for the child lifetime would block
    // the core's own geodata updater from replacing the DAT files.
    let scope = flavor.verify_scope();
    // A config whose `geodata` block configured the core's updater may have
    // replaced the geo data files while a previous core
    // ran; that same block suspends their compare for this spawn,
    // with the executable/driver/metadata pins hard in both modes. Read on
    // the executor before the verify closure: the config file is small.
    let dat_pins_suspended = flavor.dat_pins_suspended(config_path);
    // The closure needs its own copy: the executor keeps `core` for the
    // CreateProcess command line and cwd below.
    let verify_core = core.clone();
    let verify = tokio::task::spawn_blocking(move || {
        let verified = if dat_pins_suspended {
            crate::sys::core_dl::open_verified_core_user_managed_dats(&verify_core)
        } else {
            crate::sys::core_dl::open_verified_core_with_scope(&verify_core, scope)
        };
        verified.diag(Key::SupervisorVerifyFailed)
    });
    let verified_core = match verify.await {
        Ok(verified) => verified?,
        Err(join) => {
            return Err(DiagError::new(Diag::new(Key::SupervisorVerifyWorkerFailed))
                .caused_by_text(join.to_string()));
        }
    };
    let mut cmd = Command::new(core.join("xray.exe"));
    cmd.arg("run")
        .arg("-config")
        .arg(config_path)
        .current_dir(&core)
        .env("XRAY_LOCATION_ASSET", &core)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .creation_flags(CREATE_NO_WINDOW);
    let child = cmd.spawn().diag(Key::SupervisorSpawnFailed)?;
    // CreateProcess has consumed the verified paths; release the deny-write/
    // delete locks so the core's geodata updater can swap the DAT files.
    drop(verified_core);

    let raw = child
        .raw_handle()
        .ok_or_else(|| DiagError::new(Diag::new(Key::SupervisorChildExited)))?;
    let job = Job::new_kill_on_close().diag(Key::SupervisorJobCreateFailed)?;
    job.assign(HANDLE(raw))
        .diag(Key::SupervisorJobAssignFailed)?;

    let pid = child.id().unwrap_or(0);
    Ok(Child {
        child,
        _job: job,
        pid,
        pumps: Vec::new(),
    })
}

/// Pump one piped stream line-by-line through [`read_capped_line`] into the
/// shared callback, until EOF or an I/O error. Shared by
/// [`Child::pump_output`] (core logs) and `rt::apply`'s validation drain
/// so both spawns get the same per-line cap and truncation
/// marker.
pub(crate) async fn pump_stream<S>(stream: S, cb: OutputSink, is_stderr: bool)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut reader = BufReader::new(stream);
    while let Ok(Some(line)) = read_capped_line(&mut reader).await {
        if let Ok(cb) = cb.lock() {
            cb(line, is_stderr);
        }
    }
}

/// Read one line of core output, bounded by [`MAX_LINE_BYTES`]. A line longer
/// than the cap is cut there and suffixed with [`TRUNCATED_MARKER`]; the rest
/// of the line is consumed and discarded, so the reader never buffers more
/// than the cap plus one [`BufReader`] chunk. A trailing `\r` (CRLF) is
/// stripped like `BufReader::lines()` did. Returns `None` at EOF.
async fn read_capped_line<R>(reader: &mut R) -> std::io::Result<Option<String>>
where
    R: AsyncBufRead + Unpin,
{
    let keep = MAX_LINE_BYTES - TRUNCATED_MARKER.len();
    let mut line: Vec<u8> = Vec::with_capacity(keep.min(256));
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            // EOF: a partial final line is still a line.
            return Ok(if line.is_empty() {
                None
            } else {
                Some(finish_line(line))
            });
        }
        if let Some(pos) = available.iter().position(|&byte| byte == b'\n') {
            let take = pos.min(keep.saturating_sub(line.len()));
            line.extend_from_slice(&available[..take]);
            reader.consume(pos + 1);
            if take < pos {
                // Content between the budget and the newline was cut.
                line.truncate(keep);
                line.extend_from_slice(TRUNCATED_MARKER.as_bytes());
            }
            return Ok(Some(finish_line(line)));
        }
        let take = available.len().min(keep.saturating_sub(line.len()));
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.len() >= keep {
            // The line continues past the cap: skip the rest, mark the cut.
            skip_rest_of_line(reader).await?;
            line.truncate(keep);
            line.extend_from_slice(TRUNCATED_MARKER.as_bytes());
            return Ok(Some(finish_line(line)));
        }
    }
}

/// Consume and discard the remainder of an over-long line (up to the next
/// `\n` or EOF) so the next read starts at the following line.
async fn skip_rest_of_line<R>(reader: &mut R) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
{
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(());
        }
        if let Some(pos) = available.iter().position(|&byte| byte == b'\n') {
            reader.consume(pos + 1);
            return Ok(());
        }
        let len = available.len();
        reader.consume(len);
    }
}

/// Strip a trailing `\r` (CRLF) and decode lossily — the old
/// `BufReader::lines()` required valid UTF-8 and silently killed the pump on
/// the first invalid byte; lossy decoding keeps the stream flowing. The
/// decoded string is bounded by a constant factor of the cap (each invalid
/// byte becomes a 3-byte replacement char), never unbounded.
fn finish_line(mut line: Vec<u8>) -> String {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8_lossy(&line).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{
        CREATE_NO_WINDOW, Child, Job, MAX_LINE_BYTES, SpawnFlavor, TRUNCATED_MARKER,
        read_capped_line,
    };
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncWriteExt as _, BufReader};

    /// The converted spawn failure renders its keyed frame with the keyed
    /// verify chain below it.
    #[test]
    fn converted_spawn_failures_render_their_keys() {
        use crate::diag::{Diag, DiagError};
        use crate::i18n::{Key, t_fmt};
        use crate::model::settings::Language;

        let error =
            DiagError::new(Diag::new(Key::SupervisorVerifyFailed)).caused_by(DiagError::new(
                Diag::new(Key::CoreDlPayloadVerifyFailed)
                    .arg("xray.exe")
                    .arg("expected-hash")
                    .arg("actual-hash"),
            ));
        assert_eq!(error.diag().key(), Key::SupervisorVerifyFailed);
        assert_eq!(
            error.text(Language::En),
            format!(
                "{}: {}",
                crate::i18n::t(Language::En, Key::SupervisorVerifyFailed),
                t_fmt(
                    Language::En,
                    Key::CoreDlPayloadVerifyFailed,
                    &[&"xray.exe", &"expected-hash", &"actual-hash"]
                )
            )
        );
    }

    #[test]
    fn main_core_spawn_requests_the_full_four_payload_verify() {
        // The traffic-carrying main-core child loads wintun.dll and the
        // geodata DATs, so its spawn must keep the full release-pin verify —
        // only the probe spawn may narrow the scope.
        assert_eq!(
            SpawnFlavor::MainCore.verify_scope(),
            crate::sys::core_dl::VerifyScope::Full
        );
    }

    #[test]
    fn latency_probe_spawn_requests_the_exe_only_verify() {
        // The probe child executes only xray.exe against an outbound-only
        // config, so its spawn must not re-hash wintun.dll or the geodata
        // DATs on every probe click.
        assert_eq!(
            SpawnFlavor::LatencyProbe.verify_scope(),
            crate::sys::core_dl::VerifyScope::XrayExeOnly
        );
    }

    #[test]
    fn geodata_updater_configured_matches_the_generator_emission_contract() {
        use crate::sys::core_dl::geodata_updater_configured;
        use serde_json::json;

        // The exact block `gen` emits when a URL is configured:
        // cron plus one `assets` entry per non-empty URL, in payload order.
        assert!(geodata_updater_configured(&json!({"geodata": {
            "cron": "0 0 * * *",
            "assets": [
                {"url": "https://example.com/geoip.dat", "file": "geoip.dat"},
                {"url": "https://example.com/geosite.dat", "file": "geosite.dat"},
            ],
        }})));
        assert!(
            geodata_updater_configured(&json!({"geodata": {"assets": [
                {"url": "https://example.com/geoip.dat", "file": "geoip.dat"}
            ]}})),
            "geoip-only config suspends"
        );
        assert!(
            geodata_updater_configured(&json!({"geodata": {"assets": [
                {"url": "https://example.com/geosite.dat", "file": "geosite.dat"}
            ]}})),
            "geosite-only config suspends"
        );
        // The emission filter is `!url.is_empty()` with no trimming, so a
        // whitespace URL counts as configured at both ends of the contract.
        assert!(
            geodata_updater_configured(&json!({"geodata": {"assets": [
                {"url": " ", "file": "geoip.dat"}
            ]}})),
            "whitespace URL is non-empty for the emission filter"
        );

        // Shapes the generator never emits — and hand-written configs that
        // cannot lift the pins — all fail closed.
        assert!(!geodata_updater_configured(&json!({})), "no geodata key");
        assert!(
            !geodata_updater_configured(&json!({"outbounds": []})),
            "unrelated config"
        );
        assert!(
            !geodata_updater_configured(&json!({"geodata": {}})),
            "empty geodata block"
        );
        assert!(
            !geodata_updater_configured(&json!({"geodata": {"assets": []}})),
            "empty assets"
        );
        assert!(
            !geodata_updater_configured(&json!({"geodata": {"assets": [
                {"url": null, "file": "geoip.dat"}
            ]}})),
            "null URL"
        );
        assert!(
            !geodata_updater_configured(&json!({"geodata": {"assets": [
                {"url": "", "file": "geoip.dat"}
            ]}})),
            "empty URL"
        );
        assert!(
            !geodata_updater_configured(&json!({"geodata": {"assets": [
                {"file": "geoip.dat"}
            ]}})),
            "absent URL"
        );
        assert!(
            !geodata_updater_configured(&json!({"geodata": {"assets": [
                {"url": 5, "file": "geoip.dat"}
            ]}})),
            "non-string URL"
        );
        assert!(
            !geodata_updater_configured(&json!({"geodata": {"assets": ["geoip.dat"]}})),
            "non-object entry"
        );
        assert!(
            !geodata_updater_configured(&json!({"geodata": "not-an-object"})),
            "non-object geodata block"
        );
        assert!(
            !geodata_updater_configured(&json!({"geodata": {"assets": "not-an-array"}})),
            "non-array assets"
        );
        assert!(!geodata_updater_configured(&json!(null)), "null config");
    }

    #[test]
    fn dat_pins_suspended_at_fails_closed_on_unreadable_or_unparseable_configs() {
        use crate::sys::core_dl::dat_pins_suspended_at;

        let dir = tempfile::tempdir().expect("config fixture dir");
        // Unparseable bytes, a missing path, and a directory read all answer
        // false: only a parsed config carrying a geodata asset URL lifts the
        // pins.
        let garbage = dir.path().join("garbage.json");
        std::fs::write(&garbage, b"not json {").expect("write garbage config");
        assert!(!dat_pins_suspended_at(&garbage));
        assert!(!dat_pins_suspended_at(&dir.path().join("missing.json")));
        assert!(
            !dat_pins_suspended_at(dir.path()),
            "directory read fails closed"
        );
        let plain = dir.path().join("plain.json");
        std::fs::write(&plain, r#"{"api":{"listen":"127.0.0.1:1"}}"#).expect("write plain config");
        assert!(!dat_pins_suspended_at(&plain));
        let geodata = dir.path().join("geodata.json");
        std::fs::write(
            &geodata,
            r#"{"geodata":{"cron":"0 0 * * *","assets":[{"url":"https://example.com/geoip.dat","file":"geoip.dat"}]}}"#,
        )
        .expect("write geodata config");
        assert!(
            dat_pins_suspended_at(&geodata),
            "the shared predicate decides"
        );
    }

    #[test]
    fn geo_data_payload_names_are_exactly_the_two_dat_files() {
        use crate::sys::core_dl::is_geo_data_payload;

        assert!(is_geo_data_payload("geoip.dat"));
        assert!(is_geo_data_payload("geosite.dat"));
        for name in [
            "xray.exe",
            "wintun.dll",
            ".broccoli-official-release.json",
            "config.json",
            "",
        ] {
            assert!(!is_geo_data_payload(name), "{name:?} must stay hard-pinned");
        }
    }

    #[test]
    fn user_managed_suspension_keeps_the_full_payload_set_strict_except_the_dat_pair() {
        // The user-managed entry opens the FULL scope with only the geo data
        // compares suspended: every runtime payload stays in the locked set,
        // and exactly the two geo data files are suspendable — xray.exe and
        // wintun.dll pin-compare in every mode.
        let pins = crate::sys::core_dl::VerifyScope::Full.payload_pins();
        let names: Vec<&str> = pins.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            ["xray.exe", "wintun.dll", "geoip.dat", "geosite.dat"]
        );
        let suspendable: Vec<bool> = names
            .iter()
            .map(|name| crate::sys::core_dl::is_geo_data_payload(name))
            .collect();
        assert_eq!(suspendable, [false, false, true, true]);
    }

    #[test]
    fn main_core_spawn_suspends_dat_pins_exactly_when_the_config_carries_geodata() {
        let dir = tempfile::tempdir().expect("config fixture dir");
        let geodata = dir.path().join("geodata.json");
        std::fs::write(
            &geodata,
            r#"{"geodata":{"assets":[{"url":"https://example.com/geoip.dat","file":"geoip.dat"}]}}"#,
        )
        .expect("write geodata config");
        let plain = dir.path().join("plain.json");
        std::fs::write(&plain, r#"{"outbounds":[]}"#).expect("write plain config");
        let missing = dir.path().join("missing.json");

        // The traffic-carrying spawn suspends exactly when the config it is
        // about to run carries a geodata asset URL; an unreadable config
        // fails closed toward the hard pins.
        assert!(SpawnFlavor::MainCore.dat_pins_suspended(&geodata));
        assert!(!SpawnFlavor::MainCore.dat_pins_suspended(&plain));
        assert!(
            !SpawnFlavor::MainCore.dat_pins_suspended(&missing),
            "fail closed"
        );
        // The latency probe executes only xray.exe from a config that never
        // references geo data: it never suspends, geodata block or not.
        assert!(!SpawnFlavor::LatencyProbe.dat_pins_suspended(&geodata));
        assert!(!SpawnFlavor::LatencyProbe.dat_pins_suspended(&plain));
        assert!(!SpawnFlavor::LatencyProbe.dat_pins_suspended(&missing));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn overlong_line_is_truncated_with_visible_marker() {
        let (mut tx, rx) = tokio::io::duplex(64 * 1024);
        tx.write_all(b"short\n").await.expect("feed short line");
        let huge = vec![b'a'; MAX_LINE_BYTES * 3];
        tx.write_all(&huge).await.expect("feed over-long line");
        tx.write_all(b"\nnext\r\n").await.expect("feed next line");
        drop(tx);

        let mut reader = BufReader::new(rx);
        assert_eq!(
            read_capped_line(&mut reader).await.expect("read short"),
            Some("short".to_string())
        );
        let truncated = read_capped_line(&mut reader)
            .await
            .expect("read over-long")
            .expect("over-long line present");
        assert!(truncated.ends_with(TRUNCATED_MARKER));
        assert!(truncated.len() <= MAX_LINE_BYTES);
        assert_eq!(
            truncated,
            format!(
                "{}a{TRUNCATED_MARKER}",
                "a".repeat(MAX_LINE_BYTES - TRUNCATED_MARKER.len() - 1)
            )
        );
        assert_eq!(
            read_capped_line(&mut reader).await.expect("read next"),
            Some("next".to_string()),
            "CRLF stripped and the following line stays intact"
        );
        assert!(
            read_capped_line(&mut reader)
                .await
                .expect("read eof")
                .is_none()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn line_at_exact_cap_is_not_truncated() {
        let keep = MAX_LINE_BYTES - TRUNCATED_MARKER.len();
        let (mut tx, rx) = tokio::io::duplex(64 * 1024);
        tx.write_all(&vec![b'x'; keep])
            .await
            .expect("feed capped line");
        tx.write_all(b"\n").await.expect("terminate line");
        drop(tx);

        let mut reader = BufReader::new(rx);
        let line = read_capped_line(&mut reader)
            .await
            .expect("read")
            .expect("line present");
        assert_eq!(line.len(), keep);
        assert!(!line.ends_with(TRUNCATED_MARKER));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drain_output_waits_for_the_final_lines_after_child_exit() {
        // Probe diagnostics are composed from the sink right after the child
        // is known dead: joining the pumps first is what puts the child's
        // last writes into the wall. `cmd /C echo` exits immediately after
        // writing, so nothing besides the drain flushes that line.
        let mut command = tokio::process::Command::new("cmd");
        command
            .arg("/C")
            .arg("echo final-line")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .creation_flags(CREATE_NO_WINDOW);
        let spawned = command.spawn().expect("spawn echo child");
        let pid = spawned.id().unwrap_or(0);
        let job = Job::new_kill_on_close().expect("CreateJobObjectW");
        let mut child = Child {
            child: spawned,
            _job: job,
            pid,
            pumps: Vec::new(),
        };
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&lines);
        child.pump_output(Box::new(move |line, _is_stderr| {
            if let Ok(mut lines) = sink.lock() {
                lines.push(line);
            }
        }));

        let status = child.wait().await.expect("the echo child exits");
        assert!(status.success(), "echo must succeed");
        child.drain_output().await;

        assert_eq!(
            lines.lock().expect("line sink").as_slice(),
            ["final-line"].as_slice(),
            "the child's final write must reach the sink before the drain returns"
        );
    }
}
