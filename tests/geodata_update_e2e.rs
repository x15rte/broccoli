//! End-to-end geodata auto-update regressions plus the
//! restart-after-swap / clear-restore regression.
//!
//! Starts the real pinned Xray core with a top-level `geodata` block and lets
//! the core itself download, swap, reload, and (on failure) roll back the dat
//! files on its own cron schedule — broccoli never downloads anything. These
//! tests are ignored by default because they hit the real network, verify
//! real TLS, and require a runnable managed core (`%APPDATA%\broccoli\core`).

use std::net::TcpListener;
use std::time::{Duration, Instant};

use broccoli::rt::{CoreCmd, CoreEvt, CorePhase, spawn_runtime};
use parking_lot::{Mutex, MutexGuard};
use sha2::{Digest, Sha256};

static APPDATA_LOCK: Mutex<()> = Mutex::new(());

struct AppDataGuard(Option<std::ffi::OsString>);

impl AppDataGuard {
    fn install(root: &std::path::Path) -> Self {
        let previous = std::env::var_os("APPDATA");
        // SAFETY: APPDATA_LOCK serializes this integration test's process-wide
        // environment mutation for its complete runtime lifetime.
        unsafe { std::env::set_var("APPDATA", root) };
        Self(previous)
    }
}

impl Drop for AppDataGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.0.take() {
            // SAFETY: APPDATA_LOCK remains held until this guard is dropped.
            unsafe { std::env::set_var("APPDATA", previous) };
        } else {
            // SAFETY: APPDATA_LOCK remains held until this guard is dropped.
            unsafe { std::env::remove_var("APPDATA") };
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind loopback port")
        .local_addr()
        .expect("read loopback port")
        .port()
}

/// Isolated runnable config; `geodata` (when Some) is the core-native block
/// written verbatim — broccoli's own 5-field cron validation is not on this path,
/// matching `core_update_e2e`'s raw-config approach.
fn write_runnable_config(
    root: &std::path::Path,
    socks_port: u16,
    api_port: u16,
    geodata: Option<serde_json::Value>,
    routing: Option<serde_json::Value>,
) {
    let config_dir = root.join("broccoli").join("config");
    std::fs::create_dir_all(&config_dir).expect("create isolated config directory");
    let mut config = serde_json::json!({
        "log": { "loglevel": "warning" },
        "stats": {},
        "policy": { "system": {
            "statsInboundUplink": true, "statsInboundDownlink": true,
            "statsOutboundUplink": true, "statsOutboundDownlink": true } },
        "api": { "tag": "api", "listen": format!("127.0.0.1:{api_port}"),
                 "services": ["StatsService", "HandlerService", "RoutingService",
                              "LoggerService", "ReflectionService"] },
        "inbounds": [{
            "tag": "in-socks", "listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": false }
        }],
        "outbounds": [
            { "tag": "direct", "protocol": "freedom", "settings": {} },
            { "tag": "block", "protocol": "blackhole", "settings": {} }
        ]
    });
    if let Some(geodata) = geodata {
        config
            .as_object_mut()
            .expect("config object")
            .insert("geodata".into(), geodata);
    }
    if let Some(routing) = routing {
        config
            .as_object_mut()
            .expect("config object")
            .insert("routing".into(), routing);
    }
    std::fs::write(
        config_dir.join("config.json"),
        serde_json::to_vec_pretty(&config).expect("serialize isolated config"),
    )
    .expect("write isolated config");
}

fn copy_file(source: &std::path::Path, destination: &std::path::Path) {
    std::fs::copy(source, destination).expect("copy managed core payload");
}

fn copy_installed_core(source_root: &std::path::Path, destination_root: &std::path::Path) {
    let source = source_root.join("broccoli/core");
    let destination = destination_root.join("broccoli/core");
    std::fs::create_dir_all(&destination).expect("create isolated managed core");
    for name in [
        ".broccoli-official-release.json",
        "xray.exe",
        "wintun.dll",
        "geoip.dat",
        "geosite.dat",
    ] {
        copy_file(&source.join(name), &destination.join(name));
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    // digest 0.11 no longer formats its output through `LowerHex`, so the
    // bytes are written out explicitly.
    hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Parse the runtime's `[broccoli] core started (direct, pid N)` log line.
fn parse_started_pid(line: &str) -> Option<u32> {
    line.strip_prefix("[broccoli] core started (direct, pid ")
        .and_then(|rest| rest.strip_suffix(')'))
        .and_then(|pid| pid.parse().ok())
}

/// True when the process is still running (STILL_ACTIVE), not merely that its
/// handle can be opened.
fn process_alive(pid: u32) -> bool {
    use windows::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    let Ok(handle) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }) else {
        return false;
    };
    let mut code = 0;
    let alive =
        unsafe { GetExitCodeProcess(handle, &mut code) }.is_ok() && code == STILL_ACTIVE.0 as u32;
    unsafe { CloseHandle(handle) }.ok();
    alive
}

/// Drain events until the core is gRPC-ready (Running) and the runtime has
/// logged its pid. Returns (pid, number of "core started" log lines, error).
fn wait_ready(
    receiver: &std::sync::mpsc::Receiver<CoreEvt>,
    deadline: Instant,
) -> (u32, usize, Option<String>) {
    let mut core_pid = None;
    let mut start_logs = 0usize;
    let mut saw_error = None;
    let mut running = false;
    while Instant::now() < deadline && (core_pid.is_none() || !running) {
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(CoreEvt::State(CorePhase::Running)) => running = true,
            Ok(CoreEvt::State(CorePhase::Error(error))) => saw_error = Some(error.to_string()),
            Ok(CoreEvt::Log {
                line,
                from_core: false,
            }) => {
                if let Some(pid) = parse_started_pid(&line) {
                    core_pid = Some(pid);
                    start_logs += 1;
                }
            }
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("runtime stopped before the core became ready")
            }
        }
    }
    assert!(
        running,
        "core did not become gRPC-ready: {:?}",
        saw_error.as_deref().unwrap_or("no error event")
    );
    (
        core_pid.expect("runtime must log the core pid"),
        start_logs,
        saw_error,
    )
}

/// Poll `receiver` until the runtime reports the stopped phase; panics on
/// deadline expiry.
fn wait_stopped(receiver: &std::sync::mpsc::Receiver<CoreEvt>, deadline: Instant) {
    let mut stopped = false;
    while Instant::now() < deadline && !stopped {
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(CoreEvt::State(CorePhase::Stopped)) => stopped = true,
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("runtime stopped before the core reached Stopped")
            }
        }
    }
    assert!(stopped, "core did not stop cleanly within the deadline");
}

/// Poll until `pid` no longer names a running process. The runtime reports
/// Stopped only after its backend observes the child's exit, so this is a
/// lag-tolerant liveness check that a stopped core really is gone before a
/// fresh spawn re-verifies and replaces it.
fn wait_process_exit(pid: u32, deadline: Instant) {
    while Instant::now() < deadline && process_alive(pid) {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!process_alive(pid), "core process {pid} must have exited");
}

/// Drain `window` of runtime events asserting the running core stays
/// undisturbed: no error phase, no stop, and no further start. `context`
/// names the phase under observation for the failure messages.
fn assert_stays_up(receiver: &std::sync::mpsc::Receiver<CoreEvt>, window: Duration, context: &str) {
    let deadline = Instant::now() + window;
    let mut restarts = 0usize;
    let mut saw_error = None;
    while Instant::now() < deadline {
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(CoreEvt::State(CorePhase::Error(error))) => saw_error = Some(error.to_string()),
            Ok(CoreEvt::State(CorePhase::Stopped | CorePhase::Backoff { .. })) => restarts += 1,
            Ok(CoreEvt::Log {
                line,
                from_core: false,
            }) => {
                if parse_started_pid(&line).is_some() {
                    restarts += 1;
                }
            }
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("runtime stopped while {context}");
            }
        }
    }
    assert_eq!(restarts, 0, "{context}: the core must not restart");
    assert!(
        saw_error.is_none(),
        "{context}: core entered an error phase: {:?}",
        saw_error
    );
}

#[test]
#[ignore = "downloads geoip.dat from the real network through the pinned official Xray release"]
fn downloads_and_reloads_geodata_without_restart() {
    let _appdata_lock: MutexGuard<'static, ()> = APPDATA_LOCK.lock();
    let installed_root = std::path::PathBuf::from(
        std::env::var_os("APPDATA").expect("real APPDATA must be available"),
    );
    assert!(
        installed_root.join("broccoli/core/xray.exe").is_file(),
        "the managed core must be installed before exercising geodata updates"
    );
    let isolated = tempfile::tempdir().expect("create isolated APPDATA");
    copy_installed_core(&installed_root, isolated.path());
    let (socks_port, api_port) = (free_port(), free_port());
    // Xray-core releases carry geoip.dat only inside the platform zips (the
    // upload glob is `Xray-*.zip*`), so the canonical standalone source is the
    // provenance repo itself: Loyalsoldier/v2ray-rules-dat @ release — the
    // same bytes Xray's CI bundles daily.
    let geodata = serde_json::json!({
        "cron": "@every 1s",
        "assets": [{
            "url": "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat",
            "file": "geoip.dat"
        }]
    });
    // Routing rules referencing geoip/geosite register matchers, so the
    // post-swap `Reload()` actually parses the swapped file — without them the
    // reload iterates zero matchers and silently skips the file (Xray
    // common/geodata/ip_registry.go Reload).
    let routing = serde_json::json!({
        "rules": [
            { "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct" },
            { "type": "field", "domain": ["geosite:cn"], "outboundTag": "direct" }
        ]
    });
    write_runnable_config(
        isolated.path(),
        socks_port,
        api_port,
        Some(geodata),
        Some(routing),
    );
    let geoip_path = isolated.path().join("broccoli/core/geoip.dat");
    let mtime_before = std::fs::metadata(&geoip_path)
        .expect("copied geoip.dat")
        .modified()
        .expect("read geoip.dat mtime");
    let _appdata = AppDataGuard::install(isolated.path());

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(
        evt_tx,
        egui::Context::default(),
        broccoli::metrics::MetricsHandle::new(),
    );
    rt.cmd.send(CoreCmd::Start).expect("send start command");

    let (core_pid, start_logs, ready_error) =
        wait_ready(&evt_rx, Instant::now() + Duration::from_secs(60));
    assert!(
        ready_error.is_none(),
        "core entered an error phase: {:?}",
        ready_error
    );

    // The core downloads geoip.dat and swaps it in place on its own schedule;
    // the bundled file differs in freshness, so mtime proves the swap.
    let swap_deadline = Instant::now() + Duration::from_secs(120);
    let mut swapped = false;
    let mut restarts = 0usize;
    let mut saw_error = None;
    while Instant::now() < swap_deadline && !swapped {
        if let Ok(metadata) = std::fs::metadata(&geoip_path)
            && let Ok(modified) = metadata.modified()
            && modified != mtime_before
        {
            swapped = true;
        }
        if !swapped {
            match evt_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(CoreEvt::State(CorePhase::Error(error))) => saw_error = Some(error.to_string()),
                Ok(CoreEvt::State(CorePhase::Stopped)) => restarts += 1,
                Ok(CoreEvt::Log {
                    line,
                    from_core: false,
                }) => {
                    if parse_started_pid(&line).is_some() {
                        restarts += 1;
                    }
                }
                Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("runtime stopped while waiting for the geodata swap")
                }
            }
        }
    }
    assert!(
        swapped,
        "geoip.dat was never swapped by the geodata scheduler (deadline 120s)"
    );

    // Let the scheduled reloads keep running a little longer: the core must
    // stay the same process, with no error phase and no second start.
    let settle = Instant::now() + Duration::from_secs(5);
    while Instant::now() < settle {
        match evt_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(CoreEvt::State(CorePhase::Error(error))) => saw_error = Some(error.to_string()),
            Ok(CoreEvt::Log {
                line,
                from_core: false,
            }) => {
                if parse_started_pid(&line).is_some() {
                    restarts += 1;
                }
            }
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("runtime stopped while confirming the core stayed alive")
            }
        }
    }
    assert_eq!(start_logs, 1, "the core must be started exactly once");
    assert_eq!(restarts, 0, "geodata reload must not restart the core");
    assert!(
        saw_error.is_none(),
        "core entered an error phase: {:?}",
        saw_error
    );
    assert!(
        process_alive(core_pid),
        "core process must still be alive after the geodata swap"
    );
}

#[test]
#[ignore = "requires a runnable managed core at %APPDATA%\\broccoli\\core"]
fn payload_files_stay_replaceable_while_core_runs() {
    // The core's geodata updater swaps assets by downloading to a `.tmp`
    // sibling and renaming over the target (Xray app/geodata download.go),
    // which needs every open handle of the target to share delete. Broccoli
    // must not pin the payload files for the child lifetime: this
    // probe performs the updater's exact swap while the runtime supervises a
    // live core, with no network and no scheduler wait.
    let _appdata_lock: MutexGuard<'static, ()> = APPDATA_LOCK.lock();
    let installed_root = std::path::PathBuf::from(
        std::env::var_os("APPDATA").expect("real APPDATA must be available"),
    );
    assert!(
        installed_root.join("broccoli/core/xray.exe").is_file(),
        "the managed core must be installed before probing payload replaceability"
    );
    let isolated = tempfile::tempdir().expect("create isolated APPDATA");
    copy_installed_core(&installed_root, isolated.path());
    let (socks_port, api_port) = (free_port(), free_port());
    // No `geodata` block: the probe swaps the file itself, so no download.
    write_runnable_config(isolated.path(), socks_port, api_port, None, None);
    let geoip_path = isolated.path().join("broccoli/core/geoip.dat");
    let original = std::fs::read(&geoip_path).expect("read copied geoip.dat");
    let original_sha = sha256_hex(&original);
    let _appdata = AppDataGuard::install(isolated.path());

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(
        evt_tx,
        egui::Context::default(),
        broccoli::metrics::MetricsHandle::new(),
    );
    rt.cmd.send(CoreCmd::Start).expect("send start command");

    let (core_pid, _start_logs, ready_error) =
        wait_ready(&evt_rx, Instant::now() + Duration::from_secs(60));
    assert!(
        ready_error.is_none(),
        "core entered an error phase: {:?}",
        ready_error
    );

    // The updater's swap: stage a `.tmp` sibling, then rename over the target.
    // Content is byte-identical so a successful swap cannot disturb the core.
    let temp_path = isolated.path().join("broccoli/core/geoip.dat.tmp");
    std::fs::write(&temp_path, &original).expect("write swap staging file");
    std::fs::rename(&temp_path, &geoip_path).expect(
        "geoip.dat must be replaceable while the core runs; \
         payload locks must not be retained for the child lifetime",
    );
    let swapped = std::fs::read(&geoip_path).expect("read swapped geoip.dat");
    assert_eq!(
        sha256_hex(&swapped),
        original_sha,
        "identical bytes must survive the swap"
    );

    // The core must not notice the swap: same process, no error, no restart.
    let settle = Instant::now() + Duration::from_secs(5);
    let mut restarts = 0usize;
    let mut saw_error = None;
    while Instant::now() < settle {
        match evt_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(CoreEvt::State(CorePhase::Error(error))) => saw_error = Some(error.to_string()),
            Ok(CoreEvt::State(CorePhase::Stopped)) => restarts += 1,
            Ok(CoreEvt::Log {
                line,
                from_core: false,
            }) => {
                if parse_started_pid(&line).is_some() {
                    restarts += 1;
                }
            }
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("runtime stopped while confirming the core stayed alive")
            }
        }
    }
    assert_eq!(restarts, 0, "payload replacement must not restart the core");
    assert!(
        saw_error.is_none(),
        "core entered an error phase: {:?}",
        saw_error
    );
    assert!(
        process_alive(core_pid),
        "core process must still be alive after the payload swap"
    );

    rt.cmd.send(CoreCmd::Stop).expect("stop the core");
    rt.cmd.send(CoreCmd::Shutdown).expect("shutdown runtime");
}

#[test]
#[ignore = "downloads a broken geodata payload from the real network to verify rollback"]
fn broken_file_rolls_back() {
    let _appdata_lock: MutexGuard<'static, ()> = APPDATA_LOCK.lock();
    let installed_root = std::path::PathBuf::from(
        std::env::var_os("APPDATA").expect("real APPDATA must be available"),
    );
    assert!(
        installed_root.join("broccoli/core/xray.exe").is_file(),
        "the managed core must be installed before exercising geodata rollback"
    );
    let isolated = tempfile::tempdir().expect("create isolated APPDATA");
    copy_installed_core(&installed_root, isolated.path());
    let (socks_port, api_port) = (free_port(), free_port());
    // 200 OK but Go source text, not a dat: reload must fail and roll back.
    let geodata = serde_json::json!({
        "cron": "@every 1s",
        "assets": [{
            "url": "https://raw.githubusercontent.com/XTLS/Xray-core/5ca6f4b7d4dc20a881d4330e498892697627ec0c/infra/conf/geodata.go",
            "file": "geoip.dat"
        }]
    });
    let routing = serde_json::json!({
        "rules": [
            { "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct" }
        ]
    });
    write_runnable_config(
        isolated.path(),
        socks_port,
        api_port,
        Some(geodata),
        Some(routing),
    );
    let geoip_path = isolated.path().join("broccoli/core/geoip.dat");
    let original = std::fs::read(&geoip_path).expect("read copied geoip.dat");
    let original_sha = sha256_hex(&original);
    let _appdata = AppDataGuard::install(isolated.path());

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(
        evt_tx,
        egui::Context::default(),
        broccoli::metrics::MetricsHandle::new(),
    );
    rt.cmd.send(CoreCmd::Start).expect("send start command");

    let (core_pid, _start_logs, ready_error) =
        wait_ready(&evt_rx, Instant::now() + Duration::from_secs(60));
    assert!(
        ready_error.is_none(),
        "core entered an error phase: {:?}",
        ready_error
    );

    // Phase A: the core swaps the broken payload in, fails the reload, and
    // logs the all-files rollback. The rollback log line is emitted only
    // after a successful swap (Xray app/geodata download.go), so it proves
    // the swap without racing the transient swap-then-restore window — the
    // file's mtime flips back within milliseconds each tick, which made an
    // mtime-based swap check flaky.
    let swap_deadline = Instant::now() + Duration::from_secs(120);
    let mut saw_rollback_log = false;
    let mut saw_error = None;
    while Instant::now() < swap_deadline && !saw_rollback_log {
        match evt_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(CoreEvt::State(CorePhase::Error(error))) => saw_error = Some(error.to_string()),
            Ok(CoreEvt::Log {
                line,
                from_core: true,
            }) => {
                if line.contains("failed to reload geodata after downloading assets, rolling back")
                {
                    saw_rollback_log = true;
                }
            }
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("runtime stopped while waiting for the geodata rollback")
            }
        }
    }
    assert!(
        saw_rollback_log,
        "the core must log the all-files rollback after a failed reload (deadline 120s)"
    );
    assert!(
        process_alive(core_pid),
        "core process must still be alive after the broken-payload rollback"
    );

    // Phase B: after the rollback the file is restored byte-identical to the
    // pre-copy original. The restored state is the stable one between the
    // recurring 1s scheduled attempts. Drain runtime events while polling so
    // a CorePhase::Error or restart in this window fails the test instead of
    // being silently missed.
    let restore_deadline = Instant::now() + Duration::from_secs(30);
    let mut restored = false;
    let mut restarts = 0usize;
    while Instant::now() < restore_deadline && !restored {
        if let Ok(current) = std::fs::read(&geoip_path) {
            restored = sha256_hex(&current) == original_sha;
        }
        if !restored {
            match evt_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(CoreEvt::State(CorePhase::Error(error))) => saw_error = Some(error.to_string()),
                Ok(CoreEvt::State(CorePhase::Stopped)) => restarts += 1,
                Ok(CoreEvt::Log {
                    line,
                    from_core: false,
                }) => {
                    if parse_started_pid(&line).is_some() {
                        restarts += 1;
                    }
                }
                Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("runtime stopped while waiting for the geodata restore")
                }
            }
        }
    }
    assert!(
        restored,
        "the rolled-back geoip.dat must match the original bytes (sha256)"
    );

    // Drain any events queued after the restore snapshot so a late error or
    // restart from the rollback window is still observed.
    let settle = Instant::now() + Duration::from_secs(5);
    while Instant::now() < settle {
        match evt_rx.recv_timeout(Duration::from_millis(250)) {
            Ok(CoreEvt::State(CorePhase::Error(error))) => saw_error = Some(error.to_string()),
            Ok(CoreEvt::State(CorePhase::Stopped)) => restarts += 1,
            Ok(CoreEvt::Log {
                line,
                from_core: false,
            }) => {
                if parse_started_pid(&line).is_some() {
                    restarts += 1;
                }
            }
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("runtime stopped while confirming the restore held")
            }
        }
    }
    assert_eq!(restarts, 0, "geodata rollback must not restart the core");
    assert!(
        saw_error.is_none(),
        "core entered an error phase: {:?}",
        saw_error
    );
    assert!(
        process_alive(core_pid),
        "core process must still be alive after the restore window"
    );

    rt.cmd.send(CoreCmd::Stop).expect("stop the core");
    rt.cmd.send(CoreCmd::Shutdown).expect("shutdown runtime");
}

/// A frozen upstream geo data file whose bytes can never equal the geo
/// data the pinned release bundles: the tag predates the pinned archive's
/// snapshot (Xray v26.7.28-era) by about two months and v2ray-rules-dat's
/// rules churn continuously, so a later pin only widens the gap. The swap
/// this test waits for is therefore guaranteed real drift — the observable
/// state the regression lives in. A moving
/// `release`-branch URL could serve byte-identical content if the pinned
/// archive were ever rebuilt the same day, silently voiding the
/// auto-restore coverage, so the URL is frozen to a release asset; Xray's
/// geodata client follows HTTPS redirects (CheckRedirect in
/// app/geodata/download.go).
const SWAPPED_GEOIP_URL: &str =
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/202606032327/geoip.dat";
/// SHA-256 of the file `SWAPPED_GEOIP_URL` serves (measured at authoring;
/// GitHub release assets are immutable).
const SWAPPED_GEOIP_SHA256: &str =
    "2cda9118ee9995d5dc15d36661a9dc30534a6272ba6882c0c159f7ce08f0288b";

/// A user-configured geo data refresh must not wedge
/// the next core start. A running core swaps geoip.dat from a real URL;
/// restarting with the URLs still configured must reach Running with the
/// swapped bytes intact (the suspended verification accepts user-managed
/// drift), and clearing the URLs and starting again must reach Running with
/// the managed geo data restored to the release bytes (the strict
/// verification heals the drift from the retained pristine pair). Pre-fix
/// code failed terminally at each later spawn — the wedge this closes.
#[test]
#[ignore = "downloads a frozen upstream geoip.dat from the real network and restarts the managed core"]
fn url_swapped_geo_data_restarts_cleanly_and_clearing_urls_auto_restores_release_bytes() {
    let _appdata_lock: MutexGuard<'static, ()> = APPDATA_LOCK.lock();
    let installed_root = std::path::PathBuf::from(
        std::env::var_os("APPDATA").expect("real APPDATA must be available"),
    );
    assert!(
        installed_root.join("broccoli/core/xray.exe").is_file(),
        "the managed core must be installed before exercising restart-after-swap"
    );
    let isolated = tempfile::tempdir().expect("create isolated APPDATA");
    copy_installed_core(&installed_root, isolated.path());
    let core_dir = isolated.path().join("broccoli/core");
    let geoip_path = core_dir.join("geoip.dat");
    let geosite_path = core_dir.join("geosite.dat");
    let original_geoip = std::fs::read(&geoip_path).expect("read copied geoip.dat");
    let original_geosite = std::fs::read(&geosite_path).expect("read copied geosite.dat");
    let original_geoip_sha = sha256_hex(&original_geoip);
    let original_geosite_sha = sha256_hex(&original_geosite);
    // The drift premise the whole test stands on: the frozen upstream file
    // must differ from the pinned release bytes, or the swap counter below
    // greens on identical re-swaps and the strict-entry heal in phase 4
    // no-ops while every assertion still passes (silent coverage void).
    assert_ne!(
        original_geoip_sha, SWAPPED_GEOIP_SHA256,
        "the frozen upstream geoip.dat must differ from the pinned release \
         bytes or the suspension and heal phases verify nothing"
    );
    // The retained pin-verified pristine pair: the copy above is
    // the real installed core, whose bytes match the pins, so the managed
    // files themselves are the pristine bytes — mirroring the fixture in
    // geodata_dat_pin_suspension.rs (retention normally happens inside the
    // install funnel).
    let pristine_dir = core_dir.join("pristine");
    std::fs::create_dir_all(&pristine_dir).expect("create fixture pristine dir");
    copy_file(&geoip_path, &pristine_dir.join("geoip.dat"));
    copy_file(&geosite_path, &pristine_dir.join("geosite.dat"));
    let (socks_port, api_port) = (free_port(), free_port());
    let geodata = serde_json::json!({
        "cron": "@every 1s",
        "assets": [{
            "url": SWAPPED_GEOIP_URL,
            "file": "geoip.dat"
        }]
    });
    // Routing rules referencing geoip/geosite register matchers, so the
    // post-swap `Reload()` actually parses the swapped file (see
    // downloads_and_reloads_geodata_without_restart).
    let routing = serde_json::json!({
        "rules": [
            { "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct" },
            { "type": "field", "domain": ["geosite:cn"], "outboundTag": "direct" }
        ]
    });
    write_runnable_config(
        isolated.path(),
        socks_port,
        api_port,
        Some(geodata),
        Some(routing.clone()),
    );
    let _appdata = AppDataGuard::install(isolated.path());

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(
        evt_tx,
        egui::Context::default(),
        broccoli::metrics::MetricsHandle::new(),
    );
    rt.cmd.send(CoreCmd::Start).expect("send start command");

    // Phase 1: the first run with the geodata block configured reaches
    // Running.
    let (first_pid, first_start_logs, ready_error) =
        wait_ready(&evt_rx, Instant::now() + Duration::from_secs(60));
    assert!(
        ready_error.is_none(),
        "core entered an error phase: {:?}",
        ready_error
    );
    assert_eq!(first_start_logs, 1, "the core must be started exactly once");

    // Phase 2: the core's own cron downloads the frozen upstream geoip.dat
    // and swaps it in. The wait is byte-based: three consecutive swaps that
    // hash to the frozen file prove the reload accepted it — a reload
    // failure rolls the file back to the release bytes within the same
    // tick, which would reset the counter instead of satisfying it.
    let swap_deadline = Instant::now() + Duration::from_secs(120);
    let mut last_mtime = std::fs::metadata(&geoip_path)
        .expect("metadata geoip.dat")
        .modified()
        .expect("read geoip.dat mtime");
    let mut stable_swaps = 0u32;
    let mut restarts = 0usize;
    let mut saw_error = None;
    while Instant::now() < swap_deadline && stable_swaps < 3 {
        if let Ok(metadata) = std::fs::metadata(&geoip_path)
            && let Ok(modified) = metadata.modified()
            && modified != last_mtime
        {
            last_mtime = modified;
            if let Ok(current) = std::fs::read(&geoip_path) {
                if sha256_hex(&current) == SWAPPED_GEOIP_SHA256 {
                    stable_swaps += 1;
                } else {
                    stable_swaps = 0;
                }
            }
        }
        if stable_swaps < 3 {
            match evt_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(CoreEvt::State(CorePhase::Error(error))) => saw_error = Some(error.to_string()),
                Ok(CoreEvt::State(CorePhase::Stopped | CorePhase::Backoff { .. })) => restarts += 1,
                Ok(CoreEvt::Log {
                    line,
                    from_core: false,
                }) => {
                    if parse_started_pid(&line).is_some() {
                        restarts += 1;
                    }
                }
                Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    panic!("runtime stopped while waiting for the geodata swap")
                }
            }
        }
    }
    assert!(
        stable_swaps >= 3,
        "geoip.dat never settled on the frozen upstream bytes (deadline 120s)"
    );
    assert_eq!(restarts, 0, "the swap must not restart the core");
    assert!(
        saw_error.is_none(),
        "core entered an error phase: {:?}",
        saw_error
    );
    assert_stays_up(
        &evt_rx,
        Duration::from_secs(5),
        "after the geo data swap landed",
    );
    assert!(
        process_alive(first_pid),
        "core process must still be alive after the swap window"
    );

    // Phase 3: stop and start again with the URLs still configured. The
    // swapped bytes must survive the restart and the core must reach
    // Running — pre-fix code died terminally at this spawn because the
    // drifted geoip.dat failed release verification; the suspension
    // makes the drift the expected user-managed state.
    rt.cmd.send(CoreCmd::Stop).expect("stop the core");
    wait_stopped(&evt_rx, Instant::now() + Duration::from_secs(10));
    wait_process_exit(first_pid, Instant::now() + Duration::from_secs(10));
    rt.cmd.send(CoreCmd::Start).expect("restart the core");
    let (second_pid, second_start_logs, ready_error) =
        wait_ready(&evt_rx, Instant::now() + Duration::from_secs(60));
    assert!(
        ready_error.is_none(),
        "restarted core entered an error phase: {:?}",
        ready_error
    );
    assert_eq!(second_start_logs, 1, "the restarted core must start once");
    assert_ne!(
        second_pid, first_pid,
        "the restart must spawn a fresh core process"
    );
    let after_restart = std::fs::read(&geoip_path).expect("read geoip.dat after restart");
    assert_eq!(
        sha256_hex(&after_restart),
        SWAPPED_GEOIP_SHA256,
        "the URL-swapped geo data must survive a restart while URLs are configured"
    );
    assert!(
        process_alive(second_pid),
        "restarted core process must be alive"
    );
    assert_stays_up(
        &evt_rx,
        Duration::from_secs(5),
        "after the restart with URLs configured",
    );

    // Phase 4: clear the geodata URLs and start again. The strict
    // verification (no geodata block) detects the drift, restores the
    // retained pristine pair, re-verifies, and spawns — the managed geo
    // data ends up byte-identical to the release files.
    rt.cmd.send(CoreCmd::Stop).expect("stop the core");
    wait_stopped(&evt_rx, Instant::now() + Duration::from_secs(10));
    wait_process_exit(second_pid, Instant::now() + Duration::from_secs(10));
    write_runnable_config(isolated.path(), socks_port, api_port, None, Some(routing));
    rt.cmd
        .send(CoreCmd::Start)
        .expect("start the core without URLs");
    let (third_pid, third_start_logs, ready_error) =
        wait_ready(&evt_rx, Instant::now() + Duration::from_secs(120));
    assert!(
        ready_error.is_none(),
        "auto-restored core entered an error phase: {:?}",
        ready_error
    );
    assert_eq!(third_start_logs, 1, "the restored core must start once");
    assert_ne!(
        third_pid, second_pid,
        "the clear-URLs start must spawn a fresh core process"
    );
    let healed_geoip = std::fs::read(&geoip_path).expect("read healed geoip.dat");
    let healed_geosite = std::fs::read(&geosite_path).expect("read healed geosite.dat");
    assert_eq!(
        sha256_hex(&healed_geoip),
        original_geoip_sha,
        "clearing the URLs must restore the release geoip.dat bytes"
    );
    assert_eq!(
        sha256_hex(&healed_geosite),
        original_geosite_sha,
        "clearing the URLs must restore the release geosite.dat bytes"
    );
    assert!(
        std::fs::read_dir(&core_dir)
            .expect("list core directory")
            .all(|entry| {
                !entry
                    .expect("core directory entry")
                    .file_name()
                    .to_string_lossy()
                    .contains(".restore-")
            }),
        "the heal must not leave restore temp files behind"
    );
    assert_stays_up(
        &evt_rx,
        Duration::from_secs(5),
        "after the clear-URLs auto-restore start",
    );
    assert!(
        process_alive(third_pid),
        "auto-restored core process must be alive"
    );

    rt.cmd.send(CoreCmd::Stop).expect("stop the core");
    rt.cmd.send(CoreCmd::Shutdown).expect("shutdown runtime");
}
