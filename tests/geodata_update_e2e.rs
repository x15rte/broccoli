//! End-to-end geodata auto-update regressions plus the
//! restart-after-swap / clear-restore regression.
//!
//! Starts the real pinned Xray core with a top-level `geodata` block and lets
//! the core itself download, swap, reload, and (on failure) roll back the dat
//! files on its own cron schedule — broccoli never downloads anything. These
//! tests are ignored by default because they hit the real network, verify
//! real TLS, and require a runnable managed core (`%APPDATA%\broccoli\core`).
//!
//! Runtime level, not screen level: each test drives `spawn_runtime` directly
//! and never builds the app, so the live-core fixture's lock and redirect
//! stand in for the shared screen-test fixture — whose lock, redirect and
//! kittest harness are one step. The real `%APPDATA%` read — the installed
//! core it copies into the isolated root, and the geodata bytes it pins —
//! happens under the process-wide lock but BEFORE the redirect.

use std::ops::ControlFlow;
use std::time::{Duration, Instant};

use broccoli::rt::{CoreCmd, CoreEvt, CorePhase, spawn_runtime};
use sha2::{Digest, Sha256};

#[path = "common/live_core.rs"]
pub mod live_core;

/// Isolated runnable config; `geodata` (when Some) is the core-native block
/// passed verbatim — broccoli's own 5-field cron validation is not on this path,
/// matching `core_update_e2e`'s raw-config approach. Configurations enter the
/// runtime through the apply path — a start never replays a stored artefact —
/// so the helper hands the value to `CoreCmd::Apply` instead of
/// writing a file.
fn runnable_config(
    socks_port: u16,
    api_port: u16,
    geodata: Option<serde_json::Value>,
    routing: Option<serde_json::Value>,
) -> serde_json::Value {
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
    config
}

/// Apply and start one isolated configuration: the runtime validates it with
/// `xray run -test`, commits it, and starts the core on it. These tests drive
/// one runtime with a direct configuration and never compare config
/// revisions, so the candidate is sent as the first revision.
fn apply_and_start(config: serde_json::Value) -> CoreCmd {
    CoreCmd::Apply {
        value: config,
        intent: broccoli::rt::ApplyIntent::CommitAndStart { tun_mode: false },
        revision: 0,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    // digest 0.11 no longer formats its output through `LowerHex`, so the
    // bytes are written out explicitly.
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Parse the runtime's app-log event that announces a direct core start and
/// return the pid. The needle is built from the runtime's own message key (its
/// text up to the `{}` placeholder), so a wording change cannot silently make
/// every start look missing while this wait keeps timing out. `CoreEvt::AppLog`
/// carries the rendered sentence itself; the log view's `[broccoli] ` prefix is
/// added by the GUI, not here.
fn parse_started_pid(line: &str) -> Option<u32> {
    let sentence = broccoli::i18n::t(
        broccoli::model::settings::Language::En,
        broccoli::i18n::Key::RtLogCoreStartedDirect,
    );
    let (sentence, tail) = sentence.split_once("{}")?;
    line.strip_prefix(sentence)?
        .strip_suffix(tail)?
        .parse()
        .ok()
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

/// The pid a runtime event announces for a direct core start, if it is one.
/// The announcement travels as an app-authored message (`CoreEvt::AppLog`);
/// plain log lines are checked too, so the wait survives either event shape.
fn started_pid(event: &CoreEvt) -> Option<u32> {
    let text = match event {
        CoreEvt::AppLog(message) => message.text(broccoli::model::settings::Language::En),
        CoreEvt::Log { line, .. } => line.clone(),
        _ => return None,
    };
    parse_started_pid(&text)
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
    live_core::drive_events(
        receiver,
        deadline,
        "before the core became ready",
        |event| {
            match event {
                Some(CoreEvt::State {
                    phase: CorePhase::Running,
                    ..
                }) => running = true,
                Some(CoreEvt::State {
                    phase: CorePhase::Error(error),
                    ..
                }) => saw_error = Some(error.to_string()),
                Some(event) => {
                    if let Some(pid) = started_pid(&event) {
                        core_pid = Some(pid);
                        start_logs += 1;
                    }
                }
                None => {}
            }
            if core_pid.is_some() && running {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    );
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
    live_core::drive_events(
        receiver,
        deadline,
        "before the core reached Stopped",
        |event| {
            if let Some(CoreEvt::State {
                phase: CorePhase::Stopped,
                ..
            }) = event
            {
                stopped = true;
            }
            if stopped {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    );
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
    live_core::drive_events(receiver, deadline, &format!("while {context}"), |event| {
        match event {
            Some(CoreEvt::State {
                phase: CorePhase::Error(error),
                ..
            }) => saw_error = Some(error.to_string()),
            Some(CoreEvt::State {
                phase: CorePhase::Stopped | CorePhase::Backoff { .. },
                ..
            }) => restarts += 1,
            Some(event) => restarts += usize::from(started_pid(&event).is_some()),
            None => {}
        }
        ControlFlow::Continue(())
    });
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
    let _appdata_lock = live_core::appdata_lock();
    // The geodata payloads are swapped on a tree the verification accepts,
    // wherever it comes from: the pinned archive when the fixture names one,
    // else the machine's install.
    let source = tempfile::tempdir().expect("managed core staging root");
    let installed_core = live_core::managed_core_source(source.path());
    let isolated = live_core::IsolatedRoot::empty();
    isolated.install_managed_core(&installed_core);
    let (socks_port, api_port) = (live_core::free_port(), live_core::free_port());
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
    let config = runnable_config(socks_port, api_port, Some(geodata), Some(routing));
    let geoip_path = isolated.path().join("broccoli/core/geoip.dat");
    let mtime_before = std::fs::metadata(&geoip_path)
        .expect("copied geoip.dat")
        .modified()
        .expect("read geoip.dat mtime");
    let _appdata = live_core::redirect_appdata(isolated.path());

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(evt_tx, egui::Context::default());
    rt.cmd
        .send(apply_and_start(config))
        .expect("apply and start the isolated configuration");

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
    live_core::drive_events(
        &evt_rx,
        swap_deadline,
        "while waiting for the geodata swap",
        |event| {
            if let Ok(metadata) = std::fs::metadata(&geoip_path)
                && let Ok(modified) = metadata.modified()
                && modified != mtime_before
            {
                swapped = true;
            }
            match event {
                Some(CoreEvt::State {
                    phase: CorePhase::Error(error),
                    ..
                }) => saw_error = Some(error.to_string()),
                Some(CoreEvt::State {
                    phase: CorePhase::Stopped,
                    ..
                }) => restarts += 1,
                Some(event) => restarts += usize::from(started_pid(&event).is_some()),
                None => {}
            }
            if swapped {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    );
    assert!(
        swapped,
        "geoip.dat was never swapped by the geodata scheduler (deadline 120s)"
    );

    // Let the scheduled reloads keep running a little longer: the core must
    // stay the same process, with no error phase and no second start.
    let settle = Instant::now() + Duration::from_secs(5);
    live_core::drive_events(
        &evt_rx,
        settle,
        "while confirming the core stayed alive",
        |event| {
            match event {
                Some(CoreEvt::State {
                    phase: CorePhase::Error(error),
                    ..
                }) => saw_error = Some(error.to_string()),
                Some(event) => restarts += usize::from(started_pid(&event).is_some()),
                None => {}
            }
            ControlFlow::Continue(())
        },
    );
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
    let _appdata_lock = live_core::appdata_lock();
    // The geodata payloads are swapped on a tree the verification accepts,
    // wherever it comes from: the pinned archive when the fixture names one,
    // else the machine's install.
    let source = tempfile::tempdir().expect("managed core staging root");
    let installed_core = live_core::managed_core_source(source.path());
    let isolated = live_core::IsolatedRoot::empty();
    isolated.install_managed_core(&installed_core);
    let (socks_port, api_port) = (live_core::free_port(), live_core::free_port());
    // No `geodata` block: the probe swaps the file itself, so no download.
    let config = runnable_config(socks_port, api_port, None, None);
    let geoip_path = isolated.path().join("broccoli/core/geoip.dat");
    let original = std::fs::read(&geoip_path).expect("read copied geoip.dat");
    let original_sha = sha256_hex(&original);
    let _appdata = live_core::redirect_appdata(isolated.path());

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(evt_tx, egui::Context::default());
    rt.cmd
        .send(apply_and_start(config))
        .expect("apply and start the isolated configuration");

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
    live_core::drive_events(
        &evt_rx,
        settle,
        "while confirming the core stayed alive",
        |event| {
            match event {
                Some(CoreEvt::State {
                    phase: CorePhase::Error(error),
                    ..
                }) => saw_error = Some(error.to_string()),
                Some(CoreEvt::State {
                    phase: CorePhase::Stopped,
                    ..
                }) => restarts += 1,
                Some(event) => restarts += usize::from(started_pid(&event).is_some()),
                None => {}
            }
            ControlFlow::Continue(())
        },
    );
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
    let _appdata_lock = live_core::appdata_lock();
    // The geodata payloads are swapped on a tree the verification accepts,
    // wherever it comes from: the pinned archive when the fixture names one,
    // else the machine's install.
    let source = tempfile::tempdir().expect("managed core staging root");
    let installed_core = live_core::managed_core_source(source.path());
    let isolated = live_core::IsolatedRoot::empty();
    isolated.install_managed_core(&installed_core);
    let (socks_port, api_port) = (live_core::free_port(), live_core::free_port());
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
    let config = runnable_config(socks_port, api_port, Some(geodata), Some(routing));
    let geoip_path = isolated.path().join("broccoli/core/geoip.dat");
    let original = std::fs::read(&geoip_path).expect("read copied geoip.dat");
    let original_sha = sha256_hex(&original);
    let _appdata = live_core::redirect_appdata(isolated.path());

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(evt_tx, egui::Context::default());
    rt.cmd
        .send(apply_and_start(config))
        .expect("apply and start the isolated configuration");

    let (core_pid, _start_logs, ready_error) =
        wait_ready(&evt_rx, Instant::now() + Duration::from_secs(60));
    assert!(
        ready_error.is_none(),
        "core entered an error phase: {:?}",
        ready_error
    );

    // Broken-payload swap: the core swaps the broken payload in, fails the
    // reload, and logs the all-files rollback. The rollback log line is
    // emitted only after a successful swap (Xray app/geodata download.go), so
    // it proves the swap without racing the transient swap-then-restore
    // window — the file's mtime flips back within milliseconds each tick,
    // which made an mtime-based swap check flaky.
    let swap_deadline = Instant::now() + Duration::from_secs(120);
    let mut saw_rollback_log = false;
    let mut saw_error = None;
    live_core::drive_events(
        &evt_rx,
        swap_deadline,
        "while waiting for the geodata rollback",
        |event| {
            match event {
                Some(CoreEvt::State {
                    phase: CorePhase::Error(error),
                    ..
                }) => saw_error = Some(error.to_string()),
                Some(CoreEvt::Log {
                    line,
                    from_core: true,
                }) => {
                    if line
                        .contains("failed to reload geodata after downloading assets, rolling back")
                    {
                        saw_rollback_log = true;
                    }
                }
                Some(_) | None => {}
            }
            if saw_rollback_log {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    );
    assert!(
        saw_rollback_log,
        "the core must log the all-files rollback after a failed reload (deadline 120s)"
    );
    assert!(
        process_alive(core_pid),
        "core process must still be alive after the broken-payload rollback"
    );

    // Rollback restore: the file comes back byte-identical to the pre-copy
    // original. That restored state is the stable one between the recurring
    // 1s scheduled attempts. Drain runtime events while polling so a
    // CorePhase::Error or restart in this window fails the test instead of
    // being silently missed.
    let restore_deadline = Instant::now() + Duration::from_secs(30);
    let mut restored = false;
    let mut restarts = 0usize;
    live_core::drive_events(
        &evt_rx,
        restore_deadline,
        "while waiting for the geodata restore",
        |event| {
            if let Ok(current) = std::fs::read(&geoip_path) {
                restored = sha256_hex(&current) == original_sha;
            }
            match event {
                Some(CoreEvt::State {
                    phase: CorePhase::Error(error),
                    ..
                }) => saw_error = Some(error.to_string()),
                Some(CoreEvt::State {
                    phase: CorePhase::Stopped,
                    ..
                }) => restarts += 1,
                Some(event) => restarts += usize::from(started_pid(&event).is_some()),
                None => {}
            }
            if restored {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    );
    assert!(
        restored,
        "the rolled-back geoip.dat must match the original bytes (sha256)"
    );

    // Drain any events queued after the restore snapshot so a late error or
    // restart from the rollback window is still observed.
    let settle = Instant::now() + Duration::from_secs(5);
    live_core::drive_events(
        &evt_rx,
        settle,
        "while confirming the restore held",
        |event| {
            match event {
                Some(CoreEvt::State {
                    phase: CorePhase::Error(error),
                    ..
                }) => saw_error = Some(error.to_string()),
                Some(CoreEvt::State {
                    phase: CorePhase::Stopped,
                    ..
                }) => restarts += 1,
                Some(event) => restarts += usize::from(started_pid(&event).is_some()),
                None => {}
            }
            ControlFlow::Continue(())
        },
    );
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
/// snapshot by over three months and v2ray-rules-dat's
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
    let _appdata_lock = live_core::appdata_lock();
    // The geodata payloads are swapped on a tree the verification accepts,
    // wherever it comes from: the pinned archive when the fixture names one,
    // else the machine's install.
    let source = tempfile::tempdir().expect("managed core staging root");
    let installed_core = live_core::managed_core_source(source.path());
    let isolated = live_core::IsolatedRoot::empty();
    isolated.install_managed_core(&installed_core);
    let core_dir = isolated.path().join("broccoli/core");
    let geoip_path = core_dir.join("geoip.dat");
    let geosite_path = core_dir.join("geosite.dat");
    let original_geoip = std::fs::read(&geoip_path).expect("read copied geoip.dat");
    let original_geosite = std::fs::read(&geosite_path).expect("read copied geosite.dat");
    let original_geoip_sha = sha256_hex(&original_geoip);
    let original_geosite_sha = sha256_hex(&original_geosite);
    // The drift premise the whole test stands on: the frozen upstream file
    // must differ from the pinned release bytes, or the swap counter below
    // greens on identical re-swaps and the strict-verification heal no-ops
    // while every assertion still passes (silent coverage void).
    assert_ne!(
        original_geoip_sha, SWAPPED_GEOIP_SHA256,
        "the frozen upstream geoip.dat must differ from the pinned release \
         bytes or the suspension and heal checks verify nothing"
    );
    // The retained pin-verified pristine pair: the copy above is
    // the real installed core, whose bytes match the pins, so the managed
    // files themselves are the pristine bytes — mirroring the fixture in
    // geodata_dat_pin_suspension.rs (retention normally happens inside the
    // install funnel).
    let pristine_dir = core_dir.join("pristine");
    std::fs::create_dir_all(&pristine_dir).expect("create fixture pristine dir");
    std::fs::copy(&geoip_path, pristine_dir.join("geoip.dat")).expect("copy managed core payload");
    std::fs::copy(&geosite_path, pristine_dir.join("geosite.dat"))
        .expect("copy managed core payload");
    let (socks_port, api_port) = (live_core::free_port(), live_core::free_port());
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
    let config = runnable_config(socks_port, api_port, Some(geodata), Some(routing.clone()));
    let _appdata = live_core::redirect_appdata(isolated.path());

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(evt_tx, egui::Context::default());
    rt.cmd
        .send(apply_and_start(config.clone()))
        .expect("apply and start the isolated configuration");

    // First run: with the geodata block configured the core reaches Running.
    let (first_pid, first_start_logs, ready_error) =
        wait_ready(&evt_rx, Instant::now() + Duration::from_secs(60));
    assert!(
        ready_error.is_none(),
        "core entered an error phase: {:?}",
        ready_error
    );
    assert_eq!(first_start_logs, 1, "the core must be started exactly once");

    // Scheduled download: the core's own cron fetches the frozen upstream
    // geoip.dat and swaps it in. The wait is byte-based: three consecutive
    // swaps that hash to the frozen file prove the reload accepted it — a
    // reload failure rolls the file back to the release bytes within the
    // same tick, which would reset the counter instead of satisfying it.
    let swap_deadline = Instant::now() + Duration::from_secs(120);
    let mut last_mtime = std::fs::metadata(&geoip_path)
        .expect("metadata geoip.dat")
        .modified()
        .expect("read geoip.dat mtime");
    let mut stable_swaps = 0u32;
    let mut restarts = 0usize;
    let mut saw_error = None;
    live_core::drive_events(
        &evt_rx,
        swap_deadline,
        "while waiting for the geodata swap",
        |event| {
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
            match event {
                Some(CoreEvt::State {
                    phase: CorePhase::Error(error),
                    ..
                }) => saw_error = Some(error.to_string()),
                Some(CoreEvt::State {
                    phase: CorePhase::Stopped | CorePhase::Backoff { .. },
                    ..
                }) => restarts += 1,
                Some(event) => restarts += usize::from(started_pid(&event).is_some()),
                None => {}
            }
            if stable_swaps >= 3 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    );
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

    // Restart with URLs configured: stop and start again; the swapped bytes
    // must survive the restart and the core must reach Running — code
    // without the suspension died terminally at this spawn because the
    // drifted geoip.dat failed release verification, and the suspension
    // turns the drift into the expected user-managed state.
    rt.cmd.send(CoreCmd::Stop).expect("stop the core");
    wait_stopped(&evt_rx, Instant::now() + Duration::from_secs(10));
    wait_process_exit(first_pid, Instant::now() + Duration::from_secs(10));
    rt.cmd
        .send(apply_and_start(config.clone()))
        .expect("restart the core");
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

    // Without URLs: clear the geodata block and start again. The strict
    // verification detects the drift, restores the retained pristine pair,
    // re-verifies, and spawns — the managed geo data ends up byte-identical
    // to the release files.
    rt.cmd.send(CoreCmd::Stop).expect("stop the core");
    wait_stopped(&evt_rx, Instant::now() + Duration::from_secs(10));
    wait_process_exit(second_pid, Instant::now() + Duration::from_secs(10));
    rt.cmd
        .send(apply_and_start(runnable_config(
            socks_port,
            api_port,
            None,
            Some(routing),
        )))
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
