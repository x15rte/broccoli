//! End-to-end first-install updater regressions.
//!
//! Simulates choosing “Set up later”: an isolated APPDATA root has no managed
//! core, then sends either the pinned download or a transferred archive
//! through the same runtime operation. The post-install health gate works
//! from the app-owned configuration and ends its own proof process, so an
//! install settles back to the stopped phase with the core installed and a
//! stored artefact from a previous build can never reach the new core. These
//! tests are ignored by default because they require the official release
//! payload and a runnable Xray core.
//!
//! Runtime level, not screen level: each test drives `spawn_runtime` directly
//! and never builds the app, so the live-core fixture's lock and redirect
//! stand in for the shared screen-test fixture — whose lock, redirect and
//! kittest harness are one step. The real `%APPDATA%` read — the installed
//! managed core it copies into the isolated root, and the bytes a rollback
//! must restore — happens under the process-wide lock but BEFORE the redirect.

use std::ops::ControlFlow;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use broccoli::i18n::{Key, t, t_fmt};
use broccoli::model::settings::Language;
use broccoli::rt::{CoreCmd, CoreEvt, CorePhase, DownloadState, spawn_runtime};

#[path = "common/live_core.rs"]
pub mod live_core;

/// Leave a runnable-looking but unstamped `config/config.json` behind, the
/// way a previous build's start artefact could survive an app update. No test
/// may rely on it being run: the runtime regenerates or writes its own
/// configuration, and a stored artefact without this build's sidecar stamp is
/// never replayed.
fn write_runnable_config(root: &std::path::Path, socks_port: u16, api_port: u16) {
    let config_dir = root.join("broccoli").join("config");
    std::fs::create_dir_all(&config_dir).expect("create isolated config directory");
    let config = serde_json::json!({
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
    std::fs::write(
        config_dir.join("config.json"),
        serde_json::to_vec_pretty(&config).expect("serialize isolated config"),
    )
    .expect("write isolated config");
}

fn expect_terminal_update_failure(
    receiver: &std::sync::mpsc::Receiver<CoreEvt>,
    deadline: Instant,
) -> String {
    let mut failure = None;
    let mut operation_finished = false;
    live_core::drive_events(
        receiver,
        deadline,
        "before update failure reached a terminal state",
        |event| {
            match event {
                Some(CoreEvt::Download(DownloadState::Failed(error))) => failure = Some(error),
                Some(CoreEvt::Operation(None)) => operation_finished = true,
                Some(_) | None => {}
            }
            if failure.is_some() && operation_finished {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    );
    assert!(
        operation_finished,
        "failed update did not release its operation"
    );
    failure
        .expect("failed update did not report a terminal error")
        .text(Language::En)
}

#[test]
#[ignore = "starts the pinned official Xray release to verify update rollback"]
fn failed_updated_core_spawn_restores_retained_tree_and_releases_settings() {
    let _appdata_lock = live_core::appdata_lock();
    let isolated = live_core::IsolatedRoot::empty();
    // The rollback case needs a core the verification accepts, wherever it
    // comes from: the pinned archive when the fixture names one, else the
    // machine's install.
    let source = tempfile::tempdir().expect("managed core staging root");
    let installed_core = live_core::managed_core_source(source.path());
    isolated.install_managed_core(&installed_core);
    // The landed candidate is unstartable; the verified copy is the retained
    // last-good tree. The durable marker makes the first start the update's
    // health gate, whose spawn failure is a genuine start failure — the class
    // that must roll back.
    let root = isolated.path().join("broccoli");
    std::fs::rename(root.join("core"), root.join("core.bak")).expect("retain the verified tree");
    std::fs::create_dir_all(root.join("core")).expect("create the unstartable tree");
    std::fs::write(
        root.join("core").join("xray.exe"),
        b"not the pinned executable",
    )
    .expect("write the unstartable payload");
    std::fs::write(
        root.join(".core-update.pending"),
        b"broccoli-core-swap-v1\n",
    )
    .expect("write the durable swap marker");
    let _appdata = live_core::redirect_appdata(isolated.path());

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(evt_tx, egui::Context::default());
    rt.cmd
        .send(CoreCmd::Start)
        .expect("send the health-gate start command");
    let failure =
        expect_terminal_update_failure(&evt_rx, Instant::now() + Duration::from_secs(180));

    assert!(
        failure.contains("retained last-good core"),
        "the terminal must report the restored tree: {failure}"
    );
    assert_eq!(
        std::fs::read(isolated.path().join("broccoli/core/xray.exe"))
            .expect("rollback must restore the last-known-good managed core"),
        std::fs::read(installed_core.join("xray.exe")).expect("read the pinned executable"),
        "the restored tree must be the retained bytes"
    );
    assert!(
        !isolated.path().join("broccoli/core.bak").exists(),
        "rollback must consume the retained tree"
    );
    assert!(
        !isolated
            .path()
            .join("broccoli/.core-update.pending")
            .exists(),
        "rollback must remove its health marker"
    );

    rt.cmd.send(CoreCmd::Shutdown).expect("shutdown runtime");
}

#[test]
#[ignore = "downloads and health-gates the pinned official Xray release"]
fn deferred_setup_first_install_gates_the_downloaded_core_and_settles_stopped() {
    let _appdata_lock = live_core::appdata_lock();
    let isolated = live_core::IsolatedRoot::empty();
    let _appdata = live_core::redirect_appdata(isolated.path());
    // An unstamped artefact a previous build could have left behind: the
    // health-gate start writes and runs its own app-owned configuration and
    // must never replay this file.
    write_runnable_config(
        isolated.path(),
        live_core::free_port(),
        live_core::free_port(),
    );
    assert!(
        !isolated.path().join("broccoli/core/xray.exe").exists(),
        "this must begin with the deferred first-install state"
    );

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(evt_tx, egui::Context::default());
    rt.cmd
        .send(CoreCmd::UpdateCore)
        .expect("send first-install update command");

    let expected_version = broccoli::sys::core_dl::pinned_release_version()
        .strip_prefix('v')
        .expect("compiled pinned version must have a v prefix");
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut downloaded = None;
    let mut gate_settled = false;
    let mut operation_finished = false;
    live_core::drive_events(
        &evt_rx,
        deadline,
        "before the deferred first-install completed",
        |event| {
            match event {
                Some(CoreEvt::Download(DownloadState::Done(version))) => downloaded = Some(version),
                Some(CoreEvt::Download(DownloadState::Failed(error))) => {
                    panic!("deferred first-install update failed: {error}")
                }
                // The gate proves the downloaded binary and ends its own
                // process: the update completes without ever becoming the
                // running session.
                Some(CoreEvt::State {
                    phase: CorePhase::Stopped,
                    ..
                }) if downloaded.is_some() => gate_settled = true,
                Some(CoreEvt::State {
                    phase: CorePhase::Starting,
                    ..
                }) if downloaded.is_some() => {}
                Some(CoreEvt::State {
                    phase: CorePhase::Running,
                    ..
                }) => {
                    panic!("a post-install gate start must not become the running session")
                }
                Some(CoreEvt::State {
                    phase: CorePhase::Error(error),
                    ..
                }) => {
                    panic!("deferred first-install startup failed: {error}")
                }
                Some(CoreEvt::Operation(None)) if downloaded.is_some() => operation_finished = true,
                Some(_) | None => {}
            }
            if downloaded.is_some() && gate_settled && operation_finished {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    );

    assert_eq!(downloaded.as_deref(), Some(expected_version));
    assert!(
        gate_settled,
        "the post-install gate did not settle into the stopped phase"
    );
    assert!(
        operation_finished,
        "update operation did not reach a terminal state"
    );
    assert!(isolated.path().join("broccoli/core/xray.exe").is_file());
    assert!(
        !isolated.path().join("broccoli/core.bak").exists(),
        "a first install must not retain a phantom rollback tree"
    );
    assert!(
        !isolated
            .path()
            .join("broccoli/.core-update.pending")
            .exists(),
        "a health-checked install must clear its marker"
    );

    rt.cmd.send(CoreCmd::Shutdown).expect("shutdown runtime");
}

#[test]
#[ignore = "imports and health-gates the pinned official Xray release"]
fn imported_pinned_archive_gates_cleanly_and_settles_stopped() {
    let _appdata_lock = live_core::appdata_lock();
    let archive = PathBuf::from(
        std::env::var_os("BROCCOLI_TEST_XRAY_ARCHIVE")
            .expect("BROCCOLI_TEST_XRAY_ARCHIVE must point to the official pinned ZIP"),
    );
    assert!(
        archive.is_file(),
        "BROCCOLI_TEST_XRAY_ARCHIVE must point to a readable ZIP: {}",
        archive.display()
    );

    let isolated = live_core::IsolatedRoot::empty();
    let _appdata = live_core::redirect_appdata(isolated.path());
    assert!(
        !isolated.path().join("broccoli/core/xray.exe").exists(),
        "this must begin without a managed core"
    );

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(evt_tx, egui::Context::default());
    rt.cmd
        .send(CoreCmd::ImportCoreArchive(archive))
        .expect("send pinned archive import command");

    let expected_version = broccoli::sys::core_dl::pinned_release_version()
        .strip_prefix('v')
        .expect("compiled pinned version must have a v prefix");
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut downloaded = None;
    let mut gate_settled = false;
    let mut operation_finished = false;
    let mut app_logs = Vec::new();
    live_core::drive_events(
        &evt_rx,
        deadline,
        "before the imported archive completed",
        |event| {
            match event {
                Some(CoreEvt::Download(DownloadState::Done(version))) => downloaded = Some(version),
                Some(CoreEvt::Download(DownloadState::Failed(error))) => {
                    panic!("pinned archive import failed: {error}")
                }
                // The gate proves the imported binary and ends its own process:
                // the import completes without ever becoming the running
                // session.
                Some(CoreEvt::State {
                    phase: CorePhase::Stopped,
                    ..
                }) if downloaded.is_some() => gate_settled = true,
                Some(CoreEvt::State {
                    phase: CorePhase::Starting,
                    ..
                }) if downloaded.is_some() => {}
                Some(CoreEvt::State {
                    phase: CorePhase::Running,
                    ..
                }) => {
                    panic!("a post-install gate start must not become the running session")
                }
                Some(CoreEvt::State {
                    phase: CorePhase::Error(error),
                    ..
                }) => {
                    panic!("imported pinned core startup failed: {error}")
                }
                Some(CoreEvt::Operation(None)) if downloaded.is_some() => operation_finished = true,
                Some(CoreEvt::AppLog(message)) => app_logs.push(message.text(Language::En)),
                Some(_) | None => {}
            }
            if downloaded.is_some() && gate_settled && operation_finished {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    );

    assert_eq!(downloaded.as_deref(), Some(expected_version));
    assert!(
        gate_settled,
        "the post-install gate did not settle into the stopped phase"
    );
    assert!(
        operation_finished,
        "import operation did not reach a terminal state"
    );
    // The decision record of one install: the payload set the traffic spawn
    // verified, the configuration source the gate start runs, and the gate
    // completion that acknowledges the update and stops its proof process.
    assert!(
        app_logs.contains(&t_fmt(
            Language::En,
            Key::RtLogPayloadsVerified,
            &[&"xray.exe, wintun.dll, geoip.dat, geosite.dat"]
        )),
        "the traffic spawn must name the payload set it verified, got: {app_logs:?}"
    );
    assert!(
        app_logs.contains(&t(Language::En, Key::RtLogSpawnConfigGate).to_string()),
        "the gate start must name its app-owned configuration, got: {app_logs:?}"
    );
    assert!(
        app_logs.contains(&t(Language::En, Key::RtLogHealthGateCompleted).to_string()),
        "the completed gate must record the acknowledged update, got: {app_logs:?}"
    );
    for name in ["xray.exe", "wintun.dll", "geoip.dat", "geosite.dat"] {
        assert!(
            isolated.path().join("broccoli/core").join(name).is_file(),
            "managed runtime payload missing: {name}"
        );
    }
    assert!(
        !isolated.path().join("broccoli/core.bak").exists(),
        "a health-checked imported install must consume its rollback tree"
    );
    assert!(
        !isolated
            .path()
            .join("broccoli/.core-update.pending")
            .exists(),
        "a health-checked imported install must clear its health marker"
    );

    rt.cmd.send(CoreCmd::Shutdown).expect("shutdown runtime");
}
