//! End-to-end first-install updater regressions.
//!
//! Simulates choosing “Set up later”: an isolated APPDATA root has a valid
//! config but no managed core, then sends either the pinned download or a
//! transferred archive through the same runtime operation. The runtime
//! deliberately starts with a different API endpoint to cover a saved-config/
//! settings-port mismatch. These tests are ignored by default because they
//! require the official release payload and a runnable Xray core.

use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use broccoli::model::settings::Language;
use broccoli::rt::{CoreCmd, CoreEvt, CorePhase, DownloadState, spawn_runtime};
use parking_lot::{Mutex, MutexGuard};

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

fn expect_terminal_update_failure(
    receiver: &std::sync::mpsc::Receiver<CoreEvt>,
    deadline: Instant,
) -> String {
    let mut failure = None;
    let mut operation_finished = false;
    while Instant::now() < deadline && !(failure.is_some() && operation_finished) {
        match receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(CoreEvt::Download(DownloadState::Failed(error))) => failure = Some(error),
            Ok(CoreEvt::Operation(None)) => operation_finished = true,
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("runtime stopped before update failure reached a terminal state")
            }
        }
    }
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
fn failed_updated_core_restores_retained_tree_and_releases_settings() {
    let _appdata_lock: MutexGuard<'static, ()> = APPDATA_LOCK.lock();
    let installed_root = std::path::PathBuf::from(
        std::env::var_os("APPDATA").expect("real APPDATA must be available"),
    );
    assert!(
        installed_root.join("broccoli/core/xray.exe").is_file(),
        "the managed core must be installed before exercising rollback"
    );
    let isolated = tempfile::tempdir().expect("create isolated APPDATA");
    copy_installed_core(&installed_root, isolated.path());
    let api_port = free_port();
    let occupied_listener =
        TcpListener::bind(("127.0.0.1", api_port)).expect("occupy updated core API listener");
    write_runnable_config(isolated.path(), free_port(), api_port);
    let _appdata = AppDataGuard::install(isolated.path());

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(
        evt_tx,
        egui::Context::default(),
        broccoli::metrics::MetricsHandle::new(),
    );
    rt.cmd
        .send(CoreCmd::UpdateCore)
        .expect("send managed core update command");
    let failure =
        expect_terminal_update_failure(&evt_rx, Instant::now() + Duration::from_secs(180));

    assert!(
        failure.contains("restored retained last-good core"),
        "{failure}"
    );
    assert!(
        isolated.path().join("broccoli/core/xray.exe").is_file(),
        "rollback must restore the last-known-good managed core"
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

    drop(occupied_listener);
    rt.cmd.send(CoreCmd::Shutdown).expect("shutdown runtime");
}

#[test]
#[ignore = "downloads and starts the pinned official Xray release"]
fn deferred_setup_update_recovers_active_api_endpoint_and_reaches_ready_terminal_state() {
    let _appdata_lock: MutexGuard<'static, ()> = APPDATA_LOCK.lock();
    let isolated = tempfile::tempdir().expect("create isolated APPDATA");
    let _appdata = AppDataGuard::install(isolated.path());
    let (socks_port, api_port) = (free_port(), free_port());
    write_runnable_config(isolated.path(), socks_port, api_port);
    assert!(
        !isolated.path().join("broccoli/core/xray.exe").exists(),
        "this must begin with the deferred first-install state"
    );

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(
        evt_tx,
        egui::Context::default(),
        broccoli::metrics::MetricsHandle::new(),
    );
    rt.cmd
        .send(CoreCmd::UpdateCore)
        .expect("send first-install update command");

    let expected_version = broccoli::sys::core_dl::pinned_release_version()
        .strip_prefix('v')
        .expect("compiled pinned version must have a v prefix");
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut downloaded = None;
    let mut running = false;
    let mut operation_finished = false;
    while Instant::now() < deadline && !(downloaded.is_some() && running && operation_finished) {
        match evt_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(CoreEvt::Download(DownloadState::Done(version))) => downloaded = Some(version),
            Ok(CoreEvt::Download(DownloadState::Failed(error))) => {
                panic!("deferred first-install update failed: {error}")
            }
            Ok(CoreEvt::State(CorePhase::Running)) => running = true,
            Ok(CoreEvt::State(CorePhase::Error(error))) => {
                panic!("deferred first-install startup failed: {error}")
            }
            Ok(CoreEvt::Operation(None)) if downloaded.is_some() => operation_finished = true,
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("runtime stopped before the deferred first-install completed")
            }
        }
    }

    assert_eq!(downloaded.as_deref(), Some(expected_version));
    assert!(running, "downloaded core did not become gRPC-ready");
    assert!(
        operation_finished,
        "update operation did not reach a terminal state"
    );
    assert!(isolated.path().join("broccoli/core/xray.exe").is_file());
    assert!(
        !isolated.path().join("broccoli/core.bak").exists(),
        "a first install must not retain a phantom rollback tree"
    );

    rt.cmd.send(CoreCmd::Stop).expect("stop downloaded core");
    let stop_deadline = Instant::now() + Duration::from_secs(10);
    let mut stopped = false;
    while Instant::now() < stop_deadline && !stopped {
        stopped = matches!(
            evt_rx.recv_timeout(Duration::from_millis(250)),
            Ok(CoreEvt::State(CorePhase::Stopped))
        );
    }
    assert!(stopped, "downloaded core did not stop cleanly");
    rt.cmd.send(CoreCmd::Shutdown).expect("shutdown runtime");
}

#[test]
#[ignore = "imports and starts the pinned official Xray release"]
fn imported_pinned_archive_reaches_ready_terminal_state() {
    let _appdata_lock: MutexGuard<'static, ()> = APPDATA_LOCK.lock();
    let archive = PathBuf::from(
        std::env::var_os("BROCCOLI_TEST_XRAY_ARCHIVE")
            .expect("BROCCOLI_TEST_XRAY_ARCHIVE must point to the official pinned ZIP"),
    );
    assert!(
        archive.is_file(),
        "BROCCOLI_TEST_XRAY_ARCHIVE must point to a readable ZIP: {}",
        archive.display()
    );

    let isolated = tempfile::tempdir().expect("create isolated APPDATA");
    let _appdata = AppDataGuard::install(isolated.path());
    let (socks_port, api_port) = (free_port(), free_port());
    write_runnable_config(isolated.path(), socks_port, api_port);
    assert!(
        !isolated.path().join("broccoli/core/xray.exe").exists(),
        "this must begin without a managed core"
    );

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = spawn_runtime(
        evt_tx,
        egui::Context::default(),
        broccoli::metrics::MetricsHandle::new(),
    );
    rt.cmd
        .send(CoreCmd::ImportCoreArchive(archive))
        .expect("send pinned archive import command");

    let expected_version = broccoli::sys::core_dl::pinned_release_version()
        .strip_prefix('v')
        .expect("compiled pinned version must have a v prefix");
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut downloaded = None;
    let mut running = false;
    let mut operation_finished = false;
    while Instant::now() < deadline && !(downloaded.is_some() && running && operation_finished) {
        match evt_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(CoreEvt::Download(DownloadState::Done(version))) => downloaded = Some(version),
            Ok(CoreEvt::Download(DownloadState::Failed(error))) => {
                panic!("pinned archive import failed: {error}")
            }
            Ok(CoreEvt::State(CorePhase::Running)) => running = true,
            Ok(CoreEvt::State(CorePhase::Error(error))) => {
                panic!("imported pinned core startup failed: {error}")
            }
            Ok(CoreEvt::Operation(None)) if downloaded.is_some() => operation_finished = true,
            Ok(_) | Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("runtime stopped before the imported archive completed")
            }
        }
    }

    assert_eq!(downloaded.as_deref(), Some(expected_version));
    assert!(running, "imported pinned core did not become gRPC-ready");
    assert!(
        operation_finished,
        "import operation did not reach a terminal state"
    );
    for name in ["xray.exe", "wintun.dll", "geoip.dat", "geosite.dat"] {
        assert!(
            isolated.path().join("broccoli/core").join(name).is_file(),
            "managed runtime payload missing: {name}"
        );
    }
    assert!(
        !isolated.path().join("broccoli/core.bak").exists(),
        "ready imported install must consume its rollback tree"
    );
    assert!(
        !isolated
            .path()
            .join("broccoli/.core-update.pending")
            .exists(),
        "ready imported install must clear its health marker"
    );

    rt.cmd
        .send(CoreCmd::Stop)
        .expect("stop imported pinned core");
    let stop_deadline = Instant::now() + Duration::from_secs(10);
    let mut stopped = false;
    while Instant::now() < stop_deadline && !stopped {
        stopped = matches!(
            evt_rx.recv_timeout(Duration::from_millis(250)),
            Ok(CoreEvt::State(CorePhase::Stopped))
        );
    }
    assert!(stopped, "imported pinned core did not stop cleanly");
    rt.cmd.send(CoreCmd::Shutdown).expect("shutdown runtime");
}
