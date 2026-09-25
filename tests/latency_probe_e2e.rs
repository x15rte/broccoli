//! Ignored real-core coverage for the isolated one-shot latency child.
//!
//! Runtime level, not screen level: it drives `spawn_runtime` with its own
//! `egui::Context` and never builds the app, so it carries its own guards — the
//! shared screen-test fixture only ever boots the app under kittest, and an app
//! boot sweeps stale probe scratch directories, which are exactly the leftovers
//! its leftover check reads. `TMP`/`TEMP` point at a staging directory of their
//! own under the isolated root: the probe stages its scratch in the process
//! temp dir, and it stays a sibling of the APPDATA tree this test pins.
//! Run with: cargo test --test latency_probe_e2e -- --ignored --nocapture

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use broccoli::model::{OutboundModel, Protocol, ServerProfile, ServersFile, Settings};
use broccoli::rt::{ApplyIntent, CoreCmd, CoreEvt, CorePhase, GrpcClient, LatencyProbeResult};

fn write_verified_release_metadata(core: &Path) {
    let metadata = serde_json::json!({
        "schema": 3,
        "archive_asset": env!("BROCCOLI_XRAY_ARCHIVE"),
        "archive_sha256": env!("BROCCOLI_XRAY_SHA256"),
        "xray_sha256": env!("BROCCOLI_XRAY_EXE_SHA256"),
        "wintun_sha256": env!("BROCCOLI_WINTUN_SHA256"),
        "geoip_sha256": env!("BROCCOLI_GEOIP_SHA256"),
        "geosite_sha256": env!("BROCCOLI_GEOSITE_SHA256"),
        "version": env!("BROCCOLI_XRAY_VERSION").trim_start_matches('v'),
    });
    std::fs::write(
        core.join(".broccoli-official-release.json"),
        serde_json::to_vec(&metadata).expect("serialize pinned core metadata"),
    )
    .expect("write pinned core metadata");
}

fn xray() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("XRAY_EXE") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    let path = PathBuf::from(std::env::var_os("APPDATA")?)
        .join("broccoli")
        .join("core")
        .join("xray.exe");
    path.is_file().then_some(path)
}

struct AppDataGuard(Option<std::ffi::OsString>);

impl AppDataGuard {
    fn install(root: &Path) -> Self {
        let previous = std::env::var_os("APPDATA");
        // SAFETY: this ignored test owns process-global environment access for
        // its whole run.
        unsafe { std::env::set_var("APPDATA", root) };
        Self(previous)
    }
}

impl Drop for AppDataGuard {
    fn drop(&mut self) {
        // SAFETY: the test has finished all Broccoli threads before this guard
        // restores the process environment.
        unsafe {
            match self.0.take() {
                Some(value) => std::env::set_var("APPDATA", value),
                None => std::env::remove_var("APPDATA"),
            }
        }
    }
}

struct TempEnvGuard {
    tmp: Option<std::ffi::OsString>,
    temp: Option<std::ffi::OsString>,
}

impl TempEnvGuard {
    fn install(root: &Path) -> Self {
        let previous = Self {
            tmp: std::env::var_os("TMP"),
            temp: std::env::var_os("TEMP"),
        };
        // SAFETY: this ignored test owns process-global environment access for
        // its whole run.
        unsafe {
            std::env::set_var("TMP", root);
            std::env::set_var("TEMP", root);
        }
        previous
    }
}

impl Drop for TempEnvGuard {
    fn drop(&mut self) {
        // SAFETY: no Broccoli worker remains when the guard is dropped.
        unsafe {
            match self.tmp.take() {
                Some(value) => std::env::set_var("TMP", value),
                None => std::env::remove_var("TMP"),
            }
            match self.temp.take() {
                Some(value) => std::env::set_var("TEMP", value),
                None => std::env::remove_var("TEMP"),
            }
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind free loopback port")
        .local_addr()
        .expect("read free loopback port")
        .port()
}
/// The machine's LAN IPv4, discovered via a route lookup: `connect` on a UDP
/// socket never sends packets, it only selects the outgoing interface. The
/// latency probe guard rejects loopback/link-local/cloud-metadata literals
/// (src/gen/mod.rs blocked_latency_probe_host_class), so the isolated probe
/// child must target a non-loopback literal the local HTTP server listens on.
fn lan_ipv4() -> std::net::Ipv4Addr {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind route-lookup socket");
    socket
        .connect("8.8.8.8:80")
        .expect("route lookup to a public address");
    match socket.local_addr().expect("local address").ip() {
        std::net::IpAddr::V4(address) => address,
        std::net::IpAddr::V6(_) => panic!("expected an IPv4 default route"),
    }
}

fn one_freedom_profile() -> ServerProfile {
    let mut profile = ServerProfile::new("probe", OutboundModel::new(Protocol::Freedom));
    profile.id = "0123456789abcdef".into();
    profile
}

fn assert_main_unchanged(
    root: &Path,
    state_settings: &[u8],
    state_servers: &[u8],
    active_config: &[u8],
) {
    assert_eq!(
        std::fs::read(root.join("broccoli/state/settings.json")).expect("read settings"),
        state_settings
    );
    assert_eq!(
        std::fs::read(root.join("broccoli/state/servers.json")).expect("read servers"),
        state_servers
    );
    assert_eq!(
        std::fs::read(root.join("broccoli/config/config.json")).expect("read active config"),
        active_config
    );
    assert!(!root.join("broccoli/config/config.candidate.json").exists());
}

fn assert_no_probe_temp_dirs(root: &Path) {
    let leftovers: Vec<_> = std::fs::read_dir(root)
        .expect("read isolated probe temp root")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("broccoli-latency-probe-")
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "isolated latency temp directories leaked: {leftovers:?}"
    );
}

fn assert_no_main_failure_event(event: &CoreEvt) {
    match event {
        CoreEvt::State(
            phase @ (CorePhase::Starting
            | CorePhase::Stopped
            | CorePhase::Backoff { .. }
            | CorePhase::Error(_)),
        ) => panic!("main core changed phase during isolated probe: {phase:?}"),
        CoreEvt::ActiveConfig { .. } => {
            panic!("main runtime emitted an ActiveConfig event during isolated probe")
        }
        _ => {}
    }
}

fn wait_for_latency_result(
    evt_rx: &std::sync::mpsc::Receiver<CoreEvt>,
    main_grpc: &GrpcClient,
    io: &tokio::runtime::Runtime,
    initial_uptime: u32,
) -> LatencyProbeResult {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut operation_released = false;
    let mut result = None;
    while Instant::now() < deadline {
        if let Ok(event) = evt_rx.recv_timeout(Duration::from_millis(250)) {
            assert_no_main_failure_event(&event);
            match event {
                // Single-flight per child: the next LatencyProbe event is
                // this request's outcome (no correlation id).
                CoreEvt::LatencyProbe(value) => {
                    result = Some(value);
                }
                CoreEvt::Operation(None) if result.is_some() => {
                    operation_released = true;
                    break;
                }
                _ => {}
            }
        }
        let stats = io
            .block_on(main_grpc.get_sys_stats())
            .expect("main API remains reachable during isolated probe");
        assert!(
            stats.uptime >= initial_uptime,
            "main core uptime regressed during isolated probe"
        );
    }
    assert!(operation_released, "latency operation did not release");
    result.expect("latency probe result")
}

#[test]
#[ignore = "needs a real xray.exe core"]
fn latency_probe_isolated_child_preserves_running_main_core() {
    let Some(xray_source) = xray() else {
        eprintln!("SKIP: no xray.exe");
        return;
    };

    let isolated = tempfile::tempdir().expect("isolated APPDATA");
    let isolated_core = isolated.path().join("broccoli/core");
    std::fs::create_dir_all(&isolated_core).expect("create isolated core");
    if let Some(source_core) = xray_source.parent() {
        for entry in std::fs::read_dir(source_core).expect("list source core") {
            let entry = entry.expect("source core entry");
            if entry.file_type().expect("source entry type").is_file() {
                std::fs::copy(entry.path(), isolated_core.join(entry.file_name()))
                    .expect("copy isolated core asset");
            }
        }
    }
    std::fs::copy(&xray_source, isolated_core.join("xray.exe")).expect("copy isolated xray.exe");
    write_verified_release_metadata(&isolated_core);
    let _appdata = AppDataGuard::install(isolated.path());

    let probe_temp = isolated.path().join("probe-temp");
    std::fs::create_dir_all(&probe_temp).expect("create isolated probe temp root");
    let _temp_env = TempEnvGuard::install(&probe_temp);

    let http = tiny_http::Server::http("0.0.0.0:0").expect("local HTTP target");
    let lan = lan_ipv4();
    let http_port = http.server_addr().to_ip().expect("HTTP IP address").port();
    std::thread::spawn(move || {
        for request in http.incoming_requests() {
            let _ = request.respond(tiny_http::Response::from_string("ok"));
        }
    });

    let main_api_port = free_port();
    let main_config = serde_json::json!({
        "log": { "loglevel": "warning" },
        "stats": {},
        "policy": { "system": {
            "statsInboundUplink": true, "statsInboundDownlink": true,
            "statsOutboundUplink": true, "statsOutboundDownlink": true
        }},
        "api": { "tag": "api", "listen": format!("127.0.0.1:{main_api_port}"),
                 "services": ["StatsService", "HandlerService", "RoutingService",
                              "LoggerService", "ReflectionService"] },
        "outbounds": [
            { "tag": "direct", "protocol": "freedom", "settings": {} },
            { "tag": "block", "protocol": "blackhole", "settings": {} }
        ]
    });

    let profile = one_freedom_profile();
    let servers = ServersFile {
        version: 1,
        active: Some(profile.id.clone()),
        profiles: vec![profile.clone()],
        extra: Default::default(),
    };
    let mut settings = Settings::default();
    settings.routing.observatory.enabled = false;
    let state_settings = serde_json::to_vec_pretty(&settings).expect("serialize settings");
    let state_servers = serde_json::to_vec_pretty(&servers).expect("serialize servers");
    std::fs::create_dir_all(isolated.path().join("broccoli/state")).expect("create state dir");
    std::fs::write(
        isolated.path().join("broccoli/state/settings.json"),
        &state_settings,
    )
    .expect("write settings");
    std::fs::write(
        isolated.path().join("broccoli/state/servers.json"),
        &state_servers,
    )
    .expect("write servers");

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let runtime = broccoli::rt::spawn_runtime(evt_tx, egui::Context::default());
    runtime
        .cmd
        .send(CoreCmd::Apply {
            value: main_config,
            intent: ApplyIntent::CommitAndStart { tun_mode: false },
            revision: 0,
        })
        .expect("start main runtime");

    let startup_deadline = Instant::now() + Duration::from_secs(30);
    let mut running = false;
    while Instant::now() < startup_deadline && !running {
        if let Ok(event) = evt_rx.recv_timeout(Duration::from_millis(500)) {
            match event {
                CoreEvt::State(CorePhase::Running) => running = true,
                CoreEvt::State(CorePhase::Error(error)) => {
                    panic!("main core failed to start: {error}")
                }
                _ => {}
            }
        }
    }
    assert!(running, "main core did not reach Running");

    let active_config_path = isolated.path().join("broccoli/config/config.json");
    let active_config = std::fs::read(&active_config_path).expect("read active main config");
    let io = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build test async runtime");
    let main_grpc = io.block_on(async { GrpcClient::new(main_api_port) });
    let initial_uptime = io
        .block_on(main_grpc.get_sys_stats())
        .expect("main API stats")
        .uptime;

    runtime
        .cmd
        .send(CoreCmd::ProbeLatency {
            profiles: vec![profile.clone()],
            probe_url: format!("http://{lan}:{http_port}/health"),
            tun_outbound_interface: None,
            tun_adapter_name: None,
        })
        .expect("send successful isolated probe");
    let success = wait_for_latency_result(&evt_rx, &main_grpc, &io, initial_uptime);
    let statuses = success.result.expect("successful probe runner result");
    let status = statuses
        .iter()
        .find(|status| status.tag == profile.tag())
        .expect("requested profile status");
    assert!(
        status.alive,
        "local HTTP target should be alive: {status:?}"
    );
    assert!(
        status.delay_ms >= 0,
        "delay must be nonnegative: {status:?}"
    );
    assert!(
        status.last_error.is_none(),
        "alive target returned an error: {status:?}"
    );
    assert_main_unchanged(
        isolated.path(),
        &state_settings,
        &state_servers,
        &active_config,
    );
    assert_no_probe_temp_dirs(&probe_temp);

    runtime
        .cmd
        .send(CoreCmd::ProbeLatency {
            profiles: vec![profile.clone()],
            probe_url: format!("http://{lan}:{}/dead", free_port()),
            tun_outbound_interface: None,
            tun_adapter_name: None,
        })
        .expect("send dead-target isolated probe");
    let dead = wait_for_latency_result(&evt_rx, &main_grpc, &io, initial_uptime);
    let dead_status = dead
        .result
        .expect("dead target should still return an observation row")
        .into_iter()
        .find(|status| status.tag == profile.tag())
        .expect("dead target status");
    assert!(
        !dead_status.alive,
        "dead target unexpectedly alive: {dead_status:?}"
    );
    assert!(
        dead_status
            .last_error
            .as_deref()
            .is_some_and(|reason| !reason.trim().is_empty()),
        "dead target must preserve Xray's failure reason"
    );
    assert_main_unchanged(
        isolated.path(),
        &state_settings,
        &state_servers,
        &active_config,
    );
    assert_no_probe_temp_dirs(&probe_temp);

    runtime.cmd.send(CoreCmd::Stop).expect("stop main runtime");
    let stop_deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < stop_deadline {
        if matches!(
            evt_rx.recv_timeout(Duration::from_millis(250)),
            Ok(CoreEvt::State(CorePhase::Stopped))
        ) {
            break;
        }
    }
    runtime
        .cmd
        .send(CoreCmd::Shutdown)
        .expect("shutdown runtime");
    drop(runtime);
}
