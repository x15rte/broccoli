//! End-to-end: generate config → apply (with `xray run -test` gate) → supervised
//! core → traffic through the local SOCKS inbound → gRPC stats counter moves.
//! Requires a real xray.exe (`$XRAY_EXE` or `%APPDATA%\broccoli\core\xray.exe`);
//! all writable Broccoli state is redirected to a temporary APPDATA root.
//!
//! Runtime level, not screen level: it drives `spawn_runtime` with its own
//! `egui::Context` and never builds the app, so it carries its own `APPDATA`
//! guard — the shared screen-test fixture only ever boots the app under
//! kittest, an instance that must not exist in the isolated tree whose
//! committed config this test asserts.
//! Run with: cargo test --test proxy_e2e -- --ignored --nocapture

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn write_verified_release_metadata(core: &std::path::Path) {
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
use std::time::{Duration, Instant};

fn xray() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("XRAY_EXE") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let p = PathBuf::from(std::env::var_os("APPDATA")?)
        .join("broccoli")
        .join("core")
        .join("xray.exe");
    p.is_file().then_some(p)
}

struct AppDataGuard(Option<std::ffi::OsString>);

impl AppDataGuard {
    fn install(root: &std::path::Path) -> Self {
        let previous = std::env::var_os("APPDATA");
        // This ignored E2E owns the process environment for its entire run.
        unsafe { std::env::set_var("APPDATA", root) };
        Self(previous)
    }
}

impl Drop for AppDataGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.0.take() {
            unsafe { std::env::set_var("APPDATA", previous) };
        } else {
            unsafe { std::env::remove_var("APPDATA") };
        }
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[test]
#[ignore = "needs a real xray.exe core"]
fn socks_to_freedom_e2e() {
    let Some(xray_source) = xray() else {
        eprintln!("SKIP: no xray.exe");
        return;
    };
    let isolated = tempfile::tempdir().expect("isolated APPDATA");
    let isolated_core = isolated.path().join("broccoli").join("core");
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

    // Local HTTP target.
    let http = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let http_port = http.server_addr().to_ip().unwrap().port();
    std::thread::spawn(move || {
        for req in http.incoming_requests() {
            let _ = req.respond(tiny_http::Response::from_string("hello"));
        }
    });

    let socks_port = free_port();
    let api_port = free_port();
    let config = serde_json::json!({
        "log": { "loglevel": "warning" },
        "stats": {},
        "policy": { "system": {
            "statsInboundUplink": true, "statsInboundDownlink": true,
            "statsOutboundUplink": true, "statsOutboundDownlink": true } },
        "api": { "tag": "api", "listen": format!("127.0.0.1:{api_port}"),
                 // no ObservatoryService: it RequireFeatures(extension.Observatory)
                 // and this config has no observatory section.
                 "services": ["StatsService", "HandlerService", "RoutingService",
                              "LoggerService", "ReflectionService"] },
        "inbounds": [{
            "tag": "in-socks", "listen": "127.0.0.1", "port": socks_port,
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": false },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
        }],
        "outbounds": [
            { "tag": "direct", "protocol": "freedom", "settings": {} },
            { "tag": "block", "protocol": "blackhole", "settings": {} }
        ]
    });

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    // The control-plane port is ephemeral and derived from the
    // emitted config; the runtime must recover the endpoint from the active
    // config before polling, never from Settings.
    let rt = broccoli::rt::spawn_runtime(evt_tx, egui::Context::default());

    // One command guarantees Start cannot race validation or launch a stale
    // config when validation fails.
    rt.cmd
        .send(broccoli::rt::CoreCmd::Apply {
            value: config,
            intent: broccoli::rt::ApplyIntent::CommitAndStart { tun_mode: false },
            revision: 0,
        })
        .unwrap();

    // Wait for Running.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut running = false;
    let mut active_snapshot = None;
    while Instant::now() < deadline && !running {
        match evt_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(broccoli::rt::CoreEvt::ActiveConfig { snapshot }) => {
                active_snapshot = Some(snapshot);
            }
            Ok(broccoli::rt::CoreEvt::State {
                phase: broccoli::rt::CorePhase::Running,
                transport,
            }) => {
                assert!(
                    matches!(active_snapshot.as_ref(), Some(Ok(_))),
                    "core reached Running without an active config snapshot"
                );
                assert_eq!(
                    transport,
                    Some(broccoli::rt::CoreTransport::Direct),
                    "the apply-and-start command reported a non-direct backend"
                );
                running = true;
            }
            Ok(ev) => eprintln!("[e2e] evt: {ev:?}"),
            Err(_) => {}
        }
    }
    assert!(running, "core did not reach Running within 30 s");

    let active_snapshot = match active_snapshot {
        Some(Ok(snapshot)) => snapshot,
        Some(Err(error)) => panic!("active config snapshot failed: {error}"),
        None => panic!("core reached Running without an active config snapshot"),
    };
    let active_contents =
        std::fs::read_to_string(isolated.path().join("broccoli/config/config.json"))
            .expect("read isolated active config");
    assert_eq!(
        active_snapshot, active_contents,
        "preview snapshot differs from the committed active config"
    );

    // Drive one request through the SOCKS inbound.
    let out = Command::new("curl.exe")
        .args([
            "-x",
            &format!("socks5h://127.0.0.1:{socks_port}"),
            "-s",
            "--max-time",
            "15",
            &format!("http://127.0.0.1:{http_port}/hello"),
        ])
        .stdout(Stdio::piped())
        .output()
        .expect("curl");
    let body = String::from_utf8_lossy(&out.stdout);
    assert_eq!(body, "hello", "curl via socks failed: {out:?}");

    // Stats tick should report traffic on the direct outbound.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_traffic = false;
    while Instant::now() < deadline && !saw_traffic {
        if let Ok(broccoli::rt::CoreEvt::Stats(tick)) =
            evt_rx.recv_timeout(Duration::from_millis(500))
        {
            saw_traffic = tick
                .per_outbound
                .iter()
                .any(|(tag, up, down)| tag == "direct" && (*up > 0 || *down > 0));
        }
    }
    rt.cmd.send(broccoli::rt::CoreCmd::Stop).unwrap();
    let stop_deadline = Instant::now() + Duration::from_secs(10);
    let mut stopped = false;
    while Instant::now() < stop_deadline && !stopped {
        stopped = matches!(
            evt_rx.recv_timeout(Duration::from_millis(250)),
            Ok(broccoli::rt::CoreEvt::State {
                phase: broccoli::rt::CorePhase::Stopped,
                ..
            })
        );
    }
    assert!(stopped, "runtime did not confirm supervised core exit");
    rt.cmd.send(broccoli::rt::CoreCmd::Shutdown).unwrap();
    assert!(
        isolated
            .path()
            .join("broccoli/config/config.json")
            .is_file(),
        "runtime did not use the injected APPDATA root"
    );
    assert!(saw_traffic, "no traffic counter for outbound 'direct'");
}
