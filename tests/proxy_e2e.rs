//! End-to-end: generate config → apply (with `xray run -test` gate) → supervised
//! core → traffic through the local SOCKS inbound → gRPC stats counter moves.
//! Requires a real xray.exe (`$XRAY_EXE` or `%APPDATA%\broccoli\core\xray.exe`);
//! all writable Broccoli state is redirected to a temporary APPDATA root.
//!
//! Runtime level, not screen level: it drives `spawn_runtime` with its own
//! `egui::Context` and never builds the app, so the live-core fixture owns the
//! `APPDATA` redirect and the throwaway core tree — the shared screen-test
//! fixture only ever boots the app under kittest, an instance that must not
//! exist in the isolated tree whose committed config this test asserts.
//! Run with: cargo test --test proxy_e2e -- --ignored --nocapture

use std::ops::ControlFlow;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "common/live_core.rs"]
pub mod live_core;

#[test]
#[ignore = "needs a real xray.exe core"]
fn socks_to_freedom_e2e() {
    let Some(xray_source) = live_core::discover_xray() else {
        eprintln!("SKIP: no xray.exe");
        return;
    };
    let isolated = live_core::IsolatedRoot::empty();
    isolated.install_pinned_core(&xray_source);
    let _appdata = live_core::redirect_appdata(isolated.path());

    // Local HTTP target.
    let http = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let http_port = http.server_addr().to_ip().unwrap().port();
    std::thread::spawn(move || {
        for req in http.incoming_requests() {
            let _ = req.respond(tiny_http::Response::from_string("hello"));
        }
    });

    let socks_port = live_core::free_port();
    let api_port = live_core::free_port();
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
    live_core::drive_events(
        &evt_rx,
        deadline,
        "before the core reached Running",
        |event| {
            match event {
                Some(broccoli::rt::CoreEvt::ActiveConfig { snapshot }) => {
                    active_snapshot = Some(snapshot);
                }
                Some(broccoli::rt::CoreEvt::State {
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
                Some(ev) => eprintln!("[e2e] evt: {ev:?}"),
                None => {}
            }
            if running {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    );
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
    live_core::drive_events(
        &evt_rx,
        deadline,
        "while waiting for a stats tick",
        |event| {
            if let Some(broccoli::rt::CoreEvt::Stats(tick)) = event {
                saw_traffic = tick
                    .per_outbound
                    .iter()
                    .any(|(tag, up, down)| tag == "direct" && (*up > 0 || *down > 0));
            }
            if saw_traffic {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        },
    );
    rt.cmd.send(broccoli::rt::CoreCmd::Stop).unwrap();
    let stop_deadline = Instant::now() + Duration::from_secs(10);
    let mut stopped = false;
    live_core::drive_events(&evt_rx, stop_deadline, "before the core stopped", |event| {
        if matches!(
            event,
            Some(broccoli::rt::CoreEvt::State {
                phase: broccoli::rt::CorePhase::Stopped,
                ..
            })
        ) {
            stopped = true;
        }
        if stopped {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });
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
