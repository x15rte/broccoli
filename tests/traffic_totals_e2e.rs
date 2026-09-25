//! End-to-end regression for "totals not match inbound traffic": spawns the
//! app's own runtime against a real xray.exe (socks inbound → VLESS outbound
//! → a second local xray acting as the remote server), drives a real download
//! through the SOCKS inbound with curl, then asserts on the emitted
//! StatsTick that the dashboard-visible surfaces never diverge:
//!   total_up   == sum(per_inbound_totals.up)
//!   total_down == sum(per_inbound_totals.down)
//!   up         == sum(per_inbound rates up)
//!   down       == sum(per_inbound rates down)
//! The "Session traffic totals" line renders total_*, the aggregate rates and
//! the throughput plot render up/down, and the "Inbound traffic" table
//! renders per_inbound/per_inbound_totals — all four must come from the same
//! inbound counter sweep. Requires a real xray.exe
//! (`$XRAY_EXE` or `%APPDATA%\broccoli\core\xray.exe`); self-skips otherwise.
//!
//! Runtime level, not screen level: it drives `spawn_runtime` with its own
//! `egui::Context` and never builds the app, so it carries its own `APPDATA`
//! guard — the shared screen-test fixture only ever boots the app under
//! kittest, an instance that must not run beside the two cores this test
//! supervises.
//! Run with: cargo test --test traffic_totals_e2e -- --ignored --nocapture

use std::io::Read as _;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const UUID: &str = "8f4e0a2e-9b3c-4d5e-8f6a-7b8c9d0e1f2a";

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
        let saved = std::env::var_os("APPDATA");
        // SAFETY: single-threaded test setup; no other thread reads APPDATA
        // while it is redirected.
        unsafe { std::env::set_var("APPDATA", root) };
        Self(saved)
    }
}

impl Drop for AppDataGuard {
    fn drop(&mut self) {
        // SAFETY: test teardown; the runtime thread is joined before this runs.
        match &self.0 {
            Some(v) => unsafe { std::env::set_var("APPDATA", v) },
            None => unsafe { std::env::remove_var("APPDATA") },
        }
    }
}

/// Kills a spawned xray on drop, however the test exits.
struct CoreGuard {
    child: Child,
}

impl Drop for CoreGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

fn wait_for_port(port: u16, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("port {port} ({label}) did not open within 15s");
}

#[test]
#[ignore = "needs a real xray.exe core"]
fn totals_rates_and_table_share_one_counter_sweep() {
    let Some(xray_source) = xray() else {
        eprintln!("SKIP: no xray.exe");
        return;
    };

    // Isolated APPDATA with the real core payload (the runtime validates the
    // managed core before spawning).
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

    // Local HTTP target serving a 32 MiB payload.
    let payload: Vec<u8> = vec![0x5a; 32 * 1024 * 1024];
    let payload = std::sync::Arc::new(payload);
    let http = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let http_port = http.server_addr().to_ip().unwrap().port();
    let payload2 = payload.clone();
    std::thread::spawn(move || {
        for mut req in http.incoming_requests() {
            // Drain upload bodies so the sender's bytes are fully counted.
            let mut sink = Vec::new();
            let _ = req
                .as_reader()
                .take(64 * 1024 * 1024)
                .read_to_end(&mut sink);
            let response = tiny_http::Response::from_data(payload2.as_ref().clone());
            let _ = req.respond(response);
        }
    });

    // Second xray instance acting as the remote VLESS server. The loopback
    // allow rule is required: Xray 26.x blocks private-IP targets from
    // server-side inbounds by default (anti-SSRF), and this harness's HTTP
    // target lives on 127.0.0.1.
    let vless_port = free_port();
    let server_config = serde_json::json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "tag": "srv-in", "listen": "127.0.0.1", "port": vless_port,
            "protocol": "vless",
            "settings": { "clients": [{ "id": UUID, "flow": "" }], "decryption": "none" },
            "streamSettings": { "network": "tcp" }
        }],
        "outbounds": [ { "tag": "direct", "protocol": "freedom", "settings": {
            "finalRules": [ { "action": "allow", "network": "tcp,udp", "ip": ["127.0.0.0/8"] } ]
        } } ]
    });
    let server_config_path = std::env::temp_dir().join(format!(
        "broccoli-totals-server-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &server_config_path,
        serde_json::to_vec_pretty(&server_config).unwrap(),
    )
    .expect("write server config");
    let server_child = Command::new(&xray_source)
        .args(["run", "-config"])
        .arg(&server_config_path)
        .env(
            "XRAY_LOCATION_ASSET",
            xray_source.parent().expect("core dir"),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server xray");
    let _server_guard = CoreGuard {
        child: server_child,
    };
    wait_for_port(vless_port, "vless server");

    // The app's runtime against a client config mirroring the generated one.
    let socks_port = free_port();
    let api_port = free_port();
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
            "settings": { "auth": "noauth", "udp": false },
            "sniffing": { "enabled": true, "destOverride": ["http", "tls", "quic"] }
        }],
        "outbounds": [
            { "tag": "srv-repro", "protocol": "vless",
              "settings": { "vnext": [{ "address": "127.0.0.1", "port": vless_port,
                  "users": [{ "id": UUID, "encryption": "none" }] }] },
              "streamSettings": { "network": "tcp" } },
            { "tag": "direct", "protocol": "freedom", "settings": {} },
            { "tag": "block", "protocol": "blackhole", "settings": {} }
        ],
        "routing": { "domainStrategy": "AsIs",
                     "rules": [ { "type": "field", "network": "tcp", "outboundTag": "srv-repro" } ] }
    });

    let (evt_tx, evt_rx) = std::sync::mpsc::sync_channel(broccoli::rt::EVT_CHANNEL_CAPACITY);
    let rt = broccoli::rt::spawn_runtime(evt_tx, egui::Context::default());
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
    while Instant::now() < deadline && !running {
        match evt_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(broccoli::rt::CoreEvt::State(broccoli::rt::CorePhase::Running)) => running = true,
            Ok(_) => {}
            Err(_) => {}
        }
    }
    assert!(running, "core did not reach Running within 30 s");
    wait_for_port(socks_port, "socks inbound");

    // Drive a real download through the SOCKS inbound.
    let out = Command::new("curl.exe")
        .args([
            "-x",
            &format!("socks5h://127.0.0.1:{socks_port}"),
            "-s",
            "--max-time",
            "60",
            "-o",
            "nul",
            "-w",
            "%{size_download}",
            &format!("http://127.0.0.1:{http_port}/dl"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("curl download");
    assert!(out.status.success(), "curl failed: {out:?}");
    let downloaded: u64 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("size_download");
    assert_eq!(
        downloaded,
        payload.len() as u64,
        "curl must have received the full payload through the tunnel"
    );

    // Collect stats ticks: wait for the first tick that saw traffic, then
    // until the totals stop growing, then check the dashboard-visible
    // invariant — aggregate totals and rates must equal the sums of the
    // per-inbound table rows (the user's "totals not match inbound traffic").
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last: Option<broccoli::rt::StatsTick> = None;
    let mut saw_traffic = false;
    let mut stable = 0;
    while Instant::now() < deadline && (stable < 3 || !saw_traffic) {
        match evt_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(broccoli::rt::CoreEvt::Stats(tick)) => {
                if tick.total_up > 0 || tick.total_down > 0 {
                    saw_traffic = true;
                }
                if saw_traffic
                    && last.as_ref().is_some_and(|prev| {
                        prev.total_up == tick.total_up && prev.total_down == tick.total_down
                    })
                {
                    stable += 1;
                } else {
                    stable = 0;
                }
                last = Some(tick);
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    let tick = last.expect("no Stats tick within 20 s");
    let sum_in_up: u64 = tick.per_inbound_totals.iter().map(|(_, u, _)| u).sum();
    let sum_in_down: u64 = tick.per_inbound_totals.iter().map(|(_, _, d)| d).sum();
    let sum_rate_up: u64 = tick.per_inbound.iter().map(|(_, u, _)| u).sum();
    let sum_rate_down: u64 = tick.per_inbound.iter().map(|(_, _, d)| d).sum();

    assert!(
        tick.total_up > 0 && tick.total_down > 0,
        "traffic must have flowed through the tunnel (got up={} down={})",
        tick.total_up,
        tick.total_down
    );
    assert_eq!(
        tick.total_up, sum_in_up,
        "aggregate totals must equal the sum of the inbound table totals"
    );
    assert_eq!(
        tick.total_down, sum_in_down,
        "aggregate totals must equal the sum of the inbound table totals"
    );
    assert_eq!(
        tick.up, sum_rate_up,
        "aggregate rates must equal the sum of the inbound table rates"
    );
    assert_eq!(
        tick.down, sum_rate_down,
        "aggregate rates must equal the sum of the inbound table rates"
    );
}
