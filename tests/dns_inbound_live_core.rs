//! Live-core wire oracle for the runtime-added in-tun DNS listener: spawns
//! the real xray.exe with an API-only config and drives
//! `HandlerService.AddInbound` through the exact client path the app uses
//! (`rt::grpc::GrpcClient::add_dns_in_listener`). Proves the proto-only
//! receiver/dokodemo payload the runtime builds is accepted by the core,
//! that the listener binds and accepts, and that the retry protocol's
//! remove-then-add re-entry survives both an already-bound listener and a
//! failed attempt's registered tag.
//!
//! The production bind address (the TUN gateway) exists only with a TUN
//! adapter, so the oracle binds the listener on loopback instead; the
//! address is the only thing it changes — the payload is the runtime's.
//! Requires an xray.exe — the live-core fixture locates it via `$XRAY_EXE`
//! or the managed `%APPDATA%\broccoli\core\xray.exe`.
//! The test is `#[ignore]`d by default so a core-less machine reports it as
//! ignored instead of green-without-running; the body still skips cleanly when
//! the ignore is lifted without a core present.
//! Run with: cargo test --test dns_inbound_live_core -- --ignored
//! CI (test workflow) exports the pinned core as `XRAY_EXE` and runs this
//! target with the ignore lifted.

use std::io::Write as _;
use std::net::{Ipv4Addr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use broccoli::model::inbound::DNS_INBOUND_TAG;
use broccoli::rt::dns_in::{Listener, PORT};
use broccoli::rt::grpc::GrpcClient;

#[path = "common/live_core.rs"]
pub mod live_core;

/// Kills the core on drop, however the test exits.
struct CoreGuard {
    child: Child,
}

impl Drop for CoreGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for_api(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("xray API did not open port {port} within 15s");
}

/// Whether the core owns the loopback LISTEN socket on the listener's fixed
/// port. The kernel's endpoint table is the check the app itself trusts for
/// its control-plane listener (`sys::net_table`), and unlike a data-path
/// connect it is not affected by third-party WFP DNS shields a desktop may
/// run.
fn listener_is_bound(pid: u32) -> bool {
    let rows = broccoli::sys::net_table::tcp_table().expect("read the TCP endpoint table");
    broccoli::sys::net_table::loopback_api_listener_owned_by(&rows, PORT, pid)
}

#[tokio::test]
#[ignore = "needs a real xray.exe core"]
async fn in_tun_dns_listener_adds_to_a_live_core() {
    let Some(xray) = live_core::discover_xray() else {
        eprintln!("SKIP: no xray.exe (set XRAY_EXE or download the core)");
        return;
    };
    let assets = xray.parent().expect("core dir");

    let api_port = live_core::free_port();
    let config_path =
        std::env::temp_dir().join(format!("broccoli-dns-inbound-{}.json", std::process::id()));
    let config = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "api": {{ "tag": "api", "listen": "127.0.0.1:{api_port}", "services": ["HandlerService"] }},
  "inbounds": [],
  "outbounds": [ {{ "protocol": "freedom", "tag": "direct" }} ]
}}"#
    );
    let mut file = std::fs::File::create(&config_path).expect("write config");
    file.write_all(config.as_bytes()).expect("flush config");

    let child = Command::new(&xray)
        .args(["run", "-config"])
        .arg(&config_path)
        .env("XRAY_LOCATION_ASSET", assets)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn xray");
    let pid = child.id();
    let _guard = CoreGuard { child };

    wait_for_api(api_port);
    let client = GrpcClient::new(api_port);
    let listener = Listener {
        address: Ipv4Addr::LOCALHOST,
    };

    match client.add_dns_in_listener(&listener).await {
        Ok(()) => {}
        // A machine already serving DNS on loopback:53 cannot bind the
        // listener. The retry protocol still has to hold: the failed attempt
        // leaves its tag registered, and the remove-then-add re-entry must
        // reproduce the bind failure instead of tripping over that tag.
        Err(error) => {
            assert!(
                error.message().contains("failed to listen TCP on 53"),
                "an occupied port must surface the core's bind error, got: {}",
                error.message()
            );
            let retry = client.add_dns_in_listener(&listener).await;
            let retry = retry.expect_err("the occupied port cannot free itself");
            assert!(
                retry.message().contains("failed to listen TCP on 53"),
                "the retry must re-attempt the bind, not report the failed attempt's tag: {}",
                retry.message()
            );
            return;
        }
    }

    // The live handler list carries the tag the emitted interception rule
    // and the runtime share, and the core owns the bound loopback socket on
    // the fixed port — a wildcard bind (a dropped listen address in the
    // payload) would leave no loopback LISTEN row and fail this.
    let inbounds = client.list_inbounds().await.expect("list inbounds");
    assert!(
        inbounds.iter().any(|entry| entry.tag == DNS_INBOUND_TAG),
        "the added listener must be listed, got {inbounds:?}"
    );
    assert!(
        listener_is_bound(pid),
        "the core must own the loopback listener on port {PORT}"
    );

    // Remove-then-add re-entry: a second add replaces the bound listener
    // instead of failing on the already-registered tag.
    client
        .add_dns_in_listener(&listener)
        .await
        .expect("re-entry must replace the listener");
    let inbounds = client.list_inbounds().await.expect("list after re-entry");
    assert_eq!(
        inbounds
            .iter()
            .filter(|entry| entry.tag == DNS_INBOUND_TAG)
            .count(),
        1,
        "the re-entry must leave exactly one listener, got {inbounds:?}"
    );
    assert!(
        listener_is_bound(pid),
        "the replaced listener must stay bound on port {PORT}"
    );
}
