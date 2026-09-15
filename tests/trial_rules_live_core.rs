//! Live-core wire oracle for trial rules: spawns the real xray.exe
//! with an API-only config and drives `RoutingService.AddRule/RemoveRule/
//! ListRule` through the exact client path the app uses (`rt::grpc`), proving
//! the proto-only `xray.app.router.Config` payload, append semantics,
//! duplicate-ruleTag atomicity, and the rule grammar converter end to end.
//! Requires an xray.exe — located via `$XRAY_EXE` or the managed
//! `%APPDATA%\broccoli\core\xray.exe` — plus geoip.dat/geosite.dat next to it.
//! The test is `#[ignore]`d by default so a core-less machine reports it as
//! ignored instead of green-without-running; the body still skips cleanly when
//! the ignore is lifted without a core present.
//! Run with: cargo test --test trial_rules_live_core -- --ignored
//! CI (test workflow) exports the pinned core as `XRAY_EXE` and runs this
//! target with the ignore lifted.

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use broccoli::model::routing::Rule;
use broccoli::rt::TrialRuleAddOutcome;
use broccoli::rt::grpc::{GrpcClient, add_rule_outcome, pb, trial_rule_to_pb};

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

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
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

#[tokio::test]
#[ignore = "needs a real xray.exe core"]
async fn trial_rules_roundtrip_against_live_core() {
    let Some(xray) = xray() else {
        eprintln!("SKIP: no xray.exe (set XRAY_EXE or download the core)");
        return;
    };
    let assets = xray.parent().expect("core dir");
    assert!(
        assets.join("geoip.dat").is_file() && assets.join("geosite.dat").is_file(),
        "geoip.dat/geosite.dat must sit next to xray.exe ({} is used for the geosite/geoip rules)",
        assets.display()
    );

    let port = free_port();
    let config_path =
        std::env::temp_dir().join(format!("broccoli-trial-rules-{}.json", std::process::id()));
    let config = format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "api": {{ "tag": "api", "listen": "127.0.0.1:{port}", "services": ["HandlerService", "RoutingService"] }},
  "inbounds": [],
  "outbounds": [ {{ "protocol": "freedom", "tag": "direct" }} ],
  "routing": {{
    "domainStrategy": "AsIs",
    "rules": [ {{ "type": "field", "domain": ["example.org"], "outboundTag": "direct" }} ],
    "balancers": [ {{ "tag": "lb", "selector": ["direct"], "strategy": {{ "type": "random" }} }} ]
  }}
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
    let _guard = CoreGuard { child };

    wait_for_api(port);
    let client = GrpcClient::new(port);

    // The baseline rule from the config is present.
    let baseline = client.list_rules().await.expect("list baseline");
    assert!(
        baseline
            .iter()
            .any(|(target, tag)| target == "direct" && tag.is_empty()),
        "the config's untagged baseline rule must be listed, got {baseline:?}"
    );

    // Add a trial rule through the app's exact conversion path: geosite code,
    // bare domain, dotless (anchored regex), geoip code, a negated geoip,
    // and a CIDR all survive the round trip.
    let rule = Rule {
        rule_tag: "trial-e2e-a".into(),
        outbound_tag: "direct".into(),
        domain: vec![
            "geosite:cn".into(),
            "example.com".into(),
            "dotless:music".into(),
        ],
        ip: vec![
            "geoip:private".into(),
            "!geoip:cn".into(),
            "192.0.2.0/24".into(),
        ],
        ..Default::default()
    };
    let config = pb::xray::app::router::Config {
        rule: vec![trial_rule_to_pb(&rule).expect("convert trial rule")],
        ..Default::default()
    };
    client
        .add_rule(config.clone(), true)
        .await
        .expect("AddRule must succeed");
    let listed = client.list_rules().await.expect("list after add");
    assert!(
        listed
            .iter()
            .any(|(target, tag)| target == "direct" && tag == "trial-e2e-a"),
        "the injected rule must appear in the live list, got {listed:?}"
    );

    // A payload carrying a balancer with an existing tag is rejected in
    // append mode (the app never sends balancers — the core would
    // otherwise treat a duplicate tag as an error).
    let with_balancer = pb::xray::app::router::Config {
        rule: vec![trial_rule_to_pb(&rule).expect("convert trial rule")],
        balancing_rule: vec![pb::xray::app::router::BalancingRule {
            tag: "lb".into(),
            outbound_selector: vec!["direct".into()],
            strategy: "random".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let balancer_rejected = client.add_rule(with_balancer, true).await;
    assert!(
        balancer_rejected.is_err(),
        "a payload balancer must be rejected in append mode"
    );

    // A second AddRule with the same ruleTag fails atomically: the list is
    // unchanged (no duplicate injected).
    let duplicate = client.add_rule(config.clone(), true).await;
    assert!(
        duplicate.is_err(),
        "duplicate ruleTag must be rejected by the core"
    );
    let after_dup = client.list_rules().await.expect("list after duplicate");
    assert_eq!(
        after_dup
            .iter()
            .filter(|(_, tag)| tag == "trial-e2e-a")
            .count(),
        1,
        "the failed duplicate must not have landed, got {after_dup:?}"
    );

    // The app-level verdict for that same attempt: the reply is an error, but
    // the core holds the tag, so the read-back must report success — a failed
    // add here would hide a live rule from the UI and make a retry duplicate
    // it.
    let verdict = add_rule_outcome("trial-e2e-a", duplicate, Ok(after_dup.clone()))
        .expect("a tag the core holds is never reported as a failed add");
    eprintln!(
        "duplicate tag trial-e2e-a: add reply rejected, core holds it, \
         verdict = {verdict:?}"
    );
    assert_eq!(
        verdict,
        TrialRuleAddOutcome {
            rules: Some(after_dup.clone())
        },
        "the verdict must carry the live inventory it was decided from"
    );

    // A balancer target that does not exist is rejected client-side-adjacent:
    // the core validates the payload.
    let bad = Rule {
        rule_tag: "trial-e2e-b".into(),
        balancer_tag: "missing-balancer".into(),
        domain: vec!["example.com".into()],
        ..Default::default()
    };
    let bad_config = pb::xray::app::router::Config {
        rule: vec![trial_rule_to_pb(&bad).expect("convert balancer rule")],
        ..Default::default()
    };
    let rejected = client.add_rule(bad_config, true).await;
    assert!(
        rejected.is_err(),
        "a balancer tag absent from the config must be rejected"
    );

    // RemoveRule takes the trial rule out again.
    client
        .remove_rule("trial-e2e-a")
        .await
        .expect("RemoveRule must succeed");
    let final_list = client.list_rules().await.expect("list after remove");
    assert!(
        !final_list.iter().any(|(_, tag)| tag == "trial-e2e-a"),
        "the removed trial rule must be gone, got {final_list:?}"
    );
}
