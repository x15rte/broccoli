//! Generator tests: defaults assertions + golden configs (compared as parsed
//! Values, key-order independent).

use super::*;
use crate::i18n::validation_message;
use crate::model::dns::{
    DEFAULT_FAKEDNS_POOL_CIDR, DEFAULT_FAKEDNS_POOL_SIZE, SECOND_FAKEDNS_POOL_CIDR,
    SECOND_FAKEDNS_POOL_SIZE,
};
use crate::model::inbound::{
    DNS_INBOUND_TAG, DNS_OUTBOUND_TAG, LocalInboundCfg, LocalInboundProtocol, TUN_INBOUND_TAG,
};
use crate::model::validation::ValidationCode;
use crate::model::*;
use serde_json::{Map, Value, json};

const ID: &str = "0123456789abcdef"; // tag: srv-01234567

fn base_settings() -> Settings {
    Settings::default()
}

/// Deterministic goldens: the API port is ephemeral in production,
/// so tests inject a fixed port through the generation seam.
fn generate_deterministic(
    servers: &ServersFile,
    settings: &Settings,
) -> Result<Value, GenerateError> {
    generate_with_api_port(servers, settings, 10853)
}

fn single_server(outbound: OutboundModel) -> ServersFile {
    ServersFile {
        version: 1,
        active: Some(ID.into()),
        profiles: vec![ServerProfile {
            id: ID.into(),
            name: "test".into(),
            outbound,
            latency_ms: None,
            extra: Map::new(),
        }],
        extra: Map::new(),
    }
}

macro_rules! golden {
    ($file:literal, $got:expr_2021) => {{
        let got: Value = $got.expect("generate config");
        if std::env::var_os("BROCCOLI_UPDATE_GOLDENS").is_some() {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/gen")
                .join($file);
            std::fs::write(&path, serde_json::to_string_pretty(&got).unwrap()).unwrap();
            return;
        }
        let want: Value = serde_json::from_str(include_str!($file)).unwrap();
        assert_eq!(
            got,
            want,
            "golden mismatch for {}\nGOT:\n{}\n",
            $file,
            serde_json::to_string_pretty(&got).unwrap()
        );
    }};
}

fn observatory_service_count(cfg: &Value) -> usize {
    cfg["api"]["services"]
        .as_array()
        .expect("API service list")
        .iter()
        .filter(|service| service.as_str() == Some("ObservatoryService"))
        .count()
}

fn invalid_model_message(servers: &ServersFile) -> String {
    match generate_deterministic(servers, &base_settings()) {
        Err(error) => match &error {
            GenerateError::InvalidModel(_) | GenerateError::InvalidFinding(_) => {
                error.text(Language::En)
            }
            other => panic!("expected invalid model error, got {other:?}"),
        },
        Ok(_) => panic!("expected generation to reject invalid model"),
    }
}

#[test]
fn generate_on_defaults() {
    let servers = ServersFile::default();
    let settings = base_settings();
    let cfg = generate_deterministic(&servers, &settings).expect("generate config");
    // outbounds: built-ins plus the DNS outbound appended last (contract
    // order: [direct, block, dns-out] — the default outbound stays first).
    let out = cfg["outbounds"].as_array().unwrap();
    assert_eq!(out.len(), 3);
    assert_eq!(out[0]["tag"], json!("direct"));
    assert_eq!(out[0]["protocol"], json!("freedom"));
    assert_eq!(out[1]["tag"], json!("block"));
    assert_eq!(out[1]["protocol"], json!("blackhole"));
    assert_eq!(
        out[2],
        json!({ "protocol": "dns", "tag": DNS_OUTBOUND_TAG })
    );
    // inbounds: socks + http
    let tags: Vec<&str> = cfg["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["tag"].as_str())
        .collect();
    assert_eq!(tags, ["in-socks", "in-http"]);
    // always-present keys
    assert_eq!(cfg["stats"], json!({}));
    assert_eq!(cfg["api"]["tag"], json!("api"));
    assert_eq!(cfg["api"]["listen"], json!("127.0.0.1:10853"));
    assert_eq!(cfg["api"]["services"].as_array().unwrap().len(), 5);
    assert_eq!(cfg["policy"]["system"]["statsOutboundUplink"], json!(true));
    assert_eq!(cfg["log"], json!({"loglevel": "warning", "access": "none"}));
    // Seeded DNS module: 1.1.1.1 and 8.8.8.8 plain
    // UDP general servers raced in parallel, serveStale on with a 1-day
    // stale window, 8s per-server timeout default. UDP is seeded over DoH:
    // DoH-over-TCP through the tunnel chain stalls in bursts under DNS
    // floods (empirical, 2026-08-29), while plain UDP rides the same chain
    // statelessly. Exact wire form of DnsCfg::default().to_wire(false).
    assert_eq!(
        cfg["dns"],
        json!({
            "servers": [
                { "address": "1.1.1.1" },
                { "address": "8.8.8.8" }
            ],
            "enableParallelQuery": true,
            "serveStale": true,
            "serveExpiredTTL": 86400,
        })
    );
    // The SOCKS UDP:53 interception rule answers locally via dns-out.
    assert_eq!(
        cfg["routing"],
        json!({
            "rules": [
                {
                    "inboundTag": ["in-socks"],
                    "network": "udp",
                    "port": "53",
                    "outboundTag": DNS_OUTBOUND_TAG,
                }
            ]
        })
    );
    // absent by default
    for k in [
        "observatory",
        "burstObservatory",
        "fakeDns",
        "env",
        "geodata",
    ] {
        assert!(cfg.get(k).is_none(), "{k} must be absent by default");
    }
}

#[test]
fn access_log_toggle_controls_the_xray_access_channel() {
    // The per-connection access channel is not gated by loglevel ("from …
    // accepted …" lines), so the GUI pins it off unless the user enables it:
    // off → `access: "none"`, on → the key is omitted (xray defaults the
    // absent key to console).
    let servers = ServersFile::default();
    let mut settings = base_settings();
    assert!(!settings.access_log, "access logging must default off");

    let off_cfg = generate_deterministic(&servers, &settings).expect("generate config");
    assert_eq!(
        off_cfg["log"],
        json!({"loglevel": "warning", "access": "none"}),
        "default settings must pin the access channel off"
    );

    settings.access_log = true;
    let on_cfg = generate_deterministic(&servers, &settings).expect("generate config");
    assert_eq!(
        on_cfg["log"],
        json!({"loglevel": "warning"}),
        "enabling access logging must omit the access key (xray defaults it to console)"
    );
}

#[test]
fn ephemeral_api_port_is_chosen_per_launch_and_emitted_loopback_only() {
    // The port is bound from 127.0.0.1:0 at generation time — never
    // derived from persisted settings — so a same-user process cannot read the
    // control-plane port ahead of the launch.
    let picked = super::pick_ephemeral_api_port().expect("the OS must assign an ephemeral port");
    assert_ne!(picked, 0, "the OS must assign a nonzero ephemeral port");

    let servers = ServersFile::default();
    let settings = Settings::default();
    let cfg = generate(&servers, &settings).expect("generate config");
    let listen = cfg["api"]["listen"].as_str().expect("api.listen");
    let address: std::net::SocketAddr = listen.parse().expect("socket address");
    assert!(
        address.ip().is_loopback(),
        "control plane must stay loopback-only"
    );
    assert_ne!(
        address.port(),
        0,
        "emitted config must carry a nonzero port"
    );
}

#[test]
fn ephemeral_port_bind_failure_propagates_as_generate_error_not_a_panic() {
    // A bind failure is a recoverable environment condition. The
    // stub forces `TcpListener::bind` to fail; the error must surface as
    // `GenerateError::ApiPort` — never a panic on the GUI thread.
    let error = super::pick_ephemeral_api_port_inner(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "simulated bind failure",
        ))
    })
    .expect_err("a failing bind must propagate as an error");
    assert!(
        matches!(error, GenerateError::ApiPort(_)),
        "expected ApiPort, got {error}"
    );
    assert!(
        error.to_string().contains("simulated bind failure"),
        "the io error must be preserved in the display: {error}"
    );
}

#[test]
fn observatory_probe_url_rejects_ssrf_targets_with_class_name() {
    // The RUNNING core fetches the observatory probeURL
    // continuously, so the main-config emission path must apply the same
    // literal-host guard as the one-shot latency probe.
    let rejected = |url: &str, class: &str| {
        let mut settings = base_settings();
        settings.routing.observatory = ObservatoryCfg {
            enabled: true,
            probe_url: url.into(),
            ..Default::default()
        };
        let error = generate_deterministic(&ServersFile::default(), &settings)
            .expect_err("observatory probe URL must be rejected");
        let message = match error {
            GenerateError::InvalidModel(message) => message.text(Language::En),
            other => panic!("expected InvalidModel, got {other:?}"),
        };
        assert!(
            message.contains(class),
            "expected message mentioning {class:?}, got: {message}"
        );
    };

    rejected("http://127.0.0.1:18080/health", "loopback");
    rejected("http://[::1]:8080/", "loopback");
    rejected("http://[::ffff:127.0.0.1]:8080/", "loopback");
    rejected("http://169.254.10.20/", "link-local");
    rejected("http://[fe80::1]:8080/", "link-local");
    rejected("http://169.254.169.254/latest/meta-data/", "cloud-metadata");
    rejected("http://100.100.100.200/latest/", "cloud-metadata");

    // A dependency-forced observatory (a balancer needs live health data)
    // must reject the same blocked literal hosts even though the user toggle
    // is off.
    let mut forced = base_settings();
    forced.routing.observatory.probe_url = "http://127.0.0.1:1/".into();
    forced.routing.balancers.push(Balancer {
        tag: "health".into(),
        selector: vec!["srv-".into()],
        strategy: StrategyCfg {
            r#type: "leastping".into(),
            ..Default::default()
        },
        ..Default::default()
    });
    let error = generate_deterministic(&ServersFile::default(), &forced)
        .expect_err("a forced observatory must still reject blocked hosts");
    assert!(
        error.to_string().contains("loopback"),
        "expected loopback class, got: {error}"
    );

    // Public and empty probe URLs still generate.
    for url in [
        "https://www.google.com/generate_204",
        "https://example.com/probe",
        "http://example.com:8080/health",
        "",
    ] {
        let mut settings = base_settings();
        settings.routing.observatory = ObservatoryCfg {
            enabled: true,
            probe_url: url.into(),
            ..Default::default()
        };
        generate_deterministic(&ServersFile::default(), &settings).unwrap_or_else(|error| {
            panic!("public observatory probe URL {url:?} must pass: {error}")
        });
    }
}

#[test]
fn wildcard_listen_collides_with_a_specific_listen_on_shared_port() {
    let mut settings = base_settings();
    settings.local_inbounds[0].listen = "0.0.0.0".into();
    settings.local_inbounds[1].listen = "127.0.0.1".into();
    settings.local_inbounds[1].port = settings.local_inbounds[0].port;

    let error = generate_deterministic(&ServersFile::default(), &settings)
        .expect_err("wildcard and specific listen on one port must fail")
        .to_string();
    assert!(error.contains("conflicts with local inbound"), "{error}");
    assert!(error.contains("127.0.0.1:"), "{error}");
}

#[test]
fn distinct_listen_addresses_may_share_a_port() {
    let mut settings = base_settings();
    settings.local_inbounds[0].listen = "127.0.0.1".into();
    settings.local_inbounds[1].listen = "192.168.1.5".into();
    settings.local_inbounds[1].port = settings.local_inbounds[0].port;

    generate_deterministic(&ServersFile::default(), &settings)
        .expect("distinct concrete listens on one port must generate");
}

#[test]
fn invalid_listen_addresses_block_generation() {
    for bad in ["", "localhost", "127.0.0.1:8080"] {
        let mut settings = base_settings();
        settings.local_inbounds[0].listen = bad.into();
        let error = generate_deterministic(&ServersFile::default(), &settings)
            .expect_err("invalid SOCKS listen must fail")
            .to_string();
        assert!(
            error.contains("listen address must be an IP address"),
            "SOCKS listen {bad:?}: {error}"
        );

        settings = base_settings();
        settings.local_inbounds[1].listen = bad.into();
        let error = generate_deterministic(&ServersFile::default(), &settings)
            .expect_err("invalid HTTP listen must fail")
            .to_string();
        assert!(
            error.contains("listen address must be an IP address"),
            "HTTP listen {bad:?}: {error}"
        );

        settings = base_settings();
        settings.dokodemo.push(DokodemoCfg {
            tag: "in-doko-test-2".into(),
            enabled: true,
            listen_port: 20001,
            listen: bad.into(),
            network: "tcp".into(),
            address: "8.8.8.8".into(),
            port: 80,
            ..Default::default()
        });
        let error = generate_deterministic(&ServersFile::default(), &settings)
            .expect_err("invalid dokodemo listen must fail")
            .to_string();
        assert!(
            error.contains("listen address must be an IP address"),
            "dokodemo listen {bad:?}: {error}"
        );
    }
}

#[test]
fn tagless_dokodemo_entry_is_rejected_not_silently_retagged() {
    // The pre-ID in-doko-{index} fallback is gone: an enabled dokodemo entry
    // without a stable tag must block generation (empty tags are
    // String::default(), invisible to the compiler — only this pin keeps the
    // no-empty-tag-wire invariant honest).
    let mut settings = base_settings();
    settings.dokodemo.push(DokodemoCfg {
        enabled: true,
        listen_port: 20001,
        listen: "127.0.0.1".into(),
        network: "tcp".into(),
        ..Default::default()
    });
    let error = generate_deterministic(&ServersFile::default(), &settings)
        .expect_err("a tagless enabled dokodemo entry must fail generation")
        .to_string();
    assert!(
        error.contains("has no stable tag"),
        "tagless dokodemo must name the missing tag: {error}"
    );

    // The disabled entry is exempt — it never reaches the wire.
    let mut settings = base_settings();
    settings.dokodemo.push(DokodemoCfg {
        enabled: false,
        ..Default::default()
    });
    generate_deterministic(&ServersFile::default(), &settings)
        .expect("a disabled tagless dokodemo entry must not block generation");
}

#[test]
fn explicit_observatory_emits_official_config_and_service() {
    let mut settings = base_settings();
    settings.routing.observatory = ObservatoryCfg {
        enabled: true,
        subject_selector: vec!["edge-".into()],
        probe_url: "https://example.com/health".into(),
        probe_interval: DurationMs::secs(30),
        enable_concurrency: true,
        extra: Map::new(),
    };

    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");

    assert_eq!(
        cfg["observatory"],
        json!({
            "subjectSelector": ["edge-"],
            "probeURL": "https://example.com/health",
            "probeInterval": "30s",
            "enableConcurrency": true
        })
    );
    assert!(cfg.get("burstObservatory").is_none());
    assert_eq!(observatory_service_count(&cfg), 1);
}

#[test]
fn disabled_observatory_omits_config_and_service_unless_burst_is_enabled() {
    let cfg = generate_deterministic(&ServersFile::default(), &base_settings())
        .expect("generate default config");

    assert!(cfg.get("observatory").is_none());
    assert!(cfg.get("burstObservatory").is_none());
    assert_eq!(observatory_service_count(&cfg), 0);

    let mut burst_settings = base_settings();
    burst_settings.routing.burst_observatory.enabled = true;
    let burst_cfg = generate_deterministic(&ServersFile::default(), &burst_settings)
        .expect("generate burst config");

    assert!(burst_cfg.get("observatory").is_none());
    assert!(burst_cfg.get("burstObservatory").is_some());
    assert_eq!(observatory_service_count(&burst_cfg), 1);
}

/// A hand-edited settings file can still enable both engines: the generator
/// emits what the settings say, and the core serves the ordinary Observatory
/// (it is registered first). The Routing screen states that outcome.
#[test]
fn both_engines_configured_still_emit_both_blocks() {
    let mut settings = base_settings();
    settings.routing.observatory.enabled = true;
    settings.routing.burst_observatory.enabled = true;

    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");

    assert!(cfg.get("observatory").is_some());
    assert!(cfg.get("burstObservatory").is_some());
    assert_eq!(observatory_service_count(&cfg), 1);
}

/// A balancer that reads live health data forces the observatory over every
/// profile even when the burst observatory is enabled beside it: the
/// dependency needs an engine whose coverage cannot be narrowed, and the core
/// answers with the observatory because it is registered first. The burst
/// toggle is gated in the UI while such a balancer exists, so only a
/// hand-edited file reaches this shape.
#[test]
fn health_balancer_keeps_the_observatory_beside_burst() {
    let servers = single_server(OutboundModel::new(Protocol::Freedom));
    let mut settings = base_settings();
    settings.routing.burst_observatory.enabled = true;
    settings.routing.balancers.push(Balancer {
        tag: "health".into(),
        selector: vec!["srv-".into()],
        strategy: StrategyCfg {
            r#type: "leastload".into(),
            ..Default::default()
        },
        ..Default::default()
    });

    let cfg = generate_deterministic(&servers, &settings).expect("generate config");

    assert_eq!(
        cfg["observatory"]["subjectSelector"],
        json!(["srv-01234567"]),
        "the dependency forces full coverage of the profile set"
    );
    assert!(cfg.get("burstObservatory").is_some());
    assert_eq!(observatory_service_count(&cfg), 1);
}

#[test]
fn health_balancers_force_the_ordinary_observatory() {
    let servers = single_server(OutboundModel::new(Protocol::Freedom));
    let balancer = |strategy: &str, fallback: &str| Balancer {
        tag: "health".into(),
        selector: vec!["srv-".into()],
        strategy: StrategyCfg {
            r#type: strategy.into(),
            ..Default::default()
        },
        fallback_tag: fallback.into(),
        ..Default::default()
    };

    for (dependency, candidate) in [
        ("leastping", balancer("leastping", "")),
        ("leastload", balancer("leastload", "")),
        ("roundrobin fallback", balancer("roundrobin", "direct")),
        ("random fallback", balancer("random", "direct")),
    ] {
        let mut settings = base_settings();
        settings.routing.balancers.push(candidate);
        let cfg = generate_deterministic(&servers, &settings)
            .unwrap_or_else(|error| panic!("{dependency} config failed: {error}"));

        assert_eq!(
            cfg["observatory"],
            json!({
                "subjectSelector": ["srv-01234567"],
                "probeURL": "https://www.google.com/generate_204",
                "probeInterval": "10s"
            }),
            "{dependency} must force the ordinary observatory"
        );
        assert!(cfg.get("burstObservatory").is_none());
        assert_eq!(
            observatory_service_count(&cfg),
            1,
            "{dependency} must emit one ObservatoryService"
        );
    }

    // A balancer that reads no live health data leaves the extension out.
    let mut plain = base_settings();
    plain.routing.balancers.push(balancer("random", ""));
    let cfg = generate_deterministic(&servers, &plain).expect("generate plain balancer config");
    assert!(cfg.get("observatory").is_none());
    assert_eq!(observatory_service_count(&cfg), 0);

    let mut explicit_settings = base_settings();
    explicit_settings.routing.observatory.enabled = true;
    explicit_settings.routing.observatory.subject_selector = vec!["custom-".into()];
    explicit_settings
        .routing
        .balancers
        .push(balancer("leastping", ""));
    let cfg = generate_deterministic(&servers, &explicit_settings)
        .expect("explicit observatory config with dependency");
    assert_eq!(
        cfg["observatory"]["subjectSelector"],
        json!(["custom-"]),
        "an explicitly enabled observatory must preserve its user selector"
    );
}

#[test]
fn raw_override_verbatim() {
    let mut settings = base_settings();
    settings.raw_override = Some(r#"{"custom": true, "outbounds": []}"#.into());
    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");
    assert_eq!(cfg, json!({"custom": true, "outbounds": []}));
}

#[test]
fn invalid_raw_override_is_a_generation_error() {
    let mut settings = base_settings();
    settings.raw_override = Some("{not json".into());
    let error = generate_deterministic(&ServersFile::default(), &settings).unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("The raw override is not valid JSON:")
    );
}

#[test]
fn invalid_gui_targets_and_required_fields_block_generation() {
    let mut settings = base_settings();
    settings.routing.rules.push(Rule::default());
    assert!(matches!(
        generate_deterministic(&ServersFile::default(), &settings),
        Err(GenerateError::InvalidFinding(_))
    ));

    settings.routing.rules.clear();
    settings.routing.balancers.push(Balancer::default());
    assert!(matches!(
        generate_deterministic(&ServersFile::default(), &settings),
        Err(GenerateError::InvalidFinding(_))
    ));

    settings.routing.balancers.clear();
    settings.dns.servers.push(DnsServer::default());
    assert!(matches!(
        generate_deterministic(&ServersFile::default(), &settings),
        Err(GenerateError::InvalidFinding(_))
    ));
}

#[test]
fn duplicate_profile_tag_blocks_generation() {
    let mut servers = single_server(OutboundModel::default());
    servers.active = None;
    let mut colliding = servers.profiles[0].clone();
    colliding.id = "01234567different".into();
    servers.profiles.push(colliding);

    let message = invalid_model_message(&servers);
    assert!(message.contains("duplicate outbound tag"), "{message}");
    assert!(message.contains("srv-01234567"), "{message}");
}

#[test]
fn duplicate_profile_id_blocks_generation() {
    let mut servers = single_server(OutboundModel::default());
    servers.active = None;
    servers.profiles.push(servers.profiles[0].clone());

    let message = invalid_model_message(&servers);
    assert!(message.contains("duplicate ID"), "{message}");
    assert!(message.contains(ID), "{message}");
}

#[test]
fn reality_requires_a_supported_transport_blocks_generation() {
    // Reality + WebSocket slips through the generator today (the old per-profile
    // checks only ran transport security, not the REALITY transport-support
    // rule); the validation pass must reject it as an invalid model.
    let mut ob = OutboundModel::new(Protocol::Vless);
    ob.settings = ProtocolSettings::Vless(VlessSettings {
        address: "vless.example.com".into(),
        port: 443,
        // Canonical UUID user id (UUID-only policy): ID's 16-hex
        // form would be sha1-mapped by Xray to a different account.
        id: "11111111-2222-3333-4444-555555555555".into(),
        encryption: "none".into(),
        ..Default::default()
    });
    ob.stream.security = Security::Reality;
    ob.stream.reality_settings = Some(RealityModel {
        server_name: "www.microsoft.com".into(),
        fingerprint: "chrome".into(),
        password: "DqH68jf6jhword4-tu3NY5pnGvZ-ZSFFcSorTaLSEt4".into(),
        ..Default::default()
    });
    ob.stream.network = Network::Ws;
    ob.stream.ws_settings = Some(WsSettings::default());

    let message = invalid_model_message(&single_server(ob));
    assert!(message.contains("REALITY"), "{message}");
    assert!(message.contains("raw, XHTTP, or gRPC"), "{message}");
}

#[test]
fn warning_findings_never_gate_generation() {
    // A VLESS vision flow over enabled TCP mux is
    // xray-legal — MuxWithVisionFlow is advisory (Severity::Warning) and
    // must not refuse generation; only Severity::Error findings gate.
    let mut ob = OutboundModel::new(Protocol::Vless);
    ob.settings = ProtocolSettings::Vless(VlessSettings {
        address: "vless.example.com".into(),
        port: 443,
        // Canonical UUID user id (UUID-only policy).
        id: "11111111-2222-3333-4444-555555555555".into(),
        flow: "xtls-rprx-vision".into(),
        encryption: "none".into(),
        ..Default::default()
    });
    let _ = ob.stream.select_security(Security::Tls);
    ob.mux.enabled = true;
    ob.mux.concurrency = Some(8);
    let servers = single_server(ob);
    let issues = validate_profiles(&servers.profiles, servers.active.as_deref(), false);
    assert!(
        invalid_model_error(issues).is_none(),
        "a warning-only profile must generate"
    );
    generate_deterministic(&servers, &base_settings()).expect("a warning-only profile must apply");
}
#[test]
fn latency_probe_generator_is_minimal_and_preserves_profile_chains() {
    let mut first = ServerProfile::new("first", OutboundModel::new(Protocol::Freedom));
    first.id = ID.into();
    let mut second = ServerProfile::new("second", OutboundModel::new(Protocol::Freedom));
    second.id = "fedcba9876543210".into();
    second.outbound.chain_via(first.tag());
    let profiles = vec![first.clone(), second.clone()];

    let cfg = generate_latency_probe(&profiles, " https://probe.example/health ", 45678, None)
        .expect("generate isolated latency config");
    assert_eq!(
        cfg["api"],
        json!({
            "tag": "api",
            "listen": "127.0.0.1:45678",
            "services": ["ObservatoryService"]
        })
    );
    assert_eq!(
        cfg["observatory"]["subjectSelector"],
        json!([first.tag(), second.tag()])
    );
    assert_eq!(
        cfg["observatory"]["probeURL"],
        json!("https://probe.example/health")
    );
    assert_eq!(cfg["observatory"]["probeInterval"], json!("1h"));
    assert_eq!(cfg["observatory"]["enableConcurrency"], json!(true));
    assert!(cfg["observatory"].get("enabled").is_none());

    let outbounds = cfg["outbounds"].as_array().expect("probe outbounds");
    assert_eq!(
        outbounds
            .iter()
            .map(|outbound| outbound["tag"].as_str().unwrap().to_string())
            .collect::<Vec<_>>(),
        vec![
            first.tag(),
            second.tag(),
            "direct".to_string(),
            "block".to_string(),
        ]
    );
    assert_eq!(
        cfg["log"],
        json!({"loglevel": "warning", "access": "none"}),
        "probe stdout feeds failure diagnostics; its access channel must stay pinned off"
    );
    assert_eq!(
        outbounds[1]["streamSettings"]["sockopt"]["dialerProxy"],
        json!(first.tag())
    );
    assert_eq!(outbounds[2]["protocol"], json!("freedom"));
    assert_eq!(outbounds[3]["protocol"], json!("blackhole"));
    for key in [
        "inbounds",
        "routing",
        "dns",
        "stats",
        "policy",
        "burstObservatory",
    ] {
        assert!(
            cfg.get(key).is_none(),
            "{key} must be absent from probe config"
        );
    }

    let default_cfg =
        generate_latency_probe(&profiles, "", 45678, None).expect("default probe URL is valid");
    assert_eq!(
        default_cfg["observatory"]["probeURL"],
        json!("https://www.google.com/generate_204")
    );
}

#[test]
fn latency_probe_interface_binding_reaches_every_profile_outbound_only() {
    // With Some(name), every profile outbound carries
    // streamSettings.sockopt.interface; the builtin direct/block outbounds
    // must stay untouched (no streamSettings at all).
    let mut first = ServerProfile::new("first", OutboundModel::new(Protocol::Freedom));
    first.id = ID.into();
    let mut second = ServerProfile::new("second", OutboundModel::new(Protocol::Freedom));
    second.id = "fedcba9876543210".into();
    let profiles = vec![first, second];

    let cfg = generate_latency_probe(
        &profiles,
        "https://probe.example/health",
        45678,
        Some("Ethernet"),
    )
    .expect("generate isolated latency config");
    let outbounds = cfg["outbounds"].as_array().expect("probe outbounds");
    assert_eq!(outbounds.len(), 4);
    for (index, outbound) in outbounds.iter().enumerate().take(2) {
        assert_eq!(
            outbound["streamSettings"]["sockopt"]["interface"],
            json!("Ethernet"),
            "profile outbound {index} must be bound to the interface"
        );
    }
    // Builtins never gain streamSettings.
    assert!(outbounds[2].get("streamSettings").is_none());
    assert!(outbounds[3].get("streamSettings").is_none());
}

#[test]
fn latency_probe_interface_binding_preserves_existing_stream_settings() {
    // An outbound with pre-existing streamSettings (TLS security) and
    // sockopt (domainStrategy) keeps every key alongside the injected
    // interface — nothing at any level is dropped or overwritten.
    let mut vless = OutboundModel::new(Protocol::Vless);
    vless.settings = ProtocolSettings::Vless(VlessSettings {
        address: "vless.example.com".into(),
        port: 443,
        // Canonical UUID user id and canonical 4-part PQ encryption
        // (Xray rejects the bare 3-part mlkem form).
        id: "11111111-2222-3333-4444-555555555555".into(),
        encryption: "mlkem768x25519plus.native.1rtt.key".into(),
        ..Default::default()
    });
    vless.stream.security = Security::Tls;
    vless.stream.tls_settings = Some(TlsModel {
        server_name: "cdn.example.com".into(),
        fingerprint: "chrome".into(),
        ..Default::default()
    });
    vless.stream.sockopt = Some(SockoptModel {
        domain_strategy: "useip".into(),
        ..Default::default()
    });
    let profiles = vec![ServerProfile {
        id: ID.into(),
        ..ServerProfile::new("tls", vless)
    }];

    let cfg = generate_latency_probe(
        &profiles,
        "https://probe.example/health",
        45678,
        Some("Ethernet"),
    )
    .expect("generate isolated latency config");
    let outbounds = cfg["outbounds"].as_array().expect("probe outbounds");
    let stream = outbounds[0]["streamSettings"]
        .as_object()
        .expect("streamSettings");
    assert_eq!(
        stream["tlsSettings"]["serverName"],
        json!("cdn.example.com"),
        "pre-existing TLS settings must survive the interface injection"
    );
    assert_eq!(
        stream["sockopt"]["domainStrategy"],
        json!("useip"),
        "pre-existing sockopt keys must survive the interface injection"
    );
    assert_eq!(stream["sockopt"]["interface"], json!("Ethernet"));
}

#[test]
fn latency_probe_interface_binding_skips_wireguard_outbounds() {
    // WG's dial path ignores sockopt (XTLS/Xray-core#5363, same guard as
    // the bootstrap domainStrategy injection): a WG outbound must not carry
    // an inert interface binding that looks bound but isn't.
    let mut wg = OutboundModel::new(Protocol::Wireguard);
    wg.settings = ProtocolSettings::Wireguard(WireguardSettings {
        peers: vec![WireguardPeer {
            public_key: "A".repeat(44),
            endpoint: "wg.example.com:51820".into(),
            ..Default::default()
        }],
        ..Default::default()
    });
    let mut vless = OutboundModel::new(Protocol::Vless);
    vless.settings = ProtocolSettings::Vless(VlessSettings {
        address: "vless.example.com".into(),
        port: 443,
        // Canonical UUID user id and canonical 4-part PQ encryption.
        id: "11111111-2222-3333-4444-555555555555".into(),
        encryption: "mlkem768x25519plus.native.1rtt.key".into(),
        ..Default::default()
    });
    let profiles = vec![
        ServerProfile {
            id: ID.into(),
            ..ServerProfile::new("wg", wg)
        },
        ServerProfile {
            id: "fedcba9876543210".into(),
            ..ServerProfile::new("vless", vless)
        },
    ];

    let cfg = generate_latency_probe(
        &profiles,
        "https://probe.example/health",
        45678,
        Some("Ethernet"),
    )
    .expect("generate isolated latency config");
    let outbounds = cfg["outbounds"].as_array().expect("probe outbounds");
    assert!(
        outbounds[0].get("streamSettings").is_none(),
        "the WireGuard outbound must not carry an inert interface binding"
    );
    assert_eq!(
        outbounds[1]["streamSettings"]["sockopt"]["interface"],
        json!("Ethernet"),
        "non-WG profile outbounds still bind"
    );
}

#[test]
fn latency_probe_generator_rejects_invalid_inputs() {
    let valid = vec![ServerProfile {
        id: ID.into(),
        ..ServerProfile::new("valid", OutboundModel::new(Protocol::Freedom))
    }];
    let invalid = |profiles: &[ServerProfile], url: &str, port: u16| {
        let error = generate_latency_probe(profiles, url, port, None)
            .expect_err("an invalid probe input must be rejected");
        assert!(
            matches!(
                &error,
                GenerateError::InvalidModel(_) | GenerateError::InvalidFinding(_)
            ),
            "expected invalid model for url={url:?}, port={port}, got {error:?}"
        );
    };

    invalid(&[], "http://127.0.0.1:1", 45678);
    invalid(&valid, "http://127.0.0.1:1", 0);
    invalid(&valid, "ftp://127.0.0.1:1", 45678);
    invalid(&valid, "not an absolute URL", 45678);

    let mut duplicate = valid.clone();
    duplicate.push(ServerProfile {
        id: "01234567-other".into(),
        ..ServerProfile::new("duplicate", OutboundModel::new(Protocol::Freedom))
    });
    invalid(&duplicate, "http://127.0.0.1:1", 45678);

    let mut broken_chain = valid.clone();
    broken_chain[0].outbound.chain_via("srv-missing");
    invalid(&broken_chain, "http://127.0.0.1:1", 45678);

    let mut invalid_tag = valid;
    invalid_tag[0].id = "bad id".into();
    invalid(&invalid_tag, "http://127.0.0.1:1", 45678);
}

#[test]
fn latency_probe_generator_rejects_ssrf_targets_with_class_name() {
    let profiles = vec![ServerProfile {
        id: ID.into(),
        ..ServerProfile::new("valid", OutboundModel::new(Protocol::Freedom))
    }];
    let rejected = |url: &str, class: &str| {
        let error = generate_latency_probe(&profiles, url, 45678, None)
            .expect_err("probe URL must be rejected");
        let message = match error {
            GenerateError::InvalidModel(message) => message.text(Language::En),
            other => panic!("expected InvalidModel, got {other:?}"),
        };
        assert!(
            message.contains(class),
            "expected message mentioning {class:?}, got: {message}"
        );
    };

    // Loopback: IPv4 literal, IPv4 with a port, IPv6 literal, and the
    // IPv4-mapped IPv6 spelling that would otherwise smuggle 127.0.0.1 past a
    // naive IPv6-only check.
    rejected("http://127.0.0.1:18080/health", "loopback");
    rejected("http://127.0.0.1:1/", "loopback");
    rejected("http://[::1]:8080/", "loopback");
    rejected("http://[::ffff:127.0.0.1]:8080/", "loopback");
    // Link-local: IPv4 169.254.0.0/16 and IPv6 fe80::/10.
    rejected("http://169.254.10.20/", "link-local");
    rejected("http://[fe80::1]:8080/", "link-local");
    // Cloud metadata endpoints.
    rejected("http://169.254.169.254/latest/meta-data/", "cloud-metadata");
    rejected("http://100.100.100.200/latest/", "cloud-metadata");

    // Public literal and hostname URLs pass unchanged.
    for url in [
        "https://www.google.com/generate_204",
        "https://example.com/probe",
        "http://example.com:8080/health",
        "https://8.8.8.8/",
    ] {
        let cfg = generate_latency_probe(&profiles, url, 45678, None)
            .expect("public probe URL must be accepted");
        assert_eq!(cfg["observatory"]["probeURL"], json!(url));
    }
}

#[test]
fn stale_active_profile_id_blocks_generation() {
    let mut servers = single_server(OutboundModel::default());
    servers.active = Some("missing-profile".into());

    let message = invalid_model_message(&servers);
    assert!(message.contains("active server profile ID"), "{message}");
    assert!(message.contains("does not match any profile"), "{message}");
    assert!(message.contains("missing-profile"), "{message}");
}

#[test]
fn ambiguous_active_profile_id_blocks_generation() {
    let mut servers = single_server(OutboundModel::default());
    servers.profiles.push(servers.profiles[0].clone());

    let message = invalid_model_message(&servers);
    assert!(message.contains("active server profile ID"), "{message}");
    assert!(message.contains("ambiguous"), "{message}");
    assert!(message.contains("2 profiles"), "{message}");
}

#[test]
fn whitespace_profile_id_blocks_generation() {
    let mut servers = single_server(OutboundModel::default());
    servers.active = None;
    servers.profiles[0].id = " \t".into();

    let message = invalid_model_message(&servers);
    assert!(message.contains("whitespace-only ID"), "{message}");
}

#[test]
fn golden_vless_reality() {
    let mut ob = OutboundModel::new(Protocol::Vless);
    ob.settings = ProtocolSettings::Vless(VlessSettings {
        address: "vless.example.com".into(),
        port: 443,
        id: "11111111-2222-3333-4444-555555555555".into(),
        flow: "xtls-rprx-vision".into(),
        encryption: "none".into(),
        ..Default::default()
    });
    ob.stream.security = Security::Reality;
    ob.stream.reality_settings = Some(RealityModel {
        server_name: "www.microsoft.com".into(),
        fingerprint: "chrome".into(),
        password: "DqH68jf6jhword4-tu3NY5pnGvZ-ZSFFcSorTaLSEt4".into(),
        short_id: "0123456789abcdef".into(),
        ..Default::default()
    });
    golden!(
        "goldens/vless_reality.json",
        generate_deterministic(&single_server(ob), &base_settings())
    );
}

#[test]
fn golden_vless_xhttp_tls() {
    let mut ob = OutboundModel::new(Protocol::Vless);
    ob.settings = ProtocolSettings::Vless(VlessSettings {
        address: "x.example.com".into(),
        port: 443,
        id: "11111111-2222-3333-4444-555555555555".into(),
        encryption: "none".into(),
        ..Default::default()
    });
    ob.stream.network = Network::Xhttp;
    ob.stream.xhttp_settings = Some(XhttpSettings {
        host: "cdn.example.com".into(),
        path: "/xhttp".into(),
        mode: "packet-up".into(),
        x_padding_bytes: Some(Int32Range::new(100, 200)),
        uplink_chunk_size: Some(Int32Range::new(2000, 4000)),
        sc_max_each_post_bytes: Some(Int32Range::single(1_000_000)),
        ..Default::default()
    });
    ob.stream.security = Security::Tls;
    ob.stream.tls_settings = Some(TlsModel {
        server_name: "cdn.example.com".into(),
        alpn: vec!["h2".into(), "http/1.1".into()],
        fingerprint: "chrome".into(),
        ..Default::default()
    });
    golden!(
        "goldens/vless_xhttp_tls.json",
        generate_deterministic(&single_server(ob), &base_settings())
    );
}

#[test]
fn golden_vmess_ws_tls() {
    let mut ob = OutboundModel::new(Protocol::Vmess);
    ob.settings = ProtocolSettings::Vmess(VmessSettings {
        address: "vmess.example.com".into(),
        port: 443,
        id: "11111111-2222-3333-4444-555555555555".into(),
        security: "auto".into(),
        ..Default::default()
    });
    ob.stream.network = Network::Ws;
    ob.stream.ws_settings = Some(WsSettings {
        host: "vmess.example.com".into(),
        path: "/ws".into(),
        ..Default::default()
    });
    ob.stream.security = Security::Tls;
    ob.stream.tls_settings = Some(TlsModel {
        server_name: "vmess.example.com".into(),
        fingerprint: "firefox".into(),
        ..Default::default()
    });
    golden!(
        "goldens/vmess_ws_tls.json",
        generate_deterministic(&single_server(ob), &base_settings())
    );
}

#[test]
fn golden_trojan_raw_tls() {
    let mut ob = OutboundModel::new(Protocol::Trojan);
    ob.settings = ProtocolSettings::Trojan(TrojanSettings {
        address: "trojan.example.com".into(),
        port: 443,
        password: "secret".into(),
        ..Default::default()
    });
    ob.stream.security = Security::Tls;
    ob.stream.tls_settings = Some(TlsModel {
        server_name: "trojan.example.com".into(),
        ..Default::default()
    });
    golden!(
        "goldens/trojan_raw_tls.json",
        generate_deterministic(&single_server(ob), &base_settings())
    );
}

#[test]
fn golden_ss_2022() {
    let mut ob = OutboundModel::new(Protocol::Shadowsocks);
    ob.settings = ProtocolSettings::Shadowsocks(ShadowsocksSettings {
        address: "ss.example.com".into(),
        port: 8388,
        method: "2022-blake3-aes-128-gcm".into(),
        password: "MDEyMzQ1Njc4OWFiY2RlZg==".into(),
        ..Default::default()
    });
    golden!(
        "goldens/ss_2022.json",
        generate_deterministic(&single_server(ob), &base_settings())
    );
}

#[test]
fn golden_wireguard() {
    let mut ob = OutboundModel::new(Protocol::Wireguard);
    ob.settings = ProtocolSettings::Wireguard(WireguardSettings {
        secret_key: "5fIY2zEKwnvOylBo+6fzM9bKxz29gTWFM2mBZ0s5rcY=".into(),
        address: vec!["10.0.0.1/32".into()],
        peers: vec![WireguardPeer {
            public_key: "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=".into(),
            endpoint: "203.0.113.10:51820".into(),
            keep_alive: Some(25),
            allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
            ..Default::default()
        }],
        ..Default::default()
    });
    golden!(
        "goldens/wireguard.json",
        generate_deterministic(&single_server(ob), &base_settings())
    );
}

#[test]
fn golden_hysteria2() {
    let mut ob = OutboundModel::new(Protocol::Hysteria);
    ob.settings = ProtocolSettings::Hysteria(HysteriaSettings {
        address: "hy2.example.com".into(),
        port: 443,
        ..Default::default()
    });
    ob.stream.network = Network::Hysteria;
    ob.stream.hysteria_settings = Some(HysteriaTransport {
        auth: "hy2password".into(),
        udp_idle_timeout: Some(60),
        ..Default::default()
    });
    ob.stream.finalmask = Some(FinalmaskModel {
        quic_params: Some(FinalmaskQuicParams {
            congestion: "brutal".into(),
            brutal_up: "50 mbps".into(),
            brutal_down: "200 mbps".into(),
            ..Default::default()
        }),
        ..Default::default()
    });
    golden!(
        "goldens/hysteria2.json",
        generate_deterministic(&single_server(ob), &base_settings())
    );
}

#[test]
fn golden_freedom_fragment_noises() {
    let mut ob = OutboundModel::new(Protocol::Freedom);
    ob.settings = ProtocolSettings::Freedom(FreedomSettings {
        target_strategy: "UseIP".into(),
        fragment: Some(Fragment {
            packets: "tlshello".into(),
            length: Some(Int32Range::new(100, 200)),
            interval: Some(Int32Range::new(10, 20)),
            ..Default::default()
        }),
        noises: vec![Noise {
            r#type: "rand".into(),
            packet: "50-100".into(),
            delay: Some(Int32Range::new(1, 5)),
            ..Default::default()
        }],
        final_rules: vec![FreedomFinalRule {
            action: "block".into(),
            network: "udp".into(),
            port: "443".into(),
            ip: vec!["203.0.113.0/24".into()],
            ..Default::default()
        }],
        ..Default::default()
    });
    golden!(
        "goldens/freedom_fragment_noises.json",
        generate_deterministic(&single_server(ob), &base_settings())
    );
}

#[test]
fn golden_socks_out_auth() {
    let mut ob = OutboundModel::new(Protocol::Socks);
    ob.settings = ProtocolSettings::Socks(SocksSettings {
        address: "10.0.0.2".into(),
        port: 1080,
        user: "alice".into(),
        pass: "wonder".into(),
        ..Default::default()
    });
    golden!(
        "goldens/socks_out_auth.json",
        generate_deterministic(&single_server(ob), &base_settings())
    );
}

#[test]
fn golden_dokodemo() {
    let mut settings = base_settings();
    settings.dokodemo = vec![DokodemoCfg {
        tag: "in-doko-test-1".into(),
        enabled: true,
        listen_port: 5353,
        address: "8.8.8.8".into(),
        port: 53,
        ..Default::default()
    }];
    golden!(
        "goldens/dokodemo.json",
        generate_deterministic(&ServersFile::default(), &settings)
    );
}

#[test]
fn golden_tun() {
    let mut settings = base_settings();
    settings.mode = Mode::Tun;
    golden!(
        "goldens/tun.json",
        generate_deterministic(&ServersFile::default(), &settings)
    );
}

#[test]
fn golden_listen_lan() {
    let mut settings = base_settings();
    settings.local_inbounds[0].listen = "192.168.1.5".into();
    golden!(
        "goldens/listen_lan.json",
        generate_deterministic(&ServersFile::default(), &settings)
    );
}

#[test]
fn golden_fakedns() {
    let mut settings = base_settings();
    settings.dns.servers = vec![DnsServer {
        address: "1.1.1.1".into(),
        ..Default::default()
    }];
    settings.dns.fakedns.enabled = true;
    golden!(
        "goldens/fakedns.json",
        generate_deterministic(&ServersFile::default(), &settings)
    );
}

#[test]
fn golden_balancer_leastload() {
    let mut ob = OutboundModel::new(Protocol::Vless);
    ob.settings = ProtocolSettings::Vless(VlessSettings {
        address: "10.0.0.8".into(), // private IP: plaintext vless allowed (xray.go:241-259)
        port: 443,
        id: "11111111-2222-3333-4444-555555555555".into(),
        encryption: "none".into(),
        ..Default::default()
    });
    let mut settings = base_settings();
    settings.routing.rules = vec![Rule {
        rule_tag: "11111111-2222-3333-4444-555555555555".into(),
        balancer_tag: "bal".into(),
        domain: vec!["geosite:cn".into()],
        ..Rule::default()
    }];
    settings.routing.balancers = vec![Balancer {
        tag: "bal".into(),
        selector: vec!["srv-".into()],
        strategy: StrategyCfg {
            r#type: "leastload".into(),
            settings: Some(LeastLoadSettings {
                costs: vec![StrategyCost {
                    regexp: true,
                    r#match: "srv-".into(),
                    value: Some(2.0),
                    ..Default::default()
                }],
                baselines: vec![DurationMs::secs(1)],
                expected: Some(1),
                max_rtt: Some(DurationMs::secs(5)),
                tolerance: Some(0.5),
                ..Default::default()
            }),
            ..Default::default()
        },
        fallback_tag: "direct".into(),
        ..Default::default()
    }];
    golden!(
        "goldens/balancer_leastload.json",
        generate_deterministic(&single_server(ob), &settings)
    );
}

#[test]
fn fakedns_multiple_pools_emit_official_array_form() {
    let mut settings = base_settings();
    settings.dns.fakedns.enabled = true;
    settings.dns.fakedns.pools = vec![
        FakeDnsPool {
            ip_pool: DEFAULT_FAKEDNS_POOL_CIDR.into(),
            pool_size: DEFAULT_FAKEDNS_POOL_SIZE,
            ..Default::default()
        },
        FakeDnsPool {
            ip_pool: SECOND_FAKEDNS_POOL_CIDR.into(),
            pool_size: SECOND_FAKEDNS_POOL_SIZE,
            ..Default::default()
        },
    ];

    let generated =
        generate_deterministic(&ServersFile::default(), &settings).expect("generate config");
    assert_eq!(
        generated["fakeDns"],
        json!([
            {"ipPool": DEFAULT_FAKEDNS_POOL_CIDR, "poolSize": DEFAULT_FAKEDNS_POOL_SIZE},
            {"ipPool": SECOND_FAKEDNS_POOL_CIDR, "poolSize": SECOND_FAKEDNS_POOL_SIZE}
        ])
    );
}

#[test]
fn invalid_fakedns_pool_rejected_at_generation() {
    // A fakeDNS pool that Xray's fakeip holder cannot build (bad CIDR,
    // bare IP, non-positive size, LRU size not smaller than the subnet)
    // fails the core at start — generation must refuse it before a
    // candidate is ever written.
    let cases = [
        ("300.1.1.1/8", 65_535),
        ("198.18.0.0", 65_535), // bare IP: Go net.ParseCIDR rejects it
        ("198.18.0.0/15", 0),
        ("10.0.0.0/24", 65_535), // 2^8 rooms < 65535
    ];
    for (ip_pool, pool_size) in cases {
        let mut settings = base_settings();
        settings.dns.fakedns.enabled = true;
        settings.dns.fakedns.pools[0].ip_pool = ip_pool.into();
        settings.dns.fakedns.pools[0].pool_size = pool_size;
        let error = match generate_deterministic(&ServersFile::default(), &settings) {
            Err(error @ GenerateError::InvalidFinding(_)) => error.text(Language::En),
            Err(other) => panic!("expected InvalidModel, got {other:?}"),
            Ok(_) => panic!("an invalid fakeDNS pool must be rejected"),
        };
        assert!(error.contains("fakeDNS pool 1"), "{error}");
    }
}

#[test]
fn tun_user_rules_follow_the_dns_interception_rules() {
    let mut settings = base_settings();
    settings.mode = Mode::Tun;
    settings.routing.rules.push(Rule {
        inbound_tag: vec![TUN_INBOUND_TAG.into()],
        domain: vec!["domain:blocked.example".into()],
        outbound_tag: "block".into(),
        ..Default::default()
    });

    let generated =
        generate_deterministic(&ServersFile::default(), &settings).expect("generate config");
    let rules = generated["routing"]["rules"].as_array().unwrap();
    // The system rules come first — the interception rules that own DNS for
    // the intercepted inbounds (seeded DNS module: dns-in, in-tun:53,
    // in-socks:53) — and the user's rules last. Xray routes by first match,
    // so a user rule ahead of the interception rules would shadow them.
    // There is no trailing TUN catch-all either: unmatched TUN traffic falls
    // to Xray's default outbound (the first outbound, always the active
    // profile), and an unconditional in-tun catch-all would swallow appended
    // trial rules before they are evaluated.
    assert_eq!(rules.len(), 4);
    assert_eq!(rules[0]["inboundTag"], json!([DNS_INBOUND_TAG]));
    assert_eq!(rules[1]["inboundTag"], json!([TUN_INBOUND_TAG]));
    assert_eq!(rules[2]["inboundTag"], json!(["in-socks"]));
    assert_eq!(rules[3]["outboundTag"], json!("block"));
    assert_eq!(rules[3]["domain"], json!(["domain:blocked.example"]));
}

#[test]
fn tun_emits_pins_then_dns_interception_then_user_rules_in_order() {
    // The whole emitted order in one array: a user rule emitted above a pin
    // (or an interception rule above a pin) would silently shadow it under
    // Xray's first-match routing, so no single group's order pins the
    // contract on its own.
    let mut settings = base_settings();
    settings.mode = Mode::Tun;
    settings.dns.servers.push(DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    });
    settings.routing.rules.push(Rule {
        rule_tag: "user-rule".into(),
        domain: vec!["domain:blocked.example".into()],
        outbound_tag: "block".into(),
        ..Default::default()
    });
    let cfg = generate_deterministic(&single_server(vless_server("1.2.3.4", 443)), &settings)
        .expect("generate config");

    assert_eq!(
        cfg["routing"]["rules"],
        json!([
            // The DoH upstream pin: the module's dial to the active profile.
            {
                "ip": ["1.1.1.1"],
                "port": "443",
                "outboundTag": "srv-01234567",
            },
            // Local DNS interception, in emitter order: dns-in, TUN, SOCKS.
            {
                "inboundTag": [DNS_INBOUND_TAG],
                "network": "udp,tcp",
                "port": "53",
                "outboundTag": DNS_OUTBOUND_TAG,
            },
            {
                "inboundTag": [TUN_INBOUND_TAG],
                "network": "udp",
                "port": "53",
                "outboundTag": DNS_OUTBOUND_TAG,
            },
            {
                "inboundTag": ["in-socks"],
                "network": "udp",
                "port": "53",
                "outboundTag": DNS_OUTBOUND_TAG,
            },
            // The user's rules last.
            {
                "ruleTag": "user-rule",
                "domain": ["domain:blocked.example"],
                "outboundTag": "block",
            },
        ])
    );
}

#[test]
fn user_port_53_rule_is_routed_after_the_dns_interception_rules() {
    // A user rule matching UDP port 53 with no inboundTag condition (any
    // inbound, any domain) is the worst case for first-match routing: ahead
    // of the interception rules it would win every TUN/SOCKS DNS query and
    // send those queries out of the tunnel as plaintext.
    let mut settings = base_settings();
    settings.mode = Mode::Tun;
    settings.routing.rules.push(Rule {
        rule_tag: "user-port-53".into(),
        port: "53".into(),
        outbound_tag: "direct".into(),
        ..Default::default()
    });

    let generated =
        generate_deterministic(&ServersFile::default(), &settings).expect("generate config");
    let rules = generated["routing"]["rules"].as_array().unwrap();
    let user_index = rules
        .iter()
        .position(|rule| rule["ruleTag"] == json!("user-port-53"))
        .expect("the user port-53 rule on the wire");
    for (index, rule) in rules.iter().enumerate() {
        if rule["outboundTag"] == json!(DNS_OUTBOUND_TAG) {
            assert!(
                index < user_index,
                "DNS interception rule {index} must precede the user port-53 \
                 rule at {user_index}: {rule}"
            );
        }
    }
    assert_eq!(
        user_index,
        rules.len() - 1,
        "the user port-53 rule must be the last rule: {rules:?}"
    );
}

/// User report: a trial rule blocking a domain was confirmed by Test Route
/// but live TUN traffic was not blocked. Xray's `AddRule(shouldAppend=true)`
/// appends injected trial rules at the END of the live rule list, and
/// first-match routing means an unconditional `in-tun` catch-all rule would
/// swallow every TUN connection before the appended trial rule is ever
/// evaluated. The generated TUN routing must contain no such catch-all —
/// unmatched TUN traffic already falls to the default outbound (the first
/// outbound, which is always the active profile), so the catch-all is
/// redundant.
#[test]
fn tun_routing_has_no_unconditional_catch_all_shadowing_trial_rules() {
    let mut settings = base_settings();
    settings.mode = Mode::Tun;
    let generated =
        generate_deterministic(&ServersFile::default(), &settings).expect("generate config");
    let rules = generated["routing"]["rules"].as_array().unwrap();
    assert!(
        !rules.is_empty(),
        "TUN routing must still emit the DNS interception rules"
    );
    for (index, rule) in rules.iter().enumerate() {
        // A catch-all that matches every TUN connection unconditionally: its
        // only fields are inboundTag=[in-tun] and outboundTag (no domain,
        // ip, port, network, … condition that could let the connection fall
        // through to an appended trial rule).
        let is_unconditional_tun_swallow = rule.get("inboundTag")
            == Some(&json!([TUN_INBOUND_TAG]))
            && rule.get("outboundTag").is_some()
            && rule.as_object().is_some_and(|obj| {
                obj.keys()
                    .all(|k| matches!(k.as_str(), "inboundTag" | "outboundTag"))
            });
        assert!(
            !is_unconditional_tun_swallow,
            "rule {index} is an unconditional in-tun catch-all that would shadow injected trial rules: {rule}"
        );
    }
}

#[test]
fn policy_emits_all_nonempty_user_levels_and_stats_flags() {
    let mut settings = base_settings();
    settings.policy.levels.insert(
        "7".into(),
        PolicyLevelCfg {
            handshake: Some(12),
            stats_user_uplink: true,
            stats_user_downlink: true,
            stats_user_online: true,
            ..Default::default()
        },
    );

    let generated =
        generate_deterministic(&ServersFile::default(), &settings).expect("generate config");
    assert_eq!(
        generated["policy"]["levels"]["7"],
        json!({
            "handshake": 12,
            "statsUserUplink": true,
            "statsUserDownlink": true,
            "statsUserOnline": true
        })
    );
}

#[test]
fn dns_and_dokodemo_use_exact_core_wire_types() {
    let mut settings = base_settings();
    settings.dns.serve_expired_ttl = Some(30);
    settings.dns.servers.push(DnsServer {
        address: "1.1.1.1".into(),
        serve_expired_ttl: Some(60),
        timeout_ms: 3000,
        ..Default::default()
    });
    let mut dokodemo = DokodemoCfg {
        tag: "in-doko-test-3".into(),
        enabled: true,
        listen_port: 5353,
        address: "8.8.8.8".into(),
        port: 53,
        ..Default::default()
    };
    dokodemo.port_map.insert("5353".into(), "8.8.4.4:53".into());
    settings.dokodemo.push(dokodemo);

    let generated =
        generate_deterministic(&ServersFile::default(), &settings).expect("generate config");
    assert_eq!(generated["dns"]["serveExpiredTTL"], json!(30));
    // The pushed server lands after the two seeded entries.
    assert_eq!(generated["dns"]["servers"][2]["serveExpiredTTL"], json!(60));
    // A non-default timeout survives the skip threshold and reaches the wire.
    assert_eq!(generated["dns"]["servers"][2]["timeoutMs"], json!(3000));
    assert_eq!(
        generated["dns"]["servers"][0].get("timeoutMs"),
        None,
        "the 8000 default must stay off the wire"
    );
    assert_eq!(
        generated["inbounds"][2]["settings"]["portMap"]["5353"],
        json!("8.8.4.4:53")
    );
}

const GEOIP_URL: &str = "https://github.com/XTLS/Xray-core/releases/download/v26.7.28/geoip.dat";
const GEOSITE_URL: &str =
    "https://github.com/XTLS/Xray-core/releases/download/v26.7.28/geosite.dat";

#[test]
fn dns_interception_wires_dns_outbound_and_socks_udp53_rule() {
    let mut settings = base_settings();
    settings.dns.servers.push(DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    });
    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");

    // DNS outbound appended after the built-ins; default outbound unchanged.
    let out = cfg["outbounds"].as_array().unwrap();
    assert_eq!(out.len(), 3);
    assert_eq!(out[0]["tag"], json!("direct"));
    assert_eq!(out[1]["tag"], json!("block"));
    assert_eq!(
        out[2],
        json!({ "protocol": "dns", "tag": DNS_OUTBOUND_TAG })
    );

    // SOCKS UDP:53 is answered locally by the DNS module.
    assert_eq!(
        cfg["routing"]["rules"],
        json!([
            {
                "inboundTag": ["in-socks"],
                "network": "udp",
                "port": "53",
                "outboundTag": DNS_OUTBOUND_TAG,
            }
        ])
    );
}

#[test]
fn multiple_socks_entries_all_join_the_udp53_interception_rule() {
    // Every ENABLED socks entry contributes its tag to the DNS UDP:53
    // interception rule, in list order; the HTTP entry never appears.
    let mut settings = base_settings();
    settings.local_inbounds.push(LocalInboundCfg {
        tag: "in-socks-1".into(),
        port: 20808,
        ..Default::default()
    });
    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");

    assert_eq!(
        cfg["routing"]["rules"],
        json!([
            {
                "inboundTag": ["in-socks", "in-socks-1"],
                "network": "udp",
                "port": "53",
                "outboundTag": DNS_OUTBOUND_TAG,
            }
        ])
    );
}

#[test]
fn disabled_socks_entries_stay_off_the_wire_and_out_of_interception() {
    let mut settings = base_settings();
    settings.local_inbounds[0].enabled = false; // the seeded in-socks entry
    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");

    let tags: Vec<&str> = cfg["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["tag"].as_str())
        .collect();
    assert_eq!(tags, ["in-http"]);
    // No enabled socks entry and no TUN: no DNS interception rules, and
    // no dns-out outbound to receive them.
    assert_eq!(cfg["routing"]["rules"].as_array().unwrap().len(), 0);
    let out = cfg["outbounds"].as_array().unwrap();
    assert!(out.iter().all(|o| o["tag"] != DNS_OUTBOUND_TAG));
}

#[test]
fn disabled_socks_entries_are_excluded_from_the_udp53_rule() {
    // Disabled socks entries neither emit nor join the interception rule;
    // enabled ones still do.
    let mut settings = base_settings();
    settings.local_inbounds[0].enabled = false;
    settings.local_inbounds.push(LocalInboundCfg {
        tag: "in-socks-2".into(),
        port: 20808,
        ..Default::default()
    });
    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");

    let tags: Vec<&str> = cfg["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["tag"].as_str())
        .collect();
    assert_eq!(tags, ["in-http", "in-socks-2"]);
    assert_eq!(
        cfg["routing"]["rules"][0]["inboundTag"],
        json!(["in-socks-2"])
    );
}

#[test]
fn local_inbounds_emit_in_list_order() {
    let mut settings = base_settings();
    // Move the HTTP entry before the SOCKS entry and add a second HTTP
    // endpoint: the emitted inbounds must follow the list, not the protocol.
    settings.local_inbounds.swap(0, 1);
    settings.local_inbounds.push(LocalInboundCfg {
        protocol: LocalInboundProtocol::Http,
        tag: "in-http-1".into(),
        port: 20809,
        ..Default::default()
    });
    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");

    let tags: Vec<&str> = cfg["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["tag"].as_str())
        .collect();
    assert_eq!(tags, ["in-http", "in-socks", "in-http-1"]);
}

#[test]
fn profile_outbounds_emit_in_list_order() {
    // Three profiles with the first one active, as the server list keeps them
    // (`ServersFile::activate`): the emitted outbounds are the list order,
    // then the built-ins and the DNS outbound.
    let ids = ["0123456789abcdef", "fedcba9876543210", "0011223344556677"];
    let mut servers = ServersFile {
        version: 1,
        active: Some(ids[0].into()),
        profiles: ids
            .iter()
            .enumerate()
            .map(|(index, id)| ServerProfile {
                id: (*id).into(),
                name: format!("server-{index}"),
                outbound: OutboundModel::new(Protocol::Freedom),
                latency_ms: None,
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let tags = |servers: &ServersFile| -> Vec<String> {
        let cfg = generate_deterministic(servers, &base_settings()).expect("generate config");
        cfg["outbounds"]
            .as_array()
            .expect("outbounds is an array")
            .iter()
            .filter_map(|outbound| outbound["tag"].as_str().map(str::to_owned))
            .collect()
    };
    assert_eq!(
        tags(&servers),
        [
            "srv-01234567",
            "srv-fedcba98",
            "srv-00112233",
            "direct",
            "block",
            DNS_OUTBOUND_TAG
        ],
        "profile outbounds follow the list order"
    );

    // Dragging the last row to the top activates it (`ServersFile::activate`),
    // and Xray's default route is the first outbound: the dragged server must
    // take that slot on the wire, not stay behind a pinned active profile.
    servers.activate("0011223344556677");
    assert_eq!(
        tags(&servers),
        [
            "srv-00112233",
            "srv-01234567",
            "srv-fedcba98",
            "direct",
            "block",
            DNS_OUTBOUND_TAG
        ],
        "the default server is whichever profile the list leads with"
    );
}

#[test]
fn duplicate_local_inbound_tag_is_rejected() {
    // Two enabled entries sharing a tag, and an entry reusing the reserved
    // API tag, are both invalid models.
    let mut settings = base_settings();
    settings.local_inbounds.push(LocalInboundCfg {
        tag: "in-socks".into(), // collides with the seeded entry
        port: 20808,
        ..Default::default()
    });
    let error = generate_deterministic(&ServersFile::default(), &settings)
        .expect_err("duplicate local inbound tags must fail")
        .to_string();
    assert!(
        error.contains("inbound tag \"in-socks\" is duplicated"),
        "{error}"
    );

    let mut settings = base_settings();
    settings.local_inbounds.push(LocalInboundCfg {
        tag: "api".into(),
        port: 20808,
        ..Default::default()
    });
    let error = generate_deterministic(&ServersFile::default(), &settings)
        .expect_err("a local inbound reusing the API tag must fail")
        .to_string();
    assert!(
        error.contains("inbound tag \"api\" is duplicated"),
        "{error}"
    );
}

#[test]
fn password_mode_http_without_accounts_blocks_generation_at_any_bind() {
    // The trap is about the ticked intent, not the listener: Require auth
    // on an HTTP inbound with zero accounts authenticates nobody on the
    // wire (the projection drops the empty account list), loopback
    // included. The message is the shared const the row editor renders.
    for listen in ["127.0.0.1", "0.0.0.0", "::1", "192.168.1.5"] {
        let mut settings = base_settings();
        settings.local_inbounds[1] = LocalInboundCfg {
            protocol: LocalInboundProtocol::Http,
            tag: "in-http".into(),
            enabled: true,
            listen: listen.into(),
            auth: "password".into(),
            ..Default::default()
        };
        let message = match generate_deterministic(&ServersFile::default(), &settings) {
            Err(error @ GenerateError::InvalidFinding(_)) => error.text(Language::En),
            Err(error) => panic!("expected InvalidModel, got {error}"),
            Ok(_) => panic!("password-mode HTTP with zero accounts must not generate"),
        };
        assert_eq!(
            message,
            validation_message(
                &ValidationCode::LocalInboundAuthRequiresAccounts,
                Language::En
            ),
            "bind {listen}"
        );
    }
}

#[test]
fn disabled_password_mode_http_without_accounts_does_not_block_generation() {
    // Disabled entries never reach the wire, so the gate — like the row
    // error — only guards enabled ones.
    let mut settings = base_settings();
    settings.local_inbounds[1].enabled = false;
    settings.local_inbounds[1].auth = "password".into();
    generate_deterministic(&ServersFile::default(), &settings)
        .expect("a disabled password-mode HTTP row without accounts must not block");
}

#[test]
fn password_mode_http_with_accounts_and_password_mode_socks_apply_unchanged() {
    // Password-mode HTTP with ≥1 account (wildcard bind included) emits its
    // accounts; SOCKS password mode with an empty list (deny-all on the
    // wire — a separate non-security behavior) keeps applying as before.
    // Noauth HTTP needs no guard here: the default-seed and golden suites
    // already generate it unchanged at both binds.
    let mut settings = base_settings();
    settings.local_inbounds[0].auth = "password".into();
    settings.local_inbounds[1] = LocalInboundCfg {
        protocol: LocalInboundProtocol::Http,
        tag: "in-http".into(),
        enabled: true,
        listen: "0.0.0.0".into(),
        port: 10809,
        auth: "password".into(),
        accounts: vec![Account {
            user: "u".into(),
            pass: "p".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let cfg = generate_deterministic(&ServersFile::default(), &settings)
        .expect("HTTP password mode with accounts and SOCKS password mode must apply");
    let inbounds = cfg["inbounds"].as_array().unwrap();
    assert_eq!(inbounds[0]["tag"], "in-socks");
    assert_eq!(inbounds[0]["settings"]["auth"], "password");
    assert!(inbounds[0]["settings"].get("accounts").is_none());
    assert_eq!(inbounds[1]["tag"], "in-http");
    assert_eq!(inbounds[1]["settings"]["accounts"][0]["user"], "u");
    assert_eq!(inbounds[1]["settings"]["accounts"][0]["pass"], "p");
}

#[test]
fn raw_override_bypasses_the_auth_trap() {
    // The whole-config raw override is the documented
    // user-takes-full-responsibility escape — it is parsed and returned
    // verbatim before validate_settings, so even the trap state cannot gate it.
    let mut settings = base_settings();
    settings.local_inbounds[1].auth = "password".into();
    settings.raw_override = Some(r#"{"custom": true, "outbounds": []}"#.into());
    let cfg = generate_deterministic(&ServersFile::default(), &settings)
        .expect("raw override must bypass the model gate");
    assert_eq!(cfg, json!({"custom": true, "outbounds": []}));
}

#[test]
fn port_collision_between_two_local_entries_is_rejected() {
    let mut settings = base_settings();
    settings.local_inbounds.push(LocalInboundCfg {
        tag: "in-socks-1".into(),
        port: settings.local_inbounds[0].port, // same as the seeded in-socks
        ..Default::default()
    });
    let error = generate_deterministic(&ServersFile::default(), &settings)
        .expect_err("two local entries on one listen:port must fail")
        .to_string();
    assert!(error.contains("conflicts with local inbound"), "{error}");
    assert!(error.contains("in-socks"), "{error}");
}

#[test]
fn tun_adapter_dns_is_pinned_to_the_in_tun_gateway() {
    let mut settings = base_settings();
    settings.mode = Mode::Tun;
    settings.tun.dns.clear(); // no adapter DNS configured (stale-resolver state)
    settings.dns.servers.push(DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    });
    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");

    // The adapter DNS is contract-pinned to the in-tun listener address: the
    // WFP shield permits port-53 only through the TUN interface, so dnscache
    // queries must route into the tunnel via the gateway address. The
    // listener itself is added to the running core by the runtime
    // (src/rt/dns_in.rs), which derives its bind address from this pin — so
    // no inbound carries the listener's tag in the emitted config.
    let tun = cfg["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|ib| ib["protocol"] == "tun")
        .expect("tun inbound");
    assert_eq!(tun["settings"]["dns"], json!(["10.255.0.1"]));
    assert!(
        cfg["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|ib| ib["tag"] != DNS_INBOUND_TAG),
        "the in-tun DNS listener must not be emitted into the static config"
    );

    // Interception rules; DoH (TCP:443) never matches them and falls to
    // Xray's default outbound (the first outbound = the active profile). No
    // trailing TUN catch-all — one would swallow injected trial rules before
    // they are evaluated.
    assert_eq!(
        cfg["routing"]["rules"],
        json!([
            {
                "inboundTag": [DNS_INBOUND_TAG],
                "network": "udp,tcp",
                "port": "53",
                "outboundTag": DNS_OUTBOUND_TAG,
            },
            {
                "inboundTag": [TUN_INBOUND_TAG],
                "network": "udp",
                "port": "53",
                "outboundTag": DNS_OUTBOUND_TAG,
            },
            {
                "inboundTag": ["in-socks"],
                "network": "udp",
                "port": "53",
                "outboundTag": DNS_OUTBOUND_TAG,
            }
        ])
    );
    let out = cfg["outbounds"].as_array().unwrap();
    assert_eq!(
        out.last(),
        Some(&json!({ "protocol": "dns", "tag": DNS_OUTBOUND_TAG }))
    );
}

fn vless_server(host: &str, port: u16) -> OutboundModel {
    let mut ob = OutboundModel::new(Protocol::Vless);
    ob.settings = ProtocolSettings::Vless(VlessSettings {
        address: host.into(),
        port,
        id: "11111111-2222-3333-4444-555555555555".into(),
        // Canonical 4-part PQ form: Xray's conf parser requires at least
        // four dot-separated parts (encryption rule).
        encryption: "mlkem768x25519plus.native.1rtt.key".into(),
        ..Default::default()
    });
    ob
}

#[test]
fn tun_without_dns_module_keeps_plaintext_adapter_dns() {
    // No DNS module, TUN on: pinning the adapter to the gateway address
    // would point it at a listener the runtime never adds (the add is gated
    // on the module), so every tunnel DNS query would die. Fall back to the
    // stored list / plaintext resolvers — leaky but functional, and what the
    // TUN screen banner describes. The seeded DNS module is cleared here to
    // recreate the no-module state.
    let mut settings = base_settings();
    settings.mode = Mode::Tun;
    settings.tun.dns.clear();
    settings.dns.servers.clear();
    settings.dns.enable_parallel_query = false;
    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");

    let tun = cfg["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|ib| ib["protocol"] == "tun")
        .expect("tun inbound");
    assert_eq!(tun["settings"]["dns"], json!(["1.1.1.1", "8.8.8.8"]));
    assert!(
        cfg.get("dns").is_none(),
        "no module, so neither the dns block nor the in-tun listener exists"
    );
}

#[test]
fn tun_without_dns_module_keeps_stored_adapter_dns() {
    let mut settings = base_settings();
    settings.mode = Mode::Tun;
    settings.tun.dns = vec!["9.9.9.9".into()];
    // No DNS module (user cleared the seeded servers): the stored adapter
    // list is kept instead of the in-tun pin.
    settings.dns.servers.clear();
    settings.dns.enable_parallel_query = false;
    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");

    let tun = cfg["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|ib| ib["protocol"] == "tun")
        .expect("tun inbound");
    assert_eq!(tun["settings"]["dns"], json!(["9.9.9.9"]));
}

#[test]
fn bootstrap_dns_ipv6_endpoint_gets_local_server() {
    // Bracketed IPv6 DoH endpoints must not silently disable the bootstrap
    // (the host gate would reject a "[2606" fragment).
    let mut settings = base_settings();
    settings.dns.servers = vec![DnsServer {
        address: "https://[2606:4700:4700::1111]/dns-query".into(),
        ..Default::default()
    }];
    // Saved settings without a bootstrap default to empty → auto-derive from
    // the first configured server (the seeded default is "localhost").
    settings.dns.bootstrap = String::new();
    let ob = vless_server("srv.example.com", 443);
    let cfg = generate_deterministic(&single_server(ob), &settings).expect("generate config");

    let servers = cfg["dns"]["servers"].as_array().unwrap();
    assert_eq!(
        servers[1],
        json!({
            "address": "https+local://[2606:4700:4700::1111]/dns-query",
            "domains": ["domain:srv.example.com"],
            "skipFallback": true,
        })
    );
    let out = cfg["outbounds"][0].clone();
    assert_eq!(
        out["streamSettings"]["sockopt"]["domainStrategy"],
        json!("useip")
    );
}
#[test]
fn doh_dials_are_pinned_to_active_outbound() {
    // The DNS module's upstream TCP dials must land on the ACTIVE server,
    // not whatever outbound happens to be first after a GUI reorder.
    let mut settings = base_settings();
    settings.dns.servers.push(DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    });
    let ob = vless_server("1.2.3.4", 443);
    let cfg = generate_deterministic(&single_server(ob), &settings).expect("generate config");

    let rules = cfg["routing"]["rules"].as_array().unwrap();
    // The two seeded UDP servers have no pinning rule (UDP is not pinned);
    // only the pushed DoH server pins to the active outbound.
    assert_eq!(
        rules[0],
        json!({
            "ip": ["1.1.1.1"],
            "port": "443",
            "outboundTag": "srv-01234567",
        })
    );
}

#[test]
fn doh_pinning_uses_per_server_ports() {
    let mut settings = base_settings();
    settings.dns.servers.push(DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    });
    settings.dns.servers.push(DnsServer {
        address: "tcp://9.9.9.9".into(),
        port: Some(5353),
        ..Default::default()
    });
    let ob = vless_server("1.2.3.4", 443);
    let cfg = generate_deterministic(&single_server(ob), &settings).expect("generate config");

    let rules = cfg["routing"]["rules"].as_array().unwrap();
    // The two seeded UDP servers have no pinning rule; the pushed entries
    // pin in order with their per-server ports.
    assert_eq!(rules[0]["ip"], json!(["1.1.1.1"]));
    assert_eq!(rules[0]["port"], json!("443"));
    assert_eq!(rules[1]["ip"], json!(["9.9.9.9"]));
    assert_eq!(rules[1]["port"], json!("5353"));
    assert_eq!(rules[1]["outboundTag"], json!("srv-01234567"));
}

#[test]
fn doh_pinning_skipped_without_active_profile() {
    // No active server → no outboundTag to pin to; the interception rules
    // are the only system rules.
    let mut settings = base_settings();
    settings.mode = Mode::Tun;
    settings.dns.servers.push(DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    });
    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");

    let rules = cfg["routing"]["rules"].as_array().unwrap();
    assert!(
        rules.iter().all(|rule| rule["port"] != "443"),
        "no DoH pin without an active profile: {rules:?}"
    );
    assert_eq!(rules[0]["inboundTag"], json!([DNS_INBOUND_TAG]));
}

#[test]
fn doh_pinning_skipped_for_domain_dns_servers() {
    // A domain DNS server cannot be pinned by IP; skip rather than emit a
    // rule that never matches.
    let mut settings = base_settings();
    settings.dns.servers = vec![DnsServer {
        address: "https://dns.example.com/dns-query".into(),
        ..Default::default()
    }];
    let ob = vless_server("1.2.3.4", 443);
    let cfg = generate_deterministic(&single_server(ob), &settings).expect("generate config");

    let rules = cfg["routing"]["rules"].as_array().unwrap();
    assert!(
        rules.iter().all(|rule| rule["port"] != "443"),
        "no DoH pin for a domain DNS server: {rules:?}"
    );
}
#[test]
fn explicit_bootstrap_resolver_overrides_first_server() {
    // The GUI override wins over the auto-derived first server: the user
    // picks a resolver that is actually reachable directly from their
    // network (e.g. AliDNS where Cloudflare DoH is blocked).
    let mut settings = base_settings();
    settings.dns.servers.push(DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    });
    settings.dns.bootstrap = "https://223.5.5.5/dns-query".into();
    let ob = vless_server("srv.example.com", 443);
    let cfg = generate_deterministic(&single_server(ob), &settings).expect("generate config");

    let servers = cfg["dns"]["servers"].as_array().unwrap();
    // The two seeded entries stay first; the GUI override wins over them.
    assert_eq!(servers.len(), 4);
    assert_eq!(servers[0]["address"], json!("1.1.1.1"));
    assert_eq!(servers[1]["address"], json!("8.8.8.8"));
    assert_eq!(servers[2]["address"], json!("https://1.1.1.1/dns-query"));
    assert_eq!(
        servers[3],
        json!({
            "address": "https+local://223.5.5.5/dns-query",
            "domains": ["domain:srv.example.com"],
            "skipFallback": true,
        })
    );
    assert_eq!(
        cfg["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"],
        json!("useip")
    );
}

#[test]
fn explicit_bootstrap_bare_host_uses_tcp_local() {
    let mut settings = base_settings();
    settings.dns.servers.push(DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    });
    settings.dns.bootstrap = "223.5.5.5".into();
    let ob = vless_server("srv.example.com", 443);
    let cfg = generate_deterministic(&single_server(ob), &settings).expect("generate config");

    let servers = cfg["dns"]["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 4);
    assert_eq!(servers[3]["address"], json!("tcp+local://223.5.5.5:53"));
}

#[test]
fn explicit_bootstrap_domain_host_skips_bootstrap() {
    // A domain host would re-enter the DNS module to resolve itself —
    // deadlock — so the bootstrap is skipped entirely (and with it useip).
    let mut settings = base_settings();
    settings.dns.servers.push(DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    });
    settings.dns.bootstrap = "https://dns.alidns.com/dns-query".into();
    let ob = vless_server("srv.example.com", 443);
    let cfg = generate_deterministic(&single_server(ob), &settings).expect("generate config");

    let servers = cfg["dns"]["servers"].as_array().unwrap();
    assert_eq!(
        servers.len(),
        3,
        "no bootstrap entry may be appended: {servers:?}"
    );
    assert!(
        servers
            .iter()
            .all(|server| server.get("skipFallback").is_none()),
        "a domain-host bootstrap must be skipped entirely: {servers:?}"
    );
    assert_eq!(
        cfg["outbounds"][0].get("streamSettings"),
        None,
        "no useip without a bootstrap server"
    );
}

#[test]
fn explicit_bootstrap_requires_dns_module() {
    // Without a DNS module there is no dns object for the scoped server to
    // land in — and no module for useip dials to query.
    let mut settings = base_settings();
    // No DNS module (user cleared the seeded servers).
    settings.dns.servers.clear();
    settings.dns.enable_parallel_query = false;
    settings.dns.bootstrap = "https://223.5.5.5/dns-query".into();
    let ob = vless_server("srv.example.com", 443);
    let cfg = generate_deterministic(&single_server(ob), &settings).expect("generate config");

    assert_eq!(cfg.get("dns"), None, "no dns object without a module");
    assert_eq!(
        cfg["outbounds"][0].get("streamSettings"),
        None,
        "no useip without a bootstrap server"
    );
}

#[test]
fn domain_addressed_outbound_gets_bootstrap_dns_and_useip() {
    let mut settings = base_settings();
    settings.dns.servers = vec![DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    }];
    // Empty bootstrap → auto-derive from the first server (the seeded
    // default "localhost" would skip the +local rewrite under test).
    settings.dns.bootstrap = String::new();
    let cfg = generate_deterministic(
        &single_server(vless_server("srv.example.com", 443)),
        &settings,
    )
    .expect("generate config");

    // A scoped +local server answers only the proxy-server domain, dialed
    // directly (no routing) so the tunnel chain can resolve its own server.
    assert_eq!(
        cfg["dns"]["servers"],
        json!([
            { "address": "https://1.1.1.1/dns-query" },
            {
                "address": "https+local://1.1.1.1/dns-query",
                "domains": ["domain:srv.example.com"],
                "skipFallback": true
            }
        ])
    );
    // The server dial resolves through the DNS module, never the OS resolver.
    assert_eq!(
        cfg["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"],
        json!("useip")
    );
}

#[test]
fn bootstrap_dns_localhost_default_resolves_proxy_domains_via_os() {
    // DnsCfg::default() bootstraps proxy-server domains through the
    // OS resolver. The scoped entry is the bare "localhost" address — emitted
    // verbatim (no scheme rewrite, no IP-literal gate) — and stays OUT of the
    // general query path: its domains scope plus skipFallback exclude it from
    // Xray's sortClients fallback and parallel fan-out, so only 1.1.1.1 ever
    // answers system queries.
    let cfg = generate_deterministic(
        &single_server(vless_server("srv.example.com", 443)),
        &base_settings(),
    )
    .expect("generate config");

    let servers = cfg["dns"]["servers"].as_array().unwrap();
    assert_eq!(
        cfg["dns"]["servers"],
        json!([
            { "address": "1.1.1.1" },
            { "address": "8.8.8.8" },
            {
                "address": "localhost",
                "domains": ["domain:srv.example.com"],
                "skipFallback": true
            }
        ])
    );
    assert_eq!(cfg["dns"]["enableParallelQuery"], json!(true));
    // No auto-derived tcp+local bootstrap: the default is localhost, so the
    // first-server derivation is not taken (the 8.8.8.8 DoH server is a
    // general server, not a scoped bootstrap entry).
    assert!(
        servers
            .iter()
            .filter(|server| server.get("domains").is_some())
            .all(|server| !server["address"].as_str().unwrap_or("").contains("://")),
        "no scheme-derived bootstrap may appear: {servers:?}"
    );
    // Scoped: the localhost entry answers only the proxy-server domain and is
    // excluded from fallback — never the general query path.
    assert_eq!(servers[2]["domains"], json!(["domain:srv.example.com"]));
    assert_eq!(servers[2]["skipFallback"], json!(true));
    assert!(
        servers
            .iter()
            .skip(2)
            .all(|server| server.get("domains").is_some()),
        "every entry after the general servers must carry a domains scope"
    );
    // The server dial resolves through the module (useip), via the scoped
    // OS-resolver entry.
    assert_eq!(
        cfg["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"],
        json!("useip")
    );
}

#[test]
fn bootstrap_dns_skipped_when_dns_server_host_is_a_domain() {
    let mut settings = base_settings();
    settings.dns.servers = vec![DnsServer {
        address: "https://dns.example.com/dns-query".into(),
        ..Default::default()
    }];
    // Empty bootstrap → auto-derive from the first server; its domain host
    // cannot bootstrap itself (the seeded default "localhost" is the OS
    // resolver and would not deadlock, so this test must opt out of it).
    settings.dns.bootstrap = String::new();
    let cfg = generate_deterministic(
        &single_server(vless_server("srv.example.com", 443)),
        &settings,
    )
    .expect("generate config");

    // A domain-hosted DNS server cannot bootstrap itself: no scoped server
    // and no useip injection (injecting would deadlock the server dial).
    assert_eq!(cfg["dns"]["servers"].as_array().unwrap().len(), 1);
    assert!(cfg["outbounds"][0].get("streamSettings").is_none());
}

#[test]
fn bootstrap_dns_skipped_without_dns_module_or_for_ip_servers() {
    // No DNS module → nothing injected, dial stays on the OS resolver.
    let mut no_module = base_settings();
    no_module.dns.servers.clear();
    no_module.dns.enable_parallel_query = false;
    let cfg = generate_deterministic(
        &single_server(vless_server("srv.example.com", 443)),
        &no_module,
    )
    .expect("generate config");
    assert!(cfg.get("dns").is_none());
    assert!(cfg["outbounds"][0].get("streamSettings").is_none());

    // IP-addressed proxy servers need no bootstrap and get no injection.
    let mut settings = base_settings();
    settings.dns.servers = vec![DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    }];
    let cfg = generate_deterministic(&single_server(vless_server("1.2.3.4", 443)), &settings)
        .expect("generate config");
    assert_eq!(cfg["dns"]["servers"].as_array().unwrap().len(), 1);
    assert!(cfg["outbounds"][0].get("streamSettings").is_none());
}

#[test]
fn bootstrap_dns_bare_server_uses_tcp_local_on_its_port() {
    let mut settings = base_settings();
    settings.dns.servers = vec![DnsServer {
        address: "8.8.8.8".into(),
        port: Some(5353),
        ..Default::default()
    }];
    // Empty bootstrap → auto-derive from the first server (the seeded
    // default "localhost" would skip the tcp+local rewrite under test).
    settings.dns.bootstrap = String::new();
    let cfg = generate_deterministic(
        &single_server(vless_server("srv.example.com", 443)),
        &settings,
    )
    .expect("generate config");

    assert_eq!(
        cfg["dns"]["servers"][1],
        json!({
            "address": "tcp+local://8.8.8.8:5353",
            "domains": ["domain:srv.example.com"],
            "skipFallback": true
        })
    );
}

#[test]
fn explicit_user_domain_strategy_is_not_overridden() {
    let mut ob = vless_server("srv.example.com", 443);
    ob.stream.sockopt = Some(SockoptModel {
        domain_strategy: "forceip".into(),
        ..Default::default()
    });
    let mut settings = base_settings();
    settings.dns.servers.push(DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    });
    let cfg = generate_deterministic(&single_server(ob), &settings).expect("generate config");

    assert_eq!(
        cfg["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"],
        json!("forceip")
    );
}

#[test]
fn wireguard_domain_endpoint_joins_bootstrap_without_sockopt() {
    // WG peer endpoints resolve through the DNS module via
    // settings.domainStrategy, not sockopt (XTLS/Xray-core#5363) — the
    // endpoint domain still joins the bootstrap scope, but no sockopt is
    // injected into its wire form.
    let mut ob = OutboundModel::new(Protocol::Wireguard);
    ob.settings = ProtocolSettings::Wireguard(WireguardSettings {
        peers: vec![WireguardPeer {
            public_key: "A".repeat(44),
            endpoint: "wg.example.com:51820".into(),
            ..Default::default()
        }],
        ..Default::default()
    });
    let mut settings = base_settings();
    settings.dns.servers = vec![DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    }];
    // Empty bootstrap → auto-derive from the first server (the seeded
    // default "localhost" would skip the +local rewrite under test).
    settings.dns.bootstrap = String::new();
    let cfg = generate_deterministic(&single_server(ob), &settings).expect("generate config");

    assert_eq!(
        cfg["dns"]["servers"][1]["domains"],
        json!(["domain:wg.example.com"])
    );
    assert!(cfg["outbounds"][0].get("streamSettings").is_none());
}

#[test]
fn chained_outbound_defers_the_bootstrap_scope_to_its_direct_dial_outbound() {
    // A profile that dials through another never dials its own server from
    // this machine — the hop's address travels through the chain and resolves
    // on the far side — so only the chain's direct-dial outbound joins the
    // bootstrap scope and takes useip. The hop's `dialerProxy` is resolved
    // locally before the redirect, so an injection there would resolve the
    // hop's server on this machine.
    let exit = ServerProfile {
        id: "fedcba9876543210".into(),
        ..ServerProfile::new("exit", vless_server("exit.example.com", 443))
    };
    let exit_tag = exit.tag();
    let mut hop_outbound = vless_server("hop.example.com", 443);
    hop_outbound.chain_via(&exit_tag);
    let hop = ServerProfile {
        id: ID.into(),
        ..ServerProfile::new("hop", hop_outbound)
    };
    let servers = ServersFile {
        version: 1,
        active: Some(hop.id.clone()),
        profiles: vec![hop, exit],
        extra: Map::new(),
    };

    let cfg = generate_deterministic(&servers, &base_settings()).expect("generate config");

    assert_eq!(
        cfg["dns"]["servers"],
        json!([
            { "address": "1.1.1.1" },
            { "address": "8.8.8.8" },
            {
                "address": "localhost",
                "domains": ["domain:exit.example.com"],
                "skipFallback": true
            }
        ]),
        "only the direct-dial outbound's domain may be scoped"
    );
    assert_eq!(
        cfg["outbounds"][0]["streamSettings"]["sockopt"],
        json!({ "dialerProxy": exit_tag }),
        "a chained outbound carries the chain and nothing else: {}",
        cfg["outbounds"][0]
    );
    assert_eq!(
        cfg["outbounds"][1]["streamSettings"]["sockopt"]["domainStrategy"],
        json!("useip"),
        "the direct-dial outbound still resolves through the module"
    );
}

#[test]
fn bootstrap_scope_follows_a_transitive_chain_to_its_far_end() {
    // hop -> mid -> exit: only exit's server is dialed from this machine;
    // both chained hops reach theirs through it.
    let exit = ServerProfile {
        id: "fedcba9876543210".into(),
        ..ServerProfile::new("exit", vless_server("exit.example.com", 443))
    };
    let exit_tag = exit.tag();
    let mut mid_outbound = vless_server("mid.example.com", 443);
    mid_outbound.chain_via(&exit_tag);
    let mid = ServerProfile {
        id: "1111222233334444".into(),
        ..ServerProfile::new("mid", mid_outbound)
    };
    let mid_tag = mid.tag();
    let mut hop_outbound = vless_server("hop.example.com", 443);
    hop_outbound.chain_via(&mid_tag);
    let hop = ServerProfile {
        id: ID.into(),
        ..ServerProfile::new("hop", hop_outbound)
    };
    let servers = ServersFile {
        version: 1,
        active: Some(hop.id.clone()),
        profiles: vec![hop, mid, exit],
        extra: Map::new(),
    };

    let cfg = generate_deterministic(&servers, &base_settings()).expect("generate config");

    assert_eq!(cfg["dns"]["servers"].as_array().unwrap().len(), 3);
    assert_eq!(
        cfg["dns"]["servers"][2]["domains"],
        json!(["domain:exit.example.com"])
    );
    assert_eq!(
        cfg["outbounds"][0]["streamSettings"]["sockopt"],
        json!({ "dialerProxy": mid_tag })
    );
    assert_eq!(
        cfg["outbounds"][1]["streamSettings"]["sockopt"],
        json!({ "dialerProxy": exit_tag })
    );
    assert_eq!(
        cfg["outbounds"][2]["streamSettings"]["sockopt"]["domainStrategy"],
        json!("useip")
    );
}

#[test]
fn standalone_profiles_keep_the_bootstrap_scope_when_not_active() {
    // Every profile whose dial is not proxied through another keeps the
    // marking: trial rules, balancers and the observatory can dial any
    // profile tag at runtime, so such a dial must still resolve through the
    // bootstrap resolver.
    let active = ServerProfile {
        id: ID.into(),
        ..ServerProfile::new("active", vless_server("active.example.com", 443))
    };
    let standby = ServerProfile {
        id: "fedcba9876543210".into(),
        ..ServerProfile::new("standby", vless_server("standby.example.com", 443))
    };
    let servers = ServersFile {
        version: 1,
        active: Some(active.id.clone()),
        profiles: vec![active, standby],
        extra: Map::new(),
    };

    let cfg = generate_deterministic(&servers, &base_settings()).expect("generate config");

    assert_eq!(
        cfg["dns"]["servers"][2]["domains"],
        json!(["domain:active.example.com", "domain:standby.example.com"])
    );
    for index in 0..2 {
        assert_eq!(
            cfg["outbounds"][index]["streamSettings"]["sockopt"]["domainStrategy"],
            json!("useip"),
            "profile outbound {index} must take useip"
        );
    }
}

#[test]
fn chain_to_an_ip_literal_outbound_closes_the_bootstrap_gate() {
    // The only domain-addressed profile is a chained hop and the direct-dial
    // outbound is an IP literal: nothing gets scoped and no outbound takes
    // useip.
    let exit = ServerProfile {
        id: "fedcba9876543210".into(),
        ..ServerProfile::new("exit", vless_server("1.2.3.4", 443))
    };
    let mut hop_outbound = vless_server("hop.example.com", 443);
    hop_outbound.chain_via(exit.tag());
    let hop = ServerProfile {
        id: ID.into(),
        ..ServerProfile::new("hop", hop_outbound)
    };
    let servers = ServersFile {
        version: 1,
        active: Some(hop.id.clone()),
        profiles: vec![hop, exit],
        extra: Map::new(),
    };

    let cfg = generate_deterministic(&servers, &base_settings()).expect("generate config");

    assert_eq!(
        cfg["dns"]["servers"],
        json!([{ "address": "1.1.1.1" }, { "address": "8.8.8.8" }]),
        "no scoped entry without a domain-addressed direct-dial outbound"
    );
    for index in 0..2 {
        assert_eq!(
            cfg["outbounds"][index]["streamSettings"]["sockopt"].get("domainStrategy"),
            None,
            "outbound {index} must not take useip"
        );
    }
}

#[test]
fn chain_to_a_builtin_outbound_keeps_the_direct_dial_scope() {
    // A chain reference naming a builtin (`direct`) has no profile server to
    // reach: the walk ends at this outbound, whose server the OS dials.
    let mut outbound = vless_server("hop.example.com", 443);
    outbound.chain_via("direct");
    let servers = single_server(outbound);

    let cfg = generate_deterministic(&servers, &base_settings()).expect("generate config");

    assert_eq!(
        cfg["dns"]["servers"][2]["domains"],
        json!(["domain:hop.example.com"])
    );
    assert_eq!(
        cfg["outbounds"][0]["streamSettings"]["sockopt"]["domainStrategy"],
        json!("useip")
    );
}

#[test]
fn a_chain_profile_emits_the_dialer_proxy_spelling_only() {
    // The one chain spelling the pinned core reads: `outbound
    // "proxySettings"` is refused at build (infra/conf/xray.go:262). The
    // chain rides `streamSettings.sockopt.dialerProxy` in the runtime
    // config, and the retired key appears nowhere in the document.
    let exit = ServerProfile {
        id: "fedcba9876543210".into(),
        ..ServerProfile::new("exit", vless_server("exit.example.com", 443))
    };
    let exit_tag = exit.tag();
    let mut hop_outbound = vless_server("hop.example.com", 443);
    hop_outbound.chain_via(&exit_tag);
    let hop = ServerProfile {
        id: ID.into(),
        ..ServerProfile::new("hop", hop_outbound)
    };
    let servers = ServersFile {
        version: 1,
        active: Some(hop.id.clone()),
        profiles: vec![hop, exit],
        extra: Map::new(),
    };

    let cfg = generate_deterministic(&servers, &base_settings()).expect("generate config");
    assert_eq!(
        cfg["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"],
        json!(exit_tag)
    );
    assert!(
        !cfg.to_string().contains("proxySettings"),
        "the retired spelling must not appear anywhere: {cfg}"
    );

    // The isolated latency-probe child carries the same chain.
    let probe =
        generate_latency_probe(&servers.profiles, "", 45678, None).expect("generate probe config");
    assert_eq!(
        probe["outbounds"][0]["streamSettings"]["sockopt"]["dialerProxy"],
        json!(exit_tag)
    );
    assert!(!probe.to_string().contains("proxySettings"));

    // A profile that still carries the retired key gates generation outright:
    // the core never sees the key, and the message names the replacement.
    let mut marked = servers.clone();
    marked.profiles[0].outbound.retired_proxy_settings = Some(json!({"tag": "srv-exit"}));
    let error = generate_deterministic(&marked, &base_settings())
        .expect_err("an unresolved retired key must gate generation");
    let message = error.text(Language::En);
    assert!(
        message.contains("proxySettings") && message.contains("streamSettings.sockopt.dialerProxy"),
        "{message}"
    );
}

#[test]
fn tun_stored_adapter_dns_is_ignored_for_in_tun_listener() {
    let mut settings = base_settings();
    settings.mode = Mode::Tun;
    settings.tun.dns = vec!["9.9.9.9".into()]; // stored value is not user-controllable
    settings.dns.servers.push(DnsServer {
        address: "https://1.1.1.1/dns-query".into(),
        ..Default::default()
    });
    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");

    let tun = cfg["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|ib| ib["protocol"] == "tun")
        .expect("tun inbound");
    assert_eq!(tun["settings"]["dns"], json!(["10.255.0.1"]));
}

#[test]
fn geodata_geoip_url_emits_default_cron_and_single_asset() {
    let mut settings = base_settings();
    settings.geodata.geoip_url = Some(GEOIP_URL.into());

    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");
    assert_eq!(
        cfg["geodata"],
        json!({
            "cron": crate::model::settings::DEFAULT_GEODATA_CRON,
            "assets": [{ "url": GEOIP_URL, "file": "geoip.dat" }]
        })
    );
}

#[test]
fn geodata_both_urls_emit_geoip_first_then_geosite() {
    let mut settings = base_settings();
    settings.geodata.geoip_url = Some(GEOIP_URL.into());
    settings.geodata.geosite_url = Some(GEOSITE_URL.into());
    settings.geodata.cron = Some("17 3 * * 1".into());

    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");
    assert_eq!(cfg["geodata"]["cron"], json!("17 3 * * 1"));
    assert_eq!(
        cfg["geodata"]["assets"],
        json!([
            { "url": GEOIP_URL, "file": "geoip.dat" },
            { "url": GEOSITE_URL, "file": "geosite.dat" }
        ])
    );
}

#[test]
fn geodata_empty_cron_falls_back_to_default() {
    let mut settings = base_settings();
    settings.geodata.geoip_url = Some(GEOIP_URL.into());
    settings.geodata.cron = Some(String::new());

    let cfg = generate_deterministic(&ServersFile::default(), &settings).expect("generate config");
    assert_eq!(
        cfg["geodata"]["cron"],
        json!(crate::model::settings::DEFAULT_GEODATA_CRON)
    );
}

#[test]
fn geodata_http_url_is_rejected() {
    let mut settings = base_settings();
    settings.geodata.geoip_url = Some("http://example.com/geoip.dat".into());

    let error = generate_deterministic(&ServersFile::default(), &settings)
        .expect_err("non-HTTPS geodata URL must be rejected")
        .to_string();
    assert!(error.contains("https"), "{error}");
    assert!(error.contains("geodata"), "{error}");
}

#[test]
fn geodata_malformed_cron_is_rejected() {
    let mut settings = base_settings();
    settings.geodata.geoip_url = Some(GEOIP_URL.into());
    settings.geodata.cron = Some("0 4 *".into());

    let error = generate_deterministic(&ServersFile::default(), &settings)
        .expect_err("3-field geodata cron must be rejected")
        .to_string();
    assert!(error.contains("5 fields"), "{error}");
}

#[test]
fn golden_geodata() {
    let mut settings = base_settings();
    settings.geodata.geoip_url = Some(GEOIP_URL.into());
    settings.geodata.geosite_url = Some(GEOSITE_URL.into());
    golden!(
        "goldens/geodata.json",
        generate_deterministic(&ServersFile::default(), &settings)
    );
}

#[test]
fn golden_geodata_cron() {
    let mut settings = base_settings();
    settings.geodata.geoip_url = Some(GEOIP_URL.into());
    settings.geodata.geosite_url = Some(GEOSITE_URL.into());
    settings.geodata.cron = Some("17 3 * * 1".into());
    golden!(
        "goldens/geodata_cron.json",
        generate_deterministic(&ServersFile::default(), &settings)
    );
}

// ---------- per-type wire projections ----------

#[test]
fn socks_projection_omits_enabled_and_places_udp_relay_ip() {
    let cfg = LocalInboundCfg {
        tag: "in-socks".into(),
        ip: "10.0.0.2".into(),
        user_level: 1,
        ..Default::default()
    };
    let wire = cfg.to_wire(false);
    assert!(wire.get("enabled").is_none());
    assert_eq!(wire["tag"], "in-socks");
    assert_eq!(wire["protocol"], "socks");
    assert_eq!(wire["settings"]["auth"], "noauth");
    assert_eq!(wire["settings"]["udp"], true);
    assert_eq!(wire["settings"]["ip"], "10.0.0.2");
    assert_eq!(wire["settings"]["userLevel"], 1);
}

#[test]
fn socks_projection_emits_accounts_only_under_password_auth() {
    let account = Account {
        user: "u".into(),
        pass: "p".into(),
        ..Default::default()
    };
    let noauth = LocalInboundCfg {
        tag: "in-socks".into(),
        accounts: vec![account.clone()],
        ..Default::default()
    };
    let wire = noauth.to_wire(false);
    assert!(wire["settings"].get("accounts").is_none());

    let password = LocalInboundCfg {
        tag: "in-socks".into(),
        auth: "password".into(),
        accounts: vec![account],
        ..Default::default()
    };
    let wire = password.to_wire(false);
    assert_eq!(wire["settings"]["accounts"][0]["user"], "u");
    assert_eq!(wire["settings"]["accounts"][0]["pass"], "p");
}

#[test]
fn http_projection_omits_enabled_and_emits_transparent_and_accounts() {
    let cfg = LocalInboundCfg {
        protocol: LocalInboundProtocol::Http,
        tag: "in-http".into(),
        allow_transparent: true,
        user_level: 2,
        auth: "password".into(),
        accounts: vec![Account {
            user: "u".into(),
            pass: "p".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let wire = cfg.to_wire(false);
    assert!(wire.get("enabled").is_none());
    assert_eq!(wire["tag"], "in-http");
    assert_eq!(wire["protocol"], "http");
    assert_eq!(wire["settings"]["allowTransparent"], true);
    assert_eq!(wire["settings"]["userLevel"], 2);
    assert_eq!(wire["settings"]["accounts"][0]["user"], "u");
    assert_eq!(wire["settings"]["accounts"][0]["pass"], "p");
}

#[test]
fn dokodemo_projection_unix_envelope_has_no_port() {
    let cfg = DokodemoCfg {
        enabled: true,
        network: "unix".into(),
        unix_socket_path: r"C:\broccoli\sockets\dns.sock".into(),
        address: "8.8.8.8".into(),
        port: 53,
        ..Default::default()
    };
    let wire = cfg.to_wire("in-doko-test", false);
    assert!(wire.get("enabled").is_none());
    assert_eq!(wire["tag"], "in-doko-test");
    assert_eq!(wire["protocol"], "dokodemo-door");
    assert_eq!(wire["listen"], json!(r"C:\broccoli\sockets\dns.sock"));
    assert!(wire.get("port").is_none());
    assert_eq!(wire["settings"]["network"], "unix");
    assert_eq!(wire["settings"]["address"], "8.8.8.8");
    assert_eq!(wire["settings"]["port"], 53);
}

#[test]
fn dokodemo_projection_ip_modes_emit_listen_port_and_redirect() {
    let cfg = DokodemoCfg {
        enabled: true,
        listen: "0.0.0.0".into(),
        listen_port: 5353,
        address: "8.8.8.8".into(),
        port: 53,
        follow_redirect: true,
        ..Default::default()
    };
    let wire = cfg.to_wire("in-doko-ip", false);
    assert_eq!(wire["listen"], "0.0.0.0");
    assert_eq!(wire["port"], 5353);
    assert_eq!(wire["settings"]["network"], "tcp,udp");
    assert_eq!(wire["settings"]["followRedirect"], true);
}

#[test]
fn tun_projection_settings_strip_enabled_and_sniffing() {
    let cfg = TunCfg::default();
    let wire = cfg.to_wire(false);
    assert!(wire.get("enabled").is_none());
    let settings = wire["settings"].as_object().expect("TUN settings object");
    assert!(settings.get("enabled").is_none());
    assert!(settings.get("sniffing").is_none());
    assert_eq!(wire["settings"]["name"], "broccoli0");
    assert_eq!(wire["tag"], TUN_INBOUND_TAG);
    // sniffing lives in the inbound envelope, not the protocol settings
    assert_eq!(wire["sniffing"]["enabled"], true);
}

#[test]
fn sniffing_projection_appends_fakedns_once() {
    let cfg = Sniffing::default();
    let wire = cfg.to_wire(true).expect("default sniffing is emitted");
    assert_eq!(
        wire["destOverride"],
        json!(["http", "tls", "quic", "fakedns"])
    );
    // dedup: repeated projection does not append a second "fakedns"
    let again = cfg.to_wire(true).expect("still emitted");
    assert_eq!(again, wire);

    let without_trio = cfg.to_wire(false).expect("still emitted");
    assert_eq!(without_trio["destOverride"], json!(["http", "tls", "quic"]));
}

#[test]
fn sniffing_unknown_protocol_blocks_generation_only_for_emitted_rows() {
    let mut ob = OutboundModel::new(Protocol::Vless);
    ob.settings = ProtocolSettings::Vless(VlessSettings {
        address: "vless.example.com".into(),
        port: 443,
        // Canonical UUID user id (UUID-only policy).
        id: "11111111-2222-3333-4444-555555555555".into(),
        encryption: "none".into(),
        ..Default::default()
    });
    let _ = ob.stream.select_security(Security::Tls);
    let servers = single_server(ob);

    // An enabled local endpoint with an out-of-vocab destOverride item is
    // refused — Xray's SniffingConfig.Build rejects the whole config at
    // load, so the gate mirrors it. The message names
    // the inbound.
    let mut settings = base_settings();
    settings.local_inbounds[0]
        .sniffing
        .dest_override
        .push("sniffme".into());
    let error = generate_deterministic(&servers, &settings).unwrap_err();
    let message = match &error {
        GenerateError::InvalidModel(_) | GenerateError::InvalidFinding(_) => {
            error.text(Language::En)
        }
        other => panic!("expected InvalidModel, got {other:?}"),
    };
    assert!(message.contains("sniff"), "names the verdict: {message}");
    assert!(message.contains("local inbound"), "{message}");

    // The generator's own fakedns append is vocabulary-legal and the model
    // never stores it — the default rows keep generating.
    generate_deterministic(&servers, &base_settings()).expect("canonical sniffing generates");

    // Disabled rows are not emitted to the wire, so their state never
    // reaches Xray and never blocks generation (parity with the emission).
    let mut disabled = base_settings();
    disabled.local_inbounds[0].enabled = false;
    disabled.local_inbounds[0]
        .sniffing
        .dest_override
        .push("sniffme".into());
    generate_deterministic(&servers, &disabled).expect("disabled rows are not emitted");

    // Dokodemo rows gate the same way once enabled.
    let mut doko = base_settings();
    doko.dokodemo.push(DokodemoCfg {
        tag: "in-doko-sniff".into(),
        enabled: true,
        listen_port: 23456,
        address: "1.2.3.4".into(),
        port: 80,
        network: "tcp".into(),
        sniffing: Sniffing {
            dest_override: vec!["tcp".into()],
            ..Default::default()
        },
        ..Default::default()
    });
    let error = generate_deterministic(&servers, &doko).unwrap_err();
    match &error {
        GenerateError::InvalidModel(_) | GenerateError::InvalidFinding(_) => {
            let message = error.text(Language::En);
            assert!(message.contains("sniff"), "{message}");
            assert!(message.contains("in-doko-sniff"), "{message}");
        }
        other => panic!("expected InvalidModel, got {other:?}"),
    }
}

#[test]
fn dns_projection_strips_gui_group_and_appends_fakedns_server() {
    let cfg = DnsCfg {
        servers: vec![DnsServer {
            address: "1.1.1.1".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let wire = cfg.to_wire(true).expect("configured dns is emitted");
    assert!(wire.get("fakedns").is_none(), "GUI group must be stripped");
    let servers = wire["servers"].as_array().unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0]["address"], "1.1.1.1");
    assert_eq!(servers[1]["address"], "fakedns");
}

#[test]
fn dns_projection_dedups_an_existing_fakedns_server() {
    let cfg = DnsCfg {
        servers: vec![
            DnsServer {
                address: "fakedns".into(),
                ..Default::default()
            },
            DnsServer {
                address: "1.1.1.1".into(),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let wire = cfg.to_wire(true).expect("configured dns is emitted");
    assert_eq!(wire["servers"].as_array().unwrap().len(), 2);
}

#[test]
fn dns_projection_is_none_when_effectively_empty() {
    // DnsCfg::default() is the SEEDED module (1.1.1.1 + parallel queries)
    // and is therefore non-empty; an explicitly emptied module
    // (all servers cleared, parallel off) still projects to nothing.
    let cfg = DnsCfg {
        servers: vec![],
        enable_parallel_query: false,
        ..Default::default()
    };
    assert!(cfg.to_wire(false).is_none());
    // the appended fakedns server alone makes the object non-empty
    assert!(cfg.to_wire(true).is_some());
}

#[test]
fn fakedns_projection_collapses_one_pool_and_expands_many() {
    let one = FakeDnsCfg {
        enabled: true,
        pools: vec![FakeDnsPool {
            ip_pool: DEFAULT_FAKEDNS_POOL_CIDR.into(),
            pool_size: DEFAULT_FAKEDNS_POOL_SIZE,
            ..Default::default()
        }],
        ..Default::default()
    };
    let wire = one.to_wire().expect("single pool collapses to an object");
    assert!(wire.is_object());
    assert_eq!(wire["ipPool"], DEFAULT_FAKEDNS_POOL_CIDR);
    assert_eq!(wire["poolSize"], DEFAULT_FAKEDNS_POOL_SIZE);

    let many = FakeDnsCfg {
        enabled: true,
        pools: vec![
            FakeDnsPool {
                ip_pool: DEFAULT_FAKEDNS_POOL_CIDR.into(),
                pool_size: DEFAULT_FAKEDNS_POOL_SIZE,
                ..Default::default()
            },
            FakeDnsPool {
                ip_pool: "2001:db8::/32".into(),
                pool_size: 1024,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let wire = many.to_wire().expect("many pools expand to an array");
    assert!(wire.is_array());
    assert_eq!(wire.as_array().unwrap().len(), 2);
}

#[test]
fn fakedns_projection_falls_back_to_default_pool_when_empty() {
    let cfg = FakeDnsCfg {
        enabled: true,
        pools: Vec::new(),
        ..Default::default()
    };
    let wire = cfg.to_wire().expect("empty pools fall back to default");
    assert_eq!(wire["ipPool"], DEFAULT_FAKEDNS_POOL_CIDR);
    assert_eq!(wire["poolSize"], DEFAULT_FAKEDNS_POOL_SIZE);
}

#[test]
fn observatory_projection_strips_enabled_and_forces_subjects() {
    let cfg = ObservatoryCfg {
        enabled: true,
        probe_interval: DurationMs::secs(30),
        ..Default::default()
    };
    let wire = cfg.to_wire(None);
    assert!(wire.get("enabled").is_none());
    assert_eq!(wire["subjectSelector"], json!(["srv-"]));
    assert_eq!(wire["probeInterval"], "30s");

    let forced = vec!["srv-abc".to_string(), "srv-def".to_string()];
    let wire = cfg.to_wire(Some(&forced));
    assert_eq!(wire["subjectSelector"], json!(["srv-abc", "srv-def"]));
}

#[test]
fn burst_observatory_projection_strips_enabled_and_keeps_ping_config() {
    let cfg = BurstObservatoryCfg {
        enabled: true,
        ping_config: PingConfig {
            destination: "https://example.com/generate_204".into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let wire = cfg.to_wire();
    assert!(wire.get("enabled").is_none());
    assert_eq!(wire["subjectSelector"], json!(["srv-"]));
    assert_eq!(
        wire["pingConfig"]["destination"],
        "https://example.com/generate_204"
    );
    assert_eq!(wire["pingConfig"]["httpMethod"], "HEAD");
}
