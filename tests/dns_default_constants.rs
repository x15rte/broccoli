//! DNS default constants: the plaintext resolver pair and the
//! default query strategy each have one canonical public definition,
//! consumed by the DNS seed, the TUN adapter default, the generator
//! fallback, the wire-omission predicate, and the UI normalization.
//! Reaching them from outside the crate pins the reachability promise; the
//! value assertions pin the exact strings (the wire_tag_constants
//! precedent) so a later migration cannot drift them.

use broccoli::r#gen::generate_with_api_port;
use broccoli::model::dns::{DEFAULT_PLAINTEXT_RESOLVERS, DEFAULT_QUERY_STRATEGY};
use broccoli::model::{DnsCfg, Mode, ServersFile, Settings, TunCfg};
use serde_json::json;

#[test]
fn constants_equal_historical_literals() {
    assert_eq!(DEFAULT_PLAINTEXT_RESOLVERS, ["1.1.1.1", "8.8.8.8"]);
    assert_eq!(DEFAULT_QUERY_STRATEGY, "useip");
}

#[test]
fn resolver_pair_agrees_across_seed_tun_default_and_generator_fallback() {
    // DNS seed: the seeded server list is exactly the pair, in order.
    let seeded: Vec<String> = DnsCfg::default()
        .servers
        .iter()
        .map(|server| server.address.clone())
        .collect();
    assert_eq!(seeded, DEFAULT_PLAINTEXT_RESOLVERS);

    // TUN adapter default.
    assert_eq!(TunCfg::default().dns, DEFAULT_PLAINTEXT_RESOLVERS);

    // Generator fallback: TUN on, no DNS module, cleared adapter DNS — the
    // wire's tun settings.dns is the plaintext pair.
    let mut settings = Settings {
        mode: Mode::Tun,
        ..Default::default()
    };
    settings.tun.dns.clear();
    settings.dns.servers.clear();
    settings.dns.enable_parallel_query = false;
    let cfg =
        generate_with_api_port(&ServersFile::default(), &settings, 10853).expect("generate config");
    let tun = cfg["inbounds"]
        .as_array()
        .expect("inbounds")
        .iter()
        .find(|inbound| inbound["protocol"] == "tun")
        .expect("tun inbound");
    assert_eq!(tun["settings"]["dns"], json!(DEFAULT_PLAINTEXT_RESOLVERS));
}

#[test]
fn seeded_query_strategy_is_the_canonical_default() {
    assert_eq!(DnsCfg::default().query_strategy, DEFAULT_QUERY_STRATEGY);
}

#[test]
fn default_query_strategy_is_omitted_from_wire_but_others_are_emitted() {
    // The wire-omission predicate and the model default share the const: a
    // config on the default strategy emits no queryStrategy...
    let mut cfg = DnsCfg {
        query_strategy: DEFAULT_QUERY_STRATEGY.into(),
        ..Default::default()
    };
    assert!(
        cfg.to_wire(false)
            .expect("dns wire")
            .get("queryStrategy")
            .is_none()
    );

    // ...and any other strategy is emitted verbatim.
    cfg.query_strategy = "useip4".into();
    assert_eq!(
        cfg.to_wire(false).expect("dns wire")["queryStrategy"],
        json!("useip4")
    );
}
