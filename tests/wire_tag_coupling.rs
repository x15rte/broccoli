//! Wire-name coupling tests: the runtime teardown must remove
//! exactly the tag the generator emits, the WFP DNS shield must trigger on
//! exactly the emitted DNS listener, and every config reader must address the
//! emitted document through the same section and field names. The production
//! sides reference the canonical consts (`src/model/inbound.rs` for the tags,
//! `src/gen/keys.rs` for the schema keys); these tests pin the wire-level
//! agreement against the actual emitted config (and the golden fixtures) so a
//! unilateral literal re-spelling on either side fails.

use broccoli::r#gen::{generate_with_api_port, keys};
use broccoli::model::inbound::{
    API_INBOUND_TAG, BLOCK_OUTBOUND_TAG, DIRECT_OUTBOUND_TAG, DNS_INBOUND_TAG, DNS_OUTBOUND_TAG,
    TUN_INBOUND_TAG,
};
use broccoli::model::{Mode, ServersFile, Settings};
use broccoli::rt::config_needs_dns_shield;
use broccoli::rt::dns_in;
use serde_json::Value;

/// Deterministic emission of the default TUN config, mirroring the in-crate
/// golden harness (`src/gen/tests.rs::generate_deterministic` — fixed API
/// port 10853; production `generate` picks an ephemeral port per launch).
fn emitted_tun_config() -> Value {
    let settings = Settings {
        mode: Mode::Tun,
        ..Default::default()
    };
    generate_with_api_port(&ServersFile::default(), &settings, 10853)
        .expect("default TUN settings must generate")
}

/// The first inbound with the given protocol, or `None`.
fn inbound<'a>(config: &'a Value, protocol: &str) -> Option<&'a Value> {
    config
        .get(keys::INBOUNDS)?
        .as_array()?
        .iter()
        .find(|inbound| {
            inbound
                .get(keys::PROTOCOL)
                .and_then(Value::as_str)
                .is_some_and(|p| p == protocol)
        })
}

/// Tag of the first inbound with the given protocol, or `None`.
fn inbound_tag<'a>(config: &'a Value, protocol: &str) -> Option<&'a str> {
    inbound(config, protocol)?.get(keys::TAG)?.as_str()
}

/// Tag of the first outbound with the given protocol, or `None`.
fn outbound_tag<'a>(config: &'a Value, protocol: &str) -> Option<&'a str> {
    config
        .get(keys::OUTBOUNDS)?
        .as_array()?
        .iter()
        .find_map(|outbound| {
            let tag = outbound.get(keys::TAG)?.as_str()?;
            outbound
                .get(keys::PROTOCOL)
                .and_then(Value::as_str)
                .is_some_and(|p| p == protocol)
                .then_some(tag)
        })
}

/// Tag of the control-plane `api` section, or `None`.
fn api_tag(config: &Value) -> Option<&str> {
    config.get(keys::API)?.get(keys::TAG)?.as_str()
}

/// Clone of `config` with every inbound of the given protocols removed.
fn without_inbounds(config: &Value, drop_protocols: &[&str]) -> Value {
    let mut config = config.clone();
    if let Some(inbounds) = config.get_mut(keys::INBOUNDS).and_then(Value::as_array_mut) {
        inbounds.retain(|inbound| {
            let protocol = inbound
                .get(keys::PROTOCOL)
                .and_then(Value::as_str)
                .unwrap_or("");
            !drop_protocols.contains(&protocol)
        });
    }
    config
}

/// The address the emitted tun inbound pins as the adapter DNS, or `None`.
fn tun_adapter_dns(config: &Value) -> Option<&str> {
    inbound(config, "tun")?
        .get(keys::SETTINGS)?
        .get(keys::DNS)?
        .as_array()?
        .first()?
        .as_str()
}

/// The inbound tag the DNS module's interception rule names, or `None`.
fn dns_in_rule_tag(config: &Value) -> Option<&str> {
    config
        .get(keys::ROUTING)?
        .get("rules")?
        .as_array()?
        .iter()
        .find(|rule| {
            rule.get("outboundTag").and_then(Value::as_str) == Some(DNS_OUTBOUND_TAG)
                && rule.get("inboundTag").is_some()
        })?
        .get("inboundTag")?
        .as_array()?
        .first()?
        .as_str()
}

#[test]
fn emitted_tun_inbound_tag_matches_teardown_const() {
    // Both runtime teardown paths — `Runtime::cleanup_tun` (src/rt/mod.rs)
    // and the elevated helper's `HelperChild::kill` (src/rt/helper.rs) —
    // call `GrpcClient::remove_inbound(TUN_INBOUND_TAG)`. Pinning the
    // generator's emitted wire string to that same const fails if either
    // side re-spells the tag as a literal.
    let config = emitted_tun_config();
    assert_eq!(inbound_tag(&config, "tun"), Some(TUN_INBOUND_TAG));
}

#[test]
fn emitted_dns_listener_and_outbound_tags_match_consts() {
    let config = emitted_tun_config();
    // The runtime adds the in-tun DNS listener to the running core under
    // DNS_INBOUND_TAG (src/rt/dns_in.rs), and derives its bind address from
    // the emitted adapter-DNS pin; the emitted interception rule must name
    // that same tag, or the listener's queries would miss the module. The
    // safety balancer contract (src/model/safety.rs) mirrors the emitted
    // dns-out by DNS_OUTBOUND_TAG.
    assert_eq!(dns_in_rule_tag(&config), Some(DNS_INBOUND_TAG));
    let listener = dns_in::listener_for_config(&config).expect("TUN config needs the listener");
    assert_eq!(
        Some(listener.address.to_string()),
        tun_adapter_dns(&config).map(str::to_string),
        "the listener must bind the address the emitted config pins as the adapter DNS"
    );
    assert_eq!(outbound_tag(&config, "dns"), Some(DNS_OUTBOUND_TAG));
}

#[test]
fn emitted_builtin_and_api_tags_match_consts() {
    let config = emitted_tun_config();
    // The routing editor offers these as rule targets (src/ui/routing.rs),
    // the routing model defaults new rules to the direct tag
    // (src/model/routing.rs), the safety pass counts both built-ins as
    // emitted outbounds (src/model/safety.rs), and inbound validation
    // reserves the api tag (src/model/validation.rs) — all of them must
    // agree with the emitted wire strings.
    assert_eq!(outbound_tag(&config, "freedom"), Some(DIRECT_OUTBOUND_TAG));
    assert_eq!(outbound_tag(&config, "blackhole"), Some(BLOCK_OUTBOUND_TAG));
    assert_eq!(api_tag(&config), Some(API_INBOUND_TAG));
}

#[test]
fn golden_tun_tags_match_runtime_consts() {
    // The in-crate golden test byte-compares this fixture against generator
    // output, so asserting the fixture's tags equal the consts locks the
    // emitted artifact (goldens/ untouched) to the
    // runtime references as well.
    let config: Value = serde_json::from_str(include_str!("../src/gen/goldens/tun.json"))
        .expect("golden tun.json must parse");
    assert_eq!(inbound_tag(&config, "tun"), Some(TUN_INBOUND_TAG));
    assert_eq!(dns_in_rule_tag(&config), Some(DNS_INBOUND_TAG));
    assert_eq!(
        Some("10.255.0.1".to_string()),
        dns_in::listener_for_config(&config).map(|listener| listener.address.to_string()),
        "the golden must hand the runtime the in-tun listener's bind address"
    );
    assert_eq!(outbound_tag(&config, "dns"), Some(DNS_OUTBOUND_TAG));
    assert_eq!(outbound_tag(&config, "freedom"), Some(DIRECT_OUTBOUND_TAG));
    assert_eq!(outbound_tag(&config, "blackhole"), Some(BLOCK_OUTBOUND_TAG));
    assert_eq!(api_tag(&config), Some(API_INBOUND_TAG));
}

#[test]
fn golden_nested_keys_match_schema_consts() {
    // These byte-compared fixtures also carry the nested keys whose emitting
    // side is the model's own serialization rather than a generator `json!`
    // literal: the inbound envelope's `sniffing` block and the chain target's
    // `streamSettings.sockopt.dialerProxy`. Reading them through the schema
    // consts fails if the emitted spelling drifts from the const readers name.
    let tun: Value = serde_json::from_str(include_str!("../src/gen/goldens/tun.json"))
        .expect("golden tun.json must parse");
    let socks = inbound(&tun, "socks").expect("tun.json carries the SOCKS inbound");
    assert!(
        socks.get(keys::SNIFFING).is_some(),
        "the emitted inbound envelope must carry sniffing: {socks}"
    );

    let chain_json = include_str!("../src/gen/goldens/chain_dialer_proxy.json");
    let chain: Value =
        serde_json::from_str(chain_json).expect("golden chain_dialer_proxy.json must parse");
    let outbounds = chain
        .get(keys::OUTBOUNDS)
        .and_then(Value::as_array)
        .expect("chain_dialer_proxy.json carries the outbound list");
    let targets: Vec<&str> = outbounds
        .iter()
        .filter_map(|outbound| {
            outbound
                .get(keys::STREAM_SETTINGS)?
                .get(keys::SOCKOPT)?
                .get(keys::DIALER_PROXY)?
                .as_str()
        })
        .collect();
    assert_eq!(
        targets.len(),
        1,
        "the fixture states exactly one chain target: {outbounds:?}"
    );
    assert!(
        outbounds
            .iter()
            .filter_map(|outbound| outbound.get(keys::TAG).and_then(Value::as_str))
            .any(|tag| tag == targets[0]),
        "the chain target must name an emitted outbound tag: {targets:?}"
    );
}

#[test]
fn wfp_shield_fires_on_exactly_the_emitted_dns_module() {
    // The full emitted TUN config must need the shield: a tun inbound plus
    // the DNS module whose in-tun listener the runtime adds. If the shield
    // matched a drifted marker instead, this positive assertion fails.
    let config = emitted_tun_config();
    assert!(config_needs_dns_shield(&config));

    // Tun alone (module absent) -> no shield: nothing answers the adapter DNS.
    let mut no_module = config.clone();
    no_module
        .as_object_mut()
        .expect("config is an object")
        .remove(keys::DNS);
    assert!(!config_needs_dns_shield(&no_module));

    // Module alone (no tun inbound) -> no shield: no TUN interface to protect.
    let no_tun = without_inbounds(&config, &["tun"]);
    assert!(!config_needs_dns_shield(&no_tun));

    // No inbounds at all -> no shield.
    assert!(!config_needs_dns_shield(
        &serde_json::json!({ keys::INBOUNDS: [] })
    ));
}
