//! Wire-name constants: the canonical tag definitions in the model layer and
//! the generated document's schema keys in the generator both equal the
//! spellings Xray binds in its own `infra/conf` structs (each schema-key const
//! cites its binding). Production uses the constants; the remaining literals
//! of those names live in different namespaces and are deliberate —
//! `Protocol::parse` aliases, the DNS `block` action vocabulary, the settings
//! file's own keys, and the share-link grammar. Reaching the constants from
//! outside the crate pins the reachability promise; the value assertions pin
//! the exact strings so a later migration cannot drift them.

use broccoli::r#gen::keys;
use broccoli::model::inbound::{
    API_INBOUND_TAG, BLOCK_OUTBOUND_TAG, DIRECT_OUTBOUND_TAG, DNS_INBOUND_TAG, DNS_OUTBOUND_TAG,
    TUN_INBOUND_TAG,
};

#[test]
fn wire_tags_equal_historical_literals() {
    assert_eq!(TUN_INBOUND_TAG, "in-tun");
    assert_eq!(DNS_INBOUND_TAG, "dns-in");
    assert_eq!(DNS_OUTBOUND_TAG, "dns-out");
    assert_eq!(DIRECT_OUTBOUND_TAG, "direct");
    assert_eq!(BLOCK_OUTBOUND_TAG, "block");
    assert_eq!(API_INBOUND_TAG, "api");
}

#[test]
fn schema_keys_equal_upstream_literals() {
    // Top-level document sections (infra/conf/xray.go:388-409 `Config`).
    assert_eq!(keys::LOG, "log");
    assert_eq!(keys::STATS, "stats");
    assert_eq!(keys::API, "api");
    assert_eq!(keys::POLICY, "policy");
    assert_eq!(keys::INBOUNDS, "inbounds");
    assert_eq!(keys::OUTBOUNDS, "outbounds");
    assert_eq!(keys::ROUTING, "routing");
    assert_eq!(keys::DNS, "dns");
    assert_eq!(keys::OBSERVATORY, "observatory");
    assert_eq!(keys::BURST_OBSERVATORY, "burstObservatory");
    assert_eq!(keys::FAKE_DNS, "fakeDns");
    assert_eq!(keys::ENV, "env");
    assert_eq!(keys::GEODATA, "geodata");

    // Nested keys a reader addresses the document by: the api section
    // (infra/conf/api.go:16-19), the inbound and outbound detours
    // (infra/conf/xray.go:127-135, 214-222), the TUN settings
    // (infra/conf/tun.go:19), the stream and sockopt blocks
    // (infra/conf/transport_internet.go:62,
    // infra/conf/transport_sockopt.go:50-60), and the geodata assets
    // (infra/conf/geodata.go:13-46).
    assert_eq!(keys::LISTEN, "listen");
    assert_eq!(keys::SERVICES, "services");
    assert_eq!(keys::TAG, "tag");
    assert_eq!(keys::PROTOCOL, "protocol");
    assert_eq!(keys::SETTINGS, "settings");
    assert_eq!(keys::SNIFFING, "sniffing");
    assert_eq!(keys::STREAM_SETTINGS, "streamSettings");
    assert_eq!(keys::SOCKOPT, "sockopt");
    assert_eq!(keys::DIALER_PROXY, "dialerProxy");
    assert_eq!(keys::INTERFACE, "interface");
    assert_eq!(keys::DOMAIN_STRATEGY, "domainStrategy");
    assert_eq!(keys::ASSETS, "assets");
    assert_eq!(keys::URL, "url");
}
