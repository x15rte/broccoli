//! Wire-tag constants: the canonical tag definitions in the
//! model layer are public and equal the historical literals (`"in-tun"`,
//! `"dns-in"`, `"dns-out"`, `"direct"`, `"block"`, `"api"`). Production
//! uses the constants; the remaining literals of those names live in
//! different namespaces and are deliberate — top-level config-section keys
//! (`api`, `inbounds`, `outbounds`), `Protocol::parse` aliases, and the DNS
//! `block` action vocabulary. Reaching the constants from outside the crate
//! pins the reachability promise; the value assertions pin the exact strings
//! so a later migration cannot drift them.

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
