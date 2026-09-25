//! Local inbound models: socks/mixed, http, dokodemo-door,
//! tun — plus the shared sniffing config and TUN settings (tun.go:15-54).

use super::{
    dns::DEFAULT_PLAINTEXT_RESOLVERS, skip_empty_str, skip_empty_vec, skip_false, skip_zero_u16,
    skip_zero_u32,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// Wire tag of the TUN inbound: `"in-tun"`. Referenced wherever the
/// generated config must address the TUN listener by tag — emission of the
/// inbound itself, the port-collision check, routing rules that target the
/// TUN traffic, runtime teardown of the interface, and UI validation that
/// warns about (or rejects) user rules touching it.
pub const TUN_INBOUND_TAG: &str = "in-tun";

/// Wire tag of the loopback DNS inbound listener: `"dns-in"`. Referenced in
/// emission of the DNS module's inbound listener, in routing rules that
/// steer resolution traffic to it, and in WFP shield detection that checks
/// whether the system DNS points at this listener.
pub const DNS_INBOUND_TAG: &str = "dns-in";

/// Wire tag of the DNS outbound: `"dns-out"`. Referenced in emission of the
/// DNS module's outbound and in routing rules that forward DNS traffic to it.
pub const DNS_OUTBOUND_TAG: &str = "dns-out";

/// Wire tag of the generated freedom outbound: `"direct"`. Referenced in
/// emission of the built-in outbounds, in the reserved-tag checks that keep
/// profile tags from colliding with it, in the safety pass's balancer-target
/// contract, and in the routing editor's target lists and fallback targets.
pub const DIRECT_OUTBOUND_TAG: &str = "direct";

/// Wire tag of the generated blackhole outbound: `"block"`. Referenced in
/// emission of the built-in outbounds, in the reserved-tag checks that keep
/// profile tags from colliding with it, in the safety pass's balancer-target
/// contract, and in the routing editor's target lists.
pub const BLOCK_OUTBOUND_TAG: &str = "block";

/// Wire tag of the control-plane API listener: `"api"`. The generated
/// config's `api` section carries it, and inbound validation plus the
/// routing editor treat it as a reserved inbound tag alongside the TUN and
/// DNS listener tags.
pub const API_INBOUND_TAG: &str = "api";

/// The address as the socket layer sees it: an IPv4-mapped IPv6 literal
/// (`::ffff:127.0.0.1`) is the IPv4 address it carries, which is what the
/// stack binds and routes — the same re-classification the latency probe's
/// host guard and the outbound privacy check apply to their literals.
pub fn socket_address(address: std::net::IpAddr) -> std::net::IpAddr {
    match address {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
        v4 => v4,
    }
}

/// Wildcard-aware port-collision overlap: `0.0.0.0` and `::` bind every
/// interface, so they conflict with every other address on a shared port;
/// otherwise two addresses conflict only when identical — identical meaning
/// the same endpoint after [`socket_address`], so the mapped and plain
/// spellings of one address overlap too. Unparseable values (which the
/// validation layer rejects separately) still compare as text.
pub fn listen_addresses_overlap(a: &str, b: &str) -> bool {
    if is_wildcard_listen(a) || is_wildcard_listen(b) {
        return true;
    }
    match (a.parse::<std::net::IpAddr>(), b.parse::<std::net::IpAddr>()) {
        (Ok(a), Ok(b)) => socket_address(a) == socket_address(b),
        _ => a == b,
    }
}

/// True for the all-interfaces wildcard addresses: the unspecified IPv4/IPv6
/// addresses `0.0.0.0`, `::`, and their equivalent spellings (e.g. `::0`, or
/// the IPv4-mapped `::ffff:0.0.0.0`).
pub fn is_wildcard_listen(s: &str) -> bool {
    s.parse::<std::net::IpAddr>()
        .is_ok_and(|address| socket_address(address).is_unspecified())
}

/// The listener-collision rule, one definition, over one endpoint per side
/// as `(port, protocol bits, address)`: two endpoints conflict when they
/// share a port, their protocol sets intersect (a TCP+UDP listener conflicts
/// with a TCP-only or UDP-only one), and their addresses overlap —
/// [`listen_addresses_overlap`], so a wildcard bind conflicts with every
/// address on its port. The model pass (`ListenerConflict`) and the inbounds
/// screen (`Collision*`) both call this; each keeps its own concerns —
/// invalid endpoints, a zero port, an empty UNIX path, disabled listeners,
/// path normalization, labels, and message keys.
pub fn listen_endpoints_conflict(
    (port, protocols, address): (u16, u8, &str),
    (other_port, other_protocols, other_address): (u16, u8, &str),
) -> bool {
    port == other_port
        && protocols & other_protocols != 0
        && listen_addresses_overlap(address, other_address)
}

/// A listen address is always a concrete IP literal; the
/// validator lives in `crate::model::validation::validate_listen_address`.
/// Inbound sniffing (xray.go:56-100).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Sniffing {
    pub enabled: bool,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub dest_override: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub domains_excluded: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub ips_excluded: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_only: Option<bool>,
    #[serde(skip_serializing_if = "skip_false")]
    pub route_only: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for Sniffing {
    fn default() -> Self {
        Self {
            enabled: true,
            dest_override: vec!["http".into(), "tls".into(), "quic".into()],
            domains_excluded: Vec::new(),
            ips_excluded: Vec::new(),
            metadata_only: None,
            route_only: false,
            extra: Map::new(),
        }
    }
}

impl Sniffing {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            dest_override: Vec::new(),
            ..Default::default()
        }
    }

    /// Wire form of the inbound sniffing envelope. Appends "fakedns" to
    /// destOverride when the fakeDns trio is active; effectively-empty
    /// objects are omitted entirely (None).
    pub fn to_wire(&self, fakedns: bool) -> Option<Value> {
        let mut v = serde_json::to_value(self).expect(
            "model serialization is infallible: Sniffing fields are bools, string vecs, \
             and string-keyed Value maps only",
        );
        if fakedns && self.enabled {
            let obj = v.as_object_mut()?;
            let arr = obj
                .entry(String::from("destOverride"))
                .or_insert_with(|| json!([]));
            if let Some(a) = arr.as_array_mut()
                && !a.iter().any(|x| x.as_str() == Some("fakedns"))
            {
                a.push(json!("fakedns"));
            }
        }
        match v.as_object() {
            Some(o) if !o.is_empty() => Some(v),
            _ => None,
        }
    }
}

/// socks/http account — wire keys are `user`/`pass` (socks.go:13-16).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Account {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub user: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub pass: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Build the shared inbound wire envelope: `tag`/`protocol`/`settings` plus
/// the top-level `listen` (always emitted) and `port` (omitted when `None`,
/// as in dokodemo UNIX mode), folding the common `userLevel` setting into
/// `settings` and inserting the pre-computed `sniffing` envelope when present.
/// Protocol-specific settings (accounts, udp/ip, allowTransparent, portMap,
/// ...) are built by the caller and passed in as `settings`.
fn base_inbound(
    tag: &str,
    listen: &str,
    port: Option<u16>,
    protocol: &str,
    mut settings: Map<String, Value>,
    user_level: u32,
    sniffing: Option<Value>,
) -> Value {
    if user_level != 0 {
        settings.insert("userLevel".into(), json!(user_level));
    }
    let mut envelope = Map::new();
    envelope.insert("tag".into(), json!(tag));
    envelope.insert("listen".into(), json!(listen));
    if let Some(port) = port {
        envelope.insert("port".into(), json!(port));
    }
    envelope.insert("protocol".into(), json!(protocol));
    envelope.insert("settings".into(), Value::Object(settings));
    if let Some(sn) = sniffing {
        envelope.insert("sniffing".into(), sn);
    }
    Value::Object(envelope)
}

/// Local endpoint protocol. Serialized lowercase: "socks" | "http".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LocalInboundProtocol {
    Socks,
    Http,
}

impl LocalInboundProtocol {
    /// Xray wire protocol name.
    fn wire_name(self) -> &'static str {
        match self {
            Self::Socks => "socks",
            Self::Http => "http",
        }
    }
}

/// A user-managed SOCKS or HTTP local endpoint. Zero or more
/// entries of either protocol. `enabled` and `tag` are
/// GUI-owned — `enabled` never reaches the wire, `tag` is assigned once at
/// creation, persisted, and never reused after removal. `udp`/`ip` are
/// SOCKS-only, `allow_transparent` is HTTP-only; inactive fields serialize
/// as absent. `Default` is the SOCKS shape (enabled, 127.0.0.1:10808).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LocalInboundCfg {
    pub protocol: LocalInboundProtocol,
    /// Stable GUI-owned inbound tag (e.g. "in-socks-1"); hidden from the UI.
    pub tag: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "skip_zero_u16")]
    pub port: u16,
    /// Listen address (socks.go/http.go: `listen`). Always a concrete IP
    /// literal; the default 127.0.0.1 preserves the historical loopback-only
    /// behavior.
    pub listen: String,
    /// SOCKS-only: enable the UDP relay. Always serialized (legacy
    /// behavior): `false` must survive save/load.
    pub udp: bool,
    /// SOCKS-only UDP relay IP: the address advertised for UDP replies
    /// (`ip` in socks.go).
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub ip: String,
    #[serde(skip_serializing_if = "skip_zero_u32")]
    pub user_level: u32,
    /// noauth | password (password ⇒ accounts emitted)
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub auth: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub accounts: Vec<Account>,
    /// HTTP-only: allow transparent proxying (http.go).
    #[serde(skip_serializing_if = "skip_false")]
    pub allow_transparent: bool,
    pub sniffing: Sniffing,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for LocalInboundCfg {
    fn default() -> Self {
        Self {
            protocol: LocalInboundProtocol::Socks,
            tag: String::new(),
            enabled: true,
            port: 10808,
            listen: "127.0.0.1".into(),
            udp: true,
            ip: String::new(),
            user_level: 0,
            auth: "noauth".into(),
            accounts: Vec::new(),
            allow_transparent: false,
            sniffing: Sniffing::default(),
            extra: Map::new(),
        }
    }
}

impl LocalInboundCfg {
    /// Default SOCKS endpoint: enabled, 127.0.0.1:10808, UDP relay on, noauth.
    pub fn socks_default(tag: &str) -> Self {
        Self {
            tag: tag.into(),
            ..Default::default()
        }
    }

    /// Default HTTP endpoint: enabled, 127.0.0.1:10809, noauth.
    pub fn http_default(tag: &str) -> Self {
        Self {
            protocol: LocalInboundProtocol::Http,
            tag: tag.into(),
            port: 10809,
            udp: false,
            ..Default::default()
        }
    }

    /// Wire form of the local inbound. `enabled` is GUI-only and never
    /// reaches the config; the tag comes from `self.tag`. Output is
    /// byte-identical to the legacy socks/http projections for the same
    /// values: socks settings = {auth, udp, accounts? under
    /// password, ip?}, http settings = {accounts? under password,
    /// allowTransparent?}.
    pub fn to_wire(&self, fakedns: bool) -> Value {
        let mut set = Map::new();
        if self.protocol == LocalInboundProtocol::Socks {
            set.insert("auth".into(), json!(self.auth));
            set.insert("udp".into(), json!(self.udp));
            if !self.ip.is_empty() {
                set.insert("ip".into(), json!(self.ip));
            }
        }
        if self.auth == "password" && !self.accounts.is_empty() {
            set.insert(
                "accounts".into(),
                serde_json::to_value(&self.accounts).expect(
                    "model serialization is infallible: Account fields are strings and \
                     a string-keyed Value map only",
                ),
            );
        }
        if self.protocol == LocalInboundProtocol::Http && self.allow_transparent {
            set.insert("allowTransparent".into(), json!(true));
        }
        base_inbound(
            self.tag.as_str(),
            self.listen.as_str(),
            Some(self.port),
            self.protocol.wire_name(),
            set,
            self.user_level,
            self.sniffing.to_wire(fakedns),
        )
    }

    /// Whether the wire form of this inbound requires valid credentials before
    /// serving. SOCKS carries an `auth` key and password mode authenticates even
    /// with an empty account list (Xray then denies every connection). HTTP
    /// carries no auth key — `accounts` is its only authentication, so password
    /// mode with an empty account list authenticates nobody (the projection
    /// drops the empty list and Xray serves everyone). The safety exposure rule
    /// and the validation gate both derive from this — never re-implemented.
    pub(crate) fn authenticates(&self) -> bool {
        match self.protocol {
            LocalInboundProtocol::Socks => self.auth == "password",
            LocalInboundProtocol::Http => self.auth == "password" && !self.accounts.is_empty(),
        }
    }
}

/// Seed local endpoints for a fresh install: SOCKS 127.0.0.1:10808 and HTTP
/// 127.0.0.1:10809 with the historical tags.
pub fn default_local_inbounds() -> Vec<LocalInboundCfg> {
    vec![
        LocalInboundCfg::socks_default("in-socks"),
        LocalInboundCfg::http_default("in-http"),
    ]
}

/// Allocate a persisted tag for a newly-created local endpoint:
/// `in-<proto>-<n>`. The number is the larger of `*high_water` and the
/// largest numeric suffix seen in `existing` (hand-edited tags included),
/// plus one; `*high_water` is updated to the issued number and persists
/// with the settings. Because the mark never decreases, a
/// removed entry's number is never handed out again — a dangling reference
/// to it in a user-authored routing rule must keep dangling (and fail
/// validation) instead of silently retargeting the new entry. The suffix
/// space is u32; a hand-edited tag at u32::MAX falls back to a UUID-suffixed
/// tag (the dokodemo pattern) rather than overflowing.
pub fn next_local_tag(
    existing: &[LocalInboundCfg],
    protocol: LocalInboundProtocol,
    high_water: &mut u32,
) -> String {
    let proto = match protocol {
        LocalInboundProtocol::Socks => "socks",
        LocalInboundProtocol::Http => "http",
    };
    let prefix = format!("in-{proto}-");
    let max_seen = existing
        .iter()
        .filter_map(|entry| entry.tag.strip_prefix(&prefix))
        .filter_map(|suffix| suffix.parse::<u32>().ok())
        .max()
        .unwrap_or(0);
    match max_seen.max(*high_water).checked_add(1) {
        Some(n) => {
            *high_water = n;
            format!("{prefix}{n}")
        }
        None => format!("{prefix}{}", uuid::Uuid::new_v4().simple()),
    }
}

/// dokodemo-door port forward (dokodemo.go:10-45).
/// `listen_port`/`unix_socket_path` select the local listener;
/// `address`+`port` are the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DokodemoNetwork {
    Tcp,
    Udp,
    TcpUdp,
    Unix,
}

impl DokodemoNetwork {
    pub(crate) const fn canonical(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::TcpUdp => "tcp,udp",
            Self::Unix => "unix",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DokodemoCfg {
    /// Stable GUI-owned inbound tag, assigned once when the entry is
    /// created. An empty tag is invalid state: generation rejects it (and
    /// the Inbounds editor row flags it).
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub tag: String,
    #[serde(skip_serializing_if = "skip_false")]
    pub enabled: bool,
    #[serde(skip_serializing_if = "skip_zero_u16")]
    pub listen_port: u16,
    /// Local UNIX-domain socket path. It is GUI state rather than a
    /// dokodemo-door setting; the generator emits it as top-level `listen`.
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub unix_socket_path: String,
    /// Listen address for IP modes (TCP/UDP/TCP+UDP); unused by the UNIX
    /// mode, which emits `unix_socket_path` as the top-level `listen` instead.
    pub listen: String,
    /// NetworkList string, e.g. "tcp,udp"
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub network: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub address: String,
    #[serde(skip_serializing_if = "skip_zero_u16")]
    pub port: u16,
    #[serde(skip_serializing_if = "skip_false")]
    pub follow_redirect: bool,
    /// dokodemo.go:17 — map source port to a target `host:port`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub port_map: BTreeMap<String, String>,
    /// dokodemo.go:19.
    #[serde(skip_serializing_if = "skip_zero_u32")]
    pub user_level: u32,
    pub sniffing: Sniffing,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for DokodemoCfg {
    fn default() -> Self {
        Self {
            tag: String::new(),
            enabled: false,
            listen_port: 0,
            unix_socket_path: String::new(),
            listen: "127.0.0.1".into(),
            network: "tcp,udp".into(),
            address: String::new(),
            port: 0,
            follow_redirect: false,
            port_map: BTreeMap::new(),
            user_level: 0,
            sniffing: Sniffing::disabled(),
            extra: Map::new(),
        }
    }
}

impl DokodemoCfg {
    /// Parse Xray's comma-separated NetworkList without normalizing the stored
    /// string. Xray accepts token casing, but does not trim token whitespace.
    pub(crate) fn network_mode(&self) -> Result<DokodemoNetwork, String> {
        const TCP: u8 = 1;
        const UDP: u8 = 2;
        const TCP_UDP: u8 = TCP | UDP;
        const UNIX: u8 = 4;

        if self.network.is_empty() {
            return Err("listener network is empty".into());
        }

        let mut networks = 0;
        for token in self.network.split(',') {
            if token.is_empty() {
                return Err("listener network contains an empty token".into());
            }
            if token.eq_ignore_ascii_case("tcp") {
                networks |= TCP;
            } else if token.eq_ignore_ascii_case("udp") {
                networks |= UDP;
            } else if token.eq_ignore_ascii_case("unix") {
                networks |= UNIX;
            } else {
                return Err(format!("listener network contains unknown token {token:?}"));
            }
        }

        if networks & UNIX != 0 && networks & (TCP | UDP) != 0 {
            return Err("UNIX cannot be mixed with TCP or UDP in one inbound".into());
        }

        match networks {
            TCP => Ok(DokodemoNetwork::Tcp),
            UDP => Ok(DokodemoNetwork::Udp),
            TCP_UDP => Ok(DokodemoNetwork::TcpUdp),
            UNIX => Ok(DokodemoNetwork::Unix),
            _ => Err("listener network is empty".into()),
        }
    }

    /// Wire form of the dokodemo inbound. `enabled` and `tag` are GUI state;
    /// the UNIX mode emits the socket path as the top-level `listen` with no
    /// port, IP modes emit `listen` + `listen_port`.
    pub fn to_wire(&self, tag: &str, fakedns: bool) -> Value {
        let unix_listener = matches!(self.network_mode(), Ok(DokodemoNetwork::Unix));
        let network = if unix_listener {
            "unix"
        } else {
            self.network.as_str()
        };
        let mut set = Map::new();
        set.insert("network".into(), json!(network));
        set.insert("address".into(), json!(self.address));
        set.insert("port".into(), json!(self.port));
        if self.follow_redirect {
            set.insert("followRedirect".into(), json!(true));
        }
        if !self.port_map.is_empty() {
            set.insert("portMap".into(), json!(self.port_map));
        }
        base_inbound(
            tag,
            if unix_listener {
                self.unix_socket_path.as_str()
            } else {
                self.listen.as_str()
            },
            if unix_listener {
                None
            } else {
                Some(self.listen_port)
            },
            "dokodemo-door",
            set,
            self.user_level,
            self.sniffing.to_wire(fakedns),
        )
    }
}

/// Allocate a persisted tag for a newly-created dokodemo entry.
pub(crate) fn new_dokodemo_tag(entries: &[DokodemoCfg]) -> String {
    loop {
        let tag = format!("in-doko-{}", uuid::Uuid::new_v4().simple());
        if entries.iter().all(|entry| entry.tag != tag) {
            return tag;
        }
    }
}

#[cfg(test)]
mod listen_address_tests {
    use super::{is_wildcard_listen, listen_addresses_overlap, listen_endpoints_conflict};
    use crate::model::LocalInboundCfg;
    use crate::model::validation::{ValidationCode, validate_listen_address};

    #[test]
    fn wildcard_listens_overlap_every_other_address() {
        assert!(listen_addresses_overlap("0.0.0.0", "127.0.0.1"));
        assert!(listen_addresses_overlap("0.0.0.0", "0.0.0.0"));
        assert!(listen_addresses_overlap("::", "::1"));
        assert!(listen_addresses_overlap("::", "0.0.0.0")); // both wildcards
        assert!(listen_addresses_overlap("0.0.0.0", "192.168.1.5"));
    }

    #[test]
    fn identical_concrete_addresses_overlap_distinct_do_not() {
        assert!(listen_addresses_overlap("127.0.0.1", "127.0.0.1"));
        assert!(!listen_addresses_overlap("127.0.0.1", "192.168.1.5"));
        assert!(!listen_addresses_overlap("127.0.0.1", "::1"));
        // Non-canonical unspecified spellings are wildcards too.
        assert!(listen_addresses_overlap("0:0:0:0:0:0:0:0", "127.0.0.1"));
    }

    #[test]
    fn wildcard_predicate_matches_only_unspecified_addresses() {
        for wildcard in ["0.0.0.0", "::", "0:0:0:0:0:0:0:0", "::0"] {
            assert!(is_wildcard_listen(wildcard), "{wildcard:?} is a wildcard");
        }
        assert!(!is_wildcard_listen("127.0.0.1"));
        assert!(!is_wildcard_listen("::1"));
        assert!(!is_wildcard_listen(""));
    }

    /// Windows binds an IPv4-mapped literal as the IPv4 address it carries,
    /// so the two spellings of one endpoint must collide and a mapped
    /// wildcard must count as the wildcard it is — otherwise two listeners
    /// are emitted for one socket and the core fails to start with no
    /// field-scoped message.
    #[test]
    fn ipv4_mapped_spellings_overlap_their_plain_form() {
        assert!(is_wildcard_listen("::ffff:0.0.0.0"));
        assert!(listen_addresses_overlap("::ffff:0.0.0.0", "127.0.0.1"));
        assert!(listen_addresses_overlap("127.0.0.1", "::ffff:0.0.0.0"));
        assert!(listen_addresses_overlap("::ffff:127.0.0.1", "127.0.0.1"));
        assert!(listen_addresses_overlap(
            "::ffff:192.168.1.5",
            "192.168.1.5"
        ));
        // Distinct endpoints stay distinct, mapped or not.
        assert!(!listen_addresses_overlap(
            "::ffff:192.168.1.5",
            "192.168.1.6"
        ));
        assert!(!listen_addresses_overlap("::ffff:192.168.1.5", "::1"));
        // Unparseable values keep comparing as text.
        assert!(listen_addresses_overlap("weird", "weird"));
        assert!(!listen_addresses_overlap("weird", "other"));
    }

    #[test]
    fn endpoints_conflict_only_on_shared_port_intersecting_protocols_and_overlapping_addresses() {
        const TCP: u8 = 1;
        const UDP: u8 = 2;
        // Shared port, intersecting protocols, overlapping addresses.
        assert!(listen_endpoints_conflict(
            (10808, TCP, "127.0.0.1"),
            (10808, TCP, "127.0.0.1")
        ));
        assert!(listen_endpoints_conflict(
            (10808, TCP | UDP, "127.0.0.1"),
            (10808, UDP, "127.0.0.1")
        ));
        // The wildcard address conflicts with any address on a shared port.
        assert!(listen_endpoints_conflict(
            (10808, TCP, "0.0.0.0"),
            (10808, TCP, "192.168.1.5")
        ));
        assert!(listen_endpoints_conflict(
            (53, UDP, "::"),
            (53, TCP | UDP, "::1")
        ));
        // Any one third of the conjunction failing means no conflict.
        assert!(!listen_endpoints_conflict(
            (10808, TCP, "127.0.0.1"),
            (10809, TCP, "127.0.0.1")
        ));
        assert!(!listen_endpoints_conflict(
            (10808, TCP, "127.0.0.1"),
            (10808, UDP, "127.0.0.1")
        ));
        assert!(!listen_endpoints_conflict(
            (10808, TCP, "127.0.0.1"),
            (10808, TCP, "192.168.1.5")
        ));
    }

    #[test]
    fn validation_accepts_ip_literals_and_rejects_everything_else() {
        for ok in ["127.0.0.1", "0.0.0.0", "::", "::1", "192.168.1.5"] {
            assert!(
                validate_listen_address(ok).is_ok(),
                "{ok:?} must validate as a listen address"
            );
        }
        for bad in ["", "localhost", "not-an-ip", "127.0.0.1:8080"] {
            assert_eq!(
                validate_listen_address(bad),
                Err(ValidationCode::ListenAddressInvalid),
                "unexpected result for {bad:?}"
            );
        }
    }

    #[test]
    fn listen_round_trips_through_serialization() {
        let socks = LocalInboundCfg {
            listen: "192.168.1.5".into(),
            ..Default::default()
        };
        let serialized = serde_json::to_value(&socks).expect("serialize socks state");
        assert_eq!(serialized["listen"], "192.168.1.5");
        let restored: LocalInboundCfg =
            serde_json::from_value(serialized).expect("deserialize socks state");
        assert_eq!(restored.listen, "192.168.1.5");
    }
}

#[cfg(test)]
mod local_inbound_tests {
    use super::{Account, LocalInboundCfg, LocalInboundProtocol, default_local_inbounds};
    use serde_json::json;

    #[test]
    fn socks_and_http_defaults_match_the_historical_seed() {
        let socks = LocalInboundCfg::socks_default("in-socks");
        assert_eq!(socks.protocol, LocalInboundProtocol::Socks);
        assert_eq!(socks.tag, "in-socks");
        assert!(socks.enabled);
        assert_eq!(socks.port, 10808);
        assert_eq!(socks.listen, "127.0.0.1");
        assert!(socks.udp);
        assert_eq!(socks.auth, "noauth");

        let http = LocalInboundCfg::http_default("in-http");
        assert_eq!(http.protocol, LocalInboundProtocol::Http);
        assert_eq!(http.tag, "in-http");
        assert!(http.enabled);
        assert_eq!(http.port, 10809);
        assert_eq!(http.listen, "127.0.0.1");
        assert_eq!(http.auth, "noauth");
        assert!(!http.udp, "UDP relay is SOCKS-only");

        let seed = default_local_inbounds();
        assert_eq!(seed.len(), 2);
        assert_eq!(seed[0].protocol, LocalInboundProtocol::Socks);
        assert_eq!(seed[0].tag, "in-socks");
        assert_eq!(seed[1].protocol, LocalInboundProtocol::Http);
        assert_eq!(seed[1].tag, "in-http");
    }

    #[test]
    fn socks_wire_projection_matches_the_legacy_shape() {
        let cfg = LocalInboundCfg {
            tag: "in-socks-1".into(),
            ip: "10.0.0.2".into(),
            user_level: 1,
            auth: "password".into(),
            accounts: vec![Account {
                user: "u".into(),
                pass: "p".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let wire = cfg.to_wire(false);
        assert_eq!(
            wire,
            json!({
                "tag": "in-socks-1",
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {
                    "accounts": [{"pass": "p", "user": "u"}],
                    "auth": "password",
                    "ip": "10.0.0.2",
                    "udp": true,
                    "userLevel": 1
                },
                "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": true}
            })
        );
        // GUI-only state never reaches the wire; HTTP-only fields stay out
        // of the SOCKS settings.
        assert!(wire.get("enabled").is_none());
        assert!(wire["settings"].get("enabled").is_none());
        assert!(wire["settings"].get("allowTransparent").is_none());
    }

    #[test]
    fn http_wire_projection_matches_the_legacy_shape() {
        let cfg = LocalInboundCfg {
            allow_transparent: true,
            user_level: 2,
            auth: "password".into(),
            accounts: vec![Account {
                user: "u".into(),
                pass: "p".into(),
                ..Default::default()
            }],
            ..LocalInboundCfg::http_default("in-http")
        };
        let wire = cfg.to_wire(false);
        assert_eq!(
            wire,
            json!({
                "tag": "in-http",
                "listen": "127.0.0.1",
                "port": 10809,
                "protocol": "http",
                "settings": {
                    "accounts": [{"pass": "p", "user": "u"}],
                    "allowTransparent": true,
                    "userLevel": 2
                },
                "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": true}
            })
        );
        // The HTTP projection never emits auth/udp/ip (legacy behavior).
        assert!(wire["settings"].get("auth").is_none());
        assert!(wire["settings"].get("udp").is_none());
        assert!(wire["settings"].get("ip").is_none());
    }

    #[test]
    fn accounts_emit_only_under_password_auth() {
        let noauth = LocalInboundCfg::socks_default("in-socks");
        assert!(noauth.to_wire(false)["settings"].get("accounts").is_none());
        let with_accounts = LocalInboundCfg {
            auth: "noauth".into(),
            accounts: vec![Account {
                user: "u".into(),
                pass: "p".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            with_accounts.to_wire(false)["settings"]
                .get("accounts")
                .is_none(),
            "accounts must not leak into a noauth wire settings"
        );
    }

    #[test]
    fn fakedns_is_appended_to_the_sniffing_envelope() {
        let cfg = LocalInboundCfg::socks_default("in-socks");
        let wire = cfg.to_wire(true);
        assert_eq!(
            wire["sniffing"]["destOverride"],
            json!(["http", "tls", "quic", "fakedns"])
        );
    }
}

#[cfg(test)]
mod stable_tag_tests {
    use super::{DokodemoCfg, new_dokodemo_tag};

    #[test]
    fn new_tag_never_reuses_an_existing_tag() {
        let entry = DokodemoCfg {
            tag: new_dokodemo_tag(&[]),
            ..Default::default()
        };
        assert_ne!(new_dokodemo_tag(std::slice::from_ref(&entry)), entry.tag);
    }

    #[test]
    fn legacy_state_defaults_unix_socket_path_without_changing_network() {
        let config: DokodemoCfg = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "listenPort": 5353,
            "network": "tcp,udp",
            "address": "8.8.8.8",
            "port": 53
        }))
        .expect("deserialize legacy dokodemo state");

        assert_eq!(config.listen_port, 5353);
        assert_eq!(config.network, "tcp,udp");
        assert!(config.unix_socket_path.is_empty());

        let serialized = serde_json::to_value(&config).expect("serialize dokodemo state");
        assert!(serialized.get("unixSocketPath").is_none());
        assert_eq!(serialized["network"], "tcp,udp");
    }
}

/// TUN inbound (tun.go:15-54). Contract defaults:
/// name broccoli0, mtu 1500, gateway 10.255.0.1/30 + fd00::1/64
/// (dual-stack — every entry becomes an adapter address on Windows,
/// proxy/tun/tun_windows.go:119-124; the v6 address is what makes the
/// ::/1 + 8000::/1 split routes usable), dns 1.1.1.1/8.8.8.8 (plaintext
/// fallback: without a DNS module the generator cannot point the adapter at
/// the loopback DNS listener, so this default keeps tunnel resolution
/// functional — leaky but alive; with a DNS module the generator pins
/// the adapter DNS to the TUN gateway's IPv4 (tun_dns_address,
/// gen/mod.rs:346-352) regardless of this value), split default routes
/// (v4 + v6), autoOutboundsInterface "auto".
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TunCfg {
    /// Always serialized (storage): a cleared name must survive the load
    /// round-trip — with the seeded "broccoli0" default, a missing key
    /// would resurrect it after the user cleared it. `to_wire` strips the
    /// empty string so the wire form stays clean.
    pub name: String,
    /// Always serialized (storage): a cleared desc must survive the load
    /// round-trip — with the seeded "Wintun" default, a missing key
    /// would resurrect it after the user cleared it. `to_wire` strips the
    /// empty string so the wire form stays clean.
    pub desc: String,
    /// Always serialized (storage): a cleared mtu must survive the load
    /// round-trip — with the seeded 1500 default, a missing key
    /// would resurrect it after the user cleared it. `to_wire` strips the
    /// zero value so the wire form stays clean.
    pub mtu: u32,
    /// Always serialized (storage): a cleared gateway must survive the load
    /// round-trip — with the seeded dual-stack default, a missing key
    /// would resurrect it after the user cleared it. `to_wire` strips the
    /// empty list so the wire form stays clean.
    pub gateway: Vec<String>,
    /// Always serialized (storage): a cleared dns must survive the load
    /// round-trip — with the seeded 1.1.1.1/8.8.8.8 default, a missing key
    /// would resurrect it after the user cleared it. `to_wire` strips the
    /// empty list so the wire form stays clean.
    pub dns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_level: Option<u32>,
    /// Always serialized (storage): a cleared route table must survive the
    /// load round-trip — with the seeded split-route default, a missing key
    /// would resurrect it after the user cleared it. `to_wire` strips the
    /// empty list so the wire form stays clean.
    pub auto_system_routing_table: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub auto_outbounds_interface: String,
    /// Inbound envelope sniffing; serialized outside TUN protocol settings.
    pub sniffing: Sniffing,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for TunCfg {
    fn default() -> Self {
        Self {
            name: "broccoli0".into(),
            desc: "Wintun".into(),
            mtu: 1500,
            gateway: vec!["10.255.0.1/30".into(), "fd00::1/64".into()],
            dns: DEFAULT_PLAINTEXT_RESOLVERS
                .iter()
                .map(|address| (*address).into())
                .collect(),
            user_level: None,
            sniffing: Sniffing::default(),
            auto_system_routing_table: vec![
                "0.0.0.0/1".into(),
                "128.0.0.0/1".into(),
                "::/1".into(),
                "8000::/1".into(),
            ],
            auto_outbounds_interface: "auto".into(),
            extra: Map::new(),
        }
    }
}

impl TunCfg {
    /// Wire form of the TUN inbound; `sniffing` lives in the inbound
    /// envelope, not the TUN protocol settings.
    pub fn to_wire(&self, fakedns: bool) -> Value {
        let mut set = serde_json::to_value(self).expect(
            "model serialization is infallible: TunCfg fields are ints, strings, string \
             vecs, Sniffing, and string-keyed Value maps only",
        );
        if let Some(o) = set.as_object_mut() {
            // Stale-file key: state files written before the field's
            // removal carry a GUI-only "enabled" through the flatten
            // extra; Xray tun settings never take one, so strip it from
            // the wire form on round-trips.
            o.remove("enabled");
            o.remove("sniffing");
            // Storage-only empty fields: always serialized (see the struct)
            // so a user-cleared value survives the load round-trip; strip
            // them here so the wire form stays byte-identical to the
            // skip-based one.
            if self.name.is_empty() {
                o.remove("name");
            }
            if self.desc.is_empty() {
                o.remove("desc");
            }
            if self.mtu == 0 {
                o.remove("mtu");
            }
            if self.gateway.is_empty() {
                o.remove("gateway");
            }
            if self.dns.is_empty() {
                o.remove("dns");
            }
            if self.auto_system_routing_table.is_empty() {
                o.remove("autoSystemRoutingTable");
            }
        }
        let mut ib = json!({
            "tag": TUN_INBOUND_TAG,
            "protocol": "tun",
            "settings": set,
        });
        if let Some(sn) = self.sniffing.to_wire(fakedns) {
            ib.as_object_mut().unwrap().insert("sniffing".into(), sn);
        }
        ib
    }
}
#[cfg(test)]
mod tun_tests {
    use super::TunCfg;

    #[test]
    fn fresh_install_default_routing_table_covers_v4_and_v6() {
        assert_eq!(
            TunCfg::default().auto_system_routing_table,
            vec![
                "0.0.0.0/1".to_string(),
                "128.0.0.0/1".to_string(),
                "::/1".to_string(),
                "8000::/1".to_string()
            ]
        );
    }

    #[test]
    fn fresh_install_default_gateway_covers_v4_and_v6() {
        // The adapter address list must be dual-stack: Windows assigns every
        // gateway entry as an interface address, and without an IPv6 address
        // the ::/1 + 8000::/1 split routes are unsourceable.
        assert_eq!(
            TunCfg::default().gateway,
            vec!["10.255.0.1/30".to_string(), "fd00::1/64".to_string()]
        );
    }

    #[test]
    fn tun_cleared_state_survives_the_round_trip() {
        // The seeded TUN defaults (name/desc/mtu/gateway/split routes) must
        // not resurrect after the user clears them: cleared states serialize
        // explicitly and load back identical (the DnsCfg precedent,
        // cleared_dns_collapses_to_no_wire_block_and_survives_the_round_trip).
        let cleared = TunCfg {
            name: String::new(),
            desc: String::new(),
            mtu: 0,
            gateway: Vec::new(),
            auto_system_routing_table: Vec::new(),
            ..Default::default()
        };
        let value = serde_json::to_value(&cleared).expect("serialize cleared tun state");
        assert_eq!(
            value["name"],
            serde_json::json!(""),
            "a cleared name must serialize explicitly, not be omitted"
        );
        assert_eq!(
            value["desc"],
            serde_json::json!(""),
            "a cleared desc must serialize explicitly, not be omitted"
        );
        assert_eq!(
            value["mtu"],
            serde_json::json!(0),
            "a cleared mtu must serialize explicitly, not be omitted"
        );
        assert_eq!(
            value["gateway"],
            serde_json::json!([]),
            "a cleared gateway must serialize explicitly, not be omitted"
        );
        assert_eq!(
            value["autoSystemRoutingTable"],
            serde_json::json!([]),
            "a cleared route table must serialize explicitly, not be omitted"
        );
        let restored: TunCfg = serde_json::from_value(value).expect("load cleared tun state");
        assert_eq!(restored.name, "", "cleared name must load back empty");
        assert_eq!(restored.desc, "", "cleared desc must load back empty");
        assert_eq!(restored.mtu, 0, "cleared mtu must load back zero");
        assert_eq!(
            restored.gateway,
            Vec::<String>::new(),
            "cleared gateway must load back empty"
        );
        assert_eq!(
            restored.auto_system_routing_table,
            Vec::<String>::new(),
            "cleared route table must load back empty"
        );
    }
}
