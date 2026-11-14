//! Local inbound models: socks/mixed, http, dokodemo-door,
//! tun — plus the shared sniffing config and TUN settings (tun.go:15-54).

use super::{
    FinalmaskModel, dns::DEFAULT_PLAINTEXT_RESOLVERS, fold_eq, fold_lower, skip_empty_str,
    skip_empty_vec, skip_false, skip_zero_u16, skip_zero_u32,
};
use crate::r#gen::keys;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Wire tag of the TUN inbound: `"in-tun"`. Referenced wherever the
/// generated config must address the TUN listener by tag — emission of the
/// inbound itself, the port-collision check, routing rules that target the
/// TUN traffic, runtime teardown of the interface, and UI validation that
/// warns about (or rejects) user rules touching it.
pub const TUN_INBOUND_TAG: &str = "in-tun";

/// Wire tag of the loopback DNS inbound listener: `"dns-in"`. Referenced in
/// emission of the DNS module's inbound listener, in routing rules that
/// steer resolution traffic to it, and in the runtime's in-tun listener
/// derivation that reads the tag back out of a running config.
pub const DNS_INBOUND_TAG: &str = "dns-in";

/// Wire tag of the tunnel's IPv6 DNS listener: `"dns-in6"`. The runtime adds
/// one in-tun DNS listener per gateway address family the tunnel carries, and
/// Xray's inbound manager keys handlers by tag, so the IPv6 one needs its own —
/// named by the same interception rule that names [`DNS_INBOUND_TAG`].
pub const DNS_INBOUND_V6_TAG: &str = "dns-in6";

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
    /// Listener-side `streamSettings.finalmask`, edited only through the
    /// `filter` mask. The core builds the mask for an inbound's listener
    /// (`transport/internet/finalmask/filter/config.go`), so a saved value
    /// here reaches the listener it belongs to; `None` keeps the block out of
    /// the generated document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalmask: Option<FinalmaskModel>,
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
            finalmask: None,
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
        let mut wire = base_inbound(
            self.tag.as_str(),
            self.listen.as_str(),
            Some(self.port),
            self.protocol.wire_name(),
            set,
            self.user_level,
            self.sniffing.to_wire(fakedns),
        );
        if let Some(finalmask) = self.finalmask.as_ref().and_then(FinalmaskModel::wire_value)
            && let Some(object) = wire.as_object_mut()
        {
            object.insert(
                keys::STREAM_SETTINGS.into(),
                json!({ keys::FINALMASK: finalmask }),
            );
        }
        wire
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

/// Bit per network token a dokodemo `network` list may name (Xray ORs the
/// tokens it reads; `infra/conf/common.go:77`).
const DOKODEMO_TCP: u8 = 1;
const DOKODEMO_UDP: u8 = 2;
const DOKODEMO_UNIX: u8 = 4;

impl DokodemoCfg {
    /// Parse Xray's comma-separated NetworkList without normalizing the stored
    /// string. Xray accepts token casing, but does not trim token whitespace.
    pub(crate) fn network_mode(&self) -> Result<DokodemoNetwork, String> {
        const TCP_UDP: u8 = DOKODEMO_TCP | DOKODEMO_UDP;

        if self.network.is_empty() {
            return Err("listener network is empty".into());
        }

        let mut networks = 0;
        for token in self.network.split(',') {
            if token.is_empty() {
                return Err("listener network contains an empty token".into());
            }
            if fold_eq(token, "tcp") {
                networks |= DOKODEMO_TCP;
            } else if fold_eq(token, "udp") {
                networks |= DOKODEMO_UDP;
            } else if fold_eq(token, "unix") {
                networks |= DOKODEMO_UNIX;
            } else {
                return Err(format!("listener network contains unknown token {token:?}"));
            }
        }

        if networks & DOKODEMO_UNIX != 0 && networks & (DOKODEMO_TCP | DOKODEMO_UDP) != 0 {
            return Err("UNIX cannot be mixed with TCP or UDP in one inbound".into());
        }

        match networks {
            DOKODEMO_TCP => Ok(DokodemoNetwork::Tcp),
            DOKODEMO_UDP => Ok(DokodemoNetwork::Udp),
            TCP_UDP => Ok(DokodemoNetwork::TcpUdp),
            DOKODEMO_UNIX => Ok(DokodemoNetwork::Unix),
            _ => Err("listener network is empty".into()),
        }
    }

    /// The IP protocol mask the emitted inbound binds when [`Self::network_mode`]
    /// fails: the emitter answers an unparseable mode with the IP envelope
    /// (`to_wire`), and the core still serves the tokens it could read
    /// (infra/conf/common.go:77) — `tcp,` binds TCP, live on the pinned binary.
    /// Zero when no token names tcp or udp: that shape binds nothing.
    pub(crate) fn implied_ip_protocols(&self) -> u8 {
        self.network.split(',').fold(0, |mask, token| {
            if fold_eq(token, "tcp") {
                mask | DOKODEMO_TCP
            } else if fold_eq(token, "udp") {
                mask | DOKODEMO_UDP
            } else {
                mask
            }
        })
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

/// Whether the generated configuration runs a TUN inbound alongside the
/// top-level `dns` object: the TUN inbound owns the adapter DNS, and the DNS
/// module is what answers it. The runtime adds the module's in-tun listener
/// to the running core (`rt::dns_in`), the generator emits the core's leak
/// block on this same gate, and the elevated helper's system-DNS takeover
/// triggers on it. Either half alone has no tunnel DNS to protect, so both
/// consumers must read the decision from here rather than re-deriving it.
pub fn config_runs_tun_dns(config: &Value) -> bool {
    let has_tun = config
        .get(keys::INBOUNDS)
        .and_then(Value::as_array)
        .is_some_and(|inbounds| {
            inbounds.iter().any(|inbound| {
                inbound
                    .get(keys::PROTOCOL)
                    .and_then(Value::as_str)
                    .is_some_and(|protocol| protocol == "tun")
            })
        });
    has_tun && config.get(keys::DNS).is_some()
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
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunCfg {
    /// Always serialized (storage): a cleared name must survive the load
    /// round-trip — with the seeded "broccoli0" default, a missing key
    /// would resurrect it after the user cleared it. The wire form never
    /// carries the blank string: [`Self::effective_name`] names the adapter
    /// even then, so the core always creates the adapter this app tracks.
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
    /// The core's leak block: the entries whose traffic may only egress the
    /// TUN. A value is a named policy — [`TUN_LEAK_WINDNS_CLIENT`],
    /// [`TUN_LEAK_MISCONFIG_TUN`], [`TUN_LEAK_ALL`],
    /// [`TUN_LEAK_ALL_EXCEPT_LAN`], [`TUN_LEAK_ICMP`] — a `tcp`/`udp` filter
    /// with a port or range, a bare port or range, or any of these behind a
    /// CIDR prefix; [`DNS_LEAK_ALIAS`] is an alias the core expands into
    /// [`DNS_LEAK_ENTRIES`] before it matches (`parseLeak`,
    /// `ExpandWfpBlockLeak`, proxy/tun/wfp_leak.go). The load stores the
    /// canonical form ([`Self::canonical_leak_block`]). Always serialized
    /// (storage): the seeded policy must survive a round-trip after the user
    /// removes an entry, and the generator emits it whenever the TUN inbound
    /// and the DNS module are both present (the same predicate the runtime
    /// reads back).
    pub auto_system_wfp_block_leak: Vec<String>,
    /// True when the load expanded a stored [`DNS_LEAK_ALIAS`] into
    /// [`DNS_LEAK_ENTRIES`]. Never serialized: the save writes the entries the
    /// alias stands for, and a raw JSON edit migrates through the same load
    /// path. The settings pass warns from it once.
    #[serde(skip)]
    pub dns_alias_expanded: bool,
    /// Point the system resolver at the tunnel gateway. Linux-only upstream
    /// (only `LinuxTun` implements `ConfigureSystemDNS`), so the core
    /// accepts and no-ops it on Windows; the model carries it for wire
    /// fidelity, with no UI and no finding.
    #[serde(skip_serializing_if = "skip_false")]
    pub auto_system_dns_to_gateway: bool,
    /// Inbound envelope sniffing; serialized outside TUN protocol settings.
    pub sniffing: Sniffing,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The seeded TUN adapter name. The emitted inbound always names its
/// adapter, so a blank setting ([`TunCfg::effective_name`]) resolves here.
pub const DEFAULT_TUN_NAME: &str = "broccoli0";

/// The leak-block entry that drops traffic of an address family the routing
/// table does not route into the tunnel (`proxy/tun/tun_windows.go`).
pub const TUN_LEAK_MISCONFIG_TUN: &str = "misconfigtun";

/// The leak-block entry covering Windows' DNS Client service, whose own
/// queries can use protocols and ports a port filter does not see
/// (`dnsLeaks`, proxy/tun/wfp_leak.go).
pub const TUN_LEAK_WINDNS_CLIENT: &str = "windnsclient";

/// The leak-block entry covering every port of every address
/// (`parseLeak`, proxy/tun/wfp_leak.go).
pub const TUN_LEAK_ALL: &str = "all";

/// The leak-block entry covering every port except traffic to the local
/// network, which follows the DNS entries it stands for (`parseLeak`,
/// `ExpandWfpBlockLeak`, proxy/tun/wfp_leak.go).
pub const TUN_LEAK_ALL_EXCEPT_LAN: &str = "allexceptlan";

/// The leak-block entry covering ICMP (`parseLeak`, proxy/tun/wfp_leak.go).
pub const TUN_LEAK_ICMP: &str = "icmp";

/// The `dns` spelling of `autoSystemWfpBlockLeak`: an alias the core expands
/// into [`DNS_LEAK_ENTRIES`] before it matches, so it names no entry of its
/// own.
pub const DNS_LEAK_ALIAS: &str = "dns";

/// What `dns` in `autoSystemWfpBlockLeak` stands for, in the core's order
/// (`dnsLeaks`, proxy/tun/wfp_leak.go): DNS over UDP and TCP, Windows' DNS
/// Client service — which may also use other protocols and ports — and DNS
/// over TLS and QUIC.
pub const DNS_LEAK_ENTRIES: [&str; 5] = [
    "udp/53",
    "tcp/53",
    TUN_LEAK_WINDNS_CLIENT,
    "tcp/853",
    "udp/853",
];

/// The entries `dns` stands for, spelled the way a message names them, so a
/// tag that widens the alias cannot leave a sentence naming the old set.
pub static DNS_LEAK_ENTRY_LIST: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| DNS_LEAK_ENTRIES.join(", "));

/// The leak-block entries a fresh install runs: everything outside the local
/// network stays inside the tunnel, so private destinations keep their direct
/// route, plus an unrouted family the alias leaves open on that network. The
/// core follows the alias with the DNS entries it stands for
/// (`ExpandWfpBlockLeak`, proxy/tun/wfp_leak.go), which keeps the system's DNS
/// inside the tunnel and satisfies the core's DNS gate. The core drops the
/// family value while both families have routes into the TUN
/// (`newLeakFilters`, tun_windows_wfp.go:217-247), so it acts only on the
/// misconfiguration it names.
pub const DEFAULT_TUN_LEAK_BLOCK: [&str; 2] = [TUN_LEAK_ALL_EXCEPT_LAN, TUN_LEAK_MISCONFIG_TUN];

/// One port row of the leak editor: the core's `tcp|udp/<low>[-<high>]`
/// spelling, or the bare `<low>[-<high>]` form both protocols share
/// (`parseLeak`, proxy/tun/wfp_leak.go). A connection to those ports may only
/// go through the TUN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeakPort {
    protocol: Option<&'static str>,
    low: u16,
    high: u16,
}

impl LeakPort {
    /// A row built from the editor's controls: `protocol` is `tcp` or `udp`,
    /// or `None` for the bare form both protocols share. `high` follows `low`
    /// so a range never points backwards.
    pub fn new(protocol: Option<&'static str>, low: u16, high: u16) -> Self {
        debug_assert!(matches!(protocol, None | Some("tcp") | Some("udp")));
        Self {
            protocol,
            low,
            high: high.max(low),
        }
    }

    /// The protocol token the core matches, or `None` for the bare form.
    pub fn protocol(self) -> Option<&'static str> {
        self.protocol
    }

    /// The first port the row names.
    pub fn low(self) -> u16 {
        self.low
    }

    /// The last port the row names, equal to [`Self::low`] for one port.
    pub fn high(self) -> u16 {
        self.high
    }
}

/// The core's spelling of the value.
impl std::fmt::Display for LeakPort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(protocol) = self.protocol {
            write!(formatter, "{protocol}/")?;
        }
        write!(formatter, "{}", self.low)?;
        if self.high != self.low {
            write!(formatter, "-{}", self.high)?;
        }
        Ok(())
    }
}

/// Parse one stored entry as a port row: a protocol with a port or range, or
/// the bare form. A named value, a protocol with no port, and a
/// CIDR-prefixed value are not rows, so the editor renders them as they are
/// (`parseLeak`, proxy/tun/wfp_leak.go).
fn parse_leak_port(value: &str) -> Option<LeakPort> {
    let leak = parse_leak(value)?;
    if leak.prefix.is_some() || leak.low == 0 {
        return None;
    }
    let protocol = match leak.name {
        "tcp" => Some("tcp"),
        "udp" => Some("udp"),
        "" => None,
        _ => return None,
    };
    Some(LeakPort {
        protocol,
        low: leak.low,
        high: leak.high,
    })
}

/// The protocol, first port, and last port of one port row, folded the way
/// the core lowercases it, or `None` for any other spelling. The leak editor
/// asks this to decide whether an entry renders as a port row; every other
/// value stays an editable raw row.
pub fn leak_port(entry: &str) -> Option<LeakPort> {
    parse_leak_port(&fold_lower(entry))
}

/// The lowest port no entry names yet, for the editor's "add a port" button: a
/// new row that repeated an existing entry would edit the same value twice.
pub fn next_free_leak_port(entries: &[String]) -> LeakPort {
    let port = (1..=u16::MAX)
        .find(|port| {
            !entries
                .iter()
                .any(|entry| fold_eq(entry, &format!("tcp/{port}")))
        })
        .unwrap_or(1);
    LeakPort::new(Some("tcp"), port, port)
}

/// The lowest two-port range no entry names yet, for the editor's "add a
/// range" button: the same reason as [`next_free_leak_port`].
pub fn next_free_leak_range(entries: &[String]) -> LeakPort {
    let (low, high) = (1..u16::MAX)
        .find_map(|low| {
            let high = low + 1;
            (!entries
                .iter()
                .any(|entry| fold_eq(entry, &format!("tcp/{low}-{high}"))))
            .then_some((low, high))
        })
        .unwrap_or((1, 2));
    LeakPort::new(Some("tcp"), low, high)
}

/// The CIDR prefix in front of a leak value, without its brackets, masked the
/// way `netip.Prefix.Masked` leaves it (`parseLeak`, proxy/tun/wfp_leak.go).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LeakPrefix {
    address: IpAddr,
    bits: u8,
}

impl LeakPrefix {
    /// Parse the address part with Go's `netip.ParsePrefix` semantics. The
    /// prefix length is digits only, no sign and no leading zero, which the
    /// core's parser enforces; the address family must match the bracket
    /// form, and an IPv4-mapped IPv6 address is refused because Windows
    /// checks such connections as IPv4.
    fn parse(text: &str, ipv6: bool) -> Option<Self> {
        let (address, bits) = text.rsplit_once('/')?;
        if bits.is_empty()
            || !bits.bytes().all(|byte| byte.is_ascii_digit())
            || (bits.len() > 1 && bits.starts_with('0'))
        {
            return None;
        }
        let address: IpAddr = address.parse().ok()?;
        if address.is_ipv6() != ipv6 {
            return None;
        }
        if let IpAddr::V6(v6) = address
            && v6.to_ipv4_mapped().is_some()
        {
            return None;
        }
        let bits: u8 = bits.parse().ok()?;
        let width = if ipv6 { 128 } else { 32 };
        if bits > width {
            return None;
        }
        Some(Self {
            address: mask_address(address, bits),
            bits,
        })
    }
}

/// The address with its host bits cleared, the way `netip.Prefix.Masked`
/// returns it.
fn mask_address(address: IpAddr, bits: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - bits)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

/// One `autoSystemWfpBlockLeak` value the core parses: a named value, `tcp`
/// or `udp` with no port (all of them) or some (`low..=high`), or a bare port
/// or port range for both protocols, any of them behind a
/// [`LeakPrefix`] (`parseLeak`, proxy/tun/wfp_leak.go).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Leak<'a> {
    prefix: Option<LeakPrefix>,
    /// Empty for the bare port form, which applies to TCP and UDP.
    name: &'a str,
    /// Both zero for a named value and for a protocol that stands for all
    /// ports.
    low: u16,
    high: u16,
}

impl Leak<'_> {
    /// The core's own rendering (`leak.String`): the name, then `/low` or
    /// `/low-high` for some ports, the whole value behind the masked prefix,
    /// with an IPv6 one in brackets.
    fn canonical(self) -> String {
        let mut value = String::from(self.name);
        if self.low != 0 {
            if !value.is_empty() {
                value.push('/');
            }
            value.push_str(&self.low.to_string());
            if self.high != self.low {
                value.push('-');
                value.push_str(&self.high.to_string());
            }
        }
        match self.prefix {
            None => value,
            Some(prefix) => match prefix.address {
                IpAddr::V4(address) => format!("{address}/{}:{value}", prefix.bits),
                IpAddr::V6(address) => format!("[{address}/{}]:{value}", prefix.bits),
            },
        }
    }

    /// Whether the value covers traffic of `protocol` to `port`, to at least
    /// some addresses (`leak.covers`).
    fn covers(self, protocol: &str, port: u16) -> bool {
        match self.name {
            "all" => true,
            "" => self.low == 0 || self.low <= port && port <= self.high,
            name if name == protocol => self.low == 0 || self.low <= port && port <= self.high,
            _ => false,
        }
    }

    /// Whether the value keeps the system's DNS inside the tunnel
    /// (`leak.blocksDNS`): the DNS Client service, or TCP or UDP port 53.
    fn blocks_system_dns(self) -> bool {
        self.name == TUN_LEAK_WINDNS_CLIENT || self.covers("udp", 53) || self.covers("tcp", 53)
    }
}

/// Parse one lower-case leak value the way the core's `parseLeak` does: an
/// optional IPv4 or bracketed IPv6 CIDR prefix, then a named value, `tcp` or
/// `udp` with an optional `/<port>` or `/<low>-<high>`, or a bare port or
/// range for both protocols. Ports run `1..=65535`, low not above high, and
/// `tcp/1-65535` stands for the bare protocol token.
fn parse_leak(value: &str) -> Option<Leak<'_>> {
    let ipv6 = value.starts_with('[');
    let (cidr, rest) = if ipv6 {
        match value[1..].split_once("]:") {
            Some((cidr, rest)) => (Some(cidr), rest),
            // Without the `]:` the whole value is left to the rest of the
            // parse, exactly as `strings.Cut` reports no prefix.
            None => (None, value),
        }
    } else {
        match value.split_once(':') {
            Some((cidr, rest)) => (Some(cidr), rest),
            None => (None, value),
        }
    };
    let mut leak = Leak {
        prefix: None,
        name: "",
        low: 0,
        high: 0,
    };
    if let Some(cidr) = cidr {
        leak.prefix = Some(LeakPrefix::parse(cidr, ipv6)?);
    }
    let (name, ports) = match rest.split_once('/') {
        Some((name, ports)) => (name, Some(ports)),
        None => (rest, None),
    };
    match name {
        "tcp" | "udp" => {
            leak.name = name;
            if ports.is_none() {
                return Some(leak);
            }
        }
        "dns" | "windnsclient" | "misconfigtun" | "all" | "allexceptlan" | "icmp" => {
            leak.name = name;
            return ports.is_none().then_some(leak);
        }
        _ => {
            // Any other name is the bare port form, which takes no slash.
            if ports.is_some() {
                return None;
            }
        }
    }
    let ports = ports.unwrap_or(name);
    let (low, high) = match ports.split_once('-') {
        Some((low, high)) => (parse_leak_number(low)?, Some(parse_leak_number(high)?)),
        None => (parse_leak_number(ports)?, None),
    };
    if low == 0 {
        return None;
    }
    let high = match high {
        Some(high) => {
            if high < low {
                return None;
            }
            high
        }
        None => low,
    };
    if leak.name.is_empty() || low != 1 || high != u16::MAX {
        leak.low = low;
        leak.high = high;
    }
    Some(leak)
}

/// Read one port with Go's `strconv.ParseUint(text, 10, 16)`: digits only, no
/// sign, and at most 65535. Leading zeros are the same number.
fn parse_leak_number(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Whether one leak entry is a value the core parses, folded the way it
/// lowercases every entry before matching. The settings pass reports the
/// entries this refuses; the save keeps them so the user can fix them.
pub fn leak_entry_is_valid(entry: &str) -> bool {
    let folded = fold_lower(entry);
    parse_leak(folded.as_ref()).is_some()
}

/// The canonical form of one leak list, plus whether the `dns` alias was among
/// its stored spellings: every entry lowercased, the alias replaced by
/// [`DNS_LEAK_ENTRIES`] under the alias's own prefix, a CIDR masked, a port
/// written from its numeric value, `tcp/1-65535` collapsed to `tcp`, and
/// duplicates dropped with the first spelling kept and the order preserved —
/// the core's own expansion (`ExpandWfpBlockLeak`, proxy/tun/wfp_leak.go). An
/// entry the core would refuse stays as written, so the validation pass
/// reports it instead of the load rewriting it away.
fn canonicalize_leak_block(entries: &[String]) -> (Vec<String>, bool) {
    let mut canonical: Vec<String> = Vec::with_capacity(entries.len());
    let mut dns_alias_expanded = false;
    for entry in entries {
        let folded = fold_lower(entry);
        let Some(leak) = parse_leak(folded.as_ref()) else {
            // The core's build refuses this value, so the load keeps the
            // spelling the user typed and the validation pass reports it.
            push_unique_leak(&mut canonical, entry);
            continue;
        };
        if leak.name == DNS_LEAK_ALIAS {
            dns_alias_expanded = true;
        }
        for value in leak_canonical_entries(leak) {
            push_unique_leak(&mut canonical, &value);
        }
    }
    (canonical, dns_alias_expanded)
}

/// The canonical entries one parsed leak value stores: its own spelling, or
/// every entry the `dns` alias stands for under the alias's own prefix
/// (`ExpandWfpBlockLeak`, proxy/tun/wfp_leak.go).
fn leak_canonical_entries(leak: Leak<'_>) -> Vec<String> {
    if leak.name != DNS_LEAK_ALIAS {
        return vec![leak.canonical()];
    }
    DNS_LEAK_ENTRIES
        .iter()
        .map(|dns| {
            let mut dns = parse_leak(dns).expect("a stored DNS entry parses");
            dns.prefix = leak.prefix;
            dns.canonical()
        })
        .collect()
}

/// The entries one authored leak value stores, or `None` when the core would
/// refuse it (`parseLeak`, proxy/tun/wfp_leak.go): the core's canonical
/// spelling, with the `dns` alias replaced by the entries it stands for, so
/// the editor never stores the alias.
pub fn canonical_leak_entry(entry: &str) -> Option<Vec<String>> {
    let folded = fold_lower(entry);
    parse_leak(folded.as_ref()).map(leak_canonical_entries)
}

/// Replace a stored list with the entries the core builds from it
/// (`ExpandWfpBlockLeak`, proxy/tun/wfp_leak.go): folded, aliases expanded,
/// CIDRs masked, duplicates dropped in order, and an entry the core refuses
/// kept verbatim for the validation pass. The editor calls this after an edit
/// so it stores the same form a load writes.
pub fn canonicalize_leak_entries(entries: &mut Vec<String>) {
    let stored = std::mem::take(entries);
    *entries = canonicalize_leak_block(&stored).0;
}

/// Append `entry` unless the list already holds it. Every entry reaching here
/// is canonical already, so an exact comparison is the core's own duplicate
/// check.
fn push_unique_leak(list: &mut Vec<String>, entry: &str) {
    if !list.iter().any(|kept| kept == entry) {
        list.push(entry.to_string());
    }
}

/// Whether one stored leak entry keeps the system's DNS inside the tunnel,
/// read the way the core reads an expanded list (`BlocksSystemDNS`,
/// proxy/tun/wfp_leak.go): `all` and `windnsclient` block it through their
/// expansion, a port or range covering TCP or UDP port 53 blocks it, and the
/// `dns` and `allexceptlan` aliases stand for the DNS entries themselves.
fn leak_entry_blocks_system_dns(entry: &str) -> bool {
    let folded = fold_lower(entry);
    let Some(leak) = parse_leak(folded.as_ref()) else {
        return false;
    };
    leak.name == DNS_LEAK_ALIAS || leak.name == "allexceptlan" || leak.blocks_system_dns()
}

/// The leak block's scope: the two unprefixed values that state a policy for
/// every destination, or the detail list the editor shows entry by entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeakScope {
    /// Neither unprefixed scope value is stored: the list is a detail list.
    Custom,
    /// Unprefixed [`TUN_LEAK_ALL`] is stored.
    All,
    /// Unprefixed [`TUN_LEAK_ALL_EXCEPT_LAN`] is stored.
    AllExceptLan,
}

/// The scope a stored list states. [`TUN_LEAK_ALL`] wins when both scope
/// values are stored, because it covers everything the other value does
/// (`parseLeak`, `ExpandWfpBlockLeak`, proxy/tun/wfp_leak.go). A prefixed
/// `all` or `allexceptlan` limits itself to its own addresses, so it is a
/// detail entry and leaves the scope custom.
pub fn leak_scope(entries: &[String]) -> LeakScope {
    if leak_block_holds(entries, TUN_LEAK_ALL) {
        LeakScope::All
    } else if leak_block_holds(entries, TUN_LEAK_ALL_EXCEPT_LAN) {
        LeakScope::AllExceptLan
    } else {
        LeakScope::Custom
    }
}

/// Rewrite the list's scope to `scope`: drop every unprefixed scope value,
/// then add the selected spelling. A detail entry — including a prefixed
/// `all` or `allexceptlan` — is never touched.
pub fn set_leak_scope(entries: &mut Vec<String>, scope: LeakScope) {
    entries.retain(|entry| !is_unprefixed_scope_entry(entry));
    match scope {
        LeakScope::Custom => {}
        LeakScope::All => entries.push(TUN_LEAK_ALL.to_string()),
        LeakScope::AllExceptLan => entries.push(TUN_LEAK_ALL_EXCEPT_LAN.to_string()),
    }
}

/// Whether the scope's own filters already produce every block `entry` adds,
/// so the editor hides it. The relation is read from the core's expansion and
/// filter weights (`proxy/tun/wfp_leak.go:137-146`,
/// `tun_windows_wfp.go:327-335`): `all` blocks every protocol and address
/// outside the tunnel, so every valid entry is contained; `allexceptlan`
/// expands into `53`, `853` and the DNS Client service at every address, so an
/// entry no wider than those is contained. An invalid entry is never hidden:
/// the scope does not contain a value that breaks the load, and the user must
/// repair it.
pub fn leak_scope_hides(scope: LeakScope, entry: &str) -> bool {
    if !leak_entry_is_valid(entry) {
        return false;
    }
    match scope {
        LeakScope::Custom => false,
        LeakScope::All => true,
        LeakScope::AllExceptLan => leak_entry_in_dns_expansion(entry),
    }
}

/// Whether `entry` blocks no more than `allexceptlan` already adds for DNS.
/// The alias follows itself with `53`, `853` and `windnsclient` at every
/// address (`dnsLeaks`, `ExpandWfpBlockLeak`), so a stored DNS alias, the DNS
/// Client service, or a single 53/853 port — bare, protocol-qualified, or
/// CIDR-limited — is contained. A range that reaches another port is not.
fn leak_entry_in_dns_expansion(entry: &str) -> bool {
    let folded = fold_lower(entry);
    let Some(leak) = parse_leak(folded.as_ref()) else {
        return false;
    };
    match leak.name {
        DNS_LEAK_ALIAS | TUN_LEAK_WINDNS_CLIENT => true,
        TUN_LEAK_ALL | TUN_LEAK_ALL_EXCEPT_LAN | TUN_LEAK_MISCONFIG_TUN | TUN_LEAK_ICMP => false,
        _ => leak.low != 0 && leak.low == leak.high && matches!(leak.low, 53 | 853),
    }
}

/// The number of stored detail entries the scope hides, for the note that
/// names them.
pub fn leak_hidden_count(scope: LeakScope, entries: &[String]) -> usize {
    entries
        .iter()
        .filter(|entry| !is_unprefixed_scope_entry(entry) && leak_scope_hides(scope, entry))
        .count()
}

/// The number of stored entries the scope selector does not own: the detail
/// list the custom scope edits.
pub fn leak_detail_count(entries: &[String]) -> usize {
    entries
        .iter()
        .filter(|entry| !is_unprefixed_scope_entry(entry))
        .count()
}

/// Whether the list holds `value` as an unprefixed named entry.
fn leak_block_holds(entries: &[String], value: &str) -> bool {
    entries.iter().any(|entry| {
        let folded = fold_lower(entry);
        matches!(
            parse_leak(folded.as_ref()),
            Some(leak) if leak.prefix.is_none() && leak.name == value
        )
    })
}

/// Whether `entry` is one of the two unprefixed scope values.
pub fn is_unprefixed_scope_entry(entry: &str) -> bool {
    let folded = fold_lower(entry);
    matches!(
        parse_leak(folded.as_ref()),
        Some(leak) if leak.prefix.is_none()
            && matches!(leak.name, TUN_LEAK_ALL | TUN_LEAK_ALL_EXCEPT_LAN)
    )
}

impl Default for TunCfg {
    fn default() -> Self {
        Self {
            name: DEFAULT_TUN_NAME.into(),
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
            auto_system_wfp_block_leak: DEFAULT_TUN_LEAK_BLOCK
                .iter()
                .map(|entry| (*entry).into())
                .collect(),
            dns_alias_expanded: false,
            auto_system_dns_to_gateway: false,
            extra: Map::new(),
        }
    }
}

/// The stored shape of a TUN block, before the leak-list migration: the raw
/// list is what tells the load that a `dns` alias was stored, which
/// [`TunCfg`] would have lost by keeping only the canonical entries.
/// Field-for-field [`TunCfg`] minus the load-time flag.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct StoredTunCfg {
    name: String,
    desc: String,
    mtu: u32,
    gateway: Vec<String>,
    dns: Vec<String>,
    user_level: Option<u32>,
    auto_system_routing_table: Vec<String>,
    auto_outbounds_interface: String,
    auto_system_wfp_block_leak: Vec<String>,
    auto_system_dns_to_gateway: bool,
    sniffing: Sniffing,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Default for StoredTunCfg {
    /// The fresh-install seed, so a key the stored file omits loads the
    /// seeded value exactly as [`TunCfg`] did before the split.
    fn default() -> Self {
        let seed = TunCfg::default();
        Self {
            name: seed.name,
            desc: seed.desc,
            mtu: seed.mtu,
            gateway: seed.gateway,
            dns: seed.dns,
            user_level: seed.user_level,
            auto_system_routing_table: seed.auto_system_routing_table,
            auto_outbounds_interface: seed.auto_outbounds_interface,
            auto_system_wfp_block_leak: seed.auto_system_wfp_block_leak,
            auto_system_dns_to_gateway: seed.auto_system_dns_to_gateway,
            sniffing: seed.sniffing,
            extra: seed.extra,
        }
    }
}

impl<'de> Deserialize<'de> for TunCfg {
    /// Load through the leak-list migration: both a stored profile and a raw
    /// JSON edit reach the model with the canonical entries, and the alias
    /// expansion is remembered for the settings pass.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(StoredTunCfg::deserialize(deserializer)?.into())
    }
}

impl From<StoredTunCfg> for TunCfg {
    fn from(stored: StoredTunCfg) -> Self {
        let (auto_system_wfp_block_leak, dns_alias_expanded) =
            canonicalize_leak_block(&stored.auto_system_wfp_block_leak);
        Self {
            name: stored.name,
            desc: stored.desc,
            mtu: stored.mtu,
            gateway: stored.gateway,
            dns: stored.dns,
            user_level: stored.user_level,
            auto_system_routing_table: stored.auto_system_routing_table,
            auto_outbounds_interface: stored.auto_outbounds_interface,
            auto_system_wfp_block_leak,
            dns_alias_expanded,
            auto_system_dns_to_gateway: stored.auto_system_dns_to_gateway,
            sniffing: stored.sniffing,
            extra: stored.extra,
        }
    }
}

impl TunCfg {
    /// The adapter name the emitted TUN inbound carries: the trimmed
    /// setting, or [`DEFAULT_TUN_NAME`] when the setting is blank. The core
    /// fills a name-less TUN inbound with a random free `utun10`-`utun1024`
    /// name (infra/conf/tun.go), which nothing on this side can map back to
    /// the devnode to clean up, the tunnel adapter the DNS takeover must
    /// exclude from its capture, or the adapter to exclude from the latency
    /// probe's uplink pick — so the inbound always names its adapter.
    pub fn effective_name(&self) -> &str {
        let trimmed = self.name.trim();
        if trimmed.is_empty() {
            DEFAULT_TUN_NAME
        } else {
            trimmed
        }
    }

    /// Whether the leak list keeps the system's DNS inside the tunnel — port
    /// 53 over UDP or TCP, or Windows' DNS Client service, which needs
    /// resolvers of its own (`BlocksSystemDNS`, proxy/tun/wfp_leak.go). An
    /// entry is read the way the core reads it: the `dns` alias blocks the
    /// system's DNS, and a port spelling counts however it is cased or padded
    /// with zeros.
    pub fn leak_blocks_system_dns(&self) -> bool {
        self.auto_system_wfp_block_leak
            .iter()
            .any(|entry| leak_entry_blocks_system_dns(entry))
    }

    /// Whether the leak list carries the unrouted-family entry.
    pub fn leak_blocks_misconfig_tun(&self) -> bool {
        self.auto_system_wfp_block_leak
            .iter()
            .any(|entry| fold_eq(entry, TUN_LEAK_MISCONFIG_TUN))
    }

    /// Whether the leak list keeps traffic of an address family the routing
    /// table does not route into the tunnel inside the tunnel: it names
    /// [`TUN_LEAK_MISCONFIG_TUN`], or it states a non-custom scope, whose
    /// filters block every destination outside the local network
    /// (`tun_windows_wfp.go`, filter weights). A detail list without the
    /// entry can still leak, so the settings pass warns only then.
    pub fn leak_blocks_unrouted_family(&self) -> bool {
        self.leak_blocks_misconfig_tun()
            || leak_scope(&self.auto_system_wfp_block_leak) != LeakScope::Custom
    }

    /// Whether an in-memory list still carries the `dns` alias — a model
    /// built by hand rather than loaded. The settings pass warns for it
    /// exactly as it does for a load that expanded the alias.
    pub fn leak_holds_dns_alias(&self) -> bool {
        self.auto_system_wfp_block_leak
            .iter()
            .any(|entry| fold_eq(entry, DNS_LEAK_ALIAS))
    }

    /// Whether this block reached the model with the `dns` alias still
    /// spelled — a load that expanded it, or a list built in memory that still
    /// carries it. The one state the settings pass warns about.
    pub fn leak_alias_migrated(&self) -> bool {
        self.dns_alias_expanded || self.leak_holds_dns_alias()
    }

    /// The leak list in the form the core stores and the generator emits
    /// (`ExpandWfpBlockLeak`, proxy/tun/wfp_leak.go): every entry lowercased,
    /// the `dns` alias replaced by [`DNS_LEAK_ENTRIES`], a port written
    /// without leading zeros, and duplicates dropped in the model's own
    /// order. An entry the core would refuse stays as written, so validation
    /// reports it.
    pub fn canonical_leak_block(&self) -> Vec<String> {
        canonicalize_leak_block(&self.auto_system_wfp_block_leak).0
    }

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
            // The name is never blank on the wire, whatever the setting
            // holds (see `effective_name`); the other storage-only fields
            // still strip their cleared values.
            o.insert(
                "name".into(),
                Value::String(self.effective_name().to_string()),
            );
            if self.desc.is_empty() {
                o.remove("desc");
            }
            if self.mtu == 0 {
                o.remove("mtu");
            }
            // The gateway editor can hold a blank row, and a hand-edited
            // entry can carry padding; Xray parses every entry with
            // `netip.MustParsePrefix`, which trims neither and panics on a
            // blank or padded string. Emit only trimmed, non-empty entries.
            let gateways: Vec<&str> = self
                .gateway
                .iter()
                .map(|entry| entry.trim())
                .filter(|entry| !entry.is_empty())
                .collect();
            if gateways.is_empty() {
                o.remove("gateway");
            } else if gateways.len() != self.gateway.len()
                || gateways
                    .iter()
                    .zip(self.gateway.iter())
                    .any(|(trimmed, raw)| *trimmed != raw.as_str())
            {
                o.insert("gateway".into(), json!(gateways));
            }
            if self.dns.is_empty() {
                o.remove("dns");
            }
            if self.auto_system_routing_table.is_empty() {
                o.remove("autoSystemRoutingTable");
            }
            // The leak block is emitted by the generator, not here: the key
            // reaches the wire only while the TUN inbound and the DNS module
            // are both present (the predicate `config_runs_tun_dns` reads
            // back), and the generator adds the canonical value under that
            // gate.
            o.remove("autoSystemWfpBlockLeak");
        }
        // Built as a map directly: the envelope is an object by construction,
        // so adding the optional `sniffing` key needs no shape check.
        let mut ib = Map::new();
        ib.insert("tag".into(), Value::String(TUN_INBOUND_TAG.into()));
        ib.insert("protocol".into(), Value::String("tun".into()));
        ib.insert("settings".into(), set);
        if let Some(sn) = self.sniffing.to_wire(fakedns) {
            ib.insert("sniffing".into(), sn);
        }
        Value::Object(ib)
    }
}
#[cfg(test)]
mod tun_tests {
    use super::{
        DEFAULT_TUN_LEAK_BLOCK, DEFAULT_TUN_NAME, DNS_LEAK_ENTRIES, LeakScope,
        TUN_LEAK_MISCONFIG_TUN, TunCfg, leak_detail_count, leak_entry_is_valid, leak_hidden_count,
        leak_scope, leak_scope_hides, set_leak_scope,
    };
    use serde_json::json;

    /// The seeded list as the stored-file `Vec<String>`.
    fn seeded_leak_block() -> Vec<String> {
        DEFAULT_TUN_LEAK_BLOCK
            .iter()
            .map(|entry| (*entry).to_string())
            .collect()
    }

    /// Load a TUN block from its stored JSON through the model's own
    /// deserializer — the path a settings file and a raw edit both take.
    fn load(value: serde_json::Value) -> TunCfg {
        serde_json::from_value(value).expect("the fixture must load")
    }

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
    fn fresh_install_leak_block_keeps_dns_the_local_network_and_the_family_guard() {
        // The seed states the scope the built-in routing defaults need:
        // private destinations stay direct, so the local network stays open,
        // the alias follows the DNS entries it stands for inside the core, and
        // the family guard covers a family with no route into the tunnel.
        let tun = TunCfg::default();
        assert_eq!(tun.auto_system_wfp_block_leak, seeded_leak_block());
        assert!(
            !tun.dns_alias_expanded,
            "the seed writes its own spelling, so no load happened"
        );
        assert!(tun.leak_blocks_system_dns());
        assert!(tun.leak_blocks_misconfig_tun());
        assert!(
            tun.leak_blocks_unrouted_family(),
            "the alias blocks every destination outside the local network"
        );
        assert!(!tun.auto_system_dns_to_gateway);
        assert_eq!(
            leak_scope(&tun.auto_system_wfp_block_leak),
            LeakScope::AllExceptLan
        );
        assert_eq!(leak_detail_count(&tun.auto_system_wfp_block_leak), 1);
    }

    #[test]
    fn the_scope_values_keep_the_unrouted_family_inside_the_tunnel() {
        let mut tun = TunCfg::default();
        for (entries, blocked) in [
            (vec!["udp/53"], false),
            (vec!["misconfigtun"], true),
            (vec!["all"], true),
            (vec!["allexceptlan"], true),
            (vec!["1.1.1.0/24:all"], false),
        ] {
            tun.auto_system_wfp_block_leak =
                entries.iter().map(|entry| (*entry).to_string()).collect();
            assert_eq!(tun.leak_blocks_unrouted_family(), blocked, "{entries:?}");
        }
    }

    #[test]
    fn leak_scope_reads_the_stored_list() {
        let scope = |entries: &[&str]| {
            leak_scope(&entries.iter().map(|e| e.to_string()).collect::<Vec<_>>())
        };
        assert_eq!(scope(&[]), LeakScope::Custom);
        assert_eq!(scope(&["udp/53"]), LeakScope::Custom);
        assert_eq!(scope(&["all"]), LeakScope::All);
        assert_eq!(scope(&["ALL"]), LeakScope::All);
        assert_eq!(scope(&["allexceptlan"]), LeakScope::AllExceptLan);
        assert_eq!(
            scope(&["allexceptlan", "all"]),
            LeakScope::All,
            "all wins when both scope values are stored"
        );
        assert_eq!(
            scope(&["1.1.1.0/24:all"]),
            LeakScope::Custom,
            "a prefixed all is a detail entry"
        );
        assert_eq!(
            scope(&["[::/0]:allexceptlan"]),
            LeakScope::Custom,
            "a prefixed allexceptlan is a detail entry"
        );
    }

    #[test]
    fn the_scope_hides_exactly_the_entries_it_contains() {
        // `all` blocks every protocol and address outside the tunnel, so every
        // valid entry is contained.
        for entry in [
            "udp/53",
            "tcp/853",
            "53",
            "1.1.1.0/24:53",
            "dns",
            "windnsclient",
            "icmp",
            "misconfigtun",
            "tcp/443",
            "1.1.1.0/24:all",
            "allexceptlan",
        ] {
            assert!(
                leak_scope_hides(LeakScope::All, entry),
                "all contains {entry:?}"
            );
        }

        // `allexceptlan` follows itself with 53, 853 and the DNS Client
        // service, so only those forms are contained; a bare or prefixed
        // spelling of them is too.
        for entry in [
            "dns",
            "windnsclient",
            "53",
            "853",
            "tcp/53",
            "udp/853",
            "1.1.1.0/24:53",
            "[::/0]:windnsclient",
            "1.1.1.0/24:dns",
        ] {
            assert!(
                leak_scope_hides(LeakScope::AllExceptLan, entry),
                "the alias contains {entry:?}"
            );
        }
        for entry in [
            "icmp",
            "misconfigtun",
            "tcp/443",
            "10-20",
            "53-54",
            "1.1.1.0/24:443",
            "all",
            "allexceptlan",
            "tcp",
        ] {
            assert!(
                !leak_scope_hides(LeakScope::AllExceptLan, entry),
                "the alias leaves room for {entry:?}"
            );
        }

        // Custom hides nothing; an invalid entry is never hidden, because the
        // scope does not contain a value that breaks the load.
        for (scope, entry) in [
            (LeakScope::Custom, "udp/53"),
            (LeakScope::Custom, "bogus"),
            (LeakScope::All, "bogus"),
            (LeakScope::AllExceptLan, "bogus"),
        ] {
            assert!(
                !leak_scope_hides(scope, entry),
                "{scope:?} must show {entry:?}"
            );
        }
    }

    #[test]
    fn the_hidden_count_matches_the_contained_entries() {
        let entries: Vec<String> = ["allexceptlan", "udp/53", "tcp/443", "bogus"]
            .map(String::from)
            .to_vec();
        assert_eq!(leak_hidden_count(LeakScope::All, &entries), 2);
        assert_eq!(leak_hidden_count(LeakScope::AllExceptLan, &entries), 1);
        assert_eq!(leak_hidden_count(LeakScope::Custom, &entries), 0);
    }

    #[test]
    fn setting_the_scope_rewrites_only_the_scope_entry() {
        let mut entries = vec!["udp/53".to_string(), "icmp".to_string()];
        set_leak_scope(&mut entries, LeakScope::All);
        assert_eq!(entries, vec!["udp/53", "icmp", "all"]);
        set_leak_scope(&mut entries, LeakScope::AllExceptLan);
        assert_eq!(
            entries,
            vec!["udp/53", "icmp", "allexceptlan"],
            "the previous scope value goes, the detail entries stay"
        );
        set_leak_scope(&mut entries, LeakScope::Custom);
        assert_eq!(entries, vec!["udp/53", "icmp"]);
        assert_eq!(leak_detail_count(&entries), 2);
    }

    #[test]
    fn setting_the_scope_keeps_prefixed_forms_and_drops_both_scope_values() {
        let mut entries = vec![
            "1.1.1.0/24:all".to_string(),
            "all".to_string(),
            "allexceptlan".to_string(),
            "[::/0]:allexceptlan".to_string(),
            "tcp/443".to_string(),
        ];
        set_leak_scope(&mut entries, LeakScope::Custom);
        assert_eq!(
            entries,
            vec!["1.1.1.0/24:all", "[::/0]:allexceptlan", "tcp/443"]
        );
        assert_eq!(leak_detail_count(&entries), 3);
    }

    #[test]
    fn a_stored_dns_alias_loads_expanded_and_is_saved_expanded() {
        // An old profile stores the alias. The load keeps the entries it
        // stands for — in the core's order — and remembers that it expanded
        // one, which is what the settings pass warns from.
        let mut expanded: Vec<String> = DNS_LEAK_ENTRIES.map(String::from).to_vec();
        expanded.push(TUN_LEAK_MISCONFIG_TUN.to_string());
        let tun = load(json!({ "autoSystemWfpBlockLeak": ["DNS", "MisconfigTun"] }));
        assert_eq!(tun.auto_system_wfp_block_leak, expanded);
        assert!(tun.dns_alias_expanded);
        assert!(tun.leak_blocks_system_dns());
        assert!(tun.leak_blocks_misconfig_tun());

        let saved = serde_json::to_value(&tun).expect("the loaded block serializes");
        assert_eq!(saved["autoSystemWfpBlockLeak"], json!(expanded));
        assert!(
            saved.get("dnsAliasExpanded").is_none(),
            "the flag is a load-time fact, never a stored key: {saved}"
        );

        // The stored spelling an older profile wrote, exactly as it was saved.
        let legacy = load(json!({ "autoSystemWfpBlockLeak": ["dns", "misconfigtun"] }));
        assert_eq!(legacy.auto_system_wfp_block_leak, expanded);
        assert!(legacy.dns_alias_expanded);
    }

    #[test]
    fn a_port_entry_is_canonicalised_by_the_load() {
        // The core lowercases the protocol and re-renders the port it parsed,
        // so a padded or cased spelling is the entry itself.
        let tun = load(json!({ "autoSystemWfpBlockLeak": ["TCP/053", "udp/853"] }));
        assert_eq!(
            tun.auto_system_wfp_block_leak,
            vec!["tcp/53".to_string(), "udp/853".to_string()]
        );
        assert!(
            !tun.dns_alias_expanded,
            "a port entry is not the alias, so nothing was expanded"
        );
    }

    #[test]
    fn duplicate_entries_collapse_keeping_the_first_spelling() {
        // Port forms and an alias that reaches the same entries all fold to
        // one list: the core drops a value it already holds.
        let tun = load(json!({
            "autoSystemWfpBlockLeak": ["udp/53", "UDP/53", "udp/053", "dns"],
        }));
        assert_eq!(
            tun.auto_system_wfp_block_leak,
            DNS_LEAK_ENTRIES.map(String::from).to_vec()
        );
        assert!(tun.dns_alias_expanded);
    }

    #[test]
    fn a_port_the_core_refuses_is_kept_for_validation() {
        // The load must not rewrite a value the core refuses: the settings
        // pass reports the entry, and the user sees the spelling to fix.
        let tun = load(json!({
            "autoSystemWfpBlockLeak": ["tcp/0", "udp/65536", "tcp/x", "bogus"],
        }));
        assert_eq!(
            tun.auto_system_wfp_block_leak,
            vec![
                "tcp/0".to_string(),
                "udp/65536".to_string(),
                "tcp/x".to_string(),
                "bogus".to_string()
            ]
        );
        assert!(!tun.dns_alias_expanded);
    }

    #[test]
    fn every_form_the_core_parses_is_accepted() {
        // `parseLeak` covers the named values, a protocol alone, a protocol
        // with a port or a range, a bare port or range for both protocols,
        // and any of those behind an IPv4 or bracketed IPv6 CIDR prefix
        // (proxy/tun/wfp_leak.go).
        for entry in [
            "dns",
            "windnsclient",
            "misconfigtun",
            "all",
            "allexceptlan",
            "icmp",
            "tcp",
            "udp",
            "tcp/443",
            "udp/443",
            "tcp/10-20",
            "udp/10-20",
            "53",
            "10-20",
            "tcp/1-65535",
            "udp/1-65535",
            "1.1.1.0/24:53",
            "[::/0]:all",
            "[2001:db8::/32]:tcp/443",
            "8.8.8.8/32:all",
            "1.1.1.0/24:dns",
            "10.0.0.5/24:53",
            "TCP",
            "ALL",
            "udp/053",
            "tcp/443-443",
        ] {
            assert!(leak_entry_is_valid(entry), "{entry}");
        }
    }

    #[test]
    fn a_value_outside_the_core_grammar_is_refused() {
        // The core's `parseLeak` refuses each of these: an unknown name, a
        // zero or over-wide port, a reversed or dangling range, ports on a
        // named value, an unbracketed IPv6 or bracketed IPv4 prefix, a prefix
        // with leading zeros or an over-wide length, and an IPv4-mapped IPv6
        // prefix.
        for entry in [
            "bogus",
            "tcp/0",
            "udp/0",
            "tcp/65536",
            "udp/65536",
            "tcp/10-5",
            "tcp/",
            "tcp/x",
            "tcp/10-",
            "tcp/-5",
            "tcp/1-2-3",
            "53-",
            "+53",
            "dns/53",
            "all/53",
            "icmp/1",
            "[1.1.1.0/24]:53",
            "::/0:all",
            "10.0.0.0/030:53",
            "010.0.0.0/30:53",
            "1.1.1.0/24:",
            "1.1.1.0/33:53",
            "[::/129]:53",
            "[::ffff:1.2.3.4/128]:53",
        ] {
            assert!(!leak_entry_is_valid(entry), "{entry}");
        }
    }

    #[test]
    fn the_load_keeps_the_core_canonical_form_of_every_value() {
        // Lower case, CIDR masked, ports from their numeric value, duplicates
        // dropped in first-seen order, and `tcp/1-65535` rendered as `tcp`
        // (`leak.String`, proxy/tun/wfp_leak.go).
        let tun = load(json!({
            "autoSystemWfpBlockLeak": [
                "ALL",
                "1.1.1.5/24:53",
                "[2001:db8::5/32]:TCP/0443-0500",
                "TCP/1-65535",
                "UDP/010-20",
                "udp/10-20",
                "tcp/443-443",
            ],
        }));
        assert_eq!(
            tun.auto_system_wfp_block_leak,
            vec![
                "all".to_string(),
                "1.1.1.0/24:53".to_string(),
                "[2001:db8::/32]:tcp/443-500".to_string(),
                "tcp".to_string(),
                "udp/10-20".to_string(),
                "tcp/443".to_string(),
            ]
        );
    }

    #[test]
    fn a_prefixed_dns_alias_expands_with_its_prefix() {
        // The app stores the five entries the alias stands for, and a CIDR
        // prefix on the alias limits every one of them, as the core's own
        // expansion does.
        let tun = load(json!({ "autoSystemWfpBlockLeak": ["1.1.1.0/24:dns"] }));
        assert_eq!(
            tun.auto_system_wfp_block_leak,
            vec![
                "1.1.1.0/24:udp/53".to_string(),
                "1.1.1.0/24:tcp/53".to_string(),
                "1.1.1.0/24:windnsclient".to_string(),
                "1.1.1.0/24:tcp/853".to_string(),
                "1.1.1.0/24:udp/853".to_string(),
            ]
        );
        assert!(tun.dns_alias_expanded);
        assert!(tun.leak_blocks_system_dns());
    }

    #[test]
    fn the_system_dns_predicate_mirrors_the_core() {
        // `BlocksSystemDNS` over the core's expansion is true for `all`,
        // `allexceptlan` (which the expansion follows with the DNS entries),
        // `dns`, `windnsclient`, and anything covering TCP or UDP port 53,
        // however it is limited to addresses or narrowed to a range.
        for entry in [
            "all",
            "allexceptlan",
            "dns",
            "windnsclient",
            "53",
            "udp/53",
            "tcp/53",
            "tcp",
            "udp",
            "tcp/1-65535",
            "tcp/40-60",
            "udp/53-53",
            "1.1.1.0/24:53",
            "[::/0]:53",
            "1.1.1.0/24:udp/53",
            "[::/0]:allexceptlan",
            "8.8.8.8/32:all",
            "1.1.1.0/24:dns",
            "TCP/053",
        ] {
            let tun = TunCfg {
                auto_system_wfp_block_leak: vec![entry.to_string()],
                ..Default::default()
            };
            assert!(tun.leak_blocks_system_dns(), "{entry}");
        }
        for entry in [
            "icmp",
            "misconfigtun",
            "tcp/853",
            "udp/853",
            "tcp/443",
            "udp/10-20",
            "tcp/54-60",
            "1.1.1.0/24:icmp",
            "bogus",
            "tcp/0",
        ] {
            let tun = TunCfg {
                auto_system_wfp_block_leak: vec![entry.to_string()],
                ..Default::default()
            };
            assert!(!tun.leak_blocks_system_dns(), "{entry}");
        }
        let clear = TunCfg {
            auto_system_wfp_block_leak: Vec::new(),
            ..Default::default()
        };
        assert!(!clear.leak_blocks_system_dns());
    }

    #[test]
    fn the_canonical_form_is_what_the_generator_emits() {
        // A model edited in memory reaches the generator through this form:
        // folded, alias expanded in place, ports without leading zeros,
        // duplicates gone, order kept, and a value the core refuses kept
        // verbatim for the validation pass.
        let tun = TunCfg {
            auto_system_wfp_block_leak: vec![
                "DNS".into(),
                "TCP/053".into(),
                "UDP/53".into(),
                "Bogus".into(),
            ],
            ..Default::default()
        };
        let mut expected: Vec<String> = DNS_LEAK_ENTRIES.map(String::from).to_vec();
        expected.push("Bogus".into());
        assert_eq!(tun.canonical_leak_block(), expected);
    }

    #[test]
    fn wire_form_leaves_the_leak_block_to_the_generator() {
        // The key is a generator decision (TUN inbound plus DNS module), so
        // the base wire projection never carries it on its own.
        let tun = TunCfg::default();
        assert!(
            tun.to_wire(false)["settings"]
                .get("autoSystemWfpBlockLeak")
                .is_none()
        );
        assert!(
            tun.to_wire(false)["settings"]
                .get("autoSystemDnsToGateway")
                .is_none(),
            "the false Linux-only switch stays off the wire"
        );
    }

    #[test]
    fn wire_form_always_names_the_adapter() {
        // A name-less TUN inbound would let the core create a random
        // `utun10`-`utun1024` adapter (infra/conf/tun.go) that nothing on
        // this side maps back to the devnode to clean up, the tunnel adapter
        // the DNS takeover must exclude from its capture, or the adapter to
        // exclude from the probe's uplink pick, so the emitted settings
        // always carry a name.
        let blank = TunCfg {
            name: " \t ".into(),
            ..Default::default()
        };
        assert_eq!(blank.effective_name(), DEFAULT_TUN_NAME);
        assert_eq!(
            blank.to_wire(false)["settings"]["name"],
            serde_json::json!(DEFAULT_TUN_NAME)
        );

        let named = TunCfg {
            name: "  my-tun  ".into(),
            ..Default::default()
        };
        assert_eq!(named.effective_name(), "my-tun");
        assert_eq!(
            named.to_wire(false)["settings"]["name"],
            serde_json::json!("my-tun")
        );
        // Storage keeps the setting exactly as typed, blank or padded: only
        // the wire form normalizes (see the cleared-state test).
        assert_eq!(named.name, "  my-tun  ");
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

    /// The gateway editor's Add button pushes a blank row, and a hand-edited
    /// entry can carry padding. Xray parses every entry with
    /// `netip.MustParsePrefix`, which trims neither and panics the core on a
    /// blank or padded string, so the wire form holds trimmed, non-empty
    /// entries only.
    #[test]
    fn blank_and_padded_gateway_rows_never_reach_the_wire() {
        let tun = TunCfg {
            gateway: vec![
                " 10.255.0.1/30 ".into(),
                String::new(),
                " ".into(),
                "fd00::1/64".into(),
            ],
            ..Default::default()
        };
        assert_eq!(
            tun.to_wire(false)["settings"]["gateway"],
            serde_json::json!(["10.255.0.1/30", "fd00::1/64"])
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
            auto_system_wfp_block_leak: Vec::new(),
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
        assert_eq!(
            value["autoSystemWfpBlockLeak"],
            serde_json::json!([]),
            "a cleared leak block must serialize explicitly, not be omitted"
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
        assert_eq!(
            restored.auto_system_wfp_block_leak,
            Vec::<String>::new(),
            "cleared leak block must load back empty, not resurrect the seed"
        );
    }
}
