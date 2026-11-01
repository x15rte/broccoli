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
    /// TUN. Most are `tcp/<port>`/`udp/<port>` filters; [`TUN_LEAK_WINDNS_CLIENT`]
    /// blocks Windows' DNS Client service, [`TUN_LEAK_MISCONFIG_TUN`] drops an
    /// address family the routing table does not route into the tunnel, and
    /// [`DNS_LEAK_ALIAS`] is an alias the core expands into
    /// [`DNS_LEAK_ENTRIES`] before it matches (`ExpandWfpBlockLeak`,
    /// proxy/tun/wfp_leak.go). The load stores the canonical form
    /// ([`Self::canonical_leak_block`]). Always serialized (storage): the
    /// seeded policy must survive a round-trip after the user removes an
    /// entry, and the generator emits it whenever the TUN inbound and the DNS
    /// module are both present (the same predicate the runtime reads back).
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

/// The leak-block entries a fresh install runs: everything `dns` stands for,
/// then the unrouted family. A TUN session keeps the system's DNS and the
/// unrouted family inside the tunnel until the user removes an entry.
pub const DEFAULT_TUN_LEAK_BLOCK: [&str; 6] = [
    DNS_LEAK_ENTRIES[0],
    DNS_LEAK_ENTRIES[1],
    DNS_LEAK_ENTRIES[2],
    DNS_LEAK_ENTRIES[3],
    DNS_LEAK_ENTRIES[4],
    TUN_LEAK_MISCONFIG_TUN,
];

/// One `tcp/<port>` or `udp/<port>` leak entry the core parses: a connection
/// to that port may only go through the TUN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeakPort {
    tcp: bool,
    port: u16,
}

impl LeakPort {
    /// The protocol token the core matches, `tcp` or `udp`.
    pub fn protocol(self) -> &'static str {
        if self.tcp { "tcp" } else { "udp" }
    }

    /// The port the filter blocks.
    pub fn port(self) -> u16 {
        self.port
    }
}

/// The core's spelling of the value, `tcp/<port>` or `udp/<port>`.
impl std::fmt::Display for LeakPort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.protocol(), self.port())
    }
}

/// Parse one canonical `tcp/<port>` or `udp/<port>` value the way the core
/// does (`parseLeakPort`, proxy/tun/wfp_leak.go): the protocol token, then a
/// decimal port in `1..=65535`. Go's `strconv.ParseUint` reads digits only, so
/// a sign, padding, a second slash or a non-digit anywhere refuses the value.
fn parse_leak_port(value: &str) -> Option<LeakPort> {
    let (protocol, digits) = value.split_once('/')?;
    let tcp = match protocol {
        "tcp" => true,
        "udp" => false,
        _ => return None,
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port: u16 = digits.parse().ok()?;
    (port != 0).then_some(LeakPort { tcp, port })
}

/// The protocol and port of one `tcp/<port>`/`udp/<port>` leak entry, folded
/// the way the core lowercases it, or `None` for any other spelling. The leak
/// editor asks this to decide whether an entry renders as a port row; an
/// unparseable port stays an ordinary value the user can fix as text.
pub fn leak_port(entry: &str) -> Option<LeakPort> {
    parse_leak_port(&fold_lower(entry))
}

/// The lowest port no entry names yet, for the editor's "add a port" button: a
/// new row that repeated an existing entry would edit the same value twice.
pub fn next_free_leak_port(entries: &[String]) -> LeakPort {
    let held: Vec<LeakPort> = entries
        .iter()
        .filter_map(|entry| leak_port(entry))
        .collect();
    let port = (1..=u16::MAX)
        .find(|port| held.iter().all(|held| held.port != *port))
        .unwrap_or(1);
    LeakPort { tcp: true, port }
}

/// The canonical form of one leak list, plus whether the `dns` alias was among
/// its stored spellings: every entry lowercased, the alias replaced by
/// [`DNS_LEAK_ENTRIES`], a port written without leading zeros, and duplicates
/// dropped with the first spelling kept and the order preserved — the core's
/// own expansion (`ExpandWfpBlockLeak`, proxy/tun/wfp_leak.go). An entry the
/// core would refuse stays as written, so the validation pass reports it
/// instead of the load rewriting it away.
fn canonicalize_leak_block(entries: &[String]) -> (Vec<String>, bool) {
    let mut canonical: Vec<String> = Vec::with_capacity(entries.len());
    let mut dns_alias_expanded = false;
    for entry in entries {
        let folded = fold_lower(entry);
        if folded.as_ref() == DNS_LEAK_ALIAS {
            dns_alias_expanded = true;
            for leak in DNS_LEAK_ENTRIES {
                push_unique_leak(&mut canonical, leak);
            }
            continue;
        }
        match parse_leak_port(&folded) {
            Some(port) => push_unique_leak(&mut canonical, &port.to_string()),
            None => push_unique_leak(&mut canonical, &folded),
        }
    }
    (canonical, dns_alias_expanded)
}

/// Append `entry` unless the list already holds it. Every entry reaching here
/// is folded already, so an exact comparison is the core's own duplicate
/// check.
fn push_unique_leak(list: &mut Vec<String>, entry: &str) {
    if !list.iter().any(|kept| kept == entry) {
        list.push(entry.to_string());
    }
}

/// Whether one stored leak entry keeps the system's DNS inside the tunnel,
/// read the way the core reads an expanded list (`BlocksSystemDNS`,
/// proxy/tun/wfp_leak.go): the alias and the DNS Client service block it, and
/// so does a port filter on port 53.
fn leak_entry_blocks_system_dns(entry: &str) -> bool {
    let folded = fold_lower(entry);
    let folded = folded.as_ref();
    folded == DNS_LEAK_ALIAS
        || folded == TUN_LEAK_WINDNS_CLIENT
        || parse_leak_port(folded).is_some_and(|port| port.port == 53)
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
    use super::{DEFAULT_TUN_LEAK_BLOCK, DEFAULT_TUN_NAME, DNS_LEAK_ENTRIES, TunCfg};
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
    fn fresh_install_leak_block_covers_the_system_dns_and_the_unrouted_family() {
        // The seed carries every entry `dns` stands for, then the unrouted
        // family: the core installs exactly these filters inside its own
        // process, and nothing is left behind an alias a load would expand.
        let tun = TunCfg::default();
        assert_eq!(tun.auto_system_wfp_block_leak, seeded_leak_block());
        assert!(
            !tun.dns_alias_expanded,
            "the seed writes the expansion, so no load happened"
        );
        assert!(tun.leak_blocks_system_dns());
        assert!(tun.leak_blocks_misconfig_tun());
        assert!(!tun.auto_system_dns_to_gateway);
    }

    #[test]
    fn a_stored_dns_alias_loads_expanded_and_is_saved_expanded() {
        // An old profile stores the alias. The load keeps the entries it
        // stands for — in the core's order — and remembers that it expanded
        // one, which is what the settings pass warns from.
        let tun = load(json!({ "autoSystemWfpBlockLeak": ["DNS", "MisconfigTun"] }));
        assert_eq!(tun.auto_system_wfp_block_leak, seeded_leak_block());
        assert!(tun.dns_alias_expanded);
        assert!(tun.leak_blocks_system_dns());
        assert!(tun.leak_blocks_misconfig_tun());

        let saved = serde_json::to_value(&tun).expect("the loaded block serializes");
        assert_eq!(saved["autoSystemWfpBlockLeak"], json!(seeded_leak_block()));
        assert!(
            saved.get("dnsAliasExpanded").is_none(),
            "the flag is a load-time fact, never a stored key: {saved}"
        );

        // The stored spelling an older profile wrote, exactly as it was saved.
        let legacy = load(json!({ "autoSystemWfpBlockLeak": ["dns", "misconfigtun"] }));
        assert_eq!(legacy.auto_system_wfp_block_leak, seeded_leak_block());
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
    fn the_system_dns_predicate_mirrors_the_core() {
        // `BlocksSystemDNS` is true for exactly these three entries; the alias
        // stands for them, so an in-memory list holding it reads true too.
        for entry in [
            DNS_LEAK_ENTRIES[0],
            DNS_LEAK_ENTRIES[1],
            DNS_LEAK_ENTRIES[2],
        ] {
            let tun = TunCfg {
                auto_system_wfp_block_leak: vec![entry.to_string()],
                ..Default::default()
            };
            assert!(tun.leak_blocks_system_dns(), "{entry}");
        }
        for entry in ["tcp/853", "udp/853", "misconfigtun", "TCP/53", "dns"] {
            let tun = TunCfg {
                auto_system_wfp_block_leak: vec![entry.to_string()],
                ..Default::default()
            };
            let expected = matches!(entry, "TCP/53" | "dns");
            assert_eq!(tun.leak_blocks_system_dns(), expected, "{entry}");
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
        // duplicates gone, order kept, and a value the core refuses kept as
        // written.
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
        expected.push("bogus".into());
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
