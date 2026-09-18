//! Outbound model: protocol enum + per-protocol settings,
//! mux, and the wire envelope (`tag` is injected by the generator from
//! `ServerProfile::tag()`).

use super::inbound::Sniffing;
use super::stream::StreamModel;
use super::{
    Int32Range, skip_empty_map, skip_empty_str, skip_empty_vec, skip_false, skip_zero_u16,
};
use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

/// The 12 client-side outbound protocols (infra/conf/xray.go:37-52).
/// Serializes to the Xray protocol string.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Protocol {
    #[default]
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Socks,
    Http,
    Wireguard,
    Freedom,
    Blackhole,
    Dns,
    Loopback,
    Hysteria,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Vless => "vless",
            Protocol::Vmess => "vmess",
            Protocol::Trojan => "trojan",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::Socks => "socks",
            Protocol::Http => "http",
            Protocol::Wireguard => "wireguard",
            Protocol::Freedom => "freedom",
            Protocol::Blackhole => "blackhole",
            Protocol::Dns => "dns",
            Protocol::Loopback => "loopback",
            Protocol::Hysteria => "hysteria",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("vless") {
            Some(Protocol::Vless)
        } else if s.eq_ignore_ascii_case("vmess") {
            Some(Protocol::Vmess)
        } else if s.eq_ignore_ascii_case("trojan") {
            Some(Protocol::Trojan)
        } else if s.eq_ignore_ascii_case("shadowsocks") {
            Some(Protocol::Shadowsocks)
        } else if s.eq_ignore_ascii_case("socks") {
            Some(Protocol::Socks)
        } else if s.eq_ignore_ascii_case("http") {
            Some(Protocol::Http)
        } else if s.eq_ignore_ascii_case("wireguard") {
            Some(Protocol::Wireguard)
        } else if s.eq_ignore_ascii_case("freedom") || s.eq_ignore_ascii_case("direct") {
            Some(Protocol::Freedom)
        } else if s.eq_ignore_ascii_case("blackhole") || s.eq_ignore_ascii_case("block") {
            Some(Protocol::Blackhole)
        } else if s.eq_ignore_ascii_case("dns") {
            Some(Protocol::Dns)
        } else if s.eq_ignore_ascii_case("loopback") {
            Some(Protocol::Loopback)
        } else if s.eq_ignore_ascii_case("hysteria") {
            Some(Protocol::Hysteria)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub fn from_str_lossy(s: &str) -> Self {
        Self::parse(s).expect("test protocol must be recognized")
    }
    pub const ALL: [Protocol; 12] = [
        Protocol::Vless,
        Protocol::Vmess,
        Protocol::Trojan,
        Protocol::Shadowsocks,
        Protocol::Socks,
        Protocol::Http,
        Protocol::Wireguard,
        Protocol::Freedom,
        Protocol::Blackhole,
        Protocol::Dns,
        Protocol::Loopback,
        Protocol::Hysteria,
    ];
}

impl Serialize for Protocol {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for Protocol {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = String::deserialize(d)?;
        Protocol::parse(&value).ok_or_else(|| {
            serde::de::Error::custom(format!("unsupported outbound protocol \"{value}\""))
        })
    }
}

// ---------- per-protocol settings ----------

/// VLESS (vless.go:239-258). `seed` is parsed-but-inert upstream → hidden.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VlessSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub address: String,
    #[serde(skip_serializing_if = "skip_zero_u16")]
    pub port: u16,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub id: String,
    /// "" | "xtls-rprx-vision" | "xtls-rprx-vision-udp443"
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub flow: String,
    /// "none" or mlkem768x25519plus.<native|xorpub|random>.<1rtt|0rtt>.<keys>
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub encryption: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reverse: Option<VlessReverse>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// VLESS reverse proxy outbound.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VlessReverse {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<Sniffing>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// VMess (vmess.go:111-120). `alterId` is gone upstream.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VmessSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub address: String,
    #[serde(skip_serializing_if = "skip_zero_u16")]
    pub port: u16,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub id: String,
    /// aes-128-gcm | chacha20-poly1305 | auto
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub security: String,
    /// e.g. "AuthenticatedLength,NoTerminationSignal"
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub experiments: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub email: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Trojan (trojan.go:31-39). `flow` is removed upstream — not modeled.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TrojanSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub address: String,
    #[serde(skip_serializing_if = "skip_zero_u16")]
    pub port: u16,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub email: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Shadowsocks (shadowsocks.go:179-249): AEAD + 2022 methods only.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ShadowsocksSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub address: String,
    #[serde(skip_serializing_if = "skip_zero_u16")]
    pub port: u16,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub method: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub email: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// SOCKS outbound (socks.go:77-87) — note `user`/`pass`, not username/password.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SocksSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub address: String,
    #[serde(skip_serializing_if = "skip_zero_u16")]
    pub port: u16,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub user: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub pass: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub email: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// HTTP outbound (http.go:58-67).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub address: String,
    #[serde(skip_serializing_if = "skip_zero_u16")]
    pub port: u16,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub user: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub pass: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub email: String,
    #[serde(skip_serializing_if = "skip_empty_map")]
    pub headers: Map<String, Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// WireGuard (wireguard.go:59-68). mtu default 1420, domainStrategy "forceip".
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WireguardSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub secret_key: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub address: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub peers: Vec<WireguardPeer>,
    #[serde(skip_serializing_if = "skip_zero_u16")]
    pub mtu: u16,
    /// 0 or exactly 3 bytes; serializes as a JSON array of numbers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reserved: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub domain_strategy: String,
    #[serde(skip_serializing_if = "skip_false")]
    pub no_kernel_tun: bool,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for WireguardSettings {
    fn default() -> Self {
        Self {
            secret_key: String::new(),
            address: Vec::new(),
            peers: Vec::new(),
            mtu: 1420,
            reserved: None,
            domain_strategy: "forceip".into(),
            no_kernel_tun: false,
            extra: Map::new(),
        }
    }
}
/// Match Xray's accepted WireGuard key forms while enforcing the 32-byte key
/// size: 64 hexadecimal digits, or raw standard/URL-safe base64 with zero or
/// one trailing padding character.
pub(crate) fn is_valid_wireguard_key(value: &str) -> bool {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return true;
    }

    let encoded = match value.strip_suffix('=') {
        Some(raw) if !raw.ends_with('=') => raw,
        Some(_) => return false,
        None => value,
    };
    if encoded.len() != 43 {
        return false;
    }

    let mut decoded = [0_u8; 33];
    let result = if encoded.bytes().any(|byte| matches!(byte, b'+' | b'/')) {
        base64::engine::general_purpose::STANDARD_NO_PAD.decode_slice(encoded, &mut decoded)
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode_slice(encoded, &mut decoded)
    };
    matches!(result, Ok(32))
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WireguardPeer {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub public_key: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub pre_shared_key: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive: Option<u32>,
    #[serde(skip_serializing_if = "skip_empty_vec", rename = "allowedIPs")]
    pub allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub email: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Freedom (freedom.go:19-30) — direct + anti-censorship (fragment/noises/finalRules).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FreedomSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub target_strategy: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub redirect: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_level: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fragment: Option<Fragment>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub noises: Vec<Noise>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_protocol: Option<u32>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub final_rules: Vec<FreedomFinalRule>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Fragment {
    /// "tlshello" | range string like "1-3" | "" = all
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub packets: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_split: Option<Int32Range>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Noise {
    /// rand | str | hex | base64
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub r#type: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub packet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<Int32Range>,
    /// ip | ipv4 | ipv6
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub apply_to: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FreedomFinalRule {
    /// allow | block
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub action: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub network: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub port: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub ip: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_delay: Option<Int32Range>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Blackhole (blackhole.go:24-26) — the routing "block" target.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BlackholeSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<BlackholeResponse>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct BlackholeResponse {
    /// none | http
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub r#type: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for BlackholeResponse {
    fn default() -> Self {
        Self {
            r#type: "none".into(),
            extra: Map::new(),
        }
    }
}

/// DNS outbound (dns_proxy.go:60-71). nonIPQuery/blockTypes deprecated → not modeled.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DnsOutboundSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub rewrite_network: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub rewrite_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rewrite_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_level: Option<u32>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub rules: Vec<DnsOutRule>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DnsOutRule {
    /// direct | drop | return | hijack
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub action: String,
    /// PortList string, e.g. "1,3,5-10"
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub q_type: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub domain: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r_code: Option<u32>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Loopback (loopback.go:9-12) — loops back into an inbound chain.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LoopbackSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub inbound_tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<Sniffing>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Hysteria2 outbound (hysteria.go:13-17). Auth lives in transport
/// (`streamSettings.hysteriaSettings`); congestion/up/down/udphop moved to
/// `finalmask.quicParams`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HysteriaSettings {
    /// must be 2
    pub version: u32,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub address: String,
    #[serde(skip_serializing_if = "skip_zero_u16")]
    pub port: u16,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for HysteriaSettings {
    fn default() -> Self {
        Self {
            version: 2,
            address: String::new(),
            port: 0,
            extra: Map::new(),
        }
    }
}

/// Per-protocol settings, serialized untagged (the discriminant is the
/// sibling `protocol` key). Deserialization goes through
/// [`ProtocolSettings::from_value`] keyed by the protocol.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum ProtocolSettings {
    Vless(VlessSettings),
    Vmess(VmessSettings),
    Trojan(TrojanSettings),
    Shadowsocks(ShadowsocksSettings),
    Socks(SocksSettings),
    Http(HttpSettings),
    Wireguard(WireguardSettings),
    Freedom(FreedomSettings),
    Blackhole(BlackholeSettings),
    Dns(DnsOutboundSettings),
    Loopback(LoopbackSettings),
    Hysteria(HysteriaSettings),
}

impl Default for ProtocolSettings {
    fn default() -> Self {
        ProtocolSettings::Vless(VlessSettings::default())
    }
}

/// Deserialize a JSON value with the failing field path attached, so import
/// errors identify the exact value the user must repair (`settings`,
/// `streamSettings`, and `mux` all parse through this).
fn from_value_path<T>(value: Value) -> Result<T, serde_json::Error>
where
    T: serde::de::DeserializeOwned,
{
    serde_path_to_error::deserialize(value)
        .map_err(|error| <serde_json::Error as serde::de::Error>::custom(error.to_string()))
}

impl ProtocolSettings {
    pub fn protocol(&self) -> Protocol {
        match self {
            ProtocolSettings::Vless(_) => Protocol::Vless,
            ProtocolSettings::Vmess(_) => Protocol::Vmess,
            ProtocolSettings::Trojan(_) => Protocol::Trojan,
            ProtocolSettings::Shadowsocks(_) => Protocol::Shadowsocks,
            ProtocolSettings::Socks(_) => Protocol::Socks,
            ProtocolSettings::Http(_) => Protocol::Http,
            ProtocolSettings::Wireguard(_) => Protocol::Wireguard,
            ProtocolSettings::Freedom(_) => Protocol::Freedom,
            ProtocolSettings::Blackhole(_) => Protocol::Blackhole,
            ProtocolSettings::Dns(_) => Protocol::Dns,
            ProtocolSettings::Loopback(_) => Protocol::Loopback,
            ProtocolSettings::Hysteria(_) => Protocol::Hysteria,
        }
    }

    pub fn default_for(p: Protocol) -> Self {
        match p {
            Protocol::Vless => ProtocolSettings::Vless(VlessSettings::default()),
            Protocol::Vmess => ProtocolSettings::Vmess(VmessSettings::default()),
            Protocol::Trojan => ProtocolSettings::Trojan(TrojanSettings::default()),
            Protocol::Shadowsocks => ProtocolSettings::Shadowsocks(ShadowsocksSettings::default()),
            Protocol::Socks => ProtocolSettings::Socks(SocksSettings::default()),
            Protocol::Http => ProtocolSettings::Http(HttpSettings::default()),
            Protocol::Wireguard => ProtocolSettings::Wireguard(WireguardSettings::default()),
            Protocol::Freedom => ProtocolSettings::Freedom(FreedomSettings::default()),
            Protocol::Blackhole => ProtocolSettings::Blackhole(BlackholeSettings::default()),
            Protocol::Dns => ProtocolSettings::Dns(DnsOutboundSettings::default()),
            Protocol::Loopback => ProtocolSettings::Loopback(LoopbackSettings::default()),
            Protocol::Hysteria => ProtocolSettings::Hysteria(HysteriaSettings::default()),
        }
    }

    /// Parse a `settings` JSON object into the variant matching `p`.
    ///
    /// A malformed known field is fatal. Defaulting the whole object here
    /// would silently discard every valid and unknown sibling field. Errors
    /// include the failing field path so import failures identify the exact
    /// value the user must repair.
    pub fn from_value(p: Protocol, v: Value) -> Result<Self, serde_json::Error> {
        match p {
            Protocol::Vless => from_value_path(v).map(ProtocolSettings::Vless),
            Protocol::Vmess => from_value_path(v).map(ProtocolSettings::Vmess),
            Protocol::Trojan => from_value_path(v).map(ProtocolSettings::Trojan),
            Protocol::Shadowsocks => from_value_path(v).map(ProtocolSettings::Shadowsocks),
            Protocol::Socks => from_value_path(v).map(ProtocolSettings::Socks),
            Protocol::Http => from_value_path(v).map(ProtocolSettings::Http),
            Protocol::Wireguard => from_value_path(v).map(ProtocolSettings::Wireguard),
            Protocol::Freedom => from_value_path(v).map(ProtocolSettings::Freedom),
            Protocol::Blackhole => from_value_path(v).map(ProtocolSettings::Blackhole),
            Protocol::Dns => from_value_path(v).map(ProtocolSettings::Dns),
            Protocol::Loopback => from_value_path(v).map(ProtocolSettings::Loopback),
            Protocol::Hysteria => from_value_path(v).map(ProtocolSettings::Hysteria),
        }
    }
}

// ---------- mux (xray.go:102-124) ----------

/// Xray's mux block (`MuxConfig`). The wire semantics that used to live
/// only in a comment here — Xray reinterprets `concurrency` outside
/// `-1`/1..=128 and reads the XUDP knobs only while `enabled` is true —
/// are now enforced and rendered by the model rules in
/// `crate::model::validation` (`MuxXudpProxyUdp443Unsupported`,
/// `MuxConcurrencyReinterpreted`, `MuxXudpKnobsInert`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MuxModel {
    #[serde(skip_serializing_if = "skip_false")]
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xudp_concurrency: Option<i16>,
    /// reject | allow | skip (empty = Xray's wire default `reject`)
    #[serde(skip_serializing_if = "Option::is_none", rename = "xudpProxyUDP443")]
    pub xudp_proxy_udp443: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl MuxModel {
    pub fn is_empty(&self) -> bool {
        !self.enabled
            && self.concurrency.is_none()
            && self.xudp_concurrency.is_none()
            && self.xudp_proxy_udp443.is_none()
            && self.extra.is_empty()
    }
}

// ---------- the outbound envelope ----------

/// GUI model of one outbound. `tag` is NOT stored here — it derives from
/// `ServerProfile::tag()` at generation time.
#[derive(Clone, Debug, Default)]
pub struct OutboundModel {
    pub protocol: Protocol,
    pub settings: ProtocolSettings,
    pub stream: StreamModel,
    /// The raw value of the retired `proxySettings` key the stored object
    /// carried, when it did (any JSON shape). Xray's outbound build refuses a
    /// configuration that carries the key (infra/conf/xray.go:262), so the
    /// profile stays gated until the user resolves it; the value is kept only
    /// so the settings file round-trips it and is re-emitted with no
    /// migration. Generated configurations never carry it: [`Self::to_wire`]
    /// clears the field, while the gating finding
    /// `crate::model::validation::ValidationCode::OutboundProxySettingsRemoved`
    /// holds until the user resolves the key.
    pub retired_proxy_settings: Option<Value>,
    /// local IP/CIDR to bind
    pub send_through: Option<String>,
    /// asis | useip* | forceip*
    pub target_strategy: Option<String>,
    pub mux: MuxModel,
    pub extra: Map<String, Value>,
}
/// Mirror Xray's `requiresTransportSecurity` private endpoint predicate
/// (`infra/conf/xray.go` + `common/geodata/consts.go`).
pub fn endpoint_requires_transport_security(address: &str) -> bool {
    fn prefix_v4(address: u32, network: u32, prefix: u32) -> bool {
        let mask = u32::MAX << (32 - prefix);
        address & mask == network & mask
    }
    fn prefix_v6(address: u128, network: u128, prefix: u32) -> bool {
        let mask = u128::MAX << (128 - prefix);
        address & mask == network & mask
    }
    fn private_v4(address: std::net::Ipv4Addr) -> bool {
        let value = u32::from(address);
        [
            (0x0000_0000, 8),
            (0x0a00_0000, 8),
            (0x6440_0000, 10),
            (0x7f00_0000, 8),
            (0xa9fe_0000, 16),
            (0xac10_0000, 12),
            (0xc000_0000, 24),
            (0xc000_0200, 24),
            (0xc058_6300, 24),
            (0xc0a8_0000, 16),
            (0xc612_0000, 15),
            (0xc633_6400, 24),
            (0xcb00_7100, 24),
            (0xe000_0000, 3),
        ]
        .into_iter()
        .any(|(network, prefix)| prefix_v4(value, network, prefix))
    }

    if address.is_empty() {
        return false;
    }
    let mut parsed = address;
    if parsed.starts_with('[') && parsed.ends_with(']') {
        parsed = &parsed[1..parsed.len() - 1];
    }
    if parsed
        .as_bytes()
        .first()
        .is_some_and(|byte| !byte.is_ascii_alphanumeric())
        || parsed
            .as_bytes()
            .last()
            .is_some_and(|byte| !byte.is_ascii_alphanumeric())
    {
        parsed = parsed.trim();
    }

    if let Ok(ip) = parsed.parse::<std::net::IpAddr>() {
        let private = match ip {
            std::net::IpAddr::V4(ip) => private_v4(ip),
            std::net::IpAddr::V6(ip) => {
                if let Some(ipv4) = ip.to_ipv4_mapped() {
                    private_v4(ipv4)
                } else {
                    let value = u128::from(ip);
                    [
                        (0_u128, 127),
                        (0xfc00_u128 << 112, 7),
                        (0xfe80_u128 << 112, 10),
                        (0xff00_u128 << 112, 8),
                    ]
                    .into_iter()
                    .any(|(network, prefix)| prefix_v6(value, network, prefix))
                }
            }
        };
        return !private;
    }

    let domain = parsed.to_ascii_lowercase();
    let domain = domain.strip_suffix('.').unwrap_or(&domain);
    let private_suffix = [
        "lan",
        "localdomain",
        "example",
        "invalid",
        "localhost",
        "test",
        "local",
        "home.arpa",
        "internal",
    ]
    .into_iter()
    .any(|suffix| {
        domain == suffix
            || domain
                .strip_suffix(suffix)
                .is_some_and(|prefix| prefix.ends_with('.'))
    });
    let bytes = domain.as_bytes();
    let private_dotless = !bytes.is_empty()
        && bytes.len() <= 63
        && !bytes.contains(&b'.')
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    !(private_suffix || private_dotless)
}

impl OutboundModel {
    pub fn new(p: Protocol) -> Self {
        let mut model = Self {
            protocol: p,
            settings: ProtocolSettings::default_for(p),
            ..Default::default()
        };
        model.enforce_invariants();
        model
    }

    /// Make this outbound dial through `tag` — the one chain spelling the
    /// pinned core reads, `streamSettings.sockopt.dialerProxy`. Test-only:
    /// every chain fixture in the suite states the target through here.
    #[cfg(test)]
    pub(crate) fn chain_via(&mut self, tag: impl Into<String>) {
        let mut sockopt = self.stream.sockopt.take().unwrap_or_default();
        sockopt.dialer_proxy = tag.into();
        self.stream.sockopt = Some(sockopt);
    }

    /// Switch protocol and normalize the transport state that Hysteria2 owns.
    pub fn select_protocol(&mut self, protocol: Protocol) {
        let leaving_hysteria = self.protocol == Protocol::Hysteria
            || self.stream.network == super::stream::Network::Hysteria;
        self.protocol = protocol;
        self.settings = ProtocolSettings::default_for(protocol);
        if protocol == Protocol::Hysteria {
            let _ = self.stream.select_network(super::stream::Network::Hysteria);
        } else if leaving_hysteria {
            self.stream.network = super::stream::Network::Raw;
            self.stream.raw_settings = None;
            self.stream.hysteria_settings = None;
        }
        self.enforce_invariants();
    }

    /// Keep protocol/transport/security combinations executable by Xray.
    pub fn enforce_invariants(&mut self) {
        if let ProtocolSettings::Vless(settings) = &mut self.settings
            && settings.encryption.is_empty()
        {
            settings.encryption = "none".to_string();
        }
        if let ProtocolSettings::Vmess(settings) = &mut self.settings
            && !matches!(
                settings.security.as_str(),
                "auto" | "aes-128-gcm" | "chacha20-poly1305"
            )
        {
            settings.security = "auto".to_string();
        }
        if self.protocol == Protocol::Hysteria {
            if let ProtocolSettings::Hysteria(settings) = &mut self.settings {
                settings.version = 2;
            }
            let _ = self.stream.select_network(super::stream::Network::Hysteria);
            if let Some(settings) = self.stream.hysteria_settings.as_mut() {
                settings.version = 2;
            }
        }
        self.stream.enforce_invariants();
    }

    /// Serialize to the wire object with `tag` injected.
    pub fn to_wire(&self, tag: &str) -> Value {
        let mut normalized = self.clone();
        normalized.enforce_invariants();
        // The retired key is a settings-file fact only: it round-trips
        // through `servers.json` so the user still sees the profile's state,
        // and the generated document never carries it (the pinned core
        // refuses an outbound that does — infra/conf/xray.go:262).
        normalized.retired_proxy_settings = None;
        normalized.stream.retain_selected_stream_blocks_for_wire();
        let mut value = serde_json::to_value(&normalized).expect(
            "model serialization is infallible: the OutboundModel subtree serializes with \
             string map keys only and carries no float fields",
        );
        if let Value::Object(object) = &mut value {
            object.insert("tag".into(), Value::String(tag.to_string()));
        }
        value
    }
}

impl Serialize for OutboundModel {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut m = s.serialize_map(None)?;
        m.serialize_entry("protocol", self.protocol.as_str())?;
        m.serialize_entry("settings", &self.settings)?;
        if !self.stream.is_default() {
            m.serialize_entry("streamSettings", &self.stream)?;
        }
        if let Some(raw) = &self.retired_proxy_settings {
            m.serialize_entry("proxySettings", raw)?;
        }
        if let Some(v) = &self.send_through {
            m.serialize_entry("sendThrough", v)?;
        }
        if let Some(v) = &self.target_strategy {
            m.serialize_entry("targetStrategy", v)?;
        }
        if !self.mux.is_empty() {
            m.serialize_entry("mux", &self.mux)?;
        }
        for (k, v) in &self.extra {
            m.serialize_entry(k, v)?;
        }
        m.end()
    }
}

impl<'de> Deserialize<'de> for OutboundModel {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        let mut obj = match v {
            Value::Object(o) => o,
            _ => return Err(serde::de::Error::custom("outbound must be an object")),
        };
        let take = |obj: &mut Map<String, Value>, k: &str| obj.remove(k);
        let protocol = match take(&mut obj, "protocol") {
            Some(Value::String(value)) => Protocol::parse(&value).ok_or_else(|| {
                serde::de::Error::custom(format!("unsupported outbound protocol \"{value}\""))
            })?,
            Some(_) => {
                return Err(serde::de::Error::custom(
                    "outbound protocol must be a string",
                ));
            }
            None => Protocol::default(),
        };
        let settings_value = take(&mut obj, "settings").unwrap_or(Value::Object(Map::new()));
        let settings = ProtocolSettings::from_value(protocol, settings_value).map_err(|error| {
            serde::de::Error::custom(format!(
                "invalid {} outbound settings: {error}",
                protocol.as_str()
            ))
        })?;
        let stream = match take(&mut obj, "streamSettings") {
            Some(value) => from_value_path::<StreamModel>(value).map_err(|error| {
                serde::de::Error::custom(format!("invalid streamSettings: {error}"))
            })?,
            None => StreamModel::default(),
        };
        // Each of these three carries its own wire shape; a value that cannot
        // express it is fatal with the field path (the sibling fields above
        // follow the same rule), never consumed and dropped. JSON `null` is
        // the Go zero shape — an absent pointer field — so it stays legal.
        //
        // `proxySettings` is the exception: Xray's outbound build refuses a
        // configuration that carries it (infra/conf/xray.go:262, `outbound
        // "proxySettings"` → `"streamSettings.sockopt.dialerProxy"`), so the
        // key never fails the load — the profile is marked instead. Its raw
        // value is kept so the settings file round-trips the key unchanged
        // (nothing is migrated) while the gate stands. The value takes any
        // JSON shape (`json.RawMessage` upstream is not validated), and Go
        // binds the name case-insensitively: the first case variant is kept
        // and every other is dropped, so none can survive as an unknown key.
        let mut retired_proxy_settings = None;
        obj.retain(|key, value| {
            if key.eq_ignore_ascii_case("proxySettings") {
                if retired_proxy_settings.is_none() {
                    retired_proxy_settings = Some(value.clone());
                }
                false
            } else {
                true
            }
        });
        let send_through = match take(&mut obj, "sendThrough") {
            Some(value) => from_value_path::<Option<String>>(value).map_err(|error| {
                serde::de::Error::custom(format!("invalid sendThrough: {error}"))
            })?,
            None => None,
        };
        let target_strategy = match take(&mut obj, "targetStrategy") {
            Some(value) => from_value_path::<Option<String>>(value).map_err(|error| {
                serde::de::Error::custom(format!("invalid targetStrategy: {error}"))
            })?,
            None => None,
        };
        let mux = match take(&mut obj, "mux") {
            Some(value) => from_value_path::<MuxModel>(value)
                .map_err(|error| serde::de::Error::custom(format!("invalid mux: {error}")))?,
            None => MuxModel::default(),
        };
        let mut model = OutboundModel {
            protocol,
            settings,
            stream,
            retired_proxy_settings,
            send_through,
            target_strategy,
            mux,
            extra: obj,
        };
        model.enforce_invariants();
        Ok(model)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OutboundModel, Protocol, ProtocolSettings, endpoint_requires_transport_security,
        is_valid_wireguard_key,
    };
    use crate::model::settings::Language;
    use crate::model::stream::{
        FinalmaskModel, FinalmaskTcpMask, FinalmaskUdpMask, HysteriaTransport, Network,
        RawSettings, Security, XhttpSettings,
    };
    use base64::Engine as _;
    use serde_json::json;

    #[test]
    fn wireguard_key_accepts_every_xray_32_byte_encoding() {
        let bytes = [0xfb_u8; 32];
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let std_padded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let std_raw = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
        let url_padded = base64::engine::general_purpose::URL_SAFE.encode(bytes);
        let url_raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

        for value in [hex, std_padded, std_raw, url_padded, url_raw] {
            assert!(is_valid_wireguard_key(&value), "{value}");
        }
    }

    #[test]
    fn wireguard_key_rejects_malformed_or_wrong_size_values() {
        let wrong_size = base64::engine::general_purpose::STANDARD.encode([0_u8; 31]);
        let mixed_alphabet = format!(
            "-{}",
            &base64::engine::general_purpose::STANDARD_NO_PAD.encode([0xfb_u8; 32])[1..]
        );

        for value in [
            String::new(),
            "g".repeat(64),
            "0".repeat(63),
            wrong_size,
            format!(
                "{}=",
                base64::engine::general_purpose::STANDARD.encode([0_u8; 32])
            ),
            mixed_alphabet,
            format!("{}!", "A".repeat(42)),
        ] {
            assert!(!is_valid_wireguard_key(&value), "{value}");
        }
    }

    #[test]
    fn unknown_outbound_protocol_is_not_coerced_to_vless() {
        assert!(serde_json::from_value::<Protocol>(json!("future-protocol")).is_err());
        assert!(
            serde_json::from_value::<OutboundModel>(json!({
                "protocol": "future-protocol",
                "settings": {"address": "example.com", "port": 443}
            }))
            .is_err()
        );
    }

    #[test]
    fn private_endpoint_matcher_mirrors_xray_special_ranges_and_domains() {
        for private in [
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "[::1]",
            "fc00::1",
            "host.lan",
            "service.home.arpa.",
            "printer",
        ] {
            assert!(!endpoint_requires_transport_security(private), "{private}");
        }
        for public in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "example.com"] {
            assert!(endpoint_requires_transport_security(public), "{public}");
        }
    }

    #[test]
    fn public_vless_and_trojan_require_transport_security() {
        use crate::model::validation::{ValidationCode, validate_outbound};

        fn codes(outbound: &OutboundModel) -> Vec<ValidationCode> {
            validate_outbound(outbound)
                .iter()
                .map(|issue| issue.code.clone())
                .collect()
        }

        let mut vless = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(settings) = &mut vless.settings else {
            unreachable!();
        };
        settings.address = "example.com".into();
        // Canonical essentials (port, UUID id) so only the
        // transport-security rule under test can fire.
        settings.port = 443;
        settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
        assert!(codes(&vless).contains(&ValidationCode::PublicVlessRequiresTlsOrEncryption));
        let ProtocolSettings::Vless(settings) = &mut vless.settings else {
            unreachable!();
        };
        settings.encryption = "mlkem768x25519plus.native.0rtt.key".into();
        assert!(validate_outbound(&vless).is_empty());
        let ProtocolSettings::Vless(settings) = &mut vless.settings else {
            unreachable!();
        };
        settings.encryption = "none".into();
        let _ = vless.stream.select_security(Security::Tls);
        assert!(validate_outbound(&vless).is_empty());

        let mut trojan = OutboundModel::new(Protocol::Trojan);
        let ProtocolSettings::Trojan(settings) = &mut trojan.settings else {
            unreachable!();
        };
        settings.address = "8.8.8.8".into();
        settings.port = 443;
        settings.password = "secret".into();
        assert!(codes(&trojan).contains(&ValidationCode::PublicTrojanRequiresTlsOrReality));
        let ProtocolSettings::Trojan(settings) = &mut trojan.settings else {
            unreachable!();
        };
        settings.address = "router.local".into();
        assert!(validate_outbound(&trojan).is_empty());
    }

    #[test]
    fn vless_vision_flow_requires_transport_security_even_for_private_endpoints() {
        use crate::model::validation::{ValidationCode, validate_outbound};

        let mut outbound = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!();
        };
        settings.address = "router.local".into();
        // Canonical essentials (port, UUID id).
        settings.port = 443;
        settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
        settings.flow = "xtls-rprx-vision".into();
        let issues = validate_outbound(&outbound);
        let vision = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::VisionRequiresTlsOrReality)
            .expect("vision flow without security must be reported");
        assert_eq!(
            crate::i18n::validation_message(&vision.code, Language::En),
            "VLESS Vision flow requires TLS or REALITY"
        );

        let _ = outbound.stream.select_security(Security::Reality);
        if let Some(reality) = &mut outbound.stream.reality_settings {
            // Canonical essentials: Xray's REALITY client build
            // refuses an empty public key, so a clean sweep needs a valid
            // 32-byte base64url key (fingerprint/shortId/etc. may stay at
            // their empty defaults).
            reality.password = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".into();
        }
        assert!(validate_outbound(&outbound).is_empty());
    }

    #[test]
    fn protocol_transition_enters_and_leaves_hysteria_consistently() {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        outbound.select_protocol(Protocol::Hysteria);
        assert_eq!(outbound.protocol, Protocol::Hysteria);
        assert_eq!(outbound.stream.network, Network::Hysteria);
        assert_eq!(outbound.stream.security, Security::Tls);
        assert_eq!(
            outbound
                .stream
                .hysteria_settings
                .as_ref()
                .map(|settings| settings.version),
            Some(2)
        );

        outbound.select_protocol(Protocol::Trojan);
        assert_eq!(outbound.protocol, Protocol::Trojan);
        assert_eq!(outbound.stream.network, Network::Raw);
        assert_eq!(outbound.stream.security, Security::Tls);
        assert!(outbound.stream.hysteria_settings.is_none());
        assert!(matches!(outbound.settings, ProtocolSettings::Trojan(_)));
    }

    #[test]
    fn wire_output_contains_only_the_selected_transport_block() {
        let mut outbound = OutboundModel::new(Protocol::Freedom);
        outbound.stream.network = Network::Raw;
        outbound.stream.raw_settings = Some(RawSettings::default());
        outbound.stream.xhttp_settings = Some(XhttpSettings {
            mode: "definitely-invalid".into(),
            ..Default::default()
        });
        outbound.stream.hysteria_settings = Some(HysteriaTransport {
            version: 99,
            ..Default::default()
        });

        let wire = outbound.to_wire("direct");
        let stream = wire["streamSettings"].as_object().unwrap();
        assert!(stream.contains_key("tcpSettings"));
        assert!(!stream.contains_key("xhttpSettings"));
        assert!(!stream.contains_key("hysteriaSettings"));
        assert!(outbound.stream.xhttp_settings.is_some());
        assert!(outbound.stream.hysteria_settings.is_some());
    }

    #[test]
    fn inactive_security_drafts_survive_roundtrip_and_stay_off_wire() {
        let mut outbound = OutboundModel::new(Protocol::Freedom);
        outbound.stream.select_security(Security::Reality).unwrap();
        {
            let reality = outbound.stream.reality_settings.as_mut().unwrap();
            reality.server_name = "reality.example.com".into();
            reality.fingerprint = "firefox".into();
            reality.password = "reality-public-key".into();
            reality.short_id = "0123456789abcdef".into();
            reality.spider_x = "/reality-draft".into();
        }

        outbound.stream.select_security(Security::Tls).unwrap();
        {
            let tls = outbound.stream.tls_settings.as_mut().unwrap();
            tls.server_name = "tls.example.com".into();
            tls.fingerprint = "chrome".into();
            tls.alpn = vec!["h2".into(), "http/1.1".into()];
        }
        outbound.stream.select_security(Security::None).unwrap();
        outbound.stream.select_security(Security::Reality).unwrap();

        outbound.stream.select_network(Network::Hysteria).unwrap();
        assert_eq!(outbound.stream.security, Security::Tls);
        outbound.stream.select_network(Network::Grpc).unwrap();
        outbound.stream.select_security(Security::Reality).unwrap();

        let persisted = serde_json::to_vec(&outbound).unwrap();
        let mut restored: OutboundModel = serde_json::from_slice(&persisted).unwrap();
        restored.enforce_invariants();

        let assert_drafts = |model: &OutboundModel| {
            let tls = model.stream.tls_settings.as_ref().unwrap();
            assert_eq!(tls.server_name, "tls.example.com");
            assert_eq!(tls.fingerprint, "chrome");
            assert_eq!(tls.alpn, ["h2", "http/1.1"]);

            let reality = model.stream.reality_settings.as_ref().unwrap();
            assert_eq!(reality.server_name, "reality.example.com");
            assert_eq!(reality.fingerprint, "firefox");
            assert_eq!(reality.password, "reality-public-key");
            assert_eq!(reality.short_id, "0123456789abcdef");
            assert_eq!(reality.spider_x, "/reality-draft");
        };
        assert_drafts(&restored);

        for security in [Security::Tls, Security::Reality, Security::None] {
            restored.stream.select_security(security).unwrap();
            let wire = restored.to_wire("direct");
            let stream = wire["streamSettings"].as_object().unwrap();
            assert_eq!(
                stream.contains_key("tlsSettings"),
                security == Security::Tls
            );
            assert_eq!(
                stream.contains_key("realitySettings"),
                security == Security::Reality
            );
            assert_drafts(&restored);
        }
    }

    #[test]
    fn wire_omits_implicit_raw_settings_but_keeps_explicit_raw_settings() {
        let implicit = OutboundModel::new(Protocol::Freedom).to_wire("direct");
        assert!(implicit.get("streamSettings").is_none());

        let mut explicit = OutboundModel::new(Protocol::Freedom);
        explicit.stream.raw_settings = Some(RawSettings::default());
        let explicit = explicit.to_wire("direct");
        assert_eq!(
            explicit["streamSettings"],
            json!({"network": "raw", "tcpSettings": {}})
        );

        let mut tls = OutboundModel::new(Protocol::Freedom);
        tls.stream.security = Security::Tls;
        tls.stream.tls_settings = Some(Default::default());
        let tls = tls.to_wire("direct");
        assert_eq!(tls["streamSettings"]["network"], "raw");
        assert!(tls["streamSettings"].get("tcpSettings").is_none());
    }

    #[test]
    fn malformed_known_settings_field_never_defaults_or_discards_unknown_siblings() {
        let settings = json!({
            "address": "example.com",
            "port": "not-a-number",
            "futureSibling": {"preserve": true}
        });
        assert!(ProtocolSettings::from_value(Protocol::Shadowsocks, settings.clone()).is_err());
        assert_eq!(settings["futureSibling"]["preserve"], true);

        let error = serde_json::from_value::<OutboundModel>(json!({
            "protocol": "shadowsocks",
            "settings": settings
        }))
        .unwrap_err()
        .to_string();
        assert!(error.contains("invalid shadowsocks outbound settings"));
        assert!(error.contains("port"));
    }

    #[test]
    fn malformed_stream_settings_and_mux_fields_name_their_paths() {
        let stream_error = serde_json::from_value::<OutboundModel>(json!({
            "protocol": "vless",
            "streamSettings": {
                "network": "tcp",
                "sockopt": {"tcpKeepAliveIdle": "abc"}
            }
        }))
        .unwrap_err()
        .to_string();
        assert!(stream_error.contains("streamSettings"), "{stream_error}");
        assert!(
            stream_error.contains("sockopt.tcpKeepAliveIdle"),
            "{stream_error}"
        );

        let mux_error = serde_json::from_value::<OutboundModel>(json!({
            "protocol": "vless",
            "mux": {"concurrency": "many"}
        }))
        .unwrap_err()
        .to_string();
        assert!(mux_error.contains("mux"), "{mux_error}");
        assert!(mux_error.contains("concurrency"), "{mux_error}");

        // The two dial-policy fields are fatal on a shape that cannot
        // express them, exactly like the envelope fields above.
        for (fixture, field) in [
            (
                json!({"protocol": "freedom", "sendThrough": 7}),
                "sendThrough",
            ),
            (
                json!({"protocol": "freedom", "targetStrategy": ["asis"]}),
                "targetStrategy",
            ),
        ] {
            let rendered = fixture.to_string();
            let error = serde_json::from_value::<OutboundModel>(fixture)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains(field),
                "{field} must be named for {rendered}: {error}"
            );
        }
    }

    #[test]
    fn retired_proxy_settings_key_round_trips_in_settings_and_never_reaches_the_wire() {
        // Xray's outbound build refuses a configuration that carries
        // `proxySettings` (infra/conf/xray.go:262), and the field upstream is
        // a `json.RawMessage`: every JSON shape loads and is kept verbatim
        // for the settings file, while the generated wire never carries it.
        // Go binds the name case-insensitively, so case variants are caught
        // too.
        for (fixture, key) in [
            (json!({"tag": "srv-x"}), "proxySettings"),
            (json!("srv-x"), "proxySettings"),
            (json!(7), "proxySettings"),
            (json!(true), "proxySettings"),
            (json!(["srv-x"]), "proxySettings"),
            (json!(null), "proxySettings"),
            (json!({"tag": 7, "extra": {"keep": 1}}), "ProxySettings"),
            (json!("srv-x"), "proxysettings"),
        ] {
            let mut object = serde_json::Map::new();
            object.insert("protocol".into(), json!("freedom"));
            object.insert("futureKey".into(), json!("kept"));
            object.insert(key.into(), fixture.clone());
            let model: OutboundModel = serde_json::from_value(serde_json::Value::Object(object))
                .unwrap_or_else(|error| panic!("{key} = {fixture} must load: {error}"));

            assert_eq!(
                model.retired_proxy_settings.as_ref(),
                Some(&fixture),
                "the raw value must be kept ({key} = {fixture})"
            );
            assert_eq!(
                model.extra.keys().collect::<Vec<_>>(),
                vec!["futureKey"],
                "the key must not survive as an unknown key ({key} = {fixture})"
            );

            // The settings file keeps the key exactly as loaded, so an
            // unrelated save cannot silently drop the user's chain.
            let persisted = serde_json::to_value(&model).expect("model serializes");
            assert_eq!(
                persisted.get("proxySettings"),
                Some(&fixture),
                "the settings file must round-trip the key ({key} = {fixture})"
            );
            assert_eq!(
                persisted.get("futureKey"),
                Some(&json!("kept")),
                "an unknown sibling must survive ({key} = {fixture})"
            );
            let reloaded: OutboundModel =
                serde_json::from_value(persisted).expect("the persisted model reloads");
            assert_eq!(reloaded.retired_proxy_settings.as_ref(), Some(&fixture));

            // The generated outbound never carries it.
            let wire = model.to_wire("srv-01234567");
            assert!(
                wire.get("proxySettings").is_none(),
                "the wire must not carry the key ({key} = {fixture}): {wire}"
            );
            assert_eq!(wire.get("futureKey"), Some(&json!("kept")));
        }

        // Several case variants: the first value is kept, the rest never
        // survive anywhere.
        let mixed = serde_json::json!({
            "protocol": "freedom",
            "ProxySettings": {"tag": "first"},
            "proxySettings": {"tag": "second"}
        });
        let model: OutboundModel = serde_json::from_value(mixed).expect("mixed case variants load");
        assert_eq!(
            model.retired_proxy_settings.as_ref(),
            Some(&json!({"tag": "first"}))
        );
        let persisted = serde_json::to_value(&model).expect("model serializes");
        assert_eq!(
            persisted.get("proxySettings"),
            Some(&json!({"tag": "first"}))
        );
        assert!(persisted.get("ProxySettings").is_none());
    }

    #[test]
    fn envelope_dial_fields_accept_their_wire_shapes() {
        let model: OutboundModel = serde_json::from_value(json!({
            "protocol": "freedom",
            "sendThrough": "192.0.2.7",
            "targetStrategy": "useip"
        }))
        .unwrap();
        assert!(model.retired_proxy_settings.is_none());
        assert_eq!(model.send_through.as_deref(), Some("192.0.2.7"));
        assert_eq!(model.target_strategy.as_deref(), Some("useip"));

        // JSON `null` is Go's nil pointer for both: absent, not an error.
        let absent: OutboundModel = serde_json::from_value(json!({
            "protocol": "freedom",
            "sendThrough": null,
            "targetStrategy": null
        }))
        .unwrap();
        assert!(absent.send_through.is_none());
        assert!(absent.target_strategy.is_none());
    }

    #[test]
    fn finalmask_wire_preserves_exact_known_and_unknown_envelopes() {
        let unknown_tcp = json!({
            "type": "future-tcp",
            "settings": "opaque raw settings",
            "futureEnvelope": {"keep": [1, null, 3]}
        });
        let known_extra = json!({"futureEnvelope": "top-level"});
        let finalmask = FinalmaskModel {
            tcp: vec![FinalmaskTcpMask::Unknown(unknown_tcp.clone())],
            udp: vec![FinalmaskUdpMask::HeaderCustom {
                settings: serde_json::from_value(json!({
                    "mode": "prefix",
                    "client": [{"type": "hex", "packet": "00ff"}],
                    "futureSettings": {"keep": true}
                }))
                .unwrap(),
                extra: known_extra.as_object().unwrap().clone(),
            }],
            ..Default::default()
        };
        let persisted = serde_json::to_value(&finalmask).unwrap();
        let mut outbound = OutboundModel::new(Protocol::Freedom);
        outbound.stream.finalmask = Some(finalmask);

        let wire = outbound.to_wire("direct");
        let emitted = &wire["streamSettings"]["finalmask"];
        assert_eq!(emitted, &persisted);
        assert_eq!(emitted["tcp"][0], unknown_tcp);
        assert_eq!(emitted["udp"][0]["type"], "header-custom");
        assert_eq!(emitted["udp"][0]["futureEnvelope"], "top-level");
        assert_eq!(
            emitted["udp"][0]["settings"],
            json!({
                "mode": "prefix",
                "client": [{"type": "hex", "packet": "00ff"}],
                "futureSettings": {"keep": true}
            })
        );
    }
}
