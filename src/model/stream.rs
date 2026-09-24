//! streamSettings model: transports, security, sockopt,
//! finalmask. `network` selects which `<network>Settings` key is meaningful;
//! serialization always emits flat `streamSettings` wire shape.

use super::validation::ValidationCode;
use super::{Int32Range, skip_empty_map, skip_empty_str, skip_empty_vec, skip_false};
use crate::links::excerpt;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

pub const MAX_XHTTP_DOWNLOAD_DEPTH: usize = 8;

/// `streamSettings.network` (transport_internet.go:17-58).
/// h2/h3/http/quic are removed upstream — not represented.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Network {
    #[default]
    Raw,
    Xhttp,
    Kcp,
    Grpc,
    Ws,
    Httpupgrade,
    Hysteria,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Raw => "raw",
            Network::Xhttp => "xhttp",
            Network::Kcp => "kcp",
            Network::Grpc => "grpc",
            Network::Ws => "ws",
            Network::Httpupgrade => "httpupgrade",
            Network::Hysteria => "hysteria",
        }
    }
    /// Parse a `streamSettings.network` wire value (case-insensitive, with the
    /// upstream transport aliases). Unrecognized transports return `None` —
    /// deserialization is strict so a typo'd or trailing-space value fails the
    /// load instead of silently downgrading to `Raw`.
    pub fn parse(s: &str) -> Option<Self> {
        if s.eq_ignore_ascii_case("raw") || s.eq_ignore_ascii_case("tcp") {
            Some(Network::Raw)
        } else if s.eq_ignore_ascii_case("xhttp") || s.eq_ignore_ascii_case("splithttp") {
            Some(Network::Xhttp)
        } else if s.eq_ignore_ascii_case("kcp") || s.eq_ignore_ascii_case("mkcp") {
            Some(Network::Kcp)
        } else if s.eq_ignore_ascii_case("grpc") {
            Some(Network::Grpc)
        } else if s.eq_ignore_ascii_case("ws") || s.eq_ignore_ascii_case("websocket") {
            Some(Network::Ws)
        } else if s.eq_ignore_ascii_case("httpupgrade") {
            Some(Network::Httpupgrade)
        } else if s.eq_ignore_ascii_case("hysteria") {
            Some(Network::Hysteria)
        } else {
            None
        }
    }

    /// REALITY is accepted by Xray only for raw/TCP, XHTTP, and gRPC.
    pub fn supports_reality(self) -> bool {
        matches!(self, Network::Raw | Network::Xhttp | Network::Grpc)
    }
}

impl Serialize for Network {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for Network {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = String::deserialize(d)?;
        Network::parse(&value).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "unknown network value {:?} (expected one of: raw, tcp, xhttp, \
                 splithttp, kcp, mkcp, grpc, ws, websocket, httpupgrade, hysteria)",
                excerpt(&value)
            ))
        })
    }
}

/// `streamSettings.security`: "" / none | tls | reality.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Security {
    #[default]
    None,
    Tls,
    Reality,
}

impl Security {
    pub fn is_none(&self) -> bool {
        *self == Security::None
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Security::None => "none",
            Security::Tls => "tls",
            Security::Reality => "reality",
        }
    }
}

impl Serialize for Security {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}
impl<'de> Deserialize<'de> for Security {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let value = String::deserialize(d)?;
        if value.is_empty() || value.eq_ignore_ascii_case("none") {
            Ok(Security::None)
        } else if value.eq_ignore_ascii_case("tls") {
            Ok(Security::Tls)
        } else if value.eq_ignore_ascii_case("reality") {
            Ok(Security::Reality)
        } else {
            Err(serde::de::Error::custom(format!(
                "unknown security value {:?} (expected one of: \"\", none, tls, reality)",
                excerpt(&value)
            )))
        }
    }
}

// ---------- raw / TCP (transport_method.go:36-142) ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RawSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<RawHeader>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RawHeader {
    /// none | http
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<HttpCamouflageRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<HttpCamouflageResponse>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpCamouflageRequest {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub version: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub method: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub path: Vec<String>,
    /// header name → string or array of strings (Xray StringList)
    #[serde(skip_serializing_if = "skip_empty_map")]
    pub headers: Map<String, Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpCamouflageResponse {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub version: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub status: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub reason: String,
    #[serde(skip_serializing_if = "skip_empty_map")]
    pub headers: Map<String, Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ---------- XHTTP (transport_method.go:257-296) ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct XhttpSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub host: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub path: String,
    /// auto | packet-up | stream-up | stream-one
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub mode: String,
    #[serde(skip_serializing_if = "skip_empty_map")]
    pub headers: Map<String, Value>,
    #[serde(skip_serializing_if = "skip_empty_str", rename = "uplinkHTTPMethod")]
    pub uplink_http_method: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub uplink_data_placement: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub uplink_data_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uplink_chunk_size: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_padding_bytes: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_padding_obfs_mode: Option<bool>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub x_padding_key: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub x_padding_header: String,
    /// cookie | header | query | queryInHeader
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub x_padding_placement: String,
    /// repeat-x | tokenish
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub x_padding_method: String,
    #[serde(skip_serializing_if = "skip_empty_str", rename = "sessionIDPlacement")]
    pub session_id_placement: String,
    #[serde(skip_serializing_if = "skip_empty_str", rename = "sessionIDKey")]
    pub session_id_key: String,
    #[serde(skip_serializing_if = "skip_empty_str", rename = "sessionIDTable")]
    pub session_id_table: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "sessionIDLength")]
    pub session_id_length: Option<Int32Range>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub seq_placement: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub seq_key: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "noGRPCHeader")]
    pub no_grpc_header: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "noSSEHeader")]
    pub no_sse_header: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sc_max_each_post_bytes: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sc_min_posts_interval_ms: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sc_max_buffered_posts: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sc_stream_up_server_secs: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_max_header_bytes: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xmux: Option<XmuxConfig>,
    /// Recursive split up/down stream (forbidden in stream-one).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_settings: Option<Box<StreamModel>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// xmux: maxConcurrency xor maxConnections; the rest are H2/H3 knobs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct XmuxConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_max_reuse_times: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h_max_request_times: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h_max_reusable_secs: Option<Int32Range>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub h_keep_alive_period: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ---------- mKCP (transport_method.go:523-563) — header/seed/congestion removed ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct KcpSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tti: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uplink_capacity: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downlink_capacity: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwnd_multiplier: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_sending_window: Option<u32>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ---------- gRPC (snake_case keys; deprecated → XHTTP stream-up) ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GrpcSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub authority: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub service_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multi_mode: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "idle_timeout")]
    pub idle_timeout: Option<i32>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "health_check_timeout"
    )]
    pub health_check_timeout: Option<i32>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "permit_without_stream"
    )]
    pub permit_without_stream: Option<bool>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        rename = "initial_windows_size"
    )]
    pub initial_windows_size: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "user_agent")]
    pub user_agent: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ---------- WebSocket (deprecated → XHTTP H2&H3) ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct WsSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub host: String,
    /// supports `?ed=N` early-data cap
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub path: String,
    #[serde(skip_serializing_if = "skip_empty_map")]
    pub headers: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_period: Option<u32>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
impl WsSettings {
    /// Canonicalize Xray's deprecated `headers.Host` form without losing its
    /// effective value. Call only for an explicit editor mutation/migration so
    /// merely rendering an imported profile remains idempotent.
    pub(crate) fn migrate_legacy_host_header(&mut self) -> Result<bool, &'static str> {
        let Some(key) = self
            .headers
            .keys()
            .find(|key| key.eq_ignore_ascii_case("host"))
            .cloned()
        else {
            return Ok(false);
        };
        if self.host.is_empty() {
            self.host = self
                .headers
                .get(&key)
                .and_then(Value::as_str)
                .ok_or("legacy WebSocket Host header must be a string")?
                .to_owned();
        }
        self.headers.remove(&key);
        Ok(true)
    }
}

// ---------- HTTPUpgrade (deprecated → XHTTP) ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HttpupgradeSettings {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub host: String,
    /// supports `?ed=N`
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub path: String,
    /// a `host` header key here is a build error — use `host`
    #[serde(skip_serializing_if = "skip_empty_map")]
    pub headers: Map<String, Value>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ---------- hysteria transport (transport_method.go:761-787) ----------

/// hysteriaSettings.masquerade (transport_method.go Masquerade struct).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct MasqueradeCfg {
    /// "file" | "proxy" | "string" (empty = no masquerade)
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub r#type: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub dir: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub url: String,
    #[serde(skip_serializing_if = "skip_false")]
    pub rewrite_host: bool,
    /// `proxy` mode: add the `X-Forwarded-*` request headers. The core calls
    /// `httputil.ProxyRequest.SetXForwarded` when the flag is set
    /// (`transport/internet/hysteria/hub.go` at v26.9.9).
    #[serde(skip_serializing_if = "skip_false")]
    pub x_forwarded: bool,
    #[serde(skip_serializing_if = "skip_false")]
    pub insecure: bool,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub content: String,
    #[serde(skip_serializing_if = "skip_empty_map")]
    pub headers: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i32>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HysteriaTransport {
    /// MUST be 2 — the core hard-fails otherwise (transport_method.go:776).
    pub version: u32,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub auth: String,
    /// seconds, 2..=600 (default 60)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp_idle_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub masquerade: Option<MasqueradeCfg>,
    /// congestion/up/down/udphop intentionally omitted: deprecated upstream,
    /// superseded by finalmask.quicParams (transport_method.go:781).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for HysteriaTransport {
    fn default() -> Self {
        Self {
            version: 2,
            auth: String::new(),
            udp_idle_timeout: None,
            masquerade: None,
            extra: Map::new(),
        }
    }
}

// ---------- TLS (transport_security.go:300-329) — allowInsecure is REMOVED ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsModel {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub server_name: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub alpn: Vec<String>,
    /// uTLS fingerprint: chrome/firefox/safari/... (empty → chrome-auto)
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub fingerprint: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub min_version: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub max_version: String,
    /// colon-separated Go suite names
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub cipher_suites: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub curve_preferences: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub certificates: Vec<TlsCert>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_system_root: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_session_resumption: Option<bool>,
    /// comma-separated hex pins — the replacement for allowInsecure
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub pinned_peer_cert_sha256: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub verify_peer_cert_by_name: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub master_key_log: String,
    /// base64 ECHConfigList | "https://1.1.1.1/dns-query" | "name+https://…"
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub ech_config_list: String,
    /// sockopt applied to the ECH DNS query only
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ech_sockopt: Option<SockoptModel>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
fn deserialize_pem_lines<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PemLines {
        Scalar(String),
        Lines(Vec<String>),
    }

    Ok(match PemLines::deserialize(deserializer)? {
        PemLines::Scalar(value) => vec![value],
        PemLines::Lines(values) => values,
    })
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TlsCert {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub certificate_file: String,
    #[serde(
        default,
        deserialize_with = "deserialize_pem_lines",
        skip_serializing_if = "skip_empty_vec"
    )]
    pub certificate: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub key_file: String,
    #[serde(
        default,
        deserialize_with = "deserialize_pem_lines",
        skip_serializing_if = "skip_empty_vec"
    )]
    pub key: Vec<String>,
    /// encipherment | verify | issue
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub usage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ocsp_stapling: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_time_loading: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_chain: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ---------- REALITY client (transport_security.go:27-52,181-246) ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RealityModel {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub server_name: String,
    /// uTLS fingerprint, required in practice (unsafe/hellogolang rejected)
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub fingerprint: String,
    /// server x25519 public key, base64url 32B (upstream alias: publicKey)
    #[serde(skip_serializing_if = "skip_empty_str", alias = "publicKey")]
    pub password: String,
    /// hex ≤16 chars
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub short_id: String,
    /// initial crawler path, must start with '/'
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub spider_x: String,
    /// base64url 1952-byte ML-DSA-65 public key
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub mldsa65_verify: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub show: Option<bool>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub master_key_log: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ---------- sockopt (transport_sockopt.go:45-65) ----------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SockoptModel {
    /// asis | useip* | forceip*
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub domain_strategy: String,
    /// the outbound tag this server dials through (the chain target)
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub dialer_proxy: String,
    /// bind to NIC (Windows: IP_UNICAST_IF)
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub interface: String,
    /// bool or JSON number (Xray converts numbers to int32)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_fast_open: Option<Value>,
    /// Listener-only upstream; retained for lossless SocketConfig round-trips.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept_proxy_protocol: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive_idle: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_keep_alive_interval: Option<i32>,
    // --- No reader on the Windows outbound path: the editor renders no widget
    // for these, and a hand-edited profile keeps its values unchanged. ---
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub tcp_congestion: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_window_clamp: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_max_seg: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_user_timeout: Option<i32>,
    /// Go's dialer consumes it on Linux only, so no dial here uses it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_mptcp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mark: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tproxy: Option<String>,
    // --- end no-Windows-reader block ---
    /// XHTTP copies the stream sockopt into `downloadSettings`, and that dial
    /// path runs on every platform, so the stream editor still edits it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub penetrate: Option<bool>,
    /// Listener-only upstream; it has no effect on outbound dials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub v6only: Option<bool>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub custom_sockopt: Vec<CustomSockopt>,
    /// none | srvportonly | srvaddressonly | srvportandaddress |
    /// txtportonly | txtaddressonly | txtportandaddress
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub address_port_strategy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub happy_eyeballs: Option<HappyEyeballs>,
    /// Inbound HTTP/gRPC peer-address trust settings; ignored by outbound dials.
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub trusted_x_forwarded_for: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl SockoptModel {
    pub fn is_empty(&self) -> bool {
        self.domain_strategy.is_empty()
            && self.dialer_proxy.is_empty()
            && self.interface.is_empty()
            && self.tcp_fast_open.is_none()
            && self.accept_proxy_protocol.is_none()
            && self.tcp_keep_alive_idle.is_none()
            && self.tcp_keep_alive_interval.is_none()
            && self.tcp_congestion.is_empty()
            && self.tcp_window_clamp.is_none()
            && self.tcp_max_seg.is_none()
            && self.tcp_user_timeout.is_none()
            && self.tcp_mptcp.is_none()
            && self.penetrate.is_none()
            && self.mark.is_none()
            && self.tproxy.is_none()
            && self.v6only.is_none()
            && self.trusted_x_forwarded_for.is_empty()
            && self.custom_sockopt.is_empty()
            && self.address_port_strategy.is_empty()
            && self.happy_eyeballs.is_none()
            && self.extra.is_empty()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CustomSockopt {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub system: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub network: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub level: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub r#type: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub opt: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub value: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// RFC 8305 happy eyeballs (defaults: interleave 1, maxConcurrentTry 4).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HappyEyeballs {
    #[serde(skip_serializing_if = "Option::is_none", rename = "prioritizeIPv6")]
    pub prioritize_ipv6: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub try_delay_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interleave: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent_try: Option<u32>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// ---------- finalmask (transport_finalmask.go) ----------

fn finalmask_zero_i32(value: &i32) -> bool {
    *value == 0
}

fn finalmask_zero_u32(value: &u32) -> bool {
    *value == 0
}

fn finalmask_zero_range(value: &Int32Range) -> bool {
    value.from == 0 && value.to == 0
}

/// True for a port list that states no port: an empty/blank string, or the
/// numeric zero — Go's `PortList.UnmarshalJSON` reads both as an empty list
/// (`infra/conf/common.go:274-276`).
fn finalmask_empty_port_list(value: &FinalmaskPortList) -> bool {
    match value {
        FinalmaskPortList::Number(port) => *port == 0,
        FinalmaskPortList::Text(text) => text.trim().is_empty(),
    }
}

/// Presence-preserving equivalent of Xray's `json.RawMessage`.
///
/// The distinction between an omitted field and an explicit JSON `null`
/// matters to the Go config loader, so `Option<Value>` is not lossless here.
#[derive(Clone, Debug, Default)]
pub enum FinalmaskRawValue {
    #[default]
    Absent,
    Present(Value),
}

impl FinalmaskRawValue {
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    pub fn value(&self) -> Option<&Value> {
        match self {
            Self::Absent => None,
            Self::Present(value) => Some(value),
        }
    }

    pub fn value_mut(&mut self) -> Option<&mut Value> {
        match self {
            Self::Absent => None,
            Self::Present(value) => Some(value),
        }
    }
}

impl Serialize for FinalmaskRawValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Absent => serializer.serialize_unit(),
            Self::Present(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for FinalmaskRawValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::Present(Value::deserialize(deserializer)?))
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskTransform {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub op: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub args: Vec<FinalmaskTransformArg>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskTransformArg {
    /// Byte representation: `""`/`array`, `str`, `hex`, or `base64`.
    #[serde(rename = "type", skip_serializing_if = "skip_empty_str")]
    pub encoding: String,
    #[serde(skip_serializing_if = "FinalmaskRawValue::is_absent")]
    pub bytes: FinalmaskRawValue,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub u64: Option<u64>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub reuse: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub metadata: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<Box<FinalmaskTransform>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskTcpItem {
    #[serde(skip_serializing_if = "finalmask_zero_range")]
    pub delay: Int32Range,
    #[serde(skip_serializing_if = "finalmask_zero_i32")]
    pub rand: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rand_range: Option<Int32Range>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub capture: String,
    /// Byte representation: `""`/`array`, `str`, `hex`, or `base64`.
    #[serde(rename = "type", skip_serializing_if = "skip_empty_str")]
    pub encoding: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub reuse: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<FinalmaskTransform>,
    #[serde(skip_serializing_if = "FinalmaskRawValue::is_absent")]
    pub packet: FinalmaskRawValue,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for FinalmaskTcpItem {
    fn default() -> Self {
        Self {
            delay: Int32Range::single(0),
            rand: 0,
            rand_range: None,
            capture: String::new(),
            encoding: String::new(),
            reuse: String::new(),
            transform: None,
            packet: FinalmaskRawValue::Absent,
            extra: Map::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskUdpItem {
    #[serde(skip_serializing_if = "finalmask_zero_i32")]
    pub rand: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rand_range: Option<Int32Range>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub capture: String,
    /// Byte representation: `""`/`array`, `str`, `hex`, or `base64`.
    #[serde(rename = "type", skip_serializing_if = "skip_empty_str")]
    pub encoding: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub reuse: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transform: Option<FinalmaskTransform>,
    #[serde(skip_serializing_if = "FinalmaskRawValue::is_absent")]
    pub packet: FinalmaskRawValue,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for FinalmaskUdpItem {
    fn default() -> Self {
        Self {
            rand: 0,
            rand_range: None,
            capture: String::new(),
            encoding: String::new(),
            reuse: String::new(),
            transform: None,
            packet: FinalmaskRawValue::Absent,
            extra: Map::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskHeaderCustomTcp {
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub clients: Vec<Vec<FinalmaskTcpItem>>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub servers: Vec<Vec<FinalmaskTcpItem>>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub errors: Vec<Vec<FinalmaskTcpItem>>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskFragment {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub packets: String,
    #[serde(skip_serializing_if = "finalmask_zero_range")]
    pub length: Int32Range,
    #[serde(skip_serializing_if = "finalmask_zero_range")]
    pub delay: Int32Range,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub lengths: Vec<Int32Range>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub delays: Vec<Int32Range>,
    #[serde(skip_serializing_if = "finalmask_zero_range")]
    pub max_split: Int32Range,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for FinalmaskFragment {
    fn default() -> Self {
        Self {
            packets: String::new(),
            length: Int32Range::single(0),
            delay: Int32Range::single(0),
            lengths: Vec::new(),
            delays: Vec::new(),
            max_split: Int32Range::single(0),
            extra: Map::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskNoiseItem {
    #[serde(skip_serializing_if = "finalmask_zero_range")]
    pub rand: Int32Range,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rand_range: Option<Int32Range>,
    #[serde(rename = "type", skip_serializing_if = "skip_empty_str")]
    pub encoding: String,
    #[serde(skip_serializing_if = "FinalmaskRawValue::is_absent")]
    pub packet: FinalmaskRawValue,
    #[serde(skip_serializing_if = "finalmask_zero_range")]
    pub delay: Int32Range,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for FinalmaskNoiseItem {
    fn default() -> Self {
        Self {
            rand: Int32Range::single(0),
            rand_range: None,
            encoding: String::new(),
            packet: FinalmaskRawValue::Absent,
            delay: Int32Range::single(0),
            extra: Map::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskNoise {
    #[serde(skip_serializing_if = "finalmask_zero_range")]
    pub reset: Int32Range,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub noise: Vec<FinalmaskNoiseItem>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for FinalmaskNoise {
    fn default() -> Self {
        Self {
            reset: Int32Range::single(0),
            noise: Vec::new(),
            extra: Map::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskHeaderCustomUdp {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub mode: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub client: Vec<FinalmaskUdpItem>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub server: Vec<FinalmaskUdpItem>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskMkcpLegacy {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub header: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub value: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskSalamander {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub password: String,
    #[serde(skip_serializing_if = "finalmask_zero_range")]
    pub packet_size: Int32Range,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for FinalmaskSalamander {
    fn default() -> Self {
        Self {
            password: String::new(),
            packet_size: Int32Range::single(0),
            extra: Map::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskSudoku {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub password: String,
    #[serde(rename = "ascii", skip_serializing_if = "skip_empty_str")]
    pub ascii: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub custom_table: String,
    #[serde(rename = "custom_table", skip_serializing_if = "skip_empty_str")]
    pub legacy_custom_table: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub custom_tables: Vec<String>,
    #[serde(rename = "custom_tables", skip_serializing_if = "skip_empty_vec")]
    pub legacy_custom_sets: Vec<String>,
    #[serde(skip_serializing_if = "finalmask_zero_u32")]
    pub padding_min: u32,
    #[serde(rename = "padding_min", skip_serializing_if = "finalmask_zero_u32")]
    pub legacy_padding_min: u32,
    #[serde(skip_serializing_if = "finalmask_zero_u32")]
    pub padding_max: u32,
    #[serde(rename = "padding_max", skip_serializing_if = "finalmask_zero_u32")]
    pub legacy_padding_max: u32,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskXdns {
    /// Removed upstream. Kept presence-aware so imported invalid state is
    /// visible and can be removed without silently converting `null`.
    #[serde(skip_serializing_if = "FinalmaskRawValue::is_absent")]
    pub domain: FinalmaskRawValue,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub domains: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub resolvers: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskXmcProfile {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub username: String,
    #[serde(rename = "uuid", skip_serializing_if = "skip_empty_str")]
    pub uuid: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub textures_value: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub textures_signature: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskXmc {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub hostname: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub profiles: Vec<FinalmaskXmcProfile>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub password: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskXicmp {
    #[serde(rename = "dgram", skip_serializing_if = "skip_false")]
    pub dgram: bool,
    #[serde(rename = "ips", skip_serializing_if = "skip_empty_vec")]
    pub ips: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Full `TLSConfig` used by the Realm mask. This is separate from the
/// client-focused top-level TLS model because Realm accepts the server-only
/// fields too.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskRealmTls {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow_insecure: Option<bool>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub certificates: Vec<TlsCert>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub server_name: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub alpn: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_session_resumption: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_system_root: Option<bool>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub min_version: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub max_version: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub cipher_suites: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub fingerprint: String,
    #[serde(rename = "rejectUnknownSni", skip_serializing_if = "Option::is_none")]
    pub reject_unknown_sni: Option<bool>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub curve_preferences: Vec<String>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub master_key_log: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub pinned_peer_cert_sha256: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub verify_peer_cert_by_name: String,
    #[serde(rename = "echServerKeys", skip_serializing_if = "skip_empty_str")]
    pub ech_server_keys: String,
    #[serde(rename = "echConfigList", skip_serializing_if = "skip_empty_str")]
    pub ech_config_list: String,
    #[serde(rename = "echSockopt", skip_serializing_if = "Option::is_none")]
    pub ech_sockopt: Option<SockoptModel>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskRealm {
    #[serde(rename = "url", skip_serializing_if = "skip_empty_str")]
    pub url: String,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub stun_servers: Vec<String>,
    /// `"dual"` | `"v4"` | `"v6"`; empty keeps the core's dual-stack
    /// default. The core lowercases the value and falls back to dual for
    /// anything else (`transport/internet/finalmask/realm/client.go`).
    #[serde(rename = "ipMode", skip_serializing_if = "skip_empty_str")]
    pub ip_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_mapping: Option<FinalmaskRealmPortMapping>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_config: Option<FinalmaskRealmTls>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `portMapping` of the Realm mask (`infra/conf/transport_finalmask.go`
/// Realm struct at v26.9.9, proto `realm.PortMapping`). While `enabled` is
/// true, the mask asks the local gateway over UPnP or NAT-PMP to map its
/// UDP port. `timeout` and `lifetime` are seconds; the core substitutes its
/// own defaults (10 and 600) when either is 0, and a negative value fails
/// the mapping init, which the core logs before it runs without a mapping
/// (`transport/internet/finalmask/realm/portmap.go`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskRealmPortMapping {
    #[serde(skip_serializing_if = "skip_false")]
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifetime: Option<i64>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FinalmaskPortList {
    Number(u32),
    Text(String),
}

impl Default for FinalmaskPortList {
    fn default() -> Self {
        Self::Text(String::new())
    }
}

/// The `udphop` UDP mask settings (`infra/conf/transport_finalmask.go:911-965`
/// at v26.9.9). The mask hops the destination of the outbound's own UDP
/// socket: `mode` selects when a hop happens (a comma-separated, combinable
/// set of `intervalLocal` / `intervalRemote` / `perConnRemote`), `interval`
/// is the seconds range a period hop waits, `remotePorts` / `remoteIPs`
/// replace the destination, and `sockopt` configures each hopped socket.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskUdpHop {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sockopt: Option<SockoptModel>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub mode: String,
    #[serde(skip_serializing_if = "finalmask_zero_range")]
    pub interval: Int32Range,
    #[serde(skip_serializing_if = "finalmask_empty_port_list")]
    pub remote_ports: FinalmaskPortList,
    #[serde(rename = "remoteIPs", skip_serializing_if = "skip_empty_vec")]
    pub remote_ips: Vec<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for FinalmaskUdpHop {
    fn default() -> Self {
        Self {
            sockopt: None,
            // The core refuses an empty mode at config load, so a fresh mask
            // starts on the mode every UDP transport accepts. The interval
            // starts at the core's 5-second floor.
            mode: "perConnRemote".into(),
            interval: Int32Range::new(5, 10),
            remote_ports: FinalmaskPortList::default(),
            remote_ips: Vec::new(),
            extra: Map::new(),
        }
    }
}

/// Parse one `udphop` `remoteIPs` entry the way the mask build does, and
/// return the normalized prefix: the build tries `netip.ParsePrefix` and
/// falls back to `netip.ParseAddr`, appending the address width
/// (`infra/conf/transport_finalmask.go:950-960`). `None` when neither form
/// parses — the mask build rejects that entry.
pub fn finalmask_udphop_remote_ip(value: &str) -> Option<String> {
    // Go tries `netip.ParsePrefix` first: it splits at the LAST '/', parses
    // the address part with ParseAddr and strips the zone, then reads the
    // bit count with ParseUint (digits only, no sign). `fe80::1%eth0/64`
    // builds the prefix `fe80::1/64`, and a form that fails any of those
    // steps falls through to the address parse below, exactly like the
    // build's two attempts.
    if let Some(prefix) = value.rsplit_once('/').and_then(|(address, bits)| {
        let address = go_ip_addr(address)?;
        if bits.is_empty() || !bits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let bits: u8 = bits.parse().ok()?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        (bits <= width).then(|| format!("{address}/{bits}"))
    }) {
        return Some(prefix);
    }
    // Then `netip.ParseAddr` over the whole entry: an IPv6 zone (everything
    // after the first '%', which may itself contain '/' and '%') is kept
    // and `PrefixFrom` drops it before the width is attached, so
    // `fe80::1%eth0` and `fe80::1%eth0/64%x` both build `fe80::1/128`.
    // Neither parser trims, so a padded entry is refused like every other
    // malformed one.
    let address = go_ip_addr(value)?;
    let width = if address.is_ipv4() { 32 } else { 128 };
    Some(format!("{address}/{width}"))
}

/// Parse one address with Go's `netip.ParseAddr` semantics: an IPv6 address
/// may carry a zone (everything after its first `%`, non-empty, `%` allowed
/// inside), and the zone never reaches the prefix; an IPv4 address never
/// takes a zone (`1.2.3.4%eth0` is a parse error there).
fn go_ip_addr(value: &str) -> Option<std::net::IpAddr> {
    let (address, zone) = match value.split_once('%') {
        Some((address, zone)) => (address, Some(zone)),
        None => (value, None),
    };
    if let Some(zone) = zone {
        if zone.is_empty() {
            return None;
        }
        return address
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .map(std::net::IpAddr::V6);
    }
    value.parse::<std::net::IpAddr>().ok()
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskQuicParams {
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub congestion: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<bool>,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub bbr_profile: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub brutal_up: String,
    #[serde(skip_serializing_if = "skip_empty_str")]
    pub brutal_down: String,
    /// `brutalDisableLossCompensation`: passed to the brutal congestion
    /// controller (`transport/internet/hysteria/dialer.go:204`), false/absent
    /// leaves compensation on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brutal_disable_loss_compensation: Option<bool>,
    /// The raw value of the retired `quicParams.udpHop` key the stored
    /// object carried, when it did (any JSON shape). The hop moved to the
    /// `udphop` UDP mask (`infra/conf/transport_finalmask.go:88`) and the
    /// core now ignores the old key silently, so the profile stays gated
    /// until the user rebuilds the hop; the value is kept so the settings
    /// file round-trips it, while the wire pass
    /// ([`StreamModel::retain_selected_stream_blocks_for_wire`]) never emits
    /// it. JSON `null` is the Go zero shape — the field upstream is a
    /// pointer — and counts as absent, so the key is then dropped on the
    /// next save. The gating finding is
    /// `crate::model::validation::ValidationCode::FinalmaskQuicHopMoved`.
    #[serde(rename = "udpHop", skip_serializing_if = "Option::is_none")]
    pub retired_udp_hop: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_stream_receive_window: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_stream_receive_window: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_connection_receive_window: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connection_receive_window: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_idle_timeout: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_alive_period: Option<i64>,
    #[serde(
        rename = "disablePathMTUDiscovery",
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_path_mtu_discovery: Option<bool>,
    /// `disableChromeParrot`: the dialer passes `!disable_chrome_parrot` as
    /// `ChromeParrot` (`transport/internet/hysteria/dialer.go:90`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_chrome_parrot: Option<bool>,
    /// `disableGSO`: quic-go's `Transport.DisableGSO`
    /// (`transport/internet/hysteria/dialer.go:142`). The upstream key keeps
    /// the acronym's casing, so it needs an explicit rename (camelCase would
    /// spell it `disableGso`).
    #[serde(rename = "disableGSO", skip_serializing_if = "Option::is_none")]
    pub disable_gso: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_incoming_streams: Option<i64>,
    /// `disableStatelessReset`: upstream reads it on listener sessions only —
    /// the hubs build the QUIC transport's stateless-reset key
    /// (`transport/internet/hysteria/hub.go:334`,
    /// `transport/internet/splithttp/hub.go:510`) while the dialers build
    /// theirs without one (`hysteria/dialer.go:142`). Broccoli generates
    /// client configurations, so the editor offers no row for it; the field
    /// stays for lossless round-trip and raw-override use.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable_stateless_reset: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl<'de> Deserialize<'de> for FinalmaskQuicParams {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let Value::Object(mut object) = value else {
            return Err(serde::de::Error::custom("quicParams must be an object"));
        };

        // The retired `udpHop` key never fails the load — the profile is
        // marked instead. Its raw value is kept so the settings file
        // round-trips the key unchanged (nothing is migrated) while the gate
        // stands. The value takes any JSON shape (the old Go field was a
        // struct the loader now ignores without validation). A null value
        // anywhere among the case variants is the Go zero shape — the field
        // upstream is a pointer, and null sets it to nil — so the key counts
        // as absent: nothing is retained, marked, or written back. Otherwise
        // every case variant is consumed: the last match visited survives
        // for re-emission and the rest are dropped, so none can survive as
        // an unknown key.
        let null_valued = object
            .iter()
            .any(|(key, value)| key.eq_ignore_ascii_case("udpHop") && value.is_null());
        let mut retired_udp_hop = None;
        object.retain(|key, value| {
            if key.eq_ignore_ascii_case("udpHop") {
                if !null_valued {
                    retired_udp_hop = Some(value.clone());
                }
                false
            } else {
                true
            }
        });
        // An older build of this app wrote the MTU switch in the plain
        // camelCase spelling (`disablePathMtuDiscovery`); the core binds it
        // case-insensitively either way. Fold it into the upstream key so
        // the value stays tracked by the field instead of becoming an
        // unknown key that the editor cannot show.
        if let Some(value) = object.remove("disablePathMtuDiscovery") {
            object
                .entry("disablePathMTUDiscovery".to_string())
                .or_insert(value);
        }

        /// One typed field of the wire object: absent takes the field's
        /// default, and a value that cannot express the field is fatal with
        /// the key named — the sibling blocks parse through the same
        /// field-path seam.
        fn take<T, E>(object: &mut Map<String, Value>, key: &str) -> Result<T, E>
        where
            T: serde::de::DeserializeOwned + Default,
            E: serde::de::Error,
        {
            match object.remove(key) {
                Some(value) => crate::model::outbound::from_value_path(value)
                    .map_err(|error| E::custom(format!("invalid {key}: {error}"))),
                None => Ok(T::default()),
            }
        }

        Ok(Self {
            congestion: take(&mut object, "congestion")?,
            debug: take(&mut object, "debug")?,
            bbr_profile: take(&mut object, "bbrProfile")?,
            brutal_up: take(&mut object, "brutalUp")?,
            brutal_down: take(&mut object, "brutalDown")?,
            brutal_disable_loss_compensation: take(&mut object, "brutalDisableLossCompensation")?,
            retired_udp_hop,
            init_stream_receive_window: take(&mut object, "initStreamReceiveWindow")?,
            max_stream_receive_window: take(&mut object, "maxStreamReceiveWindow")?,
            init_connection_receive_window: take(&mut object, "initConnectionReceiveWindow")?,
            max_connection_receive_window: take(&mut object, "maxConnectionReceiveWindow")?,
            max_idle_timeout: take(&mut object, "maxIdleTimeout")?,
            keep_alive_period: take(&mut object, "keepAlivePeriod")?,
            disable_path_mtu_discovery: take(&mut object, "disablePathMTUDiscovery")?,
            disable_chrome_parrot: take(&mut object, "disableChromeParrot")?,
            disable_gso: take(&mut object, "disableGSO")?,
            max_incoming_streams: take(&mut object, "maxIncomingStreams")?,
            disable_stateless_reset: take(&mut object, "disableStatelessReset")?,
            extra: object,
        })
    }
}

#[derive(Clone, Debug)]
pub enum FinalmaskTcpMask {
    HeaderCustom {
        settings: FinalmaskHeaderCustomTcp,
        extra: Map<String, Value>,
    },
    Fragment {
        settings: FinalmaskFragment,
        extra: Map<String, Value>,
    },
    Sudoku {
        settings: FinalmaskSudoku,
        extra: Map<String, Value>,
    },
    Xmc {
        settings: FinalmaskXmc,
        extra: Map<String, Value>,
    },
    /// A future discriminator unknown to this Broccoli build. The complete raw
    /// envelope is retained and shown in the editor.
    Unknown(Value),
}

impl FinalmaskTcpMask {
    pub const TYPES: &'static [&'static str] = &["header-custom", "fragment", "sudoku", "xmc"];

    pub fn known_type(&self) -> Option<&'static str> {
        match self {
            Self::HeaderCustom { .. } => Some("header-custom"),
            Self::Fragment { .. } => Some("fragment"),
            Self::Sudoku { .. } => Some("sudoku"),
            Self::Xmc { .. } => Some("xmc"),
            Self::Unknown(_) => None,
        }
    }

    pub fn discriminator(&self) -> Option<&str> {
        self.known_type().or_else(|| match self {
            Self::Unknown(Value::Object(object)) => object.get("type").and_then(Value::as_str),
            _ => None,
        })
    }

    pub fn from_known_type(kind: &str) -> Option<Self> {
        let extra = Map::new();
        Some(match kind {
            "header-custom" => Self::HeaderCustom {
                settings: FinalmaskHeaderCustomTcp::default(),
                extra,
            },
            "fragment" => {
                let settings = FinalmaskFragment {
                    packets: "tlshello".into(),
                    length: Int32Range::single(100),
                    ..Default::default()
                };
                Self::Fragment { settings, extra }
            }
            "sudoku" => Self::Sudoku {
                settings: FinalmaskSudoku::default(),
                extra,
            },
            "xmc" => Self::Xmc {
                settings: FinalmaskXmc::default(),
                extra,
            },
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub enum FinalmaskUdpMask {
    HeaderCustom {
        settings: FinalmaskHeaderCustomUdp,
        extra: Map<String, Value>,
    },
    MkcpLegacy {
        settings: FinalmaskMkcpLegacy,
        extra: Map<String, Value>,
    },
    Noise {
        settings: FinalmaskNoise,
        extra: Map<String, Value>,
    },
    Salamander {
        settings: FinalmaskSalamander,
        extra: Map<String, Value>,
    },
    Sudoku {
        settings: FinalmaskSudoku,
        extra: Map<String, Value>,
    },
    Xdns {
        settings: FinalmaskXdns,
        extra: Map<String, Value>,
    },
    Xicmp {
        settings: FinalmaskXicmp,
        extra: Map<String, Value>,
    },
    Realm {
        settings: Box<FinalmaskRealm>,
        extra: Map<String, Value>,
    },
    Udphop {
        settings: Box<FinalmaskUdpHop>,
        extra: Map<String, Value>,
    },
    /// A future discriminator unknown to this Broccoli build. The complete raw
    /// envelope is retained and shown in the editor.
    Unknown(Value),
}

impl FinalmaskUdpMask {
    pub const TYPES: &'static [&'static str] = &[
        "header-custom",
        "mkcp-legacy",
        "noise",
        "salamander",
        "sudoku",
        "xdns",
        "xicmp",
        "realm",
        "udphop",
    ];

    pub fn known_type(&self) -> Option<&'static str> {
        match self {
            Self::HeaderCustom { .. } => Some("header-custom"),
            Self::MkcpLegacy { .. } => Some("mkcp-legacy"),
            Self::Noise { .. } => Some("noise"),
            Self::Salamander { .. } => Some("salamander"),
            Self::Sudoku { .. } => Some("sudoku"),
            Self::Xdns { .. } => Some("xdns"),
            Self::Xicmp { .. } => Some("xicmp"),
            Self::Realm { .. } => Some("realm"),
            Self::Udphop { .. } => Some("udphop"),
            Self::Unknown(_) => None,
        }
    }

    pub fn discriminator(&self) -> Option<&str> {
        self.known_type().or_else(|| match self {
            Self::Unknown(Value::Object(object)) => object.get("type").and_then(Value::as_str),
            _ => None,
        })
    }

    pub fn from_known_type(kind: &str) -> Option<Self> {
        let extra = Map::new();
        Some(match kind {
            "header-custom" => Self::HeaderCustom {
                settings: FinalmaskHeaderCustomUdp::default(),
                extra,
            },
            "mkcp-legacy" => Self::MkcpLegacy {
                settings: FinalmaskMkcpLegacy::default(),
                extra,
            },
            "noise" => Self::Noise {
                settings: FinalmaskNoise::default(),
                extra,
            },
            "salamander" => Self::Salamander {
                settings: FinalmaskSalamander::default(),
                extra,
            },
            "sudoku" => Self::Sudoku {
                settings: FinalmaskSudoku::default(),
                extra,
            },
            "xdns" => Self::Xdns {
                settings: FinalmaskXdns::default(),
                extra,
            },
            "xicmp" => Self::Xicmp {
                settings: FinalmaskXicmp::default(),
                extra,
            },
            "realm" => Self::Realm {
                settings: Box::new(FinalmaskRealm::default()),
                extra,
            },
            "udphop" => Self::Udphop {
                settings: Box::new(FinalmaskUdpHop::default()),
                extra,
            },
            _ => return None,
        })
    }
}

fn split_finalmask_envelope(raw: &Value) -> Option<(String, Value, Map<String, Value>)> {
    let mut object = raw.as_object()?.clone();
    let kind = object.get("type")?.as_str()?.to_string();
    object.remove("type");
    let settings = match object.remove("settings") {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(settings) => settings,
    };
    Some((kind, settings, object))
}

fn serialize_finalmask_envelope<S, T>(
    kind: &str,
    settings: &T,
    extra: &Map<String, Value>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize,
{
    let mut object = extra.clone();
    object.insert("type".into(), Value::String(kind.into()));
    object.insert(
        "settings".into(),
        serde_json::to_value(settings).map_err(<S::Error as serde::ser::Error>::custom)?,
    );
    Value::Object(object).serialize(serializer)
}

impl Serialize for FinalmaskTcpMask {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::HeaderCustom { settings, extra } => {
                serialize_finalmask_envelope("header-custom", settings, extra, serializer)
            }
            Self::Fragment { settings, extra } => {
                serialize_finalmask_envelope("fragment", settings, extra, serializer)
            }
            Self::Sudoku { settings, extra } => {
                serialize_finalmask_envelope("sudoku", settings, extra, serializer)
            }
            Self::Xmc { settings, extra } => {
                serialize_finalmask_envelope("xmc", settings, extra, serializer)
            }
            Self::Unknown(raw) => raw.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for FinalmaskTcpMask {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Value::deserialize(deserializer)?;
        let Some((kind, settings, extra)) = split_finalmask_envelope(&raw) else {
            return Ok(Self::Unknown(raw));
        };
        match kind.as_str() {
            "header-custom" => Ok(Self::HeaderCustom {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            "fragment" => Ok(Self::Fragment {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            "sudoku" => Ok(Self::Sudoku {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            "xmc" => Ok(Self::Xmc {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            _ => Ok(Self::Unknown(raw)),
        }
    }
}

impl Serialize for FinalmaskUdpMask {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::HeaderCustom { settings, extra } => {
                serialize_finalmask_envelope("header-custom", settings, extra, serializer)
            }
            Self::MkcpLegacy { settings, extra } => {
                serialize_finalmask_envelope("mkcp-legacy", settings, extra, serializer)
            }
            Self::Noise { settings, extra } => {
                serialize_finalmask_envelope("noise", settings, extra, serializer)
            }
            Self::Salamander { settings, extra } => {
                serialize_finalmask_envelope("salamander", settings, extra, serializer)
            }
            Self::Sudoku { settings, extra } => {
                serialize_finalmask_envelope("sudoku", settings, extra, serializer)
            }
            Self::Xdns { settings, extra } => {
                serialize_finalmask_envelope("xdns", settings, extra, serializer)
            }
            Self::Xicmp { settings, extra } => {
                serialize_finalmask_envelope("xicmp", settings, extra, serializer)
            }
            Self::Realm { settings, extra } => {
                serialize_finalmask_envelope("realm", settings, extra, serializer)
            }
            Self::Udphop { settings, extra } => {
                serialize_finalmask_envelope("udphop", settings, extra, serializer)
            }
            Self::Unknown(raw) => raw.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for FinalmaskUdpMask {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Value::deserialize(deserializer)?;
        let Some((kind, settings, extra)) = split_finalmask_envelope(&raw) else {
            return Ok(Self::Unknown(raw));
        };
        match kind.as_str() {
            "header-custom" => Ok(Self::HeaderCustom {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            "mkcp-legacy" => Ok(Self::MkcpLegacy {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            "noise" => Ok(Self::Noise {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            "salamander" => Ok(Self::Salamander {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            "sudoku" => Ok(Self::Sudoku {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            "xdns" => Ok(Self::Xdns {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            "xicmp" => Ok(Self::Xicmp {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            "realm" => Ok(Self::Realm {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            "udphop" => Ok(Self::Udphop {
                settings: serde_json::from_value(settings)
                    .map_err(<D::Error as serde::de::Error>::custom)?,
                extra,
            }),
            _ => Ok(Self::Unknown(raw)),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FinalmaskModel {
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub tcp: Vec<FinalmaskTcpMask>,
    #[serde(skip_serializing_if = "skip_empty_vec")]
    pub udp: Vec<FinalmaskUdpMask>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quic_params: Option<FinalmaskQuicParams>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl FinalmaskModel {
    pub fn is_empty(&self) -> bool {
        self.tcp.is_empty()
            && self.udp.is_empty()
            && self.quic_params.is_none()
            && self.extra.is_empty()
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StreamModel {
    #[serde(alias = "method")]
    pub network: Network,
    #[serde(
        rename = "tcpSettings",
        alias = "rawSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub raw_settings: Option<RawSettings>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        alias = "splithttpSettings",
        alias = "splitHttpSettings"
    )]
    pub xhttp_settings: Option<XhttpSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kcp_settings: Option<KcpSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grpc_settings: Option<GrpcSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_settings: Option<WsSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub httpupgrade_settings: Option<HttpupgradeSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hysteria_settings: Option<HysteriaTransport>,
    #[serde(skip_serializing_if = "Security::is_none")]
    pub security: Security,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_settings: Option<TlsModel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reality_settings: Option<RealityModel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sockopt: Option<SockoptModel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finalmask: Option<FinalmaskModel>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl StreamModel {
    pub fn xhttp_download_depth(&self) -> usize {
        let mut depth = 0;
        let mut stream = self;
        while stream.network == Network::Xhttp {
            let Some(next) = stream
                .xhttp_settings
                .as_ref()
                .and_then(|settings| settings.download_settings.as_deref())
            else {
                break;
            };
            depth += 1;
            stream = next;
        }
        depth
    }

    /// Remove inactive transport and security blocks on a cloned wire model.
    /// Xray builds every non-nil transport block but selects one security block.
    pub(crate) fn retain_selected_stream_blocks_for_wire(&mut self) {
        if self.network != Network::Raw {
            self.raw_settings = None;
        }
        if self.network != Network::Xhttp {
            self.xhttp_settings = None;
        }
        if self.network != Network::Kcp {
            self.kcp_settings = None;
        }
        if self.network != Network::Grpc {
            self.grpc_settings = None;
        }
        if self.network != Network::Ws {
            self.ws_settings = None;
        }
        if self.network != Network::Httpupgrade {
            self.httpupgrade_settings = None;
        }
        if self.network != Network::Hysteria {
            self.hysteria_settings = None;
        }
        match self.security {
            Security::None => {
                self.tls_settings = None;
                self.reality_settings = None;
            }
            Security::Tls => self.reality_settings = None,
            Security::Reality => self.tls_settings = None,
        }
        if let Some(websocket) = self.ws_settings.as_mut() {
            // `self` is the cloned wire model. Canonicalize Xray's accepted
            // legacy Host header here without mutating persisted/imported state.
            let _ = websocket.migrate_legacy_host_header();
        }
        if let Some(download) = self
            .xhttp_settings
            .as_mut()
            .and_then(|settings| settings.download_settings.as_deref_mut())
        {
            download.enforce_invariants();
            download.retain_selected_stream_blocks_for_wire();
        }
        if let Some(finalmask) = self.finalmask.as_mut() {
            if let Some(quic) = finalmask.quic_params.as_mut() {
                // The retired key is a settings-file fact only: it
                // round-trips through `servers.json` so the user still sees
                // the profile's state, and the generated document never
                // carries it.
                quic.retired_udp_hop = None;
            }
            for mask in finalmask.udp.iter_mut() {
                if let FinalmaskUdpMask::Udphop { settings, .. } = mask {
                    // The hop socket takes prefixes; an address entry is
                    // spelled out with its width (`infra/conf/
                    // transport_finalmask.go:950-960` normalizes the same
                    // way). An entry that parses as neither form stays
                    // verbatim — the validation gate names it before the
                    // wire is ever built.
                    for entry in settings.remote_ips.iter_mut() {
                        if let Some(normalized) = finalmask_udphop_remote_ip(entry) {
                            *entry = normalized;
                        }
                    }
                }
            }
        }
    }

    /// True when serializing would produce nothing meaningful (raw network,
    /// no security, no sockopt/finalmask) — the generator omits the whole
    /// `streamSettings` key in that case.
    pub fn is_default(&self) -> bool {
        self.network == Network::Raw
            && self.raw_settings.is_none()
            && self.xhttp_settings.is_none()
            && self.kcp_settings.is_none()
            && self.grpc_settings.is_none()
            && self.ws_settings.is_none()
            && self.httpupgrade_settings.is_none()
            && self.hysteria_settings.is_none()
            && self.security == Security::None
            && self.tls_settings.is_none()
            && self.reality_settings.is_none()
            && self.sockopt.is_none()
            && self.finalmask.is_none()
            && self.extra.is_empty()
    }

    /// Select a transport while keeping the cross-field Xray invariants valid.
    pub fn select_network(&mut self, network: Network) -> Result<(), ValidationCode> {
        if self.security == Security::Reality
            && network != Network::Hysteria
            && !network.supports_reality()
        {
            return Err(ValidationCode::RealityRequiresTransport);
        }
        self.network = network;
        match network {
            Network::Raw => {
                self.raw_settings.get_or_insert_with(RawSettings::default);
            }
            Network::Xhttp => {
                self.xhttp_settings
                    .get_or_insert_with(XhttpSettings::default);
            }
            Network::Kcp => {
                self.kcp_settings.get_or_insert_with(KcpSettings::default);
            }
            Network::Grpc => {
                self.grpc_settings.get_or_insert_with(GrpcSettings::default);
            }
            Network::Ws => {
                self.ws_settings.get_or_insert_with(WsSettings::default);
            }
            Network::Httpupgrade => {
                self.httpupgrade_settings
                    .get_or_insert_with(HttpupgradeSettings::default);
            }
            Network::Hysteria => {
                let settings = self
                    .hysteria_settings
                    .get_or_insert_with(HysteriaTransport::default);
                settings.version = 2;
                self.security = Security::Tls;
                self.tls_settings.get_or_insert_with(TlsModel::default);
            }
        }
        Ok(())
    }

    /// Select security if Xray supports it for the current transport.
    pub fn select_security(&mut self, security: Security) -> Result<(), ValidationCode> {
        if self.network == Network::Hysteria && security != Security::Tls {
            return Err(ValidationCode::HysteriaTransportRequiresTls);
        }
        if security == Security::Reality && !self.network.supports_reality() {
            return Err(ValidationCode::RealityRequiresTransport);
        }
        self.security = security;
        match security {
            Security::None => {}
            Security::Tls => {
                self.tls_settings.get_or_insert_with(TlsModel::default);
            }
            Security::Reality => {
                self.reality_settings
                    .get_or_insert_with(RealityModel::default);
            }
        }
        Ok(())
    }

    /// Normalize safe invariants in persisted models. An incompatible REALITY
    /// profile stays invalid (and is rejected by validation) rather than being
    /// silently downgraded to plaintext; an xHTTP `stream-one` block keeps its
    /// `downloadSettings` subtree for the same reason (validation reports
    /// `StreamOneNoDownload` and generation refuses to emit it).
    pub fn enforce_invariants(&mut self) {
        // Raw/TCP has no required settings object. Preserve its absence so a
        // default outbound remains wire-minimal; explicit rawSettings/tcpSettings
        // stays present and all non-raw transports are still materialized.
        let raw_settings_were_absent = self.network == Network::Raw && self.raw_settings.is_none();
        let network = self.network;
        let _ = self.select_network(network);
        if raw_settings_were_absent {
            self.raw_settings = None;
        }
        let security = self.security;
        let _ = self.select_security(security);
        if let Some(xhttp) = self.xhttp_settings.as_mut() {
            // `mode == "stream-one"` with `downloadSettings` set stays exactly
            // as loaded: Xray's SplitHTTPConfig.Build refuses the combination
            // (infra/conf/transport_method.go:500-501 "Can not use
            // \"downloadSettings\" in \"stream-one\" mode."), so validation
            // reports `StreamOneNoDownload` (Error tier), generation refuses
            // to emit the config, and the editor repairs it from the model's
            // own repair affordance. Dropping the subtree here would delete an
            // imported transport block with no message instead.
            if let Some(xmux) = xhttp.xmux.as_mut()
                && xmux.max_concurrency.is_some()
            {
                xmux.max_connections = None;
            }
        }
        // Preserve imported `headers.Host` exactly until the user explicitly
        // accepts the migration in the editor. Xray still accepts it and
        // normalizes it during config construction; automatic normalization
        // here would make read-only persistence and golden generation mutate
        // an imported profile.
        if let Some(sockopt) = self.sockopt.as_mut()
            && sockopt.address_port_strategy == "txt"
        {
            sockopt.address_port_strategy = "txtportandaddress".into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CustomSockopt, FinalmaskModel, FinalmaskTcpMask, FinalmaskUdpMask, HappyEyeballs,
        HysteriaTransport, MAX_XHTTP_DOWNLOAD_DEPTH, RawSettings, Security, SockoptModel,
        StreamModel, TlsCert, TlsModel, WsSettings, XhttpSettings,
    };
    use crate::model::{OutboundModel, Protocol};
    use serde_json::{Map, json};

    #[test]
    fn raw_transport_uses_canonical_tcp_settings_wire_key() {
        let stream = StreamModel {
            raw_settings: Some(RawSettings::default()),
            ..Default::default()
        };

        let wire = serde_json::to_value(stream).unwrap();
        assert!(wire.get("tcpSettings").is_some());
        assert!(wire.get("rawSettings").is_none());
    }

    #[test]
    fn raw_transport_accepts_canonical_and_legacy_wire_keys() {
        for key in ["tcpSettings", "rawSettings"] {
            let stream: StreamModel = serde_json::from_value(json!({
                "network": "raw",
                (key): {}
            }))
            .unwrap();
            assert!(stream.raw_settings.is_some(), "{key}");
        }
    }

    #[test]
    fn tls_inline_pem_uses_xray_string_array_wire_shape() {
        let certificate = TlsCert {
            certificate: vec![
                "-----BEGIN CERTIFICATE-----".into(),
                "certificate-body".into(),
                "-----END CERTIFICATE-----".into(),
            ],
            key: vec![
                "-----BEGIN PRIVATE KEY-----".into(),
                "private-key-body".into(),
                "-----END PRIVATE KEY-----".into(),
            ],
            ..Default::default()
        };

        assert_eq!(
            serde_json::to_value(certificate).unwrap(),
            json!({
                "certificate": [
                    "-----BEGIN CERTIFICATE-----",
                    "certificate-body",
                    "-----END CERTIFICATE-----"
                ],
                "key": [
                    "-----BEGIN PRIVATE KEY-----",
                    "private-key-body",
                    "-----END PRIVATE KEY-----"
                ]
            })
        );
    }

    #[test]
    fn tls_inline_pem_migrates_legacy_scalar_state() {
        let certificate: TlsCert = serde_json::from_value(json!({
            "certificate": "legacy certificate",
            "key": "legacy key"
        }))
        .unwrap();

        assert_eq!(certificate.certificate, vec!["legacy certificate"]);
        assert_eq!(certificate.key, vec!["legacy key"]);
        assert_eq!(
            serde_json::to_value(certificate).unwrap(),
            json!({
                "certificate": ["legacy certificate"],
                "key": ["legacy key"]
            })
        );
    }

    #[test]
    fn tls_ech_sockopt_uses_socket_config_wire_shape_and_preserves_extensions() {
        let persisted = json!({
            "echConfigList": "example.com+https://1.1.1.1/dns-query",
            "echSockopt": {
                "domainStrategy": "UseIPv4",
                "tcpFastOpen": false,
                "acceptProxyProtocol": true,
                "tcpKeepAliveIdle": 30,
                "customSockopt": [{
                    "system": "windows",
                    "network": "tcp",
                    "level": "6",
                    "type": "int",
                    "opt": "31",
                    "value": "4",
                    "futureCustom": {"kept": true}
                }],
                "happyEyeballs": {
                    "prioritizeIPv6": true,
                    "interleave": 2,
                    "futureHappyEyeballs": [1, 2]
                },
                "trustedXForwardedFor": ["X-Forwarded-For"],
                "futureSocketOption": {"kept": "losslessly"}
            },
            "futureTlsOption": 7
        });
        let tls: TlsModel = serde_json::from_value(persisted.clone()).unwrap();
        let sockopt = tls.ech_sockopt.as_ref().unwrap();
        assert_eq!(sockopt.domain_strategy, "UseIPv4");
        assert_eq!(sockopt.accept_proxy_protocol, Some(true));
        assert_eq!(
            sockopt.extra["futureSocketOption"],
            json!({"kept": "losslessly"})
        );
        assert_eq!(
            sockopt.custom_sockopt[0].extra["futureCustom"],
            json!({"kept": true})
        );
        assert_eq!(
            sockopt.happy_eyeballs.as_ref().unwrap().extra["futureHappyEyeballs"],
            json!([1, 2])
        );
        assert_eq!(serde_json::to_value(&tls).unwrap(), persisted);

        let mut outbound = OutboundModel::new(Protocol::Freedom);
        outbound.stream.security = Security::Tls;
        outbound.stream.tls_settings = Some(tls);
        let wire = outbound.to_wire("direct");
        assert_eq!(
            wire["streamSettings"]["tlsSettings"]["echSockopt"],
            persisted["echSockopt"]
        );
        assert!(
            wire["streamSettings"]["tlsSettings"]
                .get("ech_socket_settings")
                .is_none()
        );
    }

    #[test]
    fn tls_ech_sockopt_rejects_malformed_known_socket_fields() {
        let error = serde_json::from_value::<TlsModel>(json!({
            "echSockopt": {"tcpKeepAliveIdle": "thirty"}
        }))
        .unwrap_err();
        assert!(error.to_string().contains("expected i32"));
    }

    #[test]
    fn finalmask_all_official_loaders_round_trip_exact_wire_envelopes() {
        let value = json!({
            "tcp": [
                {"type": "header-custom", "settings": {
                    "clients": [[{"delay": "1-2", "type": "hex", "packet": "00ff"}]],
                    "futureHeader": true
                }, "futureEnvelope": 1},
                {"type": "fragment", "settings": {
                    "packets": "tlshello", "lengths": ["100-200", "1-2"],
                    "delays": [1, "2-3"], "maxSplit": "1-4"
                }},
                {"type": "sudoku", "settings": {
                    "password": "pw", "ascii": "ascii", "customTable": "table",
                    "custom_table": "legacy", "customTables": ["a"],
                    "custom_tables": ["legacy-a"], "paddingMin": 1,
                    "padding_min": 2, "paddingMax": 3, "padding_max": 4
                }},
                {"type": "xmc", "settings": {
                    "hostname": "play.example", "password": "secret",
                    "profiles": [{
                        "username": "Player_1",
                        "uuid": "11111111-2222-3333-4444-555555555555",
                        "texturesValue": "value", "texturesSignature": "signature"
                    }]
                }}
            ],
            "udp": [
                {"type": "sudoku", "settings": {"password": "pw"}},
                {"type": "header-custom", "settings": {
                    "mode": "prefix",
                    "client": [{"rand": 8, "randRange": "1-254", "capture": "saved"}],
                    "server": [{"reuse": "saved"}]
                }},
                {"type": "mkcp-legacy", "settings": {"header": "dns", "value": "dns.example"}},
                {"type": "noise", "settings": {
                    "reset": "1-2",
                    "noise": [{"rand": "4-8", "randRange": "0-255", "delay": "1-3"}]
                }},
                {"type": "salamander", "settings": {"password": "pw", "packetSize": "1200-1400"}},
                {"type": "xdns", "settings": {
                    "domains": ["dns.example"], "resolvers": ["dns.example+udp://1.1.1.1:53"]
                }},
                {"type": "udphop", "settings": {
                    "mode": "intervalLocal,intervalRemote",
                    "interval": "5-10",
                    "remotePorts": "443,10000-10010",
                    "remoteIPs": ["203.0.113.10", "2001:db8::/48"],
                    "sockopt": {"domainStrategy": "UseIPv4", "interface": "eth0"},
                    "futureHop": {"kept": true}
                }}
            ],
            "quicParams": {
                "congestion": "force-brutal", "debug": false,
                "bbrProfile": "aggressive", "brutalUp": "8 mbps",
                "brutalDown": "16 mbps",
                "initStreamReceiveWindow": 16384,
                "maxStreamReceiveWindow": 32768,
                "initConnectionReceiveWindow": 65536,
                "maxConnectionReceiveWindow": 131072,
                "maxIdleTimeout": 30, "keepAlivePeriod": 10,
                "disablePathMTUDiscovery": false,
                "brutalDisableLossCompensation": true,
                "disableChromeParrot": true, "disableGSO": true,
                "disableStatelessReset": false,
                "maxIncomingStreams": 8,
                "futureQuic": {"kept": true}
            },
            "futureFinalmask": [1, 2, 3]
        });
        let model: FinalmaskModel = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&model).unwrap(), value);
        assert!(crate::model::validation::validate_finalmask(&model).is_empty());
        assert_eq!(model.tcp.len(), 4);
        assert_eq!(model.udp.len(), 7);

        // `realm` and `xicmp` demand the same wrap slot as `udphop` — the
        // last list entry — so their official envelopes round-trip in their
        // own chains, each led by the `sudoku` mask that must wrap first.
        for tail in [
            json!({"udp": [
                {"type": "sudoku", "settings": {"password": "pw"}},
                {"type": "xicmp", "settings": {"dgram": true, "ips": ["198.51.100.1"]}},
            ]}),
            json!({"udp": [
                {"type": "sudoku", "settings": {"password": "pw"}},
                {"type": "realm", "settings": {
                    "url": "realm://token@realm.example/id",
                    "stunServers": ["stun.example:3478"],
                    "tlsConfig": {
                        "serverName": "realm.example",
                        "echSockopt": {"domainStrategy": "UseIPv4"},
                        "futureTls": "kept"
                    }
                }},
            ]}),
        ] {
            let tail_model: FinalmaskModel = serde_json::from_value(tail.clone()).unwrap();
            assert_eq!(serde_json::to_value(&tail_model).unwrap(), tail);
            assert!(crate::model::validation::validate_finalmask(&tail_model).is_empty());
        }
    }

    #[test]
    fn quic_switches_are_absent_until_set_and_keep_their_upstream_spellings() {
        // The core's QuicParamsConfig reads this block with plain
        // `encoding/json` (`infra/conf/transport_finalmask.go:993-1011`):
        // an absent switch is the false zero value, and each set key must
        // re-emit under the exact spelling — `disableGSO` keeps its acronym
        // casing where camelCase would spell `disableGso`.
        let defaults: super::FinalmaskQuicParams =
            serde_json::from_value(json!({})).expect("an empty quicParams block loads");
        let wire = serde_json::to_value(&defaults).expect("the defaults serialize");
        assert_eq!(wire, json!({}), "unset switches must not emit anything");

        let loaded: super::FinalmaskQuicParams = serde_json::from_value(json!({
            "brutalDisableLossCompensation": true,
            "disableChromeParrot": true,
            "disableGSO": true,
            "disableStatelessReset": false
        }))
        .expect("the switches load");
        assert_eq!(loaded.brutal_disable_loss_compensation, Some(true));
        assert_eq!(loaded.disable_chrome_parrot, Some(true));
        assert_eq!(loaded.disable_gso, Some(true));
        assert_eq!(
            loaded.disable_stateless_reset,
            Some(false),
            "an explicit false is a value, not the unset state"
        );
        assert_eq!(
            serde_json::to_value(&loaded).expect("the switches serialize"),
            json!({
                "brutalDisableLossCompensation": true,
                "disableChromeParrot": true,
                "disableGSO": true,
                "disableStatelessReset": false
            }),
            "each switch must keep its upstream spelling"
        );
    }

    #[test]
    fn quic_path_mtu_switch_keeps_the_upstream_spelling_and_folds_the_legacy_one() {
        // `disablePathMTUDiscovery` is the upstream key. An older build of
        // this app wrote the plain camelCase spelling for it; that value now
        // stays tracked by the field (the core binds both spellings
        // case-insensitively) and re-emits under the upstream key only.
        let legacy: super::FinalmaskQuicParams = serde_json::from_value(json!({
            "disablePathMtuDiscovery": true
        }))
        .expect("the legacy spelling loads");
        assert_eq!(legacy.disable_path_mtu_discovery, Some(true));
        assert!(legacy.extra.is_empty());
        assert_eq!(
            serde_json::to_value(&legacy).expect("the switch serializes"),
            json!({"disablePathMTUDiscovery": true})
        );

        let canonical: super::FinalmaskQuicParams = serde_json::from_value(json!({
            "disablePathMTUDiscovery": false
        }))
        .expect("the upstream spelling loads");
        assert_eq!(canonical.disable_path_mtu_discovery, Some(false));
        assert!(canonical.extra.is_empty());
        assert_eq!(
            serde_json::to_value(&canonical).expect("the switch serializes"),
            json!({"disablePathMTUDiscovery": false})
        );
    }

    #[test]
    fn finalmask_unknown_discriminators_and_null_settings_are_lossless() {
        let value = json!({
            "tcp": [
                {"type": "future-tcp", "settings": {"raw": [1, null]}, "top": true},
                {"type": "fragment", "settings": null}
            ],
            "udp": [
                {"type": "future-udp", "settings": "opaque"},
                {"notEvenAnEnvelope": 7}
            ]
        });
        let model: FinalmaskModel = serde_json::from_value(value.clone()).unwrap();
        assert!(matches!(model.tcp[0], FinalmaskTcpMask::Unknown(_)));
        assert!(matches!(model.udp[0], FinalmaskUdpMask::Unknown(_)));
        assert!(matches!(model.udp[1], FinalmaskUdpMask::Unknown(_)));
        let serialized = serde_json::to_value(&model).unwrap();
        assert_eq!(serialized["tcp"][0], value["tcp"][0]);
        assert_eq!(serialized["udp"], value["udp"]);
        assert_eq!(serialized["tcp"][1]["type"], "fragment");
        assert_eq!(serialized["tcp"][1]["settings"], json!({}));
    }

    #[test]
    fn finalmask_validation_reports_representative_upstream_bounds() {
        let invalid: FinalmaskModel = serde_json::from_value(json!({
            "tcp": [
                {"type": "fragment", "settings": {"packets": "0", "length": 0}},
                {"type": "xmc", "settings": {
                    "password": "", "profiles": [{
                        "username": "x", "uuid": "bad",
                        "texturesValue": "", "texturesSignature": ""
                    }]
                }}
            ],
            "udp": [
                {"type": "noise", "settings": {
                    "noise": [{"rand": 1, "type": "hex", "packet": "00"}]
                }},
                {"type": "salamander", "settings": {"packetSize": "0-2049"}},
                {"type": "xdns", "settings": {"resolvers": ["https://dns.example"]}},
                {"type": "xicmp", "settings": {"ips": ["not-an-ip"]}},
                {"type": "realm", "settings": {"url": "https://example", "stunServers": []}},
                {"type": "udphop", "settings": {
                    "mode": "intervalLocal,banana", "interval": 4,
                    "remotePorts": 70000, "remoteIPs": ["nope"]
                }}
            ],
            "quicParams": {
                "congestion": "force-brutal", "brutalUp": "1 kbps",
                "bbrProfile": "turbo",
                "initStreamReceiveWindow": 1, "maxIdleTimeout": 3,
                "keepAlivePeriod": 61, "maxIncomingStreams": 7
            }
        }))
        .unwrap();
        let issues = crate::model::validation::validate_finalmask(&invalid);
        for (code, path) in [
            (
                crate::model::validation::ValidationCode::FinalmaskPacketsFirstNotZero,
                "finalmask.tcp[0].settings.packets",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskXmcUsernameInvalid,
                "finalmask.tcp[1].settings.profiles[0].username",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskNoisePacketExclusive,
                "finalmask.udp[0].settings.noise[0]",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskSalamanderPacketSize,
                "finalmask.udp[1].settings.packetSize",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskXdnsResolverUdp,
                "finalmask.udp[2].settings.resolvers[0]",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskXicmpIpInvalid,
                "finalmask.udp[3].settings.ips[0]",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskRealmScheme,
                "finalmask.udp[4].settings.url",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskUdpHopModeInvalid,
                "finalmask.udp[5].settings.mode",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskUdpHopIntervalTooSmall,
                "finalmask.udp[5].settings.interval",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskPortNumberRange,
                "finalmask.udp[5].settings.remotePorts",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskUdpHopIpInvalid,
                "finalmask.udp[5].settings.remoteIPs[0]",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskQuicBandwidthTooSmall,
                "finalmask.quicParams.brutalUp",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskQuicBbrProfileInvalid,
                "finalmask.quicParams.bbrProfile",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskQuicReceiveWindowTooSmall,
                "finalmask.quicParams.initStreamReceiveWindow",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskQuicMaxIdleTimeoutInvalid,
                "finalmask.quicParams.maxIdleTimeout",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskQuicKeepAlivePeriodInvalid,
                "finalmask.quicParams.keepAlivePeriod",
            ),
            (
                crate::model::validation::ValidationCode::FinalmaskQuicMaxIncomingStreamsInvalid,
                "finalmask.quicParams.maxIncomingStreams",
            ),
        ] {
            assert!(
                issues
                    .iter()
                    .any(|issue| issue.code == code && issue.path.as_deref() == Some(path)),
                "missing {code:?} at {path:?} in {issues:#?}"
            );
        }
    }

    #[test]
    fn retired_quic_udp_hop_key_round_trips_in_settings_and_never_reaches_the_wire() {
        // The hop moved to the `udphop` UDP mask and the core ignores the old
        // key silently (`infra/conf/transport_finalmask.go:88`). Every
        // non-null JSON shape loads, is kept verbatim for the settings file,
        // gates the profile, and never reaches the generated document. Go
        // binds the name case-insensitively, so case variants are caught too.
        for (fixture, key) in [
            (
                json!({"ports": "443,10000-10010", "interval": "5-10"}),
                "udpHop",
            ),
            (json!("srv-exit"), "Udphop"),
            (json!(7), "UDPHOP"),
            (json!(true), "udphop"),
            (json!(["a"]), "udpHop"),
        ] {
            let value = json!({
                "network": "hysteria",
                "finalmask": {
                    "quicParams": {"congestion": "bbr", key: fixture, "futureKey": "kept"}
                }
            });
            let stream: StreamModel = serde_json::from_value(value)
                .unwrap_or_else(|error| panic!("{key} = {fixture} must load: {error}"));
            let quic = stream
                .finalmask
                .as_ref()
                .and_then(|finalmask| finalmask.quic_params.as_ref())
                .expect("the quic params must load");
            assert_eq!(
                quic.retired_udp_hop.as_ref(),
                Some(&fixture),
                "the raw value must be kept ({key} = {fixture})"
            );
            assert_eq!(
                quic.extra.keys().collect::<Vec<_>>(),
                vec!["futureKey"],
                "the key must not survive as an unknown key ({key} = {fixture})"
            );
            // Every shape gates: the finding never inspects the value.
            assert!(
                crate::model::validation::validate_finalmask(
                    stream.finalmask.as_ref().expect("the finalmask loads")
                )
                .iter()
                .any(|issue| issue.code
                    == crate::model::validation::ValidationCode::FinalmaskQuicHopMoved),
                "{key} = {fixture} must gate"
            );

            // The settings file keeps the key exactly as loaded, so an
            // unrelated save cannot silently drop the user's hop.
            let persisted = serde_json::to_value(&stream).expect("the stream serializes");
            assert_eq!(
                persisted["finalmask"]["quicParams"]["udpHop"], fixture,
                "the settings file must round-trip the key ({key} = {fixture})"
            );
            let reloaded: StreamModel = serde_json::from_value(persisted)
                .unwrap_or_else(|error| panic!("{key} = {fixture} must reload: {error}"));
            let reloaded = reloaded
                .finalmask
                .and_then(|finalmask| finalmask.quic_params)
                .unwrap();
            assert_eq!(reloaded.retired_udp_hop.as_ref(), Some(&fixture));

            // The generated document never carries it.
            let mut wire_stream = stream.clone();
            wire_stream.retain_selected_stream_blocks_for_wire();
            let wire = serde_json::to_value(&wire_stream).expect("the stream serializes");
            assert!(
                wire["finalmask"]["quicParams"].get("udpHop").is_none(),
                "the wire must not carry the key ({key} = {fixture}): {wire}"
            );
            assert_eq!(wire["finalmask"]["quicParams"]["futureKey"], "kept");
        }

        // Several case variants, all non-null: every variant is consumed and
        // the last visited survives for re-emission ("udpHop" sorts after
        // "Udphop"), so no other variant survives anywhere.
        let mixed = json!({
            "network": "hysteria",
            "finalmask": {"quicParams": {
                "Udphop": {"ports": "first"}, "udpHop": {"ports": "second"}
            }}
        });
        let stream: StreamModel = serde_json::from_value(mixed).expect("mixed case variants load");
        let quic = stream
            .finalmask
            .as_ref()
            .and_then(|finalmask| finalmask.quic_params.as_ref())
            .unwrap();
        assert_eq!(quic.retired_udp_hop, Some(json!({"ports": "second"})));
        assert!(quic.extra.is_empty());
        let persisted = serde_json::to_value(&stream).expect("the stream serializes");
        assert_eq!(
            persisted["finalmask"]["quicParams"]["udpHop"],
            json!({"ports": "second"})
        );
        assert!(persisted["finalmask"]["quicParams"].get("Udphop").is_none());

        // JSON `null` is Go's nil pointer: the key is consumed as the Go zero
        // shape, so it marks nothing and is gone from the next save. It also
        // must not survive as an unknown key, and a null under any case
        // variant clears the key whatever the other variants carry.
        for (fixture, expected_extra) in [
            (json!({"quicParams": {"udpHop": null}}), 0),
            (json!({"quicParams": {"UDPHOP": null}}), 0),
            (
                json!({"quicParams": {"udpHop": {"ports": "443"}, "Udphop": null}}),
                0,
            ),
            (
                json!({"quicParams": {"Udphop": null, "futureKey": "kept"}}),
                1,
            ),
        ] {
            let value = json!({"network": "hysteria", "finalmask": fixture});
            let rendered = value.to_string();
            let stream: StreamModel = serde_json::from_value(value)
                .unwrap_or_else(|error| panic!("{rendered} must load: {error}"));
            let quic = stream
                .finalmask
                .as_ref()
                .and_then(|finalmask| finalmask.quic_params.as_ref())
                .expect("the quic params load");
            assert!(
                quic.retired_udp_hop.is_none(),
                "{rendered} must not mark the profile"
            );
            assert_eq!(quic.extra.len(), expected_extra, "{rendered}");
            assert!(
                !quic
                    .extra
                    .keys()
                    .any(|key| key.eq_ignore_ascii_case("udpHop")),
                "{rendered}"
            );
            let persisted = serde_json::to_value(&stream).expect("the stream serializes");
            assert!(
                persisted["finalmask"]["quicParams"]
                    .as_object()
                    .expect("the quic params serialize to an object")
                    .keys()
                    .all(|key| !key.eq_ignore_ascii_case("udpHop")),
                "{rendered} must not be written back: {persisted}"
            );
        }
    }

    #[test]
    fn retired_quic_udp_hop_key_gates_with_the_mask_migration_text() {
        use crate::model::validation::{Severity, ValidationCode, validate_finalmask};

        // The retired key produces one gating finding that names the mask and
        // the equivalence, while the hopped shape itself stays legal.
        let stream: StreamModel = serde_json::from_value(json!({
            "network": "hysteria",
            "finalmask": {"quicParams": {"udpHop": {"ports": "443", "interval": 0}}}
        }))
        .unwrap();
        let issues = validate_finalmask(stream.finalmask.as_ref().unwrap());
        assert_eq!(issues.len(), 1, "{issues:#?}");
        assert_eq!(issues[0].code, ValidationCode::FinalmaskQuicHopMoved);
        assert_eq!(issues[0].severity, Severity::Error);
        assert_eq!(issues[0].path, None);

        // A rebuilt hop mask validates clean.
        let rebuilt: StreamModel = serde_json::from_value(json!({
            "network": "hysteria",
            "finalmask": {"udp": [{"type": "udphop", "settings": {
                "mode": "intervalLocal,intervalRemote",
                "interval": "5-10",
                "remotePorts": "443",
                "remoteIPs": ["203.0.113.10"]
            }}]}
        }))
        .unwrap();
        assert!(validate_finalmask(rebuilt.finalmask.as_ref().unwrap()).is_empty());
    }

    #[test]
    fn udphop_wire_normalizes_remote_ips_to_prefixes() {
        // The hop socket takes prefixes: an address entry gains its width and
        // a prefix keeps its length, the way the mask build normalizes both
        // (`infra/conf/transport_finalmask.go:950-960`). An IPv6 zone is
        // accepted in either form — Go's ParseAddr keeps it and both
        // ParsePrefix and PrefixFrom strip it again — so `fe80::1%eth0`
        // becomes `fe80::1/128` and `fe80::1%eth0/64` becomes
        // `fe80::1/64`. The stored settings keep the text the user typed,
        // and an entry that parses as neither form stays verbatim (the gate
        // names it before the wire is ever built).
        let mut stream: StreamModel = serde_json::from_value(json!({
            "network": "hysteria",
            "finalmask": {"udp": [{"type": "udphop", "settings": {
                "mode": "perConnRemote",
                "interval": "5-10",
                "remoteIPs": [
                    "203.0.113.10", "2001:0db8::/48", "not-an-ip",
                    "fe80::1%eth0", "fe80::1%eth0/64", "fe80::1%eth0%more",
                    "fe80::1%eth0/64%x", "fe80::1%", "1.2.3.4%eth0"
                ]
            }}]}
        }))
        .unwrap();
        let stored = serde_json::to_value(&stream).expect("the stream serializes");
        assert_eq!(
            stored["finalmask"]["udp"][0]["settings"]["remoteIPs"],
            json!([
                "203.0.113.10",
                "2001:0db8::/48",
                "not-an-ip",
                "fe80::1%eth0",
                "fe80::1%eth0/64",
                "fe80::1%eth0%more",
                "fe80::1%eth0/64%x",
                "fe80::1%",
                "1.2.3.4%eth0"
            ])
        );
        stream.retain_selected_stream_blocks_for_wire();
        let wire = serde_json::to_value(&stream).expect("the stream serializes");
        assert_eq!(
            wire["finalmask"]["udp"][0]["settings"]["remoteIPs"],
            json!([
                "203.0.113.10/32",
                "2001:db8::/48",
                "not-an-ip",
                "fe80::1/128",
                "fe80::1/64",
                "fe80::1/128",
                "fe80::1/128",
                "fe80::1%",
                "1.2.3.4%eth0"
            ])
        );
    }

    #[test]
    fn realm_ip_mode_and_port_mapping_round_trip_and_stay_absent_when_unset() {
        use crate::model::validation::validate_finalmask;

        // A mask that sets neither key keeps its exact stored shape: the
        // envelope carries no `ipMode` and no `portMapping`.
        let bare: StreamModel = serde_json::from_value(json!({
            "network": "hysteria",
            "finalmask": {"udp": [{"type": "realm", "settings": {
                "url": "realm://token@realm.example/id",
                "stunServers": ["stun.example.com:3478"]
            }}]}
        }))
        .unwrap();
        assert_eq!(
            serde_json::to_value(&bare).unwrap()["finalmask"]["udp"][0]["settings"],
            json!({
                "url": "realm://token@realm.example/id",
                "stunServers": ["stun.example.com:3478"]
            })
        );

        // Both settings survive a settings-file round trip exactly, with the
        // core's own spelling preserved: `ipMode` keeps the case the user
        // typed (the core lowercases it at build), and unknown keys stay.
        let value = json!({
            "network": "hysteria",
            "finalmask": {"udp": [{"type": "realm", "settings": {
                "url": "realm://token@realm.example/id",
                "stunServers": ["stun.example.com:3478"],
                "ipMode": "V6",
                "portMapping": {"enabled": true, "timeout": 15, "lifetime": 300},
                "futureRealm": {"kept": true}
            }}]}
        });
        let stream: StreamModel = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&stream).unwrap(), value);
        assert!(validate_finalmask(stream.finalmask.as_ref().unwrap()).is_empty());

        // A partial `portMapping` keeps only the keys it carries. `enabled:
        // false` is the core's zero value, so the model drops it like every
        // other boolean and the object stays empty.
        for (mapping, expected) in [
            (json!({"enabled": false}), json!({})),
            (json!({"timeout": 30}), json!({"timeout": 30})),
            (json!({"lifetime": 300}), json!({"lifetime": 300})),
        ] {
            let stream: StreamModel = serde_json::from_value(json!({
                "network": "hysteria",
                "finalmask": {"udp": [{"type": "realm", "settings": {
                    "url": "realm://token@realm.example/id",
                    "stunServers": ["stun.example.com:3478"],
                    "portMapping": mapping
                }}]}
            }))
            .unwrap();
            let stored = serde_json::to_value(&stream).unwrap();
            assert_eq!(
                stored["finalmask"]["udp"][0]["settings"]["portMapping"], expected,
                "{stored}"
            );
            assert!(
                validate_finalmask(stream.finalmask.as_ref().unwrap()).is_empty(),
                "{stored}"
            );
        }
    }

    #[test]
    fn hysteria_masquerade_x_forwarded_round_trips_and_stays_absent_when_unset() {
        // An unset switch emits nothing, so profiles that never touched it
        // keep their exact wire shape.
        let bare: HysteriaTransport = serde_json::from_value(json!({
            "version": 2,
            "auth": "pw",
            "masquerade": {
                "type": "proxy", "url": "https://masq.example.com", "rewriteHost": true
            }
        }))
        .unwrap();
        assert_eq!(
            serde_json::to_value(&bare).unwrap()["masquerade"],
            json!({
                "type": "proxy", "url": "https://masq.example.com", "rewriteHost": true
            })
        );

        let value = json!({
            "version": 2,
            "auth": "pw",
            "masquerade": {
                "type": "proxy", "url": "https://masq.example.com",
                "rewriteHost": true, "xForwarded": true, "insecure": true
            }
        });
        let transport: HysteriaTransport = serde_json::from_value(value.clone()).unwrap();
        assert!(transport.masquerade.as_ref().unwrap().x_forwarded);
        assert_eq!(serde_json::to_value(&transport).unwrap(), value);
    }

    #[test]
    fn sockopt_validation_matches_xray_tfo_and_keepalive_build_semantics() {
        use crate::model::validation::{ValidationCode, validate_sockopt};

        let fractional_tfo = SockoptModel {
            tcp_fast_open: Some(json!(12.75)),
            ..Default::default()
        };
        assert!(validate_sockopt(&fractional_tfo, "stream.sockopt").is_empty());

        let conflicting_keepalive = SockoptModel {
            tcp_keep_alive_idle: Some(-1),
            tcp_keep_alive_interval: Some(30),
            ..Default::default()
        };
        assert!(
            validate_sockopt(&conflicting_keepalive, "stream.sockopt")
                .iter()
                .any(|issue| issue.code == ValidationCode::SockoptKeepaliveSigns)
        );
    }

    #[test]
    fn keepalive_validation_compares_signs_directly_without_multiply_overflow() {
        use crate::model::validation::{ValidationCode, validate_sockopt};

        fn reports_keepalive_conflict(model: &SockoptModel) -> bool {
            validate_sockopt(model, "stream.sockopt")
                .iter()
                .any(|issue| issue.code == ValidationCode::SockoptKeepaliveSigns)
        }

        // Large same-sign values: 86400 * 86400 overflows i32 and wrapped
        // negative under the old `wrapping_mul(...) < 0` check, falsely
        // reporting "opposite signs". Must be accepted.
        let one_day_keepalive = SockoptModel {
            tcp_keep_alive_idle: Some(86400),
            tcp_keep_alive_interval: Some(86400),
            ..Default::default()
        };
        assert!(!reports_keepalive_conflict(&one_day_keepalive));

        // Strictly opposite signs are rejected in both orders.
        let idle_negative = SockoptModel {
            tcp_keep_alive_idle: Some(-1),
            tcp_keep_alive_interval: Some(5),
            ..Default::default()
        };
        assert!(reports_keepalive_conflict(&idle_negative));

        let interval_negative = SockoptModel {
            tcp_keep_alive_idle: Some(5),
            tcp_keep_alive_interval: Some(-1),
            ..Default::default()
        };
        assert!(reports_keepalive_conflict(&interval_negative));

        // Large opposite-sign values: -86400 * 86400 wrapped positive under
        // the old check and slipped through. Must be rejected.
        let large_opposite_signs = SockoptModel {
            tcp_keep_alive_idle: Some(-86400),
            tcp_keep_alive_interval: Some(86400),
            ..Default::default()
        };
        assert!(reports_keepalive_conflict(&large_opposite_signs));

        // A missing field defaults to 0, which pairs as same-sign with any
        // other value (0 * x == 0 under the old check): no error. This must
        // hold for missing and explicit-zero values alike.
        for model in [
            SockoptModel {
                tcp_keep_alive_idle: None,
                tcp_keep_alive_interval: Some(-5),
                ..Default::default()
            },
            SockoptModel {
                tcp_keep_alive_idle: Some(-5),
                tcp_keep_alive_interval: None,
                ..Default::default()
            },
            SockoptModel {
                tcp_keep_alive_idle: Some(0),
                tcp_keep_alive_interval: Some(-5),
                ..Default::default()
            },
            SockoptModel {
                tcp_keep_alive_idle: Some(-5),
                tcp_keep_alive_interval: Some(0),
                ..Default::default()
            },
        ] {
            assert!(!reports_keepalive_conflict(&model));
        }

        // Same-sign negatives are not a conflict either.
        let both_negative = SockoptModel {
            tcp_keep_alive_idle: Some(-1),
            tcp_keep_alive_interval: Some(-5),
            ..Default::default()
        };
        assert!(!reports_keepalive_conflict(&both_negative));
    }

    #[test]
    fn sockopt_empty_check_covers_every_modeled_field() {
        macro_rules! assert_non_empty {
            ($field:ident, $value:expr_2021) => {{
                let mut sockopt = SockoptModel::default();
                sockopt.$field = $value;
                assert!(!sockopt.is_empty(), stringify!($field));
            }};
        }

        assert!(SockoptModel::default().is_empty());
        assert_non_empty!(domain_strategy, "UseIP".into());
        assert_non_empty!(dialer_proxy, "out".into());
        assert_non_empty!(interface, "Ethernet".into());
        assert_non_empty!(tcp_fast_open, Some(json!(true)));
        assert_non_empty!(accept_proxy_protocol, Some(false));
        assert_non_empty!(tcp_keep_alive_idle, Some(1));
        assert_non_empty!(tcp_keep_alive_interval, Some(1));
        assert_non_empty!(tcp_congestion, "bbr".into());
        assert_non_empty!(tcp_window_clamp, Some(1));
        assert_non_empty!(tcp_max_seg, Some(1));
        assert_non_empty!(tcp_user_timeout, Some(1));
        assert_non_empty!(tcp_mptcp, Some(false));
        assert_non_empty!(penetrate, Some(false));
        assert_non_empty!(mark, Some(0));
        assert_non_empty!(tproxy, Some("off".into()));
        assert_non_empty!(v6only, Some(false));
        assert_non_empty!(trusted_x_forwarded_for, vec!["X-Forwarded-For".into()]);
        assert_non_empty!(custom_sockopt, vec![CustomSockopt::default()]);
        assert_non_empty!(address_port_strategy, "srvportonly".into());
        assert_non_empty!(happy_eyeballs, Some(HappyEyeballs::default()));
        let mut extra = Map::new();
        extra.insert("future".into(), json!(true));
        assert_non_empty!(extra, extra);
    }

    #[test]
    fn websocket_legacy_host_migrates_before_header_removal() {
        let mut settings: WsSettings = serde_json::from_value(json!({
            "headers": {
                "hOsT": "legacy.example",
                "X-Test": "kept"
            }
        }))
        .unwrap();

        assert!(settings.migrate_legacy_host_header().unwrap());
        assert_eq!(settings.host, "legacy.example");
        assert_eq!(
            settings.headers,
            Map::from_iter([("X-Test".into(), json!("kept"))])
        );
    }

    #[test]
    fn websocket_legacy_host_is_canonicalized_for_wire_output() {
        let stream: StreamModel = serde_json::from_value(json!({
            "network": "ws",
            "wsSettings": {
                "headers": {
                    "Host": "wire.example",
                    "X-Test": "kept"
                }
            }
        }))
        .unwrap();
        let original = serde_json::to_value(&stream).unwrap();
        let mut outbound = OutboundModel::new(Protocol::Freedom);
        outbound.stream = stream;

        let wire = outbound.to_wire("direct");
        let websocket = &wire["streamSettings"]["wsSettings"];
        assert_eq!(websocket["host"], "wire.example");
        assert!(websocket["headers"].get("Host").is_none());
        assert_eq!(websocket["headers"]["X-Test"], "kept");
        assert_eq!(serde_json::to_value(&outbound.stream).unwrap(), original);
    }
    #[test]
    fn xhttp_download_depth_is_bounded_without_mutating_imported_nesting() {
        fn nested(depth: usize) -> StreamModel {
            let mut root = StreamModel::default();
            let mut current = &mut root;
            for _ in 0..depth {
                current.network = super::Network::Xhttp;
                let settings = current
                    .xhttp_settings
                    .get_or_insert_with(XhttpSettings::default);
                current = settings
                    .download_settings
                    .get_or_insert_with(|| Box::new(StreamModel::default()))
                    .as_mut();
            }
            root
        }

        let at_limit = nested(MAX_XHTTP_DOWNLOAD_DEPTH);
        assert_eq!(at_limit.xhttp_download_depth(), MAX_XHTTP_DOWNLOAD_DEPTH);
        let over_limit = nested(MAX_XHTTP_DOWNLOAD_DEPTH + 1);
        let original = serde_json::to_value(&over_limit).unwrap();
        assert_eq!(
            over_limit.xhttp_download_depth(),
            MAX_XHTTP_DOWNLOAD_DEPTH + 1
        );
        assert_eq!(serde_json::to_value(over_limit).unwrap(), original);
    }

    #[test]
    fn security_deserialize_accepts_all_wire_values() {
        for (wire, expected) in [
            ("none", Security::None),
            ("", Security::None),
            ("tls", Security::Tls),
            ("reality", Security::Reality),
            // Case-insensitive, as the previous lenient parser was.
            ("TLS", Security::Tls),
            ("Reality", Security::Reality),
        ] {
            let parsed: Security = serde_json::from_value(json!(wire))
                .unwrap_or_else(|e| panic!("security {wire:?} must deserialize: {e}"));
            assert_eq!(parsed, expected, "security {wire:?}");
            assert_eq!(
                serde_json::to_value(parsed).unwrap(),
                json!(parsed.as_str()),
                "security {wire:?} must round-trip"
            );
        }
    }

    #[test]
    fn security_deserialize_rejects_unknown_values_naming_value_and_field() {
        // A typo'd or trailing-space value must fail loudly, never silently
        // downgrade to plaintext.
        for wire in ["tls ", "nonee", "reality!", "1", "plain"] {
            let error = serde_json::from_value::<Security>(json!(wire))
                .expect_err(&format!("security {wire:?} must be rejected"));
            let message = format!("{error}");
            assert!(message.contains("security"), "names the field: {message}");
            assert!(message.contains(wire), "names the value: {message}");
        }
    }

    #[test]
    fn network_deserialize_accepts_all_wire_values_and_aliases() {
        for (wire, expected) in [
            ("raw", super::Network::Raw),
            ("tcp", super::Network::Raw),
            ("xhttp", super::Network::Xhttp),
            ("splithttp", super::Network::Xhttp),
            ("kcp", super::Network::Kcp),
            ("mkcp", super::Network::Kcp),
            ("grpc", super::Network::Grpc),
            ("ws", super::Network::Ws),
            ("websocket", super::Network::Ws),
            ("httpupgrade", super::Network::Httpupgrade),
            ("hysteria", super::Network::Hysteria),
        ] {
            let parsed: super::Network = serde_json::from_value(json!(wire))
                .unwrap_or_else(|e| panic!("network {wire:?} must deserialize: {e}"));
            assert_eq!(parsed, expected, "network {wire:?}");
            assert_eq!(
                serde_json::to_value(parsed).unwrap(),
                json!(parsed.as_str()),
                "network {wire:?} must round-trip"
            );
        }
    }

    #[test]
    fn network_deserialize_rejects_unknown_transports_naming_value_and_field() {
        // A typo'd or trailing-space transport must fail loudly, never
        // silently switch to raw.
        for wire in ["xhttp ", "raw ", "unknown", "quic", "tls"] {
            let error = serde_json::from_value::<super::Network>(json!(wire))
                .expect_err(&format!("network {wire:?} must be rejected"));
            let message = format!("{error}");
            assert!(message.contains("network"), "names the field: {message}");
            assert!(message.contains(wire), "names the value: {message}");
        }
    }

    #[test]
    fn unknown_network_in_stream_model_error_path_names_field() {
        let value = json!({ "network": "xhttp ", "security": "none" });
        let bytes = serde_json::to_vec(&value).unwrap();
        let mut de = serde_json::Deserializer::from_slice(&bytes);
        let error = serde_path_to_error::deserialize::<_, StreamModel>(&mut de)
            .expect_err("unknown network must fail StreamModel deserialization");
        let message = format!("{}: {}", error.path(), error.inner());
        assert!(message.contains("network"), "names the field: {message}");
        assert!(message.contains("xhttp "), "names the value: {message}");
    }

    #[test]
    fn unknown_enum_errors_bound_the_echoed_value() {
        // A multi-MB value in a hand-edited state file must never be embedded
        // whole in the load error: the echo is truncated to 48
        // chars with a `…` marker, mirroring the links module's excerpt
        // convention.
        let huge = "x".repeat(1 << 20);
        for ty in ["network", "security"] {
            let error = match ty {
                "network" => serde_json::from_value::<super::Network>(json!(huge))
                    .expect_err("huge unknown network must be rejected"),
                _ => serde_json::from_value::<Security>(json!(huge))
                    .expect_err("huge unknown security must be rejected"),
            };
            let message = format!("{error}");
            assert!(
                !message.contains(&huge),
                "{ty} error must not embed the full value ({} chars): {message}",
                huge.len()
            );
            assert!(
                message.len() < 200,
                "{ty} error must stay bounded, got {} chars: {message}",
                message.len()
            );
            assert!(
                message.contains('…'),
                "{ty} error marks the truncation: {message}"
            );
            assert!(
                message.contains(ty),
                "{ty} error names the field: {message}"
            );
        }
    }

    #[test]
    fn stream_one_download_settings_survive_load_and_stay_reported() {
        // Xray refuses `downloadSettings` in `stream-one` mode
        // (infra/conf/transport_method.go:500-501), but the loaded state keeps
        // the subtree: validation reports it and generation refuses to emit
        // it, so an imported or hand-edited profile is repaired by the user
        // instead of silently losing a whole nested transport block.
        let outbound: OutboundModel = serde_json::from_value(json!({
            "protocol": "vless",
            "settings": {
                "address": "example.com",
                "port": 443,
                "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
                "encryption": "none"
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {"serverName": "example.com"},
                "xhttpSettings": {
                    "mode": "stream-one",
                    "path": "/up",
                    "downloadSettings": {
                        "network": "ws",
                        "wsSettings": {"path": "/down"}
                    }
                }
            }
        }))
        .expect("the stream-one + downloadSettings state must load");

        let xhttp = outbound
            .stream
            .xhttp_settings
            .as_ref()
            .expect("xhttp settings survive load");
        assert_eq!(xhttp.mode, "stream-one");
        let download = xhttp
            .download_settings
            .as_deref()
            .expect("the nested download stream must survive load");
        assert_eq!(download.network, super::Network::Ws);
        assert_eq!(
            download.ws_settings.as_ref().map(|ws| ws.path.as_str()),
            Some("/down")
        );

        let issues = crate::model::validation::validate_outbound(&outbound);
        let finding = issues
            .iter()
            .find(|issue| {
                issue.code == crate::model::validation::ValidationCode::StreamOneNoDownload
            })
            .expect("stream-one + downloadSettings must still be reported");
        assert_eq!(
            finding.path.as_deref(),
            Some("stream.xhttpSettings.downloadSettings")
        );
        assert_eq!(finding.severity, crate::model::validation::Severity::Error);

        // Both generator entries gate on the first Error finding, so the
        // refused combination never reaches the wire even though the model
        // keeps it for the user to repair.
        let profile = crate::model::ServerProfile::new("example", outbound);
        let error = crate::r#gen::generate_latency_probe(&[profile], "", 45678, None)
            .expect_err("the probe generator must refuse the invalid pair");
        assert!(
            error.to_string().contains("downloadSettings"),
            "the refusal names the offending field: {error}"
        );
    }
}
