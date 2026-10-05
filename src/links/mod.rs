//! Share-link import/export + QR rendering.
//!
//! Xray-core has **no** share-link support (zero `vless://` matches in the Go
//! tree); the canonical spec is XTLS Discussion #716 ("VMessAEAD / VLESS
//! 分享链接标准提案") plus de-facto ecosystem conventions:
//!
//! - `vless://uuid@host:port?key=value…#name` — #716, current revision.
//! - `trojan://password@host:port?key=value…#name` — same query grammar;
//!   `security` defaults to `tls` (trojan implies TLS).
//! - `vmess://uuid@host:port?...#name` — the canonical #716 URL grammar.
//!   The obsolete Base64-JSON form is accepted on import only.
//! - `ss://base64url(method:password)@host:port#name` — SIP002; the plain
//!   userinfo form (`ss://method:password@…`) and the legacy
//!   whole-URI-base64 form are accepted on import. Export always uses the
//!   base64url userinfo form.
//!
//! Beyond #716, import accepts four schemes for protocols Xray supports but
//! the discussion never spells — `socks5://` / `socks://`, `http://` /
//! `https://`, `wg://` / `wireguard://`, `hysteria2://` / `hy2://` — one row
//! each in [`IMPORT_ONLY`]. Export never renders them: a protocol outside
//! [`SHAREABLE`] is refused by [`to_link`]. Their link grammars follow the
//! clients that emit them, which have no external spec, so import is
//! deliberately tolerant and export stays out of scope.
//!
//! Inputs that name removed or unrepresentable behavior are rejected, never
//! dropped or normalized:
//! - mKCP `seed` / non-`none` `headerType`, SIP002 `plugin=`, VMess `aid > 0`,
//!   `security=xtls`, SOCKS4/4a, Hysteria 1, `obfs=gecko`, and removed
//!   transports.
//! - gRPC `mode=guna`, which Xray's boolean `multiMode` cannot express.
//! - URL fields that are duplicated after percent-decoding, empty when #716
//!   forbids emptiness, or valid only for a different transport or security
//!   mode.
//!
//! Query parameters other clients emit that have no effective Xray field
//! (`allowInsecure`, `mux=…`, the QUIC / TLS-fragment knobs, …) are listed in
//! [`IGNORED_PARAMS`]: import drops them, keeps the model default, and reports
//! each through [`ParsedLink::ignored`] so the import can warn. A parameter
//! whose value spells a switch turned off (`0`, `false`, `no`) is already the
//! model default and is dropped silently. A parameter that is neither part of
//! the selected scheme's grammar nor on that list still refuses the link.
//!
//! Export also returns [`LinkError::Lossy`] for local-only mux/proxy/binding,
//! sockopt, rich headers, and advanced settings not carried by the target
//! grammar. Official XHTTP `extra` and finalmask `fm` JSON are preserved.
//!
//! REALITY PQ key: #716 names the parameter `pqv`; the early
//! `mldsa65Verify` alias is accepted on import, but the two may not coexist.
//! Export always emits `pqv`.
//!
//! The query grammar is declared once per transport in [`TRANSPORTS`]: a
//! transport's `type` value, the fields it carries with their import defaults
//! and export spellings, the model facts it cannot carry, and its settings
//! block. Import, export and the representability ladder all walk that table.
//! The shareable protocols are declared the same way in [`SHAREABLE`].
//!
//! Import also accepts the upstream aliases for a transport's `type` value —
//! `raw` for `tcp`, `mkcp` for `kcp`, `splithttp` for `xhttp`, `websocket`
//! for `ws` (infra/conf/transport_internet.go:14-28, the same set the model's
//! `Network::parse` carries) — and canonicalizes them: export always writes
//! the spec spelling, and RAW's is nothing at all.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fmt::Write as _;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::diag::Diag;
use crate::i18n::{Key, t_fmt, validation_issue_message};
use crate::model::Int32Range;
use crate::model::outbound::{
    HttpSettings, HysteriaSettings, OutboundModel, Protocol, ProtocolSettings, ShadowsocksSettings,
    SocksSettings, TrojanSettings, VlessSettings, VmessSettings, WireguardPeer, WireguardSettings,
    vless_encryption_supported,
};
use crate::model::servers::ServerProfile;
use crate::model::settings::Language;
use crate::model::stream::{
    FinalmaskModel, FinalmaskPortList, FinalmaskQuicParams, FinalmaskSalamander, FinalmaskUdpHop,
    FinalmaskUdpMask, GrpcSettings, HttpCamouflageRequest, HttpupgradeSettings, HysteriaTransport,
    KcpSettings, Network, RawHeader, RawSettings, RealityModel, Security, StreamModel, TlsModel,
    WsSettings, XhttpSettings,
};
use crate::model::validation::{
    ValidationIssue, is_canonical_uuid, is_vision_flow, validate_outbound,
};

/// A share-link failure that has no language yet. `Display` renders English
/// for logs and tests; the display boundary renders the active language with
/// [`LinkError::text`].
#[derive(Debug, Clone)]
pub enum LinkError {
    /// A link that names behavior the current Xray core does not support.
    Unsupported(Diag),
    /// A link that does not satisfy the share-link grammar.
    Malformed(Diag),
    /// A profile that the share-link grammar cannot carry.
    Lossy(Diag),
    /// A profile that the model validation pass refused. `prefix` introduces
    /// the finding; `None` renders the bare finding.
    InvalidModel {
        prefix: Option<Key>,
        issue: Box<ValidationIssue>,
    },
}

impl LinkError {
    /// Render the failure in `language`.
    pub fn text(&self, language: Language) -> String {
        match self {
            Self::Unsupported(message) | Self::Malformed(message) | Self::Lossy(message) => {
                message.text(language)
            }
            Self::InvalidModel { prefix, issue } => {
                let finding = validation_issue_message(issue, language);
                match prefix {
                    Some(prefix) => t_fmt(language, *prefix, &[&finding]),
                    None => finding,
                }
            }
        }
    }
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text(Language::En))
    }
}

impl Error for LinkError {}

/// A share link parsed into a profile plus the compatibility parameters the
/// grammar recognized but dropped.
///
/// Derefs to the profile, so a call site that does not care about the report
/// reads exactly like a plain profile.
#[derive(Debug, Clone)]
pub struct ParsedLink {
    pub profile: ServerProfile,
    /// The query parameters (and legacy-vmess JSON keys) other clients emit
    /// that have no effective Xray field, in link order. The profile already
    /// carries every model default they would have overridden; see
    /// [`IGNORED_PARAMS`].
    pub ignored: Vec<String>,
}

impl Deref for ParsedLink {
    type Target = ServerProfile;

    fn deref(&self) -> &Self::Target {
        &self.profile
    }
}

impl DerefMut for ParsedLink {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.profile
    }
}

/// Only a value that spells a switch turned off is the model default already;
/// every other presentation — including a bare flag with no value — is a
/// setting the link carries, so the report names it.
fn ignored_value_is_reported(value: &str) -> bool {
    !matches!(value.to_ascii_lowercase().as_str(), "0" | "false" | "no")
}

/// Record `key` once, in link order.
fn record_ignored(ignored: &mut Vec<String>, key: &str) {
    if !ignored.iter().any(|seen| seen == key) {
        ignored.push(key.to_string());
    }
}

/// Query parameters and legacy-vmess JSON keys other clients emit that have no
/// effective Xray field. Import drops each present one, keeps the model
/// default, and reports it through [`ParsedLink::ignored`]; export never
/// writes one, and a key that is neither here nor part of the selected
/// scheme's grammar still refuses the link.
const IGNORED_PARAMS: &[&str] = &[
    // Multiplex and its brutal congestion rates.
    "mux",
    "mux_protocol",
    "mux_max_connections",
    "mux_min_streams",
    "mux_max_streams",
    "mux_padding",
    "brutal_enabled",
    "brutal_up_mbps",
    "brutal_down_mbps",
    // XUDP packet encoding.
    "packetEncoding",
    // Dial (socket) fields.
    "reuse_addr",
    "connect_timeout",
    "tcp_fast_open",
    "tcp_multi_path",
    "udp_fragment",
    "bind_interface",
    "inet4_bind_address",
    "inet6_bind_address",
    // TLS knobs the share grammar does not spell.
    "disable_sni",
    "tls_min_version",
    "tls_max_version",
    "tls_cipher_suites",
    "tls_curve_preferences",
    "tls_certificate",
    "tls_certificate_path",
    "tls_certificate_public_key_sha256",
    "tls_client_certificate",
    "tls_client_certificate_path",
    "tls_client_key",
    "tls_client_key_path",
    "tls_fragment",
    "tls_fragment_fallback_delay",
    "tls_record_fragment",
    "tls_spoof_enabled",
    "tls_spoof",
    "tls_spoof_method",
    "tls_tricks",
    "ech_enabled",
    "ech_config_path",
    "ech_server_name",
    // QUIC transport knobs.
    "quic_idle_timeout",
    "quic_keep_alive_period",
    "quic_stream_receive_window",
    "quic_connection_receive_window",
    "quic_max_concurrent_streams",
    "quic_initial_packet_size",
    "quic_disable_path_mtu_discovery",
    // Certificate-verification switches: Xray replaced them with the pin
    // (`streamSettings.tlsSettings.pinnedPeerCertSha256`).
    "allowInsecure",
    "insecure",
    "allow_insecure",
    // SOCKS over-UDP: Xray's SOCKS outbound has no such switch.
    "uot",
    // WireGuard keys with no Xray field, including the AmneziaWG set.
    "use_system_interface",
    "workers",
    "udp_timeout",
    "enable_amnezia",
    "jc",
    "jmin",
    "jmax",
    "s1",
    "s2",
    "s3",
    "s4",
    "h1",
    "h2",
    "h3",
    "h4",
    "i1",
    "i2",
    "i3",
    "i4",
    "i5",
    "header_protection_key",
    "content_padding_addition",
    "rekey_after_time",
    "rekey_timeout",
    "reject_after_time",
    "keepalive_timeout",
    "max_handshake_attempts",
    "random_trailers",
    "disable_cookies",
];

/// Whether `key` is a recognized compatibility parameter.
fn is_ignored_param(key: &str) -> bool {
    IGNORED_PARAMS.contains(&key)
}

/// Drop `key` when it is a compatibility parameter with a reporting value,
/// returning whether it was consumed.
fn drop_ignored_param(ignored: &mut Vec<String>, key: &str, value: &str) -> bool {
    if is_ignored_param(key) {
        if ignored_value_is_reported(value) {
            record_ignored(ignored, key);
        }
        true
    } else {
        false
    }
}

/// A malformed-link failure whose message carries its key and values.
fn malformed(message: Diag) -> LinkError {
    LinkError::Malformed(message)
}

/// A lossy-export failure: `field` names the profile field that has no
/// share-link representation, and `key` carries the message.
fn lossy(field: &str, key: Key) -> LinkError {
    LinkError::Lossy(Diag::new(key).arg(field))
}

// ---------- percent / base64 helpers ----------

/// encodeURIComponent-compatible percent-encoding.
fn pct_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'!'
            | b'~'
            | b'*'
            | b'\''
            | b'('
            | b')' => out.push(b as char),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Strict percent-decoding (no `+` translation — for userinfo/fragment).
fn pct_decode(s: &str) -> Result<String, LinkError> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 3 > b.len() {
                return Err(malformed(
                    Diag::new(Key::LinkPercentTruncated).arg(excerpt_debug(s)),
                ));
            }
            let hi = hex_val(b[i + 1]).ok_or_else(|| {
                malformed(Diag::new(Key::LinkPercentEscape).arg(excerpt_debug(s)))
            })?;
            let lo = hex_val(b[i + 2]).ok_or_else(|| {
                malformed(Diag::new(Key::LinkPercentEscape).arg(excerpt_debug(s)))
            })?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out)
        .map_err(|_| malformed(Diag::new(Key::LinkPercentUtf8).arg(excerpt_debug(s))))
}

/// Query fields use the same strict percent-decoding as every other #716 URL
/// component. In particular, `+` is a literal plus (and canonical output
/// writes it as `%2B`); form-url-encoded `+`-as-space is not part of #716.
fn form_decode(s: &str) -> Result<String, LinkError> {
    pct_decode(s)
}

/// Bound on base64 payloads in share links: link bodies are structurally
/// small (JSON envelopes, keys, `method:password` pairs), so anything larger
/// is hostile input. Rejected before any engine allocates a decode buffer.
const MAX_B64_INPUT_LEN: usize = 1 << 20; // 1 MiB

/// Per-link length cap: share links are structurally small, so a single line
/// longer than this is hostile input. `parse_link` rejects it before any
/// per-component decode buffer is allocated.
pub const MAX_LINK_LEN: usize = 1 << 20; // 1 MiB

/// Aggregate cap for one bulk paste/subscription blob. The import dialog
/// refuses larger pastes before the worker thread sees them; `parse_bulk`
/// enforces the same bound as defense in depth.
pub const MAX_BULK_LEN: usize = 4 * MAX_LINK_LEN; // 4 MiB

/// Maximum characters of attacker-controlled input embedded in a rendered
/// diagnostic. Errors must never echo the full raw input; the bounded
/// echo surfaces listed on [`excerpt`] all share this one bound. Public
/// through `crate::excerpt`, so a test asserting the bound reads it here
/// instead of copying the number.
pub const MAX_ERROR_EXCERPT_CHARS: usize = 48;

/// Maximum bytes of a decoded profile name derived from a `#fragment`.
/// Names are persisted in `servers.json` and laid out every frame by the
/// dashboard/server list, so an unbounded fragment would be a one-time
/// multi-second layout followed by permanently retained per-frame cost
/// (LINK-002). Fragment names above this bound are rejected at import.
const MAX_PROFILE_NAME_LEN: usize = 512;

/// Canonical crate-wide bound for attacker-controlled text in diagnostics:
/// the first [`MAX_ERROR_EXCERPT_CHARS`] characters, truncated on a UTF-8
/// boundary with a trailing `…`. Every surface that echoes user-editable
/// text bounds it here: share-link parse errors, parameterized
/// `model::validation::ValidationCode` payloads, state-load semantic
/// errors, raw-override generation and parse errors, and the dashboard's
/// echoed generation errors. A hostile value can never inflate rendered
/// error text; identity below the bound keeps short values byte-identical.
pub fn excerpt(s: &str) -> String {
    let mut end = MAX_ERROR_EXCERPT_CHARS.min(s.len());
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    if end < s.len() {
        format!("{}…", &s[..end])
    } else {
        s.to_owned()
    }
}

/// Debug-escaped bounded excerpt, for `{:?}`-style error embeds.
pub(crate) fn excerpt_debug(s: &str) -> String {
    format!("{:?}", excerpt(s))
}

/// Character-class precheck for one base64 engine alphabet (no allocation).
/// Padded engines additionally admit `=`; no-pad engines reject it. This is a
/// superset of what the engine accepts (length and padding placement are
/// still validated by the decode pass), so decodable input is never skipped.
fn b64_alphabet_ok(s: &str, url_safe: bool, padded: bool) -> bool {
    s.bytes().all(|b| {
        b.is_ascii_uppercase()
            || b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || (if url_safe {
                matches!(b, b'-' | b'_')
            } else {
                matches!(b, b'+' | b'/')
            })
            || (padded && b == b'=')
    })
}

/// Try the base64 variants seen in the wild, first success wins.
fn b64_decode_any(s: &str) -> Option<Vec<u8>> {
    if s.len() > MAX_B64_INPUT_LEN {
        return None;
    }
    for (eng, url_safe, padded) in [
        (&URL_SAFE_NO_PAD, true, false),
        (&URL_SAFE, true, true),
        (&STANDARD, false, true),
        (&STANDARD_NO_PAD, false, false),
    ] {
        // Skip engines whose alphabet the input cannot match without
        // allocating a decode buffer (~3/4 x input per pass).
        if !b64_alphabet_ok(s, url_safe, padded) {
            continue;
        }
        if let Ok(v) = eng.decode(s) {
            return Some(v);
        }
    }
    None
}

// ---------- small parsed-query wrapper ----------

struct Query(Vec<(String, String)>);

impl Query {
    fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.as_str())
    }

    fn get_ne(&self, key: &str) -> Option<&str> {
        self.get(key).filter(|value| !value.is_empty())
    }
}

fn parse_query(query: &str) -> Result<Query, LinkError> {
    let mut values = Vec::new();
    let mut keys = HashSet::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = form_decode(raw_key)?;
        if !keys.insert(key.clone()) {
            return Err(malformed(
                Diag::new(Key::LinkQueryDuplicate).arg(excerpt_debug(&key)),
            ));
        }
        values.push((key, form_decode(raw_value)?));
    }
    Ok(Query(values))
}

// ---------- generic link structure ----------

/// Split `userinfo@host:port?query#fragment` (body after `scheme://`).
/// The fragment is raw (still percent-encoded); the query is raw.
fn split_link(body: &str) -> (&str, &str, &str) {
    let (rest, frag) = match body.find('#') {
        Some(i) => (&body[..i], &body[i + 1..]),
        None => (body, ""),
    };
    let (auth, query) = match rest.find('?') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    (auth, query, frag)
}

/// Sanitize a decoded profile name before it is stored (LINK-002): reject
/// names over [`MAX_PROFILE_NAME_LEN`] bytes and strip control characters,
/// so a crafted value can never inject newlines/escapes into a persisted
/// name or become a permanently retained rendering cost. Returns `None` when
/// the name filters down to nothing — callers fall back to the host-derived
/// default (an empty name cannot round-trip a share link). Shared by the
/// `#fragment` import path and the legacy vmess `ps` field.
fn sanitize_profile_name(decoded: &str) -> Result<Option<String>, LinkError> {
    if decoded.len() > MAX_PROFILE_NAME_LEN {
        return Err(malformed(
            Diag::new(Key::LinkNameTooLong).arg(MAX_PROFILE_NAME_LEN),
        ));
    }
    let cleaned: String = decoded.chars().filter(|c| !c.is_control()).collect();
    if cleaned.is_empty() {
        return Ok(None);
    }
    Ok(Some(cleaned))
}

/// Decode a `#fragment` into a stored profile name. Returns `None` when the
/// fragment is empty or filters down to nothing — callers then fall back to
/// the host-derived default (an empty name cannot round-trip a share link).
///
/// Names are persisted in `servers.json` and drawn verbatim every frame by
/// the dashboard and server list, so the decoded result is bounded and
/// control characters are stripped (LINK-002): a crafted `%0A`/`%0D`/`%00`/
/// `%1B` fragment must never inject newlines/escapes into a name, and a
/// multi-MB fragment must never become a permanently retained rendering
/// cost. Over-long fragments are rejected, not truncated, so the stored
/// name always denotes exactly the pasted link.
fn fragment_name(frag: &str) -> Result<Option<String>, LinkError> {
    if frag.is_empty() {
        return Ok(None);
    }
    sanitize_profile_name(&pct_decode(frag)?)
}

fn validate_host(host: &str, scheme: &str) -> Result<(), LinkError> {
    if host.is_empty() {
        return Err(malformed(Diag::new(Key::LinkHostMissing).arg(scheme)));
    }
    if !host.is_ascii() {
        return Err(malformed(Diag::new(Key::LinkHostIdn).arg(scheme)));
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    if host.contains(':')
        || host.bytes().any(|byte| {
            byte.is_ascii_control()
                || matches!(byte, b'/' | b'\\' | b'@' | b'?' | b'#' | b'[' | b']' | b'%')
        })
    {
        return Err(malformed(
            Diag::new(Key::LinkHostInvalid)
                .arg(excerpt_debug(host))
                .arg(scheme),
        ));
    }

    // A dotted all-numeric value is an IPv4 literal, not a DNS name. Reject
    // malformed/ambiguous forms such as 999.1.1.1 and 01.2.3.4.
    if host.contains('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(malformed(
            Diag::new(Key::LinkHostIpv4)
                .arg(excerpt_debug(host))
                .arg(scheme),
        ));
    }

    let dns = host.strip_suffix('.').unwrap_or(host);
    if dns.is_empty()
        || dns.len() > 253
        || dns.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(malformed(
            Diag::new(Key::LinkHostInvalid)
                .arg(excerpt_debug(host))
                .arg(scheme),
        ));
    }
    match url::Host::parse(dns) {
        Ok(url::Host::Domain(parsed)) if parsed.eq_ignore_ascii_case(dns) => {}
        _ => {
            return Err(malformed(
                Diag::new(Key::LinkHostInvalid)
                    .arg(excerpt_debug(host))
                    .arg(scheme),
            ));
        }
    }
    Ok(())
}

/// Split `userinfo@host`. `required` decides whether a body without `@` is
/// malformed (the #716 URL grammar requires the userinfo) or carries none
/// (the import-only schemes keep credentials in query fields).
fn split_authority<'a>(
    auth: &'a str,
    scheme: &str,
    required: bool,
) -> Result<(&'a str, &'a str), LinkError> {
    match auth.split_once('@') {
        Some((userinfo, host)) => {
            if host.contains('@') {
                return Err(malformed(Diag::new(Key::LinkUserinfoAt).arg(scheme)));
            }
            Ok((userinfo, host))
        }
        None if required => Err(malformed(Diag::new(Key::LinkUserinfoMissing).arg(scheme))),
        None => Ok(("", auth)),
    }
}

/// Split `host[:port]` / `[v6][:port]`. Returns the host without brackets and
/// the port text when the link carries one.
fn split_host_port<'a>(hp: &'a str, scheme: &str) -> Result<(String, Option<&'a str>), LinkError> {
    if let Some(rest) = hp.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(|| {
            malformed(
                Diag::new(Key::LinkHostIpv6)
                    .arg(excerpt_debug(hp))
                    .arg(scheme),
            )
        })?;
        let host = &rest[..end];
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(malformed(Diag::new(Key::LinkHostIpv6Brackets).arg(scheme)));
        }
        let tail = &rest[end + 1..];
        if tail.is_empty() {
            return Ok((host.to_string(), None));
        }
        match tail.strip_prefix(':') {
            Some(port) => Ok((host.to_string(), Some(port))),
            None => Err(malformed(Diag::new(Key::LinkHostBracketed).arg(scheme))),
        }
    } else {
        if hp.contains('[') || hp.contains(']') {
            return Err(malformed(Diag::new(Key::LinkHostBracketed).arg(scheme)));
        }
        match hp.rsplit_once(':') {
            Some((h, p)) => {
                if h.contains(':') {
                    return Err(malformed(
                        Diag::new(Key::LinkHostIpv6Unbracketed).arg(scheme),
                    ));
                }
                Ok((h.to_string(), Some(p)))
            }
            None => Ok((hp.to_string(), None)),
        }
    }
}

/// The host and port both finite, with the grammar's shared checks.
fn finish_host_port(host: String, port_s: &str, scheme: &str) -> Result<(String, u16), LinkError> {
    validate_host(&host, scheme)?;
    let port: u16 = port_s.parse().map_err(|_| {
        malformed(
            Diag::new(Key::LinkPortInvalid)
                .arg(excerpt_debug(port_s))
                .arg(scheme),
        )
    })?;
    if port == 0 {
        return Err(malformed(Diag::new(Key::LinkPortZero).arg(scheme)));
    }
    Ok((host, port))
}

/// Parse `host:port` / `[v6]:port`. Returns host without brackets.
fn parse_host_port(hp: &str, scheme: &str) -> Result<(String, u16), LinkError> {
    let (host, port_s) = split_host_port(hp, scheme)?;
    let port_s = port_s.ok_or_else(|| malformed(Diag::new(Key::LinkPortMissing).arg(scheme)))?;
    finish_host_port(host, port_s, scheme)
}

/// Parse `host[:port]` / `[v6][:port]`, using `default_port` when the link
/// omits one (the grammars of the import-only schemes allow the omission).
fn parse_host_port_default(
    hp: &str,
    scheme: &str,
    default_port: u16,
) -> Result<(String, u16), LinkError> {
    let (host, port_s) = split_host_port(hp, scheme)?;
    match port_s {
        Some(port_s) => finish_host_port(host, port_s, scheme),
        None => {
            validate_host(&host, scheme)?;
            Ok((host, default_port))
        }
    }
}

/// `host:port`, re-bracketing IPv6.
fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The import grammar's UUID rule: [`is_canonical_uuid`]'s verdict mapped to
/// the grammar's own `LinkUuidInvalid` diagnostic — the rule has one
/// definition (the model's), and this keeps only the message channel.
fn check_uuid(id: &str, scheme: &str) -> Result<(), LinkError> {
    if !is_canonical_uuid(id) {
        Err(malformed(
            Diag::new(Key::LinkUuidInvalid)
                .arg(excerpt_debug(id))
                .arg(scheme),
        ))
    } else {
        Ok(())
    }
}

fn split_alpn(v: Option<&str>) -> Vec<String> {
    v.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

fn validate_url_query(
    q: &Query,
    proto: Protocol,
    ignored: &mut Vec<String>,
) -> Result<(), LinkError> {
    let transport = match q.get("type") {
        Some("") => return Err(malformed(Diag::new(Key::LinkQueryEmpty).arg("type"))),
        Some(value) => value,
        None => DEFAULT_TYPE,
    };
    let spec = transport_for_type(transport)?;

    let default_security = if proto == Protocol::Trojan {
        "tls"
    } else {
        "none"
    };
    let security = match q.get("security") {
        Some("") => return Err(malformed(Diag::new(Key::LinkQueryEmpty).arg("security"))),
        Some(value) => value,
        None => default_security,
    };
    match security {
        "none" | "tls" | "reality" => {}
        "xtls" => {
            return Err(LinkError::Unsupported(Diag::new(Key::LinkUnsupportedXtls)));
        }
        other => {
            return Err(malformed(
                Diag::new(Key::LinkSecurityUnknown).arg(excerpt_debug(other)),
            ));
        }
    }

    if let Some(encryption) = q.get("encryption") {
        if proto == Protocol::Trojan {
            return Err(LinkError::Unsupported(Diag::new(
                Key::LinkUnsupportedTrojanEncryption,
            )));
        }
        if encryption.is_empty() {
            return Err(malformed(Diag::new(Key::LinkQueryEmpty).arg("encryption")));
        }
    }
    if q.get("flow").is_some() && proto != Protocol::Vless {
        return Err(LinkError::Unsupported(Diag::new(Key::LinkUnsupportedFlow)));
    }
    if q.get("pqv").is_some() && q.get("mldsa65Verify").is_some() {
        return Err(malformed(Diag::new(Key::LinkRealityMldsaDuplicate)));
    }

    if let Some(mode) = q.get("mode") {
        if mode.is_empty() {
            return Err(malformed(Diag::new(Key::LinkQueryEmpty).arg("mode")));
        }
        let Some(field) = spec.field("mode") else {
            return Err(LinkError::Unsupported(
                Diag::new(Key::LinkUnsupportedTransportMode).arg(transport),
            ));
        };
        if let Some(validate) = field.validate {
            validate(mode)?;
        }
    }

    for (key, value) in &q.0 {
        let allowed = match key.as_str() {
            "type" | "security" | "fm" => true,
            "encryption" => matches!(proto, Protocol::Vless | Protocol::Vmess),
            "flow" => proto == Protocol::Vless,
            "sni" | "fp" => matches!(security, "tls" | "reality"),
            "alpn" | "ech" | "pcs" | "vcn" => security == "tls",
            "pbk" | "sid" | "pqv" | "mldsa65Verify" | "spx" => security == "reality",
            "seed" => {
                // The pinned core parses the key and ignores it
                // (`infra/conf/transport_method.go` KCPConfig.Build reads
                // neither `seed` nor `header`), so only the absence of a value
                // is tolerated: a seed names obfuscation the core cannot run.
                if value.is_empty() {
                    continue;
                }
                return Err(LinkError::Unsupported(
                    Diag::new(Key::LinkUnsupportedField).arg(key),
                ));
            }
            "headerType" => {
                // RAW carries it as an import-only field (the HTTP camouflage
                // Xray still builds); every other transport's header
                // obfuscation was removed, so only `none` — the absence of
                // one — is tolerated there.
                if spec.network == Network::Raw {
                    true
                } else if matches!(value.as_str(), "" | "none") {
                    continue;
                } else {
                    return Err(LinkError::Unsupported(
                        Diag::new(Key::LinkUnsupportedField).arg(key),
                    ));
                }
            }
            "aid" | "alterId" => {
                return Err(LinkError::Unsupported(Diag::new(
                    Key::LinkUnsupportedVmessAlterId,
                )));
            }
            // Every transport-scoped parameter is answered by the selected
            // transport's own row, so a key the table carries nowhere is
            // unknown here exactly like a key for another transport.
            other => spec.field(other).is_some(),
        };
        if !allowed {
            if drop_ignored_param(ignored, key, value) {
                continue;
            }
            return Err(LinkError::Unsupported(
                Diag::new(Key::LinkUnsupportedQueryField).arg(excerpt_debug(key)),
            ));
        }

        if value.is_empty()
            && (matches!(key.as_str(), "sni" | "fp" | "alpn" | "pbk" | "fm")
                || spec.field(key).is_some_and(|field| field.require_value))
        {
            return Err(malformed(Diag::new(Key::LinkQueryEmpty).arg(key)));
        }
    }
    Ok(())
}

// ---------- shared security (TLS / REALITY) mapping ----------

/// Apply `security` + TLS/REALITY params onto `stream`.
/// `default_tls`: trojan links default to `security=tls`.
fn apply_security(q: &Query, stream: &mut StreamModel, default_tls: bool) -> Result<(), LinkError> {
    let sec = q
        .get("security")
        .unwrap_or(if default_tls { "tls" } else { "none" });
    match sec {
        "none" => {}
        "tls" => {
            stream.security = Security::Tls;
            stream.tls_settings = Some(TlsModel {
                server_name: q.get_ne("sni").unwrap_or_default().to_string(),
                fingerprint: q.get_ne("fp").unwrap_or("chrome").to_string(),
                alpn: split_alpn(q.get("alpn")),
                ech_config_list: q.get("ech").unwrap_or_default().to_string(),
                pinned_peer_cert_sha256: q.get("pcs").unwrap_or_default().to_string(),
                verify_peer_cert_by_name: q.get("vcn").unwrap_or_default().to_string(),
                ..Default::default()
            });
        }
        "reality" => {
            stream.security = Security::Reality;
            let pqv = q.get("pqv").or_else(|| q.get("mldsa65Verify"));
            stream.reality_settings = Some(RealityModel {
                server_name: q.get_ne("sni").unwrap_or_default().to_string(),
                fingerprint: q.get_ne("fp").unwrap_or_default().to_string(),
                password: q.get_ne("pbk").unwrap_or_default().to_string(),
                short_id: q.get("sid").unwrap_or_default().to_string(),
                spider_x: q.get("spx").unwrap_or_default().to_string(),
                mldsa65_verify: pqv.unwrap_or_default().to_string(),
                ..Default::default()
            });
        }
        "xtls" => {
            return Err(LinkError::Unsupported(Diag::new(Key::LinkUnsupportedXtls)));
        }
        other => {
            return Err(malformed(
                Diag::new(Key::LinkSecurityUnknown).arg(excerpt_debug(other)),
            ));
        }
    }
    Ok(())
}

/// Emit `security` + TLS/REALITY params. `always`: trojan emits
/// `security=none` explicitly (its default is tls).
fn security_params(stream: &StreamModel, always: bool, q: &mut Vec<(String, String)>) {
    match stream.security {
        Security::None => {
            if always {
                q.push(("security".into(), "none".into()));
            }
        }
        Security::Tls => {
            q.push(("security".into(), "tls".into()));
            if let Some(t) = &stream.tls_settings {
                if !t.server_name.is_empty() {
                    q.push(("sni".into(), t.server_name.clone()));
                }
                if !t.fingerprint.is_empty() {
                    q.push(("fp".into(), t.fingerprint.clone()));
                }
                if !t.alpn.is_empty() {
                    q.push(("alpn".into(), t.alpn.join(",")));
                }
                if !t.ech_config_list.is_empty() {
                    q.push(("ech".into(), t.ech_config_list.clone()));
                }
                if !t.pinned_peer_cert_sha256.is_empty() {
                    q.push(("pcs".into(), t.pinned_peer_cert_sha256.clone()));
                }
                if !t.verify_peer_cert_by_name.is_empty() {
                    q.push(("vcn".into(), t.verify_peer_cert_by_name.clone()));
                }
            }
        }
        Security::Reality => {
            q.push(("security".into(), "reality".into()));
            if let Some(r) = &stream.reality_settings {
                if !r.server_name.is_empty() {
                    q.push(("sni".into(), r.server_name.clone()));
                }
                if !r.fingerprint.is_empty() {
                    q.push(("fp".into(), r.fingerprint.clone()));
                }
                if !r.password.is_empty() {
                    q.push(("pbk".into(), r.password.clone()));
                }
                if !r.short_id.is_empty() {
                    q.push(("sid".into(), r.short_id.clone()));
                }
                if !r.mldsa65_verify.is_empty() {
                    q.push(("pqv".into(), r.mldsa65_verify.clone()));
                }
                if !r.spider_x.is_empty() {
                    q.push(("spx".into(), r.spider_x.clone()));
                }
            }
        }
    }
}

// ---------- share grammar: one declaration per transport ----------

/// #716's default transport: an absent `type` names it, and export omits the
/// parameter for it.
const DEFAULT_TYPE: &str = "tcp";

/// #716's default `path`, used by every transport whose link omits it.
const DEFAULT_PATH: &str = "/";

/// A field's value rule: `Ok` when the grammar accepts the link's value.
type ValueRule = fn(&str) -> Result<(), LinkError>;

/// One query field a transport's share grammar carries, in export order.
struct Field {
    /// The parameter's name in the query string.
    key: &'static str,
    /// The value import uses when the link omits the parameter. An empty
    /// string is the grammar's "no value" for a parameter whose model field is
    /// optional (`mtu`, `extra`).
    default: &'static str,
    /// #716 forbids an empty value for this parameter in a link.
    require_value: bool,
    /// The grammar's value rule beyond emptiness, when it has one — the `mode`
    /// vocabularies. The field's setter shares it, so an accepted link value
    /// has exactly one judge.
    validate: Option<ValueRule>,
    /// The value to write on export, or `None` when the model holds none.
    get: fn(&StreamModel) -> Result<Option<String>, LinkError>,
    /// Fill the model from `value` (the link's, else the declared default).
    set: fn(&mut StreamModel, &str) -> Result<(), LinkError>,
}

/// One model fact a transport's share grammar cannot carry: a set value
/// refuses export.
struct Refused {
    /// The diagnostic in force for the fact.
    key: Key,
    /// Whether the model holds the fact.
    is_set: fn(&StreamModel) -> bool,
}

/// One transport's share grammar. The table is the only place that knows a
/// transport's query keys: import walks the fields, export walks the `type`
/// value and the same fields, and the representability ladder walks the
/// refused facts and the settings block's presence.
struct TransportSpec {
    network: Network,
    /// The transport's settings block as the model names it
    /// (`streamSettings.kcpSettings`); every diagnostic about the block uses
    /// this one path.
    path: &'static str,
    /// The `type` query value; `None` for a transport the grammar cannot spell
    /// at all (hysteria), which import reports as an unknown transport and
    /// export refuses through [`unshareable_transport`].
    type_string: Option<&'static str>,
    /// The upstream alias spellings of `type_string` that import accepts
    /// (`raw` for `tcp`, `mkcp` for `kcp`, `splithttp` for `xhttp`,
    /// `websocket` for `ws`; infra/conf/transport_internet.go:16-24, the same
    /// set [`Network::parse`] carries). Export never writes one:
    /// `type_string` is the only spelling the grammar emits.
    type_aliases: &'static [&'static str],
    /// The fields the grammar carries, in export order. Their setters
    /// materialize the settings block, so a link that omits every field still
    /// imports the block Xray would build for the transport.
    fields: &'static [Field],
    /// The model facts the grammar cannot carry, in refusal order.
    refused: &'static [Refused],
    /// Whether the settings block holds anything at all, for the
    /// unselected-transport rule.
    is_present: fn(&StreamModel) -> bool,
}

impl TransportSpec {
    /// This transport's field for `key`, when the grammar carries it.
    fn field(&self, key: &str) -> Option<&'static Field> {
        self.fields.iter().find(|field| field.key == key)
    }

    /// The `type` value, or the refusal for a transport the grammar cannot
    /// spell.
    fn spelling(&self) -> Result<&'static str, LinkError> {
        self.type_string.ok_or_else(unshareable_transport)
    }
}

/// The refusal for a transport the share grammar cannot spell. Hysteria is the
/// only one — the grammar has no `type` value, no field and no scheme for it —
/// and unlike the transports Xray removed it is a live model network, so
/// export states the reason instead of reporting an unknown `type`.
fn unshareable_transport() -> LinkError {
    LinkError::Unsupported(Diag::new(Key::LinkUnsupportedHysteria))
}

/// The table, in the order the representability ladder reports transports.
const TRANSPORTS: &[TransportSpec] = &[RAW, KCP, WS, GRPC, HTTPUPGRADE, XHTTP, HYSTERIA];

/// The row for `network`. The table declares every `Network` variant, so
/// adding one is a compile error here rather than a transport the grammar
/// silently skips.
fn transport_spec(network: Network) -> &'static TransportSpec {
    match network {
        Network::Raw => &RAW,
        Network::Kcp => &KCP,
        Network::Ws => &WS,
        Network::Grpc => &GRPC,
        Network::Httpupgrade => &HTTPUPGRADE,
        Network::Xhttp => &XHTTP,
        Network::Hysteria => &HYSTERIA,
    }
}

/// Resolve a link's `type` parameter to its row: the one home for the
/// transports Xray removed (http/h2/h3 and quic) and for values the grammar
/// does not spell. An absent `type` is #716's default transport; an empty one
/// is refused before this runs.
fn transport_for_type(ty: &str) -> Result<&'static TransportSpec, LinkError> {
    match ty {
        "http" | "h2" | "h3" => Err(LinkError::Unsupported(Diag::new(
            Key::LinkUnsupportedTypeHttp,
        ))),
        "quic" => Err(LinkError::Unsupported(Diag::new(
            Key::LinkUnsupportedTypeQuic,
        ))),
        other => TRANSPORTS
            .iter()
            .find(|spec| spec.type_string == Some(other) || spec.type_aliases.contains(&other))
            .ok_or_else(|| {
                malformed(Diag::new(Key::LinkTransportUnknown).arg(excerpt_debug(other)))
            }),
    }
}

/// The export value of a text parameter: `None` when the model holds nothing
/// or holds an empty string — canonical output omits the parameter then.
fn export_text(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

/// A numeric parameter as the query spells it.
fn export_number(value: Option<u32>) -> Option<String> {
    value.map(|value| value.to_string())
}

/// A `u32` parameter as the link spells it: decimal, and malformed under its
/// own key otherwise.
fn numeric_param(key: &'static str, value: &str) -> Result<u32, LinkError> {
    value.parse::<u32>().map_err(|_| {
        malformed(
            Diag::new(Key::LinkNumericParam)
                .arg(key)
                .arg(excerpt_debug(value)),
        )
    })
}

// ----- raw / TCP -----

/// Raw has no settings parameters of its own: its camouflage block is model
/// state the grammar cannot carry, and a non-empty block refuses export either
/// way.
fn raw_settings_present(stream: &StreamModel) -> bool {
    option_has_fields(&stream.raw_settings)
}

/// Refuse the three raw camouflage getters before export renders them: the
/// refusal on [`RAW`]'s `refused` list fires first, so reaching one means a
/// camouflage block would be silently dropped.
fn raw_camouflage_get(stream: &StreamModel) -> Result<Option<String>, LinkError> {
    if raw_settings_present(stream) {
        Err(lossy(
            "streamSettings.rawSettings",
            Key::LinkLossyRawCamouflage,
        ))
    } else {
        Ok(None)
    }
}

/// The request block the raw camouflage fields write into. The link must name
/// `headerType=http` first — the same rule the legacy VMess JSON path
/// enforces (`LinkRawCamouflage`).
fn raw_camouflage_request(
    stream: &mut StreamModel,
) -> Result<&mut HttpCamouflageRequest, LinkError> {
    let settings = stream.raw_settings.get_or_insert_default();
    let header = settings.header.get_or_insert_default();
    if header.r#type != "http" {
        return Err(malformed(Diag::new(Key::LinkRawCamouflage)));
    }
    Ok(header.request.get_or_insert_default())
}

/// `headerType` for the raw transport (import-only): Xray still builds the
/// HTTP request and response camouflage (`infra/conf/transport_method.go`
/// `tcpHeaderLoader` carries `none` and `http`), so `http` imports the
/// settings block the legacy VMess JSON path builds. `none` and an omitted
/// value are the model default and set nothing.
fn raw_header_type(stream: &mut StreamModel, value: &str) -> Result<(), LinkError> {
    match value {
        "" | "none" => Ok(()),
        "http" => {
            let settings = stream.raw_settings.get_or_insert_default();
            settings.header.get_or_insert_default().r#type = "http".into();
            Ok(())
        }
        other => Err(malformed(
            Diag::new(Key::LinkRawHeaderType).arg(excerpt_debug(other)),
        )),
    }
}

/// The raw camouflage `Host` header (import-only), mirroring the legacy VMess
/// mapping: a comma list becomes an array.
fn raw_host(stream: &mut StreamModel, value: &str) -> Result<(), LinkError> {
    if value.is_empty() {
        return Ok(());
    }
    let hosts: Vec<Value> = value
        .split(',')
        .filter(|host| !host.is_empty())
        .map(|host| Value::String(host.to_string()))
        .collect();
    let request = raw_camouflage_request(stream)?;
    let entry = if hosts.len() == 1 {
        hosts
            .into_iter()
            .next()
            .unwrap_or(Value::String(String::new()))
    } else {
        Value::Array(hosts)
    };
    request.headers.insert("Host".into(), entry);
    Ok(())
}

/// The raw camouflage request path list (import-only).
fn raw_path(stream: &mut StreamModel, value: &str) -> Result<(), LinkError> {
    if value.is_empty() {
        return Ok(());
    }
    let request = raw_camouflage_request(stream)?;
    request.path = value
        .split(',')
        .filter(|path| !path.is_empty())
        .map(str::to_string)
        .collect();
    Ok(())
}

const RAW_HEADER_TYPE: Field = Field {
    key: "headerType",
    default: "",
    require_value: false,
    validate: None,
    get: raw_camouflage_get,
    set: raw_header_type,
};

const RAW_HOST: Field = Field {
    key: "host",
    default: "",
    require_value: false,
    validate: None,
    get: raw_camouflage_get,
    set: raw_host,
};

const RAW_PATH_FIELD: Field = Field {
    key: "path",
    default: "",
    require_value: false,
    validate: None,
    get: raw_camouflage_get,
    set: raw_path,
};

const RAW: TransportSpec = TransportSpec {
    network: Network::Raw,
    path: "streamSettings.rawSettings",
    type_string: Some(DEFAULT_TYPE),
    type_aliases: &["raw"],
    fields: &[RAW_HEADER_TYPE, RAW_HOST, RAW_PATH_FIELD],
    refused: &[Refused {
        key: Key::LinkLossyRawCamouflage,
        is_set: raw_settings_present,
    }],
    is_present: raw_settings_present,
};

// ----- mKCP -----

const KCP: TransportSpec = TransportSpec {
    network: Network::Kcp,
    path: "streamSettings.kcpSettings",
    type_string: Some("kcp"),
    type_aliases: &["mkcp"],
    fields: &[
        Field {
            key: "mtu",
            default: "",
            require_value: true,
            validate: None,
            get: |stream| {
                Ok(export_number(
                    stream.kcp_settings.as_ref().and_then(|kcp| kcp.mtu),
                ))
            },
            set: |stream, value| {
                let settings = stream.kcp_settings.get_or_insert_default();
                if !value.is_empty() {
                    settings.mtu = Some(numeric_param("mtu", value)?);
                }
                Ok(())
            },
        },
        Field {
            key: "tti",
            default: "",
            require_value: true,
            validate: None,
            get: |stream| {
                Ok(export_number(
                    stream.kcp_settings.as_ref().and_then(|kcp| kcp.tti),
                ))
            },
            set: |stream, value| {
                let settings = stream.kcp_settings.get_or_insert_default();
                if !value.is_empty() {
                    settings.tti = Some(numeric_param("tti", value)?);
                }
                Ok(())
            },
        },
    ],
    refused: &[Refused {
        key: Key::LinkLossyKcp,
        // The mKCP congestion knobs have no share-link spelling.
        is_set: |stream| {
            stream.kcp_settings.as_ref().is_some_and(|kcp| {
                kcp.uplink_capacity.is_some()
                    || kcp.downlink_capacity.is_some()
                    || kcp.cwnd_multiplier.is_some()
                    || kcp.max_sending_window.is_some()
                    || !kcp.extra.is_empty()
            })
        },
    }],
    is_present: |stream| option_has_fields(&stream.kcp_settings),
};

// ----- WebSocket -----

const WS: TransportSpec = TransportSpec {
    network: Network::Ws,
    path: "streamSettings.wsSettings",
    type_string: Some("ws"),
    type_aliases: &["websocket"],
    fields: &[
        Field {
            key: "host",
            default: "",
            require_value: false,
            validate: None,
            get: |stream| {
                Ok(export_text(
                    stream.ws_settings.as_ref().map(|ws| ws.host.clone()),
                ))
            },
            set: |stream, value| {
                stream.ws_settings.get_or_insert_default().host = value.to_string();
                Ok(())
            },
        },
        Field {
            key: "path",
            default: DEFAULT_PATH,
            require_value: true,
            validate: None,
            get: |stream| {
                Ok(export_text(
                    stream.ws_settings.as_ref().map(|ws| ws.path.clone()),
                ))
            },
            set: |stream, value| {
                stream.ws_settings.get_or_insert_default().path = value.to_string();
                Ok(())
            },
        },
    ],
    refused: &[Refused {
        key: Key::LinkLossyWs,
        // Custom headers and the heartbeat keepalive have no share-link
        // spelling.
        is_set: |stream| {
            stream.ws_settings.as_ref().is_some_and(|ws| {
                !ws.headers.is_empty() || ws.heartbeat_period.is_some() || !ws.extra.is_empty()
            })
        },
    }],
    is_present: |stream| option_has_fields(&stream.ws_settings),
};

// ----- gRPC -----

/// The gRPC `mode` vocabulary: `gun` and `multi` are the two spellings of the
/// boolean `multiMode` the model carries, and `guna` has no field at all.
fn validate_grpc_mode(value: &str) -> Result<(), LinkError> {
    match value {
        "gun" | "multi" => Ok(()),
        "guna" => Err(LinkError::Unsupported(Diag::new(
            Key::LinkUnsupportedGrpcGuna,
        ))),
        other => Err(malformed(
            Diag::new(Key::LinkGrpcModeUnknown).arg(excerpt_debug(other)),
        )),
    }
}

const GRPC: TransportSpec = TransportSpec {
    network: Network::Grpc,
    path: "streamSettings.grpcSettings",
    type_string: Some("grpc"),
    type_aliases: &[],
    fields: &[
        Field {
            key: "serviceName",
            default: "",
            require_value: true,
            validate: None,
            get: |stream| {
                Ok(export_text(
                    stream
                        .grpc_settings
                        .as_ref()
                        .map(|grpc| grpc.service_name.clone()),
                ))
            },
            set: |stream, value| {
                stream.grpc_settings.get_or_insert_default().service_name = value.to_string();
                Ok(())
            },
        },
        Field {
            key: "authority",
            default: "",
            require_value: false,
            validate: None,
            get: |stream| {
                Ok(export_text(
                    stream
                        .grpc_settings
                        .as_ref()
                        .map(|grpc| grpc.authority.clone()),
                ))
            },
            set: |stream, value| {
                stream.grpc_settings.get_or_insert_default().authority = value.to_string();
                Ok(())
            },
        },
        Field {
            key: "mode",
            // A `gun` link and an omitted one import alike: `gun` is the
            // boolean's absent default.
            default: "gun",
            require_value: true,
            validate: Some(validate_grpc_mode),
            get: |stream| {
                let multi_mode = stream
                    .grpc_settings
                    .as_ref()
                    .and_then(|grpc| grpc.multi_mode);
                Ok(match multi_mode {
                    Some(true) => Some("multi".to_string()),
                    Some(false) => Some("gun".to_string()),
                    None => None,
                })
            },
            set: |stream, value| {
                validate_grpc_mode(value)?;
                let multi_mode = if value == "multi" { Some(true) } else { None };
                stream.grpc_settings.get_or_insert_default().multi_mode = multi_mode;
                Ok(())
            },
        },
    ],
    refused: &[Refused {
        key: Key::LinkLossyGrpc,
        // The gRPC keepalive/health knobs and the user agent have no
        // share-link spelling.
        is_set: |stream| {
            stream.grpc_settings.as_ref().is_some_and(|grpc| {
                grpc.idle_timeout.is_some()
                    || grpc.health_check_timeout.is_some()
                    || grpc.permit_without_stream.is_some()
                    || grpc.initial_windows_size.is_some()
                    || grpc.user_agent.is_some()
                    || !grpc.extra.is_empty()
            })
        },
    }],
    is_present: |stream| option_has_fields(&stream.grpc_settings),
};

// ----- HTTPUpgrade -----

const HTTPUPGRADE: TransportSpec = TransportSpec {
    network: Network::Httpupgrade,
    path: "streamSettings.httpupgradeSettings",
    type_string: Some("httpupgrade"),
    type_aliases: &[],
    fields: &[
        Field {
            key: "host",
            default: "",
            require_value: false,
            validate: None,
            get: |stream| {
                Ok(export_text(
                    stream
                        .httpupgrade_settings
                        .as_ref()
                        .map(|upgrade| upgrade.host.clone()),
                ))
            },
            set: |stream, value| {
                stream.httpupgrade_settings.get_or_insert_default().host = value.to_string();
                Ok(())
            },
        },
        Field {
            key: "path",
            default: DEFAULT_PATH,
            require_value: true,
            validate: None,
            get: |stream| {
                Ok(export_text(
                    stream
                        .httpupgrade_settings
                        .as_ref()
                        .map(|upgrade| upgrade.path.clone()),
                ))
            },
            set: |stream, value| {
                stream.httpupgrade_settings.get_or_insert_default().path = value.to_string();
                Ok(())
            },
        },
    ],
    refused: &[Refused {
        key: Key::LinkLossyHttpupgrade,
        // Custom headers have no share-link spelling.
        is_set: |stream| {
            stream
                .httpupgrade_settings
                .as_ref()
                .is_some_and(|upgrade| !upgrade.headers.is_empty() || !upgrade.extra.is_empty())
        },
    }],
    is_present: |stream| option_has_fields(&stream.httpupgrade_settings),
};

// ----- XHTTP -----

/// The XHTTP `mode` vocabulary is the model's (the same set Xray's
/// `SplitHTTPConfig.Build` accepts); the link spells `auto` for the wire
/// default, which the empty model value also means.
fn validate_xhttp_mode(value: &str) -> Result<(), LinkError> {
    if crate::model::validation::xhttp_mode_supported(value) {
        Ok(())
    } else {
        Err(malformed(
            Diag::new(Key::LinkXhttpModeUnknown).arg(excerpt_debug(value)),
        ))
    }
}

const XHTTP: TransportSpec = TransportSpec {
    network: Network::Xhttp,
    path: "streamSettings.xhttpSettings",
    type_string: Some("xhttp"),
    type_aliases: &["splithttp"],
    fields: &[
        Field {
            key: "host",
            default: "",
            require_value: false,
            validate: None,
            get: |stream| {
                Ok(export_text(
                    stream.xhttp_settings.as_ref().map(|x| x.host.clone()),
                ))
            },
            set: |stream, value| {
                stream.xhttp_settings.get_or_insert_default().host = value.to_string();
                Ok(())
            },
        },
        Field {
            key: "path",
            default: DEFAULT_PATH,
            require_value: true,
            validate: None,
            get: |stream| {
                Ok(export_text(
                    stream.xhttp_settings.as_ref().map(|x| x.path.clone()),
                ))
            },
            set: |stream, value| {
                stream.xhttp_settings.get_or_insert_default().path = value.to_string();
                Ok(())
            },
        },
        Field {
            key: "mode",
            default: "auto",
            require_value: true,
            validate: Some(validate_xhttp_mode),
            get: |stream| {
                Ok(export_text(
                    stream.xhttp_settings.as_ref().map(|x| x.mode.clone()),
                ))
            },
            set: |stream, value| {
                validate_xhttp_mode(value)?;
                // Xray's empty model value and #716's `auto` have identical
                // semantics; keeping the model default makes canonical output
                // omit the optional parameter.
                let mode = if value == "auto" {
                    String::new()
                } else {
                    value.to_string()
                };
                stream.xhttp_settings.get_or_insert_default().mode = mode;
                Ok(())
            },
        },
        Field {
            // Everything except host/path/mode is carried by #716's
            // percent-encoded `extra` JSON object.
            key: "extra",
            default: "",
            require_value: true,
            validate: None,
            get: |stream| {
                let Some(xhttp) = stream.xhttp_settings.as_ref() else {
                    return Ok(None);
                };
                let mut value = serde_json::to_value(xhttp).map_err(|error| {
                    LinkError::Lossy(
                        Diag::new(Key::LinkLossyXhttpSerialize)
                            .arg("streamSettings.xhttpSettings")
                            .arg(error),
                    )
                })?;
                if let Value::Object(object) = &mut value {
                    object.remove("host");
                    object.remove("path");
                    object.remove("mode");
                }
                if !value.as_object().is_some_and(|object| !object.is_empty()) {
                    return Ok(None);
                }
                let json = serde_json::to_string(&value).map_err(|error| {
                    LinkError::Lossy(
                        Diag::new(Key::LinkLossyXhttpEncode)
                            .arg("streamSettings.xhttpSettings")
                            .arg(error),
                    )
                })?;
                Ok(Some(json))
            },
            set: |stream, value| {
                if value.is_empty() {
                    return Ok(());
                }
                // `extra` carries everything except host/path/mode. Reject
                // those reserved keys instead of allowing a second, ambiguous
                // source.
                let parsed: Value = serde_json::from_str(value).map_err(|error| {
                    malformed(Diag::new(Key::LinkXhttpExtraJson).arg(excerpt(&error.to_string())))
                })?;
                let object = parsed
                    .as_object()
                    .ok_or_else(|| malformed(Diag::new(Key::LinkXhttpExtraObject)))?;
                if let Some(field) = ["host", "path", "mode"]
                    .into_iter()
                    .find(|field| object.contains_key(*field))
                {
                    return Err(malformed(
                        Diag::new(Key::LinkXhttpExtraReserved).arg(excerpt_debug(field)),
                    ));
                }
                let mut settings: XhttpSettings =
                    serde_json::from_value(parsed).map_err(|error| {
                        malformed(
                            Diag::new(Key::LinkXhttpExtraJson).arg(excerpt(&error.to_string())),
                        )
                    })?;
                // The link's own host/path/mode parameters were applied before
                // this field and #716 spells them outside `extra`, so their
                // values stay in force.
                let previous = stream.xhttp_settings.take().unwrap_or_default();
                settings.host = previous.host;
                settings.path = previous.path;
                settings.mode = previous.mode;
                stream.xhttp_settings = Some(settings);
                Ok(())
            },
        },
    ],
    refused: &[],
    is_present: |stream| option_has_fields(&stream.xhttp_settings),
};

// ----- hysteria -----

/// Hysteria is a live model network with no share grammar — no `type` value,
/// no field, no scheme — so only its block's presence can refuse an export,
/// under the unselected-transport rule.
const HYSTERIA: TransportSpec = TransportSpec {
    network: Network::Hysteria,
    path: "streamSettings.hysteriaSettings",
    type_string: None,
    type_aliases: &[],
    fields: &[],
    refused: &[],
    is_present: |stream| option_has_fields(&stream.hysteria_settings),
};

/// Apply the link's `type` parameter: the row's fields, each with the link's
/// value or the field's declared default.
fn apply_transport_query(q: &Query, stream: &mut StreamModel) -> Result<(), LinkError> {
    let spec = transport_for_type(q.get("type").unwrap_or(DEFAULT_TYPE))?;
    stream.network = spec.network;
    for field in spec.fields {
        (field.set)(stream, q.get(field.key).unwrap_or(field.default))?;
    }
    Ok(())
}

/// Transport params for URL-style export. Nothing is emitted for plain raw.
fn transport_params(stream: &StreamModel, q: &mut Vec<(String, String)>) -> Result<(), LinkError> {
    let spec = transport_spec(stream.network);
    let type_string = spec.spelling()?;
    if type_string != DEFAULT_TYPE {
        q.push(("type".into(), type_string.into()));
    }
    for field in spec.fields {
        if let Some(value) = (field.get)(stream)? {
            q.push((field.key.into(), value));
        }
    }
    Ok(())
}

fn finalmask_param(stream: &StreamModel, q: &mut Vec<(String, String)>) -> Result<(), LinkError> {
    if let Some(finalmask) = &stream.finalmask
        && !finalmask.is_empty()
    {
        let json = serde_json::to_string(finalmask).map_err(|error| {
            LinkError::Lossy(
                Diag::new(Key::LinkLossyFinalmaskEncode)
                    .arg("streamSettings.finalmask")
                    .arg(error),
            )
        })?;
        q.push(("fm".into(), json));
    }
    Ok(())
}

fn validate_finalmask(finalmask: &FinalmaskModel) -> Result<(), LinkError> {
    if let Some(issue) = crate::model::validation::validate_finalmask(finalmask)
        .into_iter()
        .next()
    {
        return Err(LinkError::InvalidModel {
            prefix: Some(Key::LinkFinalmaskInvalid),
            issue: Box::new(issue),
        });
    }
    Ok(())
}

fn apply_finalmask(q: &Query, stream: &mut StreamModel) -> Result<(), LinkError> {
    if let Some(fm) = q.get_ne("fm") {
        let fm: FinalmaskModel = serde_json::from_str(fm).map_err(|e| {
            malformed(Diag::new(Key::LinkFinalmaskJson).arg(excerpt(&e.to_string())))
        })?;
        validate_finalmask(&fm)?;
        stream.finalmask = Some(fm);
    }
    Ok(())
}

// ---------- shareable protocols ----------

/// One protocol a share link names: the scheme in its URL, and the parser for
/// the body after `scheme://`.
struct Shareable {
    scheme: &'static str,
    protocol: Protocol,
    parse: fn(&str, &mut Vec<String>) -> Result<ServerProfile, LinkError>,
}

/// The share grammar's supported set, one row per shareable protocol: the
/// schemes `parse_link` accepts and the protocols `to_link` renders. Any other
/// protocol is refused with [`unsupported_protocol`].
const SHAREABLE: &[Shareable] = &[
    Shareable {
        scheme: "vless",
        protocol: Protocol::Vless,
        parse: |body, ignored| parse_url_style(body, Protocol::Vless, ignored),
    },
    Shareable {
        scheme: "vmess",
        protocol: Protocol::Vmess,
        parse: parse_vmess_body,
    },
    Shareable {
        scheme: "trojan",
        protocol: Protocol::Trojan,
        parse: |body, ignored| parse_url_style(body, Protocol::Trojan, ignored),
    },
    Shareable {
        scheme: "ss",
        protocol: Protocol::Shadowsocks,
        parse: parse_ss,
    },
];

/// The import-only set: schemes for protocols Xray supports but #716 never
/// spells. Their link grammars follow the clients that emit them, which have
/// no external spec, so import is deliberately tolerant
/// (see [`IGNORED_PARAMS`]) while `to_link` never renders one. The removed
/// spellings (`socks4`/`socks4a`, Hysteria 1) sit here too, so the scheme
/// table stays the single registry and each gets its own diagnostic instead
/// of the generic unknown-scheme message.
const IMPORT_ONLY: &[Shareable] = &[
    Shareable {
        scheme: "socks5",
        protocol: Protocol::Socks,
        parse: parse_socks,
    },
    Shareable {
        scheme: "socks",
        protocol: Protocol::Socks,
        parse: parse_socks,
    },
    Shareable {
        scheme: "socks4",
        protocol: Protocol::Socks,
        parse: |_, _| {
            Err(LinkError::Unsupported(Diag::new(
                Key::LinkUnsupportedSocks4,
            )))
        },
    },
    Shareable {
        scheme: "socks4a",
        protocol: Protocol::Socks,
        parse: |_, _| {
            Err(LinkError::Unsupported(Diag::new(
                Key::LinkUnsupportedSocks4,
            )))
        },
    },
    Shareable {
        scheme: "http",
        protocol: Protocol::Http,
        parse: |body, ignored| parse_http(body, false, ignored),
    },
    Shareable {
        scheme: "https",
        protocol: Protocol::Http,
        parse: |body, ignored| parse_http(body, true, ignored),
    },
    Shareable {
        scheme: "wg",
        protocol: Protocol::Wireguard,
        parse: parse_wireguard,
    },
    Shareable {
        scheme: "wireguard",
        protocol: Protocol::Wireguard,
        parse: parse_wireguard,
    },
    Shareable {
        scheme: "hysteria2",
        protocol: Protocol::Hysteria,
        parse: parse_hysteria2,
    },
    Shareable {
        scheme: "hy2",
        protocol: Protocol::Hysteria,
        parse: parse_hysteria2,
    },
    Shareable {
        scheme: "hysteria",
        protocol: Protocol::Hysteria,
        parse: |_, _| {
            Err(LinkError::Unsupported(Diag::new(
                Key::LinkUnsupportedHysteria1,
            )))
        },
    },
];

/// #716 names the VMess URL form when the body carries a userinfo, and the
/// obsolete whole-body Base64-JSON form otherwise.
fn parse_vmess_body(body: &str, ignored: &mut Vec<String>) -> Result<ServerProfile, LinkError> {
    if body.contains('@') {
        parse_url_style(body, Protocol::Vmess, ignored)
    } else {
        parse_legacy_vmess(body, ignored)
    }
}

/// `Ok` when the grammar names `protocol` in either direction.
fn shareable(protocol: Protocol) -> bool {
    SHAREABLE.iter().any(|row| row.protocol == protocol)
}

/// The refusal for a protocol outside the share set.
fn unsupported_protocol(protocol: Protocol) -> LinkError {
    LinkError::Unsupported(Diag::new(Key::LinkUnsupportedProtocol).arg(protocol.as_str()))
}

// ---------- URL-style links (VLESS / VMess / Trojan) ----------

fn parse_url_style(
    body: &str,
    proto: Protocol,
    ignored: &mut Vec<String>,
) -> Result<ServerProfile, LinkError> {
    let scheme = proto.as_str();
    let (auth, query, frag) = split_link(body);
    let (userinfo, hp) = split_authority(auth, scheme, true)?;
    let user = pct_decode(userinfo)?;
    let (host, port) = parse_host_port(hp, scheme)?;
    let q = parse_query(query)?;
    validate_url_query(&q, proto, ignored)?;
    let mut stream = StreamModel::default();
    apply_security(&q, &mut stream, proto == Protocol::Trojan)?;
    apply_transport_query(&q, &mut stream)?;
    apply_finalmask(&q, &mut stream)?;
    match stream.security {
        Security::Tls => {
            if let Some(tls) = stream.tls_settings.as_mut()
                && tls.server_name.is_empty()
            {
                tls.server_name = host.clone();
            }
        }
        Security::Reality => {
            if let Some(reality) = stream.reality_settings.as_mut()
                && reality.server_name.is_empty()
            {
                reality.server_name = host.clone();
            }
        }
        Security::None => {}
    }

    let mut outbound = OutboundModel::new(proto);
    match proto {
        Protocol::Vless => {
            if user.is_empty() {
                return Err(malformed(Diag::new(Key::LinkUuidMissing).arg("vless")));
            }
            check_uuid(&user, "vless")?;
            outbound.settings = ProtocolSettings::Vless(VlessSettings {
                address: host,
                port,
                id: user,
                flow: q.get("flow").unwrap_or_default().to_string(),
                encryption: q.get_ne("encryption").unwrap_or("none").to_string(),
                ..Default::default()
            });
        }
        Protocol::Vmess => {
            if user.is_empty() {
                return Err(malformed(Diag::new(Key::LinkUuidMissing).arg("vmess")));
            }
            check_uuid(&user, "vmess")?;
            // #716 accepts `encryption=none`; current Xray's VMess builder
            // maps it through its default branch to SecurityType_AUTO because
            // the wire enum has no NONE value (infra/conf/vmess.go:25-36).
            outbound.settings = ProtocolSettings::Vmess(VmessSettings {
                address: host,
                port,
                id: user,
                security: match q.get_ne("encryption") {
                    Some("none") | None => "auto".to_string(),
                    Some(security) => security.to_string(),
                },
                ..Default::default()
            });
        }
        Protocol::Trojan => {
            if user.is_empty() {
                return Err(malformed(Diag::new(Key::LinkTrojanPasswordEmpty)));
            }
            outbound.settings = ProtocolSettings::Trojan(TrojanSettings {
                address: host,
                port,
                password: user,
                ..Default::default()
            });
        }
        _ => unreachable!("URL-style parser supports VLESS, VMess, and Trojan"),
    }
    outbound.stream = stream;
    let name = match fragment_name(frag)? {
        Some(name) => name,
        None => match &outbound.settings {
            ProtocolSettings::Vless(settings) => settings.address.clone(),
            ProtocolSettings::Vmess(settings) => settings.address.clone(),
            ProtocolSettings::Trojan(settings) => settings.address.clone(),
            _ => unreachable!(),
        },
    };
    Ok(ServerProfile::new(name, outbound))
}

fn render_query(q: &[(String, String)]) -> String {
    q.iter()
        .map(|(k, v)| format!("{}={}", pct_encode(k), pct_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn fragment_suffix(name: &str) -> String {
    if name.is_empty() {
        String::new()
    } else {
        format!("#{}", pct_encode(name))
    }
}

fn vless_link(p: &ServerProfile, s: &VlessSettings) -> Result<String, LinkError> {
    let mut q: Vec<(String, String)> = Vec::new();
    q.push((
        "encryption".into(),
        if s.encryption.is_empty() {
            "none".into()
        } else {
            s.encryption.clone()
        },
    ));
    if !s.flow.is_empty() {
        q.push(("flow".into(), s.flow.clone()));
    }
    security_params(&p.outbound.stream, false, &mut q);
    transport_params(&p.outbound.stream, &mut q)?;
    finalmask_param(&p.outbound.stream, &mut q)?;
    Ok(format!(
        "vless://{}@{}?{}{}",
        pct_encode(&s.id),
        host_port(&s.address, s.port),
        render_query(&q),
        fragment_suffix(&p.name),
    ))
}

fn trojan_link(p: &ServerProfile, s: &TrojanSettings) -> Result<String, LinkError> {
    let mut q: Vec<(String, String)> = Vec::new();
    security_params(&p.outbound.stream, true, &mut q);
    transport_params(&p.outbound.stream, &mut q)?;
    finalmask_param(&p.outbound.stream, &mut q)?;
    Ok(format!(
        "trojan://{}@{}?{}{}",
        pct_encode(&s.password),
        host_port(&s.address, s.port),
        render_query(&q),
        fragment_suffix(&p.name),
    ))
}

// ---------- VMess legacy Base64-JSON import ----------

fn parse_legacy_vmess(body: &str, ignored: &mut Vec<String>) -> Result<ServerProfile, LinkError> {
    let raw = b64_decode_any(body).ok_or_else(|| malformed(Diag::new(Key::LinkVmessBase64)))?;
    let v: Value = serde_json::from_slice(&raw)
        .map_err(|e| malformed(Diag::new(Key::LinkVmessJson).arg(excerpt(&e.to_string()))))?;
    let o = v
        .as_object()
        .ok_or_else(|| malformed(Diag::new(Key::LinkVmessObject)))?;
    const LEGACY_FIELDS: &[&str] = &[
        "v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni",
        "alpn", "fp", "vcn", "pcs", "insecure",
    ];
    if let Some(field) = o
        .keys()
        .find(|field| !LEGACY_FIELDS.contains(&field.as_str()))
    {
        return Err(LinkError::Unsupported(
            Diag::new(Key::LinkUnsupportedLegacyField).arg(excerpt_debug(field)),
        ));
    }
    for (field, value) in o {
        let valid_type = match field.as_str() {
            "v" | "port" | "aid" => value.is_string() || value.is_number(),
            "alpn" => {
                value.is_string()
                    || value
                        .as_array()
                        .is_some_and(|items| items.iter().all(Value::is_string))
            }
            _ => value.is_string(),
        };
        if !valid_type {
            return Err(malformed(
                Diag::new(Key::LinkLegacyFieldType).arg(excerpt_debug(field)),
            ));
        }
    }
    // Legacy v/port/aid may be numeric and ALPN may be an array; all other
    // recognized fields were checked as strings above.
    let get = |k: &str| -> String {
        match o.get(k) {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(","),
            _ => String::new(),
        }
    };
    let version = get("v");
    if !version.is_empty() && version != "2" {
        return Err(LinkError::Unsupported(
            Diag::new(Key::LinkUnsupportedLegacyVersion).arg(excerpt_debug(&version)),
        ));
    }

    let addr = get("add");
    if addr.is_empty() {
        return Err(malformed(Diag::new(Key::LinkVmessAdd)));
    }
    let port_s = get("port");
    let port: u16 = port_s
        .parse()
        .map_err(|_| malformed(Diag::new(Key::LinkVmessPort).arg(excerpt_debug(&port_s))))?;
    if port == 0 {
        return Err(malformed(Diag::new(Key::LinkPortZero).arg("vmess")));
    }
    let id = get("id");
    check_uuid(&id, "vmess")?;
    let aid = get("aid");
    if !aid.is_empty() && aid != "0" {
        return Err(LinkError::Unsupported(
            Diag::new(Key::LinkUnsupportedVmessAlterIdValue).arg(excerpt(&aid)),
        ));
    }

    let mut stream = StreamModel::default();
    match get("tls").to_ascii_lowercase().as_str() {
        "" | "none" => {}
        "tls" => {
            stream.security = Security::Tls;
            stream.tls_settings = Some(TlsModel {
                server_name: {
                    let sni = get("sni");
                    if sni.is_empty() { addr.clone() } else { sni }
                },
                fingerprint: {
                    let fp = get("fp");
                    if fp.is_empty() { "chrome".into() } else { fp }
                },
                alpn: split_alpn(Some(&get("alpn"))),
                ..Default::default()
            });
        }
        other => {
            return Err(LinkError::Unsupported(
                Diag::new(Key::LinkUnsupportedVmessTls).arg(excerpt_debug(other)),
            ));
        }
    }

    // Client exports write `vcn` / `pcs` on every legacy vmess body (empty
    // when unset) and `insecure` unconditionally. The TLS fields map onto the
    // model when TLS is on; without TLS they name nothing, so they join the
    // compatibility report. `insecure` has no Xray field at all — the
    // certificate pin replaces it.
    let vcn = get("vcn");
    let pcs = get("pcs");
    if stream.security == Security::Tls {
        if let Some(tls) = stream.tls_settings.as_mut() {
            tls.verify_peer_cert_by_name = vcn;
            tls.pinned_peer_cert_sha256 = pcs;
        }
    } else {
        if !vcn.is_empty() {
            record_ignored(ignored, "vcn");
        }
        if !pcs.is_empty() {
            record_ignored(ignored, "pcs");
        }
    }
    if let Some(insecure) = o.get("insecure").and_then(Value::as_str)
        && ignored_value_is_reported(insecure)
    {
        record_ignored(ignored, "insecure");
    }

    let net = get("net");
    let typ = get("type");
    let host = get("host");
    let path = get("path");
    match net.to_ascii_lowercase().as_str() {
        "" | "tcp" | "raw" => {
            stream.network = Network::Raw;
            match typ.as_str() {
                "" | "none" => {
                    if !host.is_empty() || !path.is_empty() {
                        return Err(LinkError::Unsupported(Diag::new(
                            Key::LinkUnsupportedVmessTcpHostPath,
                        )));
                    }
                }
                "http" => {
                    // v2rayN semantics: host/path may be comma-separated lists.
                    let mut headers = Map::new();
                    if !host.is_empty() {
                        let hosts: Vec<&str> = host.split(',').filter(|h| !h.is_empty()).collect();
                        headers.insert(
                            "Host".to_string(),
                            if hosts.len() == 1 {
                                Value::String(hosts[0].to_string())
                            } else {
                                Value::Array(
                                    hosts.iter().map(|h| Value::String(h.to_string())).collect(),
                                )
                            },
                        );
                    }
                    stream.raw_settings = Some(RawSettings {
                        header: Some(RawHeader {
                            r#type: "http".into(),
                            request: Some(HttpCamouflageRequest {
                                path: path
                                    .split(',')
                                    .filter(|p| !p.is_empty())
                                    .map(str::to_string)
                                    .collect(),
                                headers,
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    });
                }
                other => {
                    return Err(malformed(
                        Diag::new(Key::LinkVmessTcpType).arg(excerpt_debug(other)),
                    ));
                }
            }
        }
        "kcp" | "mkcp" => {
            if !matches!(typ.as_str(), "" | "none") || !path.is_empty() || !host.is_empty() {
                return Err(LinkError::Unsupported(Diag::new(
                    Key::LinkUnsupportedVmessKcp,
                )));
            }
            stream.network = Network::Kcp;
            stream.kcp_settings = Some(KcpSettings::default());
        }
        "ws" | "websocket" => {
            if !matches!(typ.as_str(), "" | "none") {
                return Err(LinkError::Unsupported(
                    Diag::new(Key::LinkUnsupportedVmessWebsocket).arg(excerpt_debug(&typ)),
                ));
            }
            stream.network = Network::Ws;
            stream.ws_settings = Some(WsSettings {
                host,
                path,
                ..Default::default()
            });
        }
        "grpc" => {
            let multi_mode = match typ.as_str() {
                "" | "none" | "gun" => None,
                "multi" => Some(true),
                "guna" => {
                    return Err(LinkError::Unsupported(Diag::new(
                        Key::LinkUnsupportedGrpcGuna,
                    )));
                }
                other => {
                    return Err(malformed(
                        Diag::new(Key::LinkGrpcModeUnknown).arg(excerpt_debug(other)),
                    ));
                }
            };
            stream.network = Network::Grpc;
            stream.grpc_settings = Some(GrpcSettings {
                service_name: path,
                authority: host,
                multi_mode,
                ..Default::default()
            });
        }
        "httpupgrade" => {
            if !matches!(typ.as_str(), "" | "none") {
                return Err(LinkError::Unsupported(
                    Diag::new(Key::LinkUnsupportedVmessHttpupgrade).arg(excerpt_debug(&typ)),
                ));
            }
            stream.network = Network::Httpupgrade;
            stream.httpupgrade_settings = Some(HttpupgradeSettings {
                host,
                path,
                ..Default::default()
            });
        }
        "xhttp" | "splithttp" => {
            // The vmess link's `type` doubles as the xhttp mode: the absent,
            // `none` and `auto` spellings all mean the wire default (the
            // empty mode), and every other spelling must be a mode the
            // model's vocabulary accepts.
            let mode = match typ.as_str() {
                "" | "none" | "auto" => String::new(),
                other if crate::model::validation::xhttp_mode_supported(other) => typ,
                other => {
                    return Err(LinkError::Unsupported(
                        Diag::new(Key::LinkUnsupportedVmessXhttp).arg(excerpt_debug(other)),
                    ));
                }
            };
            stream.network = Network::Xhttp;
            stream.xhttp_settings = Some(XhttpSettings {
                host,
                path,
                mode,
                ..Default::default()
            });
        }
        "http" | "h2" | "h3" => {
            return Err(LinkError::Unsupported(Diag::new(
                Key::LinkUnsupportedVmessNetHttp,
            )));
        }
        "quic" => {
            return Err(LinkError::Unsupported(Diag::new(
                Key::LinkUnsupportedVmessNetQuic,
            )));
        }
        other => {
            return Err(malformed(
                Diag::new(Key::LinkVmessNet).arg(excerpt_debug(other)),
            ));
        }
    }

    let name = match get("ps") {
        ps if !ps.is_empty() => match sanitize_profile_name(&ps)? {
            Some(cleaned) => cleaned,
            None => addr.clone(),
        },
        _ => addr.clone(),
    };
    let mut ob = OutboundModel::new(Protocol::Vmess);
    ob.settings = ProtocolSettings::Vmess(VmessSettings {
        address: addr,
        port,
        id,
        security: {
            // The legacy `scy: none` spelling has the same current-Xray
            // SecurityType_AUTO semantics as the #716 URL alias above.
            let security = get("scy");
            if security.is_empty() || security == "none" {
                "auto".to_string()
            } else {
                security
            }
        },
        ..Default::default()
    });
    ob.stream = stream;
    Ok(ServerProfile::new(name, ob))
}

fn vmess_link(profile: &ServerProfile, settings: &VmessSettings) -> Result<String, LinkError> {
    let mut query: Vec<(String, String)> = Vec::new();
    if !settings.security.is_empty() && settings.security != "auto" {
        query.push(("encryption".into(), settings.security.clone()));
    }
    security_params(&profile.outbound.stream, false, &mut query);
    transport_params(&profile.outbound.stream, &mut query)?;
    finalmask_param(&profile.outbound.stream, &mut query)?;
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{}", render_query(&query))
    };
    Ok(format!(
        "vmess://{}@{}{}{}",
        pct_encode(&settings.id),
        host_port(&settings.address, settings.port),
        query,
        fragment_suffix(&profile.name),
    ))
}

// ---------- ss (SIP002) ----------

fn parse_ss(body: &str, ignored: &mut Vec<String>) -> Result<ServerProfile, LinkError> {
    let (rest, frag0) = match body.find('#') {
        Some(i) => (&body[..i], &body[i + 1..]),
        None => (body, ""),
    };
    let (rest, raw_query) = match rest.find('?') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    let query = parse_query(raw_query)?;
    // SIP002 `plugin=` names a transport the model cannot carry (its own
    // diagnostic); a recognized compatibility parameter is dropped; any other
    // query field makes the link unsupported, the first key deciding the
    // message.
    if query.0.iter().any(|(key, _)| key == "plugin") {
        return Err(LinkError::Unsupported(Diag::new(
            Key::LinkUnsupportedSsPlugin,
        )));
    }
    for (key, value) in &query.0 {
        if drop_ignored_param(ignored, key, value) {
            continue;
        }
        return Err(LinkError::Unsupported(
            Diag::new(Key::LinkUnsupportedSsQueryField).arg(excerpt_debug(key)),
        ));
    }
    let mut frag = frag0.to_string();
    let (userinfo, hp) = match rest.find('@') {
        Some(i) if !rest[i + 1..].contains('@') => {
            // SIP002 userinfo@host form: a trailing '/' is a separator
            // (plugin links are `…@host:port/?plugin=…`), never part of the
            // authority (LINK-003).
            let hp = rest[i + 1..].strip_suffix('/').unwrap_or(&rest[i + 1..]);
            (rest[..i].to_string(), hp.to_string())
        }
        Some(_) => return Err(malformed(Diag::new(Key::LinkSsUserinfoAt))),
        None => {
            // Legacy form: base64 of the whole `method:password@host:port#tag`.
            // Never strip a trailing '/' here — the standard-base64 alphabet
            // includes '/', so the payload may legitimately end with one;
            // truncating it silently decodes to different bytes (LINK-003).
            let dec =
                b64_decode_any(rest).ok_or_else(|| malformed(Diag::new(Key::LinkSsBase64)))?;
            let dec = String::from_utf8(dec).map_err(|_| malformed(Diag::new(Key::LinkSsUtf8)))?;
            let (d, dfrag) = match dec.find('#') {
                Some(i) => (&dec[..i], &dec[i + 1..]),
                None => (dec.as_str(), ""),
            };
            if frag.is_empty() && !dfrag.is_empty() {
                frag = dfrag.to_string();
            }
            match d.rfind('@') {
                Some(i) => (d[..i].to_string(), d[i + 1..].to_string()),
                None => return Err(malformed(Diag::new(Key::LinkUserinfoMissing).arg("ss"))),
            }
        }
    };

    // Userinfo: base64url(method:password) preferred; plain
    // (percent-encoded) method:password as fallback.
    let creds = match b64_decode_any(&userinfo) {
        Some(b) => match String::from_utf8(b) {
            Ok(s) if s.contains(':') => s,
            _ => pct_decode(&userinfo)?,
        },
        None => pct_decode(&userinfo)?,
    };
    let (method, password) = creds
        .split_once(':')
        .ok_or_else(|| malformed(Diag::new(Key::LinkSsUserinfoFormat)))?;
    if method.is_empty() {
        return Err(malformed(Diag::new(Key::LinkSsMethodEmpty)));
    }
    if password.is_empty() {
        return Err(malformed(Diag::new(Key::LinkSsPasswordEmpty)));
    }
    let (host, port) = parse_host_port(&hp, "ss")?;
    let name = match fragment_name(&frag)? {
        Some(name) => name,
        None => host.clone(),
    };

    let mut ob = OutboundModel::new(Protocol::Shadowsocks);
    ob.settings = ProtocolSettings::Shadowsocks(ShadowsocksSettings {
        address: host,
        port,
        method: method.to_string(),
        password: password.to_string(),
        ..Default::default()
    });
    Ok(ServerProfile::new(name, ob))
}

fn ss_link(p: &ServerProfile, s: &ShadowsocksSettings) -> Result<String, LinkError> {
    let userinfo = URL_SAFE_NO_PAD.encode(format!("{}:{}", s.method, s.password));
    Ok(format!(
        "ss://{}@{}{}",
        userinfo,
        host_port(&s.address, s.port),
        fragment_suffix(&p.name),
    ))
}

// ---------- import-only schemes (SOCKS5 / HTTP / WireGuard / Hysteria 2) ----------

/// Validate an import-only scheme's query against its own key list: a key the
/// scheme defines passes, a recognized compatibility parameter is dropped and
/// reported, and anything else refuses the link.
fn validate_scheme_query(
    q: &Query,
    own: &[&str],
    ignored: &mut Vec<String>,
) -> Result<(), LinkError> {
    for (key, value) in &q.0 {
        if own.contains(&key.as_str()) {
            continue;
        }
        if drop_ignored_param(ignored, key, value) {
            continue;
        }
        return Err(LinkError::Unsupported(
            Diag::new(Key::LinkUnsupportedQueryField).arg(excerpt_debug(key)),
        ));
    }
    Ok(())
}

/// The first of `keys` present in `q`; two spellings of the same field are
/// refused rather than silently preferred.
fn one_of<'a>(q: &'a Query, keys: &[&str]) -> Result<Option<&'a str>, LinkError> {
    let mut found: Option<&str> = None;
    for key in keys {
        if q.get(key).is_some() {
            if let Some(seen) = found {
                return Err(malformed(Diag::new(Key::LinkQueryDuplicate).arg(seen)));
            }
            found = Some(key);
        }
    }
    Ok(found.and_then(|key| q.get(key)))
}

/// Apply the TLS parameters the import-only schemes share with #716 (`sni`,
/// `fp`, `alpn`, `ech`, `pcs`, `vcn`) onto a stream, with `host` as the
/// default `serverName`. The caller has already decided TLS is on.
fn apply_tls_params(q: &Query, stream: &mut StreamModel, host: &str) {
    stream.security = Security::Tls;
    stream.tls_settings = Some(TlsModel {
        server_name: q.get_ne("sni").unwrap_or(host).to_string(),
        fingerprint: q.get_ne("fp").unwrap_or("chrome").to_string(),
        alpn: split_alpn(q.get("alpn")),
        ech_config_list: q.get("ech").unwrap_or_default().to_string(),
        pinned_peer_cert_sha256: q.get("pcs").unwrap_or_default().to_string(),
        verify_peer_cert_by_name: q.get("vcn").unwrap_or_default().to_string(),
        ..Default::default()
    });
}

/// Split a link userinfo into `user` / `pass`, accepting the plain
/// (percent-encoded `user:pass`) spelling and the base64(`user:pass`) spelling
/// other clients emit. A bare value that is not base64 credentials is the
/// user name.
fn link_credentials(userinfo: &str) -> Result<(String, String), LinkError> {
    if userinfo.is_empty() {
        return Ok((String::new(), String::new()));
    }
    let literal = pct_decode(userinfo)?;
    if let Some((user, pass)) = literal.split_once(':') {
        return Ok((user.to_string(), pass.to_string()));
    }
    if let Some(decoded) = b64_decode_any(userinfo)
        && let Ok(text) = String::from_utf8(decoded)
        && let Some((user, pass)) = text.split_once(':')
    {
        return Ok((user.to_string(), pass.to_string()));
    }
    Ok((literal, String::new()))
}

/// `socks5://` / `socks://` — the two client userinfo spellings: a base64
/// `user:pass` with no query, or a plain `user:pass`. Xray's SOCKS outbound
/// speaks SOCKS5 only, so `socks4`/`socks4a` are refused by their own rows.
fn parse_socks(body: &str, ignored: &mut Vec<String>) -> Result<ServerProfile, LinkError> {
    const SCHEME: &str = "socks";
    let (auth, query, frag) = split_link(body);
    let (userinfo, hp) = split_authority(auth, SCHEME, false)?;
    let (host, port) = parse_host_port_default(hp, SCHEME, 1080)?;
    let q = parse_query(query)?;
    validate_scheme_query(&q, &["version"], ignored)?;
    if let Some(version) = q.get_ne("version")
        && version != "5"
    {
        return Err(LinkError::Unsupported(Diag::new(
            Key::LinkUnsupportedSocks4,
        )));
    }
    let (user, pass) = link_credentials(userinfo)?;
    let name = match fragment_name(frag)? {
        Some(name) => name,
        None => host.clone(),
    };
    let mut outbound = OutboundModel::new(Protocol::Socks);
    outbound.settings = ProtocolSettings::Socks(SocksSettings {
        address: host,
        port,
        user,
        pass,
        ..Default::default()
    });
    Ok(ServerProfile::new(name, outbound))
}

/// Fold a client-emitted `headers` value into the model's map. The wire form
/// is a flat alternating `name,value` list joined by `,`; an odd element count
/// or a repeated name has no single meaning and is refused.
fn http_headers(raw: &str) -> Result<Map<String, Value>, LinkError> {
    let items: Vec<&str> = raw.split(',').collect();
    let mut headers = Map::new();
    if !items.len().is_multiple_of(2) {
        return Err(malformed(Diag::new(Key::LinkHttpHeaders)));
    }
    for pair in items.chunks(2) {
        if pair[0].is_empty()
            || headers
                .insert(pair[0].to_string(), Value::String(pair[1].to_string()))
                .is_some()
        {
            return Err(malformed(Diag::new(Key::LinkHttpHeaders)));
        }
    }
    Ok(headers)
}

/// `http://` / `https://` — the link a client exports for an HTTP CONNECT
/// outbound. `https` (or `security=tls`) turns TLS on; the default port is 443
/// with TLS and 80 without.
fn parse_http(
    body: &str,
    scheme_tls: bool,
    ignored: &mut Vec<String>,
) -> Result<ServerProfile, LinkError> {
    const SCHEME: &str = "http";
    let (auth, query, frag) = split_link(body);
    let (userinfo, hp) = split_authority(auth, SCHEME, false)?;
    let q = parse_query(query)?;
    const OWN: &[&str] = &[
        "security", "sni", "fp", "alpn", "ech", "pcs", "vcn", "path", "headers",
    ];
    validate_scheme_query(&q, OWN, ignored)?;
    // `security` may agree with the scheme or turn TLS on for `http`; `none`
    // against an `https` scheme contradicts the scheme rather than naming a
    // setting, so it refuses the link instead of being silently overridden.
    let tls = match (scheme_tls, q.get("security")) {
        (_, Some("")) => return Err(malformed(Diag::new(Key::LinkQueryEmpty).arg("security"))),
        (_, Some("tls")) => true,
        (true, Some("none")) => return Err(malformed(Diag::new(Key::LinkHttpTlsConflict))),
        (_, Some("none")) | (false, None) => false,
        (true, None) => true,
        (_, Some(other)) => {
            return Err(malformed(
                Diag::new(Key::LinkSecurityUnknown).arg(excerpt_debug(other)),
            ));
        }
    };
    let (host, port) = parse_host_port_default(hp, SCHEME, if tls { 443 } else { 80 })?;
    let (user, pass) = link_credentials(userinfo)?;
    // A password-only userinfo (`:token@host`) is the emitting client's bare
    // token spelling: its own import reads the token as the user name.
    let (user, pass) = if user.is_empty() && !pass.is_empty() {
        (pass, String::new())
    } else {
        (user, pass)
    };
    let mut stream = StreamModel::default();
    if tls {
        apply_tls_params(&q, &mut stream, &host);
    } else {
        for key in ["sni", "fp", "alpn", "ech", "pcs", "vcn"] {
            if q.get(key).is_some() {
                return Err(LinkError::Unsupported(
                    Diag::new(Key::LinkUnsupportedQueryField).arg(key),
                ));
            }
        }
    }
    if q.get_ne("path").is_some() {
        // Xray's HTTP outbound has no request path.
        record_ignored(ignored, "path");
    }
    let headers = match q.get_ne("headers") {
        Some(raw) => http_headers(raw)?,
        None => Map::new(),
    };
    let name = match fragment_name(frag)? {
        Some(name) => name,
        None => host.clone(),
    };
    let mut outbound = OutboundModel::new(Protocol::Http);
    outbound.settings = ProtocolSettings::Http(HttpSettings {
        address: host,
        port,
        user,
        pass,
        headers,
        ..Default::default()
    });
    outbound.stream = stream;
    Ok(ServerProfile::new(name, outbound))
}

/// Append the host prefix an address omits, as the emitting clients do before
/// they hand the value to the core.
fn fix_address(value: &str) -> String {
    if value.contains('/') {
        return value.to_string();
    }
    match value.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(_)) => format!("{value}/32"),
        Ok(std::net::IpAddr::V6(_)) => format!("{value}/128"),
        Err(_) => value.to_string(),
    }
}

/// `wg://` / `wireguard://` — the two client spellings: the private key in a
/// `private_key` parameter with `-`-joined `local_address` values, or the
/// private key in the userinfo with comma-joined `address` / `ip` values.
/// Exactly one peer is modeled.
fn parse_wireguard(body: &str, ignored: &mut Vec<String>) -> Result<ServerProfile, LinkError> {
    const SCHEME: &str = "wireguard";
    let (auth, query, frag) = split_link(body);
    let (userinfo, hp) = split_authority(auth, SCHEME, false)?;
    let userinfo = (!userinfo.is_empty()).then_some(userinfo);
    let q = parse_query(query)?;
    const OWN: &[&str] = &[
        "private_key",
        "privatekey",
        "public_key",
        "publickey",
        "peer_public_key",
        "pre_shared_key",
        "preshared_key",
        "presharedkey",
        "psk",
        "reserved",
        "address",
        "ip",
        "local_address",
        "mtu",
        "dns",
        "fm",
        "persistent_keepalive_interval",
        "persistent_keepalive",
        "keepalive",
    ];
    validate_scheme_query(&q, OWN, ignored)?;
    let (host, port) = parse_host_port_default(hp, SCHEME, 51820)?;
    // Query values arrive percent-decoded (`parse_query`); only the userinfo
    // is still raw.
    let secret_key = match one_of(&q, &["private_key", "privatekey"])? {
        Some(value) => value.to_string(),
        None => match userinfo {
            Some(userinfo) => pct_decode(userinfo)?,
            None => String::new(),
        },
    };
    if secret_key.is_empty() {
        return Err(malformed(Diag::new(Key::LinkWgSecretKey)));
    }
    let public_key = one_of(&q, &["public_key", "publickey", "peer_public_key"])?
        .unwrap_or_default()
        .to_string();
    if public_key.is_empty() {
        return Err(malformed(Diag::new(Key::LinkWgPublicKey)));
    }
    let pre_shared_key = one_of(
        &q,
        &["pre_shared_key", "preshared_key", "presharedkey", "psk"],
    )?
    .unwrap_or_default()
    .to_string();
    let keep_alive = match one_of(
        &q,
        &[
            "persistent_keepalive_interval",
            "persistent_keepalive",
            "keepalive",
        ],
    )? {
        Some(value) => Some(numeric_param("keepalive", value)?),
        None => None,
    };
    let address_text = one_of(&q, &["local_address", "address", "ip"])?.unwrap_or_default();
    let address: Vec<String> = address_text
        .split(['-', ','])
        .map(str::trim)
        .filter(|address| !address.is_empty())
        .map(fix_address)
        .collect();
    if address.is_empty() {
        return Err(malformed(Diag::new(Key::LinkWgAddress)));
    }
    let reserved = match q.get_ne("reserved") {
        Some(raw) => {
            let bytes = raw
                .split(['-', ','])
                .map(str::trim)
                .filter(|byte| !byte.is_empty())
                .map(|byte| byte.parse::<u8>())
                .collect::<Result<Vec<u8>, _>>()
                .map_err(|_| malformed(Diag::new(Key::LinkWgReserved)))?;
            Some(bytes)
        }
        None => None,
    };
    let mtu = match q.get_ne("mtu") {
        Some(value) => u16::try_from(numeric_param("mtu", value)?).map_err(|_| {
            malformed(
                Diag::new(Key::LinkNumericParam)
                    .arg("mtu")
                    .arg(excerpt_debug(value)),
            )
        })?,
        None => 1420,
    };
    let remote_dns: Vec<String> = q
        .get_ne("dns")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(str::to_string)
        .collect();
    let mut stream = StreamModel::default();
    apply_finalmask(&q, &mut stream)?;
    let name = match fragment_name(frag)? {
        Some(name) => name,
        None => host.clone(),
    };
    let mut outbound = OutboundModel::new(Protocol::Wireguard);
    outbound.settings = ProtocolSettings::Wireguard(WireguardSettings {
        secret_key,
        address,
        peers: vec![WireguardPeer {
            public_key,
            pre_shared_key,
            endpoint: host_port(&host, port),
            keep_alive,
            ..Default::default()
        }],
        mtu,
        reserved,
        remote_dns,
        ..Default::default()
    });
    outbound.stream = stream;
    Ok(ServerProfile::new(name, outbound))
}

/// A single numeric port, or `None` when the text is a list or range.
fn parse_single_port(text: &str, scheme: &str) -> Result<Option<u16>, LinkError> {
    match text.parse::<u16>() {
        Ok(0) => Err(malformed(Diag::new(Key::LinkPortZero).arg(scheme))),
        Ok(port) => Ok(Some(port)),
        Err(_) => Ok(None),
    }
}

/// Parse the comma-separated port list a Hysteria 2 authority or `mport`
/// carries (`20000-30000`, `20000-30000,443`): every item is a single port or an
/// ascending range, all 1..=65535, and the text reaches Xray's `PortList`
/// verbatim (`infra/conf/common.go:247-268`). Returns the list's first port,
/// which becomes the outbound's initial destination.
fn parse_hop_port_list(text: &str, scheme: &str) -> Result<u16, LinkError> {
    let invalid = |item: &str| {
        malformed(
            Diag::new(Key::LinkPortInvalid)
                .arg(excerpt_debug(item))
                .arg(scheme),
        )
    };
    let mut first = None;
    for item in text.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (from, to) = match item.split_once('-') {
            Some((from, to)) => (from.trim(), to.trim()),
            None => (item, item),
        };
        let from: u16 = from.parse().map_err(|_| invalid(item))?;
        let to: u16 = to.parse().map_err(|_| invalid(item))?;
        if from == 0 || from > to {
            return Err(invalid(item));
        }
        first.get_or_insert(from);
    }
    first.ok_or_else(|| invalid(text))
}

/// The Hysteria 2 authority: `host`, `host:port`, or `host:portList`. A port
/// list is the hopping set the service advertises, and no single port names
/// it, so the list's first port becomes the outbound's destination while the
/// whole list rides the hop mask.
fn parse_hysteria_authority(
    hp: &str,
    scheme: &str,
) -> Result<(String, u16, Option<String>), LinkError> {
    let (host, port_text) = split_host_port(hp, scheme)?;
    validate_host(&host, scheme)?;
    let Some(port_text) = port_text else {
        return Ok((host, 443, None));
    };
    if let Some(port) = parse_single_port(port_text, scheme)? {
        return Ok((host, port, None));
    }
    let first = parse_hop_port_list(port_text, scheme)?;
    Ok((host, first, Some(port_text.to_string())))
}

/// The salamander packet-size range a Hysteria 2 link carries.
fn hysteria_packet_size(q: &Query) -> Result<Int32Range, LinkError> {
    let parse = |value: &str| {
        value
            .parse::<i32>()
            .map_err(|_| malformed(Diag::new(Key::LinkHysteriaPacketSize)))
    };
    match (q.get_ne("minPacketSize"), q.get_ne("maxPacketSize")) {
        (None, None) => Ok(Int32Range::single(0)),
        (Some(min), None) => Ok(Int32Range::single(parse(min)?)),
        (None, Some(max)) => Ok(Int32Range::single(parse(max)?)),
        (Some(min), Some(max)) => {
            let (min, max) = (parse(min)?, parse(max)?);
            if min > max {
                return Err(malformed(Diag::new(Key::LinkHysteriaPacketSize)));
            }
            Ok(Int32Range::new(min, max))
        }
    }
}

/// The QUIC parameters a Hysteria 2 link carries: `upmbps`/`downmbps` select
/// the brutal congestion controller, so a one-sided rate is refused.
fn hysteria_quic_params(q: &Query) -> Result<Option<FinalmaskQuicParams>, LinkError> {
    let up = q.get_ne("upmbps");
    let down = q.get_ne("downmbps");
    let bbr = q.get_ne("bbr_profile");
    let parrot = q.get_ne("disable_chrome_parrot");
    if up.is_none() && down.is_none() && bbr.is_none() && parrot.is_none() {
        return Ok(None);
    }
    if up.is_some() != down.is_some() {
        return Err(malformed(Diag::new(Key::LinkHysteriaBrutal)));
    }
    let mut quic = FinalmaskQuicParams::default();
    if let (Some(up), Some(down)) = (up, down) {
        quic.congestion = "force-brutal".into();
        quic.brutal_up = format!("{} mbps", numeric_param("upmbps", up)?);
        quic.brutal_down = format!("{} mbps", numeric_param("downmbps", down)?);
    }
    if let Some(bbr) = bbr {
        quic.bbr_profile = bbr.to_string();
    }
    if let Some(value) = parrot {
        quic.disable_chrome_parrot = Some(!matches!(
            value.to_ascii_lowercase().as_str(),
            "0" | "false" | "no"
        ));
    }
    Ok(Some(quic))
}

/// The `finalmask` a Hysteria 2 link carries: salamander obfuscation,
/// destination hopping (from the authority's port list or `mport`), and the
/// QUIC congestion parameters. Returns `None` when the link names none of
/// them.
fn hysteria_finalmask(
    q: &Query,
    authority_ports: Option<&str>,
) -> Result<Option<FinalmaskModel>, LinkError> {
    let mut udp: Vec<FinalmaskUdpMask> = Vec::new();
    let obfs = q.get_ne("obfs");
    let obfs_password = q.get_ne("obfs-password");
    if let Some(kind) = obfs
        && kind != "salamander"
    {
        return Err(LinkError::Unsupported(
            Diag::new(Key::LinkUnsupportedHysteriaObfs).arg(excerpt_debug(kind)),
        ));
    }
    // A packet size belongs to the salamander mask; without an obfuscation it
    // names a setting that cannot take effect, so it refuses the link instead
    // of disappearing.
    if obfs.is_none()
        && obfs_password.is_none()
        && let Some(key) = ["minPacketSize", "maxPacketSize"]
            .into_iter()
            .find(|key| q.get_ne(key).is_some())
    {
        return Err(LinkError::Unsupported(
            Diag::new(Key::LinkUnsupportedQueryField).arg(key),
        ));
    }
    if obfs.is_some() || obfs_password.is_some() {
        let password =
            obfs_password.ok_or_else(|| malformed(Diag::new(Key::LinkHysteriaObfsPassword)))?;
        udp.push(FinalmaskUdpMask::Salamander {
            settings: FinalmaskSalamander {
                password: password.to_string(),
                packet_size: hysteria_packet_size(q)?,
                ..Default::default()
            },
            extra: Map::new(),
        });
    }
    // The hop set comes from the authority's port list or `mport` — one
    // spelling only, so a link naming both is refused rather than silently
    // preferring one.
    let ports = match (authority_ports, q.get_ne("mport")) {
        (Some(_), Some(_)) => {
            return Err(malformed(Diag::new(Key::LinkQueryDuplicate).arg("mport")));
        }
        (Some(ports), None) => ports.to_string(),
        (None, Some(mport)) => {
            // The core's `PortList` is the judge of this text; a value it
            // cannot parse would fail at config load.
            parse_hop_port_list(mport, "hysteria2")?;
            mport.to_string()
        }
        (None, None) => String::new(),
    };
    if ports.is_empty() {
        // A hop interval names nothing without a hop set.
        if q.get_ne("hop_interval").is_some() {
            return Err(LinkError::Unsupported(
                Diag::new(Key::LinkUnsupportedQueryField).arg("hop_interval"),
            ));
        }
    } else {
        let mut hop = FinalmaskUdpHop {
            remote_ports: FinalmaskPortList::Text(ports),
            ..Default::default()
        };
        if let Some(interval) = q.get_ne("hop_interval") {
            let seconds: i32 = interval
                .parse()
                .map_err(|_| malformed(Diag::new(Key::LinkHysteriaHopInterval)))?;
            hop.mode = "intervalRemote".into();
            hop.interval = Int32Range::single(seconds);
        }
        udp.push(FinalmaskUdpMask::Udphop {
            settings: Box::new(hop),
            extra: Map::new(),
        });
    }
    let quic = hysteria_quic_params(q)?;
    if udp.is_empty() && quic.is_none() {
        return Ok(None);
    }
    Ok(Some(FinalmaskModel {
        udp,
        quic_params: quic,
        ..Default::default()
    }))
}

/// `hysteria2://` / `hy2://` — Hysteria 2 over Xray's `hysteria` outbound and
/// transport. Auth is the userinfo and TLS is always on; the link's
/// obfuscation and hopping fields map onto `finalmask`.
fn parse_hysteria2(body: &str, ignored: &mut Vec<String>) -> Result<ServerProfile, LinkError> {
    const SCHEME: &str = "hysteria2";
    let (auth, query, frag) = split_link(body);
    let (userinfo, hp) = split_authority(auth, SCHEME, false)?;
    let q = parse_query(query)?;
    const OWN: &[&str] = &[
        "security",
        "sni",
        "fp",
        "alpn",
        "ech",
        "pcs",
        "vcn",
        "pinSHA256",
        "obfs",
        "obfs-password",
        "minPacketSize",
        "maxPacketSize",
        "mport",
        "hop_interval",
        "upmbps",
        "downmbps",
        "bbr_profile",
        "disable_chrome_parrot",
    ];
    validate_scheme_query(&q, OWN, ignored)?;
    // Hysteria runs on QUIC with TLS always on: only an explicit `tls` is a
    // value the grammar can honor.
    match q.get("security") {
        Some("") => return Err(malformed(Diag::new(Key::LinkQueryEmpty).arg("security"))),
        Some("tls") | None => {}
        Some(other) => {
            return Err(malformed(
                Diag::new(Key::LinkSecurityUnknown).arg(excerpt_debug(other)),
            ));
        }
    }
    let (host, port, authority_ports) = parse_hysteria_authority(hp, SCHEME)?;
    let password = pct_decode(userinfo)?;
    let mut stream = StreamModel::default();
    apply_tls_params(&q, &mut stream, &host);
    // `pinSHA256` is the emitting client's name for the certificate pin; a
    // comma list names a leaf-certificate thumbprint this grammar cannot
    // derive.
    if let Some(pin) = q.get_ne("pinSHA256") {
        if pin.contains(',') {
            return Err(malformed(Diag::new(Key::LinkHysteriaPin)));
        }
        if let Some(tls) = stream.tls_settings.as_mut() {
            if !tls.pinned_peer_cert_sha256.is_empty() {
                return Err(malformed(
                    Diag::new(Key::LinkQueryDuplicate).arg("pinSHA256"),
                ));
            }
            tls.pinned_peer_cert_sha256 = pin.to_string();
        }
    }
    stream.network = Network::Hysteria;
    stream.hysteria_settings = Some(HysteriaTransport {
        version: 2,
        auth: password,
        ..Default::default()
    });
    stream.finalmask = hysteria_finalmask(&q, authority_ports.as_deref())?;
    let name = match fragment_name(frag)? {
        Some(name) => name,
        None => host.clone(),
    };
    let mut outbound = OutboundModel::new(Protocol::Hysteria);
    outbound.settings = ProtocolSettings::Hysteria(HysteriaSettings {
        version: 2,
        address: host,
        port,
        ..Default::default()
    });
    outbound.stream = stream;
    Ok(ServerProfile::new(name, outbound))
}

/// The import grammar's `?encryption=` check, delegating to the shared model
/// predicate (`vless_encryption_supported`) so a link never imports a value
/// the model finding refuses. The model's empty draft seam is not a link
/// value: empty is malformed here.
fn validate_vless_encryption(value: &str) -> bool {
    !value.is_empty() && vless_encryption_supported(value)
}

/// The REALITY grammar's fingerprint accept-set, derived from the canonical
/// model vocabulary (`src/model/fingerprint.rs`): every canonical table name
/// except `""` / `unsafe` / `hellogolang`. The editor's trimmed REALITY
/// option list does not narrow this grammar — a link naming any other
/// canonical fingerprint imports as before.
fn supported_reality_fingerprint(value: &str) -> bool {
    crate::model::fingerprint::reality_import_supported(value)
}

fn validate_reality(stream: &StreamModel) -> Result<(), LinkError> {
    let Some(reality) = stream.reality_settings.as_ref() else {
        // Missing settings and the transport-support rule are reported by the
        // model validation pass before this links-local grammar check runs.
        return Ok(());
    };
    if reality.server_name.is_empty() {
        return Err(malformed(Diag::new(Key::LinkRealityServerNameEmpty)));
    }
    validate_host(&reality.server_name, "REALITY sni")?;
    if !supported_reality_fingerprint(&reality.fingerprint) {
        return Err(malformed(
            Diag::new(Key::LinkRealityFingerprint).arg(excerpt_debug(&reality.fingerprint)),
        ));
    }
    // Shape checks delegate to the shared model predicates
    // (src/model/validation.rs) — the same predicates the model validation
    // pass runs on the TLS/REALITY stream blocks, so import and model can
    // never drift. The messages below are the grammar's renderings of those
    // predicates.
    if !crate::model::validation::reality_public_key_valid(&reality.password) {
        return Err(malformed(Diag::new(Key::LinkRealityPbk)));
    }
    if !crate::model::validation::reality_short_id_valid(&reality.short_id) {
        return Err(malformed(Diag::new(Key::LinkRealitySid)));
    }
    if !crate::model::validation::reality_mldsa65_verify_valid(&reality.mldsa65_verify) {
        return Err(malformed(Diag::new(Key::LinkRealityPqv)));
    }
    if !crate::model::validation::reality_spider_x_valid(&reality.spider_x) {
        return Err(malformed(Diag::new(Key::LinkRealitySpx)));
    }
    Ok(())
}

/// The TLS grammar's fingerprint accept-set, derived from the canonical
/// model vocabulary (`src/model/fingerprint.rs`): the editor table verbatim
/// — `""`, `unsafe`, and `hellogolang` included, wire-only names excluded.
/// Accept/reject decisions are identical to the historical
/// `"" || unsafe || hellogolang || supported_reality_fingerprint(value)`
/// composition.
fn supported_tls_fingerprint(value: &str) -> bool {
    crate::model::fingerprint::FINGERPRINTS.contains(&value)
}

fn validate_tls(tls: &TlsModel) -> Result<(), LinkError> {
    if !supported_tls_fingerprint(&tls.fingerprint) {
        return Err(malformed(
            Diag::new(Key::LinkTlsFingerprint).arg(excerpt_debug(&tls.fingerprint)),
        ));
    }
    if !tls.server_name.is_empty() {
        validate_host(&tls.server_name, "TLS serverName")?;
    }
    if tls.alpn.len() > 1
        && tls
            .alpn
            .iter()
            .any(|value| value.eq_ignore_ascii_case("frommitm"))
    {
        return Err(malformed(Diag::new(Key::LinkTlsAlpnFromMitm)));
    }
    if !crate::model::validation::pinned_peer_cert_sha256_valid(&tls.pinned_peer_cert_sha256) {
        return Err(malformed(Diag::new(Key::LinkTlsPcs)));
    }
    Ok(())
}

fn string_map_is_valid(map: &Map<String, Value>) -> bool {
    map.values().all(Value::is_string)
}

fn raw_header_value_is_valid(value: &Value) -> bool {
    value.is_string()
        || value
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string))
}

fn validate_xhttp(settings: &XhttpSettings) -> Result<(), LinkError> {
    // Vocabulary / cross-field refusals delegate to the shared predicates in
    // `crate::model::validation`: the import grammar and the
    // model pass decide identically on every value because they run the same
    // code, mirroring Xray's SplitHTTPConfig.Build
    // (infra/conf/transport_method.go:317-459).
    let mode = if settings.mode.is_empty() {
        "auto"
    } else {
        settings.mode.as_str()
    };
    if !crate::model::validation::xhttp_mode_supported(&settings.mode) {
        return Err(malformed(
            Diag::new(Key::LinkXhttpMode).arg(excerpt_debug(&settings.mode)),
        ));
    }
    if !string_map_is_valid(&settings.headers) {
        return Err(malformed(Diag::new(Key::LinkXhttpHeaderValues)));
    }
    if settings
        .headers
        .keys()
        .any(|key| key.eq_ignore_ascii_case("host"))
    {
        return Err(malformed(Diag::new(Key::LinkXhttpHostHeader)));
    }
    if !crate::model::validation::xpadding_bytes_supported(settings.x_padding_bytes) {
        return Err(malformed(Diag::new(Key::LinkXhttpPaddingBytes)));
    }
    if !crate::model::validation::xpadding_placement_supported(&settings.x_padding_placement) {
        return Err(malformed(Diag::new(Key::LinkXhttpPaddingPlacement)));
    }
    if !crate::model::validation::xpadding_method_supported(&settings.x_padding_method) {
        return Err(malformed(Diag::new(Key::LinkXhttpPaddingMethod)));
    }
    if !crate::model::validation::uplink_data_placement_supported(&settings.uplink_data_placement) {
        return Err(malformed(Diag::new(Key::LinkXhttpUplinkPlacement)));
    }
    if !crate::model::validation::uplink_placement_mode_supported(
        &settings.uplink_data_placement,
        mode,
    ) {
        return Err(malformed(Diag::new(Key::LinkXhttpUplinkMode)));
    }
    if !crate::model::validation::uplink_http_method_mode_supported(
        &settings.uplink_http_method,
        mode,
    ) {
        return Err(malformed(Diag::new(Key::LinkXhttpUplinkMethod)));
    }
    if !crate::model::validation::session_id_placement_supported(&settings.session_id_placement) {
        return Err(malformed(Diag::new(Key::LinkXhttpSessionPlacement)));
    }
    if !crate::model::validation::seq_placement_supported(&settings.seq_placement) {
        return Err(malformed(Diag::new(Key::LinkXhttpSeqPlacement)));
    }
    if !settings.session_id_table.is_empty() {
        let range = settings
            .session_id_length
            .ok_or_else(|| malformed(Diag::new(Key::LinkXhttpSessionLength)))?;
        if !crate::model::validation::range_has_session_room(&settings.session_id_table, range) {
            return Err(malformed(Diag::new(Key::LinkXhttpSessionSpace)));
        }
    }
    if settings
        .server_max_header_bytes
        .is_some_and(|value| !crate::model::validation::server_max_header_bytes_ok(value))
    {
        return Err(malformed(Diag::new(Key::LinkXhttpServerMaxHeader)));
    }
    if crate::model::validation::xmux_limits_conflict(settings.xmux.as_ref()) {
        return Err(malformed(Diag::new(Key::LinkXhttpXmux)));
    }
    if mode == "stream-one" && settings.download_settings.is_some() {
        return Err(malformed(Diag::new(Key::LinkXhttpStreamOne)));
    }
    if let Some(download) = settings.download_settings.as_deref() {
        validate_stream_core(download)?;
    }
    Ok(())
}

fn validate_stream_core(stream: &StreamModel) -> Result<(), LinkError> {
    match stream.security {
        Security::None => {}
        Security::Tls => {
            if let Some(tls) = stream.tls_settings.as_ref() {
                validate_tls(tls)?;
            }
        }
        Security::Reality => validate_reality(stream)?,
    }

    match stream.network {
        Network::Raw => {
            if let Some(header) = stream
                .raw_settings
                .as_ref()
                .and_then(|settings| settings.header.as_ref())
            {
                if !matches!(header.r#type.as_str(), "" | "none" | "http") {
                    return Err(malformed(
                        Diag::new(Key::LinkRawHeaderType).arg(excerpt_debug(&header.r#type)),
                    ));
                }
                if header.r#type != "http"
                    && (header.request.is_some() || header.response.is_some())
                {
                    return Err(malformed(Diag::new(Key::LinkRawCamouflage)));
                }
                if header.request.as_ref().is_some_and(|request| {
                    request
                        .headers
                        .values()
                        .any(|value| !raw_header_value_is_valid(value))
                }) || header.response.as_ref().is_some_and(|response| {
                    response
                        .headers
                        .values()
                        .any(|value| !raw_header_value_is_valid(value))
                }) {
                    return Err(malformed(Diag::new(Key::LinkRawHeaderValues)));
                }
            }
        }
        Network::Kcp => {
            if let Some(kcp) = stream.kcp_settings.as_ref() {
                if kcp
                    .mtu
                    .is_some_and(|mtu| !crate::model::validation::kcp_mtu_hard_ok(mtu))
                {
                    return Err(malformed(Diag::new(Key::LinkKcpMtu)));
                }
                if kcp
                    .tti
                    .is_some_and(|tti| !crate::model::validation::kcp_tti_hard_ok(tti))
                {
                    return Err(malformed(Diag::new(Key::LinkKcpTti)));
                }
                if kcp.cwnd_multiplier == Some(0) {
                    return Err(malformed(Diag::new(Key::LinkKcpCwnd)));
                }
                if let Some(window) = kcp.max_sending_window
                    && window < kcp.mtu.unwrap_or(1350)
                {
                    return Err(malformed(Diag::new(Key::LinkKcpWindow)));
                }
            }
        }
        Network::Ws => {
            if stream
                .ws_settings
                .as_ref()
                .is_some_and(|settings| !string_map_is_valid(&settings.headers))
            {
                return Err(malformed(Diag::new(Key::LinkWsHeaderValues)));
            }
        }
        Network::Grpc => {
            if stream
                .grpc_settings
                .as_ref()
                .is_none_or(|settings| settings.service_name.is_empty())
            {
                return Err(malformed(Diag::new(Key::LinkGrpcServiceName)));
            }
        }
        Network::Httpupgrade => {
            if let Some(settings) = stream.httpupgrade_settings.as_ref()
                && !string_map_is_valid(&settings.headers)
            {
                return Err(malformed(Diag::new(Key::LinkHttpupgradeHeaderValues)));
            }
        }
        Network::Xhttp => {
            if let Some(settings) = stream.xhttp_settings.as_ref() {
                validate_xhttp(settings)?;
            }
        }
        Network::Hysteria => {
            // The import-only `hysteria2://` links build this transport, so
            // the arm refuses nothing: export still refuses it through
            // `transport_params`' `spelling()`, and `vless://…?type=hysteria`
            // is refused as an unknown transport (the row spells no `type`).
        }
    }
    if let Some(finalmask) = stream.finalmask.as_ref() {
        validate_finalmask(finalmask)?;
    }
    Ok(())
}

/// Pure, side-effect-free validation for imported/shareable profiles.
///
/// This mirrors the local Xray configuration builders' required fields and
/// cross-field invariants. Callers that persist an imported profile should
/// additionally run the generated scratch config through `xray run -test`.
pub fn validate_profile(profile: &ServerProfile) -> Result<(), LinkError> {
    validate_profile_inner(profile).map(|_| ())
}

/// The advisory half of [`validate_profile`]'s model pass: the findings a
/// profile carries that are xray-legal and never refuse it. The import path
/// logs them, so a profile the editors flag amber is not accepted in silence.
pub fn profile_advisories(profile: &ServerProfile) -> Result<Vec<ValidationIssue>, LinkError> {
    validate_profile_inner(profile)
}

/// One walk, two seams: the refusal [`validate_profile`] reports and the
/// advisory findings [`profile_advisories`] returns come from the same pass,
/// so the import grammar and the logged warnings cannot drift apart.
fn validate_profile_inner(profile: &ServerProfile) -> Result<Vec<ValidationIssue>, LinkError> {
    let settings_protocol = profile.outbound.settings.protocol();
    if profile.outbound.protocol != settings_protocol {
        return Err(malformed(
            Diag::new(Key::LinkProtocolMismatch)
                .arg(profile.outbound.protocol.as_str())
                .arg(settings_protocol.as_str()),
        ));
    }

    match &profile.outbound.settings {
        ProtocolSettings::Vless(settings) => {
            validate_host(&settings.address, "vless")?;
            if settings.port == 0 {
                return Err(malformed(Diag::new(Key::LinkPortZero).arg("vless")));
            }
            check_uuid(&settings.id, "vless")?;
            if !settings.flow.is_empty() && !is_vision_flow(&settings.flow) {
                return Err(malformed(
                    Diag::new(Key::LinkVlessFlow).arg(excerpt_debug(&settings.flow)),
                ));
            }
            if !validate_vless_encryption(&settings.encryption) {
                return Err(malformed(
                    Diag::new(Key::LinkVlessEncryption).arg(excerpt_debug(&settings.encryption)),
                ));
            }
        }
        ProtocolSettings::Vmess(settings) => {
            validate_host(&settings.address, "vmess")?;
            if settings.port == 0 {
                return Err(malformed(Diag::new(Key::LinkPortZero).arg("vmess")));
            }
            check_uuid(&settings.id, "vmess")?;
            // The link grammar stays stricter than the wire: the core maps an
            // unknown spelling onto `auto` (the model pass warns about that),
            // while this grammar — like the fingerprint one — refuses a link
            // whose parameter it cannot carry as the sender meant it.
            if !crate::model::validation::vmess_security_supported(&settings.security) {
                return Err(LinkError::Unsupported(
                    Diag::new(Key::LinkUnsupportedVmessEncryption)
                        .arg(excerpt_debug(&settings.security)),
                ));
            }
        }
        ProtocolSettings::Trojan(settings) => {
            validate_host(&settings.address, "trojan")?;
            if settings.port == 0 || settings.password.is_empty() {
                return Err(malformed(Diag::new(Key::LinkTrojanIncomplete)));
            }
        }
        ProtocolSettings::Shadowsocks(settings) => {
            validate_host(&settings.address, "ss")?;
            if settings.port == 0 || settings.password.is_empty() {
                return Err(malformed(Diag::new(Key::LinkSsIncomplete)));
            }
            if !crate::model::validation::shadowsocks_method_supported(&settings.method) {
                return Err(malformed(
                    Diag::new(Key::LinkSsMethod).arg(excerpt_debug(&settings.method)),
                ));
            }
            if !crate::model::validation::shadowsocks_2022_key_usable(
                &settings.method,
                &settings.password,
            ) {
                return Err(malformed(Diag::new(Key::LinkSsKeyMaterial)));
            }
        }
        ProtocolSettings::Socks(settings) => {
            validate_host(&settings.address, "socks")?;
            if settings.port == 0 {
                return Err(malformed(Diag::new(Key::LinkPortZero).arg("socks")));
            }
        }
        ProtocolSettings::Http(settings) => {
            validate_host(&settings.address, "http")?;
            if settings.port == 0 {
                return Err(malformed(Diag::new(Key::LinkPortZero).arg("http")));
            }
        }
        ProtocolSettings::Wireguard(settings) => {
            // The key material, the peer essentials, and the reserved length
            // are model rules: the `validate_outbound` pass below refuses
            // them as the keyed `InvalidModel`, for the editor, generation,
            // and this importer alike.
            if settings.address.is_empty() {
                return Err(malformed(Diag::new(Key::LinkWgAddress)));
            }
        }
        ProtocolSettings::Hysteria(settings) => {
            validate_host(&settings.address, "hysteria2")?;
            if settings.port == 0 {
                return Err(malformed(Diag::new(Key::LinkPortZero).arg("hysteria2")));
            }
        }
        other => return Err(unsupported_protocol(other.protocol())),
    }

    // Model validation pass: protocol, stream, and transport-security
    // invariants in one sweep (no short-circuit). The verdict's first
    // blocking finding blocks the import/export; its advisory findings are
    // the profile that is xray-legal and imports fine, returned to the
    // caller instead of dropped. Remaining #716 grammar checks run below.
    let verdict = validate_outbound(&profile.outbound);
    let advisories: Vec<ValidationIssue> = verdict.advisory().cloned().collect();
    if let Some(issue) = verdict.into_first_blocking() {
        return Err(LinkError::InvalidModel {
            prefix: None,
            issue: Box::new(issue),
        });
    }

    validate_stream_core(&profile.outbound.stream)?;
    Ok(advisories)
}

fn option_has_fields<T: Serialize>(value: &Option<T>) -> bool {
    let Some(value) = value else {
        return false;
    };
    match serde_json::to_value(value) {
        Ok(Value::Object(object)) => !object.is_empty(),
        Ok(Value::Null) => false,
        Ok(_) | Err(_) => true,
    }
}

fn validate_protocol_exportable(settings: &ProtocolSettings) -> Result<(), LinkError> {
    match settings {
        ProtocolSettings::Vless(settings) => {
            if settings.level.is_some() {
                return Err(lossy("settings.level", Key::LinkLossyPolicyLevel));
            }
            if !settings.email.is_empty() {
                return Err(lossy("settings.email", Key::LinkLossyEmail));
            }
            if settings.reverse.is_some() {
                return Err(lossy("settings.reverse", Key::LinkLossyVlessReverse));
            }
            if !settings.extra.is_empty() {
                return Err(lossy("settings.extra", Key::LinkLossyVlessExtra));
            }
        }
        ProtocolSettings::Vmess(settings) => {
            if !settings.experiments.is_empty() {
                return Err(lossy(
                    "settings.experiments",
                    Key::LinkLossyVmessExperiments,
                ));
            }
            if settings.level.is_some() {
                return Err(lossy("settings.level", Key::LinkLossyPolicyLevel));
            }
            if !settings.email.is_empty() {
                return Err(lossy("settings.email", Key::LinkLossyEmail));
            }
            if !settings.extra.is_empty() {
                return Err(lossy("settings.extra", Key::LinkLossyVmessExtra));
            }
        }
        ProtocolSettings::Trojan(settings) => {
            if settings.level.is_some() {
                return Err(lossy("settings.level", Key::LinkLossyPolicyLevel));
            }
            if !settings.email.is_empty() {
                return Err(lossy("settings.email", Key::LinkLossyEmail));
            }
            if !settings.extra.is_empty() {
                return Err(lossy("settings.extra", Key::LinkLossyTrojanExtra));
            }
        }
        ProtocolSettings::Shadowsocks(settings) => {
            if settings.level.is_some() {
                return Err(lossy("settings.level", Key::LinkLossyPolicyLevel));
            }
            if !settings.email.is_empty() {
                return Err(lossy("settings.email", Key::LinkLossyEmail));
            }
            if !settings.extra.is_empty() {
                return Err(lossy("settings.extra", Key::LinkLossySsExtra));
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_tls_exportable(tls: &TlsModel) -> Result<(), LinkError> {
    if !tls.min_version.is_empty()
        || !tls.max_version.is_empty()
        || !tls.cipher_suites.is_empty()
        || !tls.curve_preferences.is_empty()
        || !tls.certificates.is_empty()
        || tls.disable_system_root.is_some()
        || tls.enable_session_resumption.is_some()
        || !tls.master_key_log.is_empty()
        || tls.ech_sockopt.is_some()
        || !tls.extra.is_empty()
    {
        return Err(lossy(
            "streamSettings.tlsSettings",
            Key::LinkLossyTlsAdvanced,
        ));
    }
    Ok(())
}

fn validate_reality_exportable(reality: &RealityModel) -> Result<(), LinkError> {
    if reality.show.is_some() || !reality.master_key_log.is_empty() || !reality.extra.is_empty() {
        return Err(lossy(
            "streamSettings.realitySettings",
            Key::LinkLossyRealityAdvanced,
        ));
    }
    Ok(())
}

fn validate_url_stream_exportable(stream: &StreamModel) -> Result<(), LinkError> {
    if stream
        .sockopt
        .as_ref()
        .is_some_and(|sockopt| !sockopt.is_empty())
    {
        return Err(lossy("streamSettings.sockopt", Key::LinkLossySockopt));
    }
    if !stream.extra.is_empty() {
        return Err(lossy("streamSettings.extra", Key::LinkLossyStreamExtra));
    }

    match stream.security {
        Security::None => {}
        Security::Tls => {
            let tls = stream
                .tls_settings
                .as_ref()
                .ok_or_else(|| lossy("streamSettings.tlsSettings", Key::LinkLossyTlsMissing))?;
            validate_tls_exportable(tls)?;
        }
        Security::Reality => {
            let reality = stream.reality_settings.as_ref().ok_or_else(|| {
                lossy(
                    "streamSettings.realitySettings",
                    Key::LinkLossyRealityMissing,
                )
            })?;
            validate_reality_exportable(reality)?;
        }
    }
    if stream.security != Security::Tls && option_has_fields(&stream.tls_settings) {
        return Err(lossy(
            "streamSettings.tlsSettings",
            Key::LinkLossyTlsUnselected,
        ));
    }
    if stream.security != Security::Reality && option_has_fields(&stream.reality_settings) {
        return Err(lossy(
            "streamSettings.realitySettings",
            Key::LinkLossyRealityUnselected,
        ));
    }

    // The selected transport's own refusals, then every other transport's
    // block: a transport the grammar cannot spell is refused before either.
    let selected = transport_spec(stream.network);
    selected.spelling()?;
    for refused in selected.refused {
        if (refused.is_set)(stream) {
            return Err(lossy(selected.path, refused.key));
        }
    }
    for spec in TRANSPORTS {
        if spec.network != stream.network && (spec.is_present)(stream) {
            return Err(lossy(spec.path, Key::LinkLossyTransportUnselected));
        }
    }
    Ok(())
}

fn validate_ss_stream_exportable(stream: &StreamModel) -> Result<(), LinkError> {
    let has_stream_state = stream.network != Network::Raw
        || TRANSPORTS.iter().any(|spec| (spec.is_present)(stream))
        || stream.security != Security::None
        || option_has_fields(&stream.tls_settings)
        || option_has_fields(&stream.reality_settings)
        || stream
            .sockopt
            .as_ref()
            .is_some_and(|sockopt| !sockopt.is_empty())
        || stream
            .finalmask
            .as_ref()
            .is_some_and(|finalmask| !finalmask.is_empty())
        || !stream.extra.is_empty();
    if has_stream_state {
        return Err(lossy("streamSettings", Key::LinkLossySsStream));
    }
    Ok(())
}

fn validate_exportable(profile: &ServerProfile) -> Result<(), LinkError> {
    if !profile.extra.is_empty() {
        return Err(lossy("profile.extra", Key::LinkLossyProfileExtra));
    }
    if profile.chain_target().is_some() {
        return Err(lossy(
            "streamSettings.sockopt.dialerProxy",
            Key::LinkLossyDialerProxy,
        ));
    }
    if profile.outbound.send_through.is_some() {
        return Err(lossy("sendThrough", Key::LinkLossySendThrough));
    }
    if profile.outbound.target_strategy.is_some() {
        return Err(lossy("targetStrategy", Key::LinkLossyTargetStrategy));
    }
    if !profile.outbound.mux.is_empty() {
        return Err(lossy("mux", Key::LinkLossyMux));
    }
    if !profile.outbound.extra.is_empty() {
        return Err(lossy("outbound.extra", Key::LinkLossyOutboundExtra));
    }
    validate_protocol_exportable(&profile.outbound.settings)?;
    if matches!(&profile.outbound.settings, ProtocolSettings::Shadowsocks(_)) {
        validate_ss_stream_exportable(&profile.outbound.stream)
    } else {
        validate_url_stream_exportable(&profile.outbound.stream)
    }
}

// ---------- public API ----------

/// Parse one share link into a fresh profile (random uuid id; name from the
/// `#fragment`, else the server host) plus the compatibility parameters the
/// grammar recognized but dropped.
pub fn parse_link(s: &str) -> Result<ParsedLink, LinkError> {
    let s = s.trim();
    if s.len() > MAX_LINK_LEN {
        return Err(malformed(
            Diag::new(Key::LinkTooLong).arg(s.len()).arg(MAX_LINK_LEN),
        ));
    }
    let scheme_end = s
        .find("://")
        .ok_or_else(|| malformed(Diag::new(Key::LinkNoScheme).arg(excerpt_debug(s))))?;
    let scheme = &s[..scheme_end];
    let valid_scheme = !scheme.is_empty()
        && scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if !valid_scheme {
        return Err(malformed(
            Diag::new(Key::LinkBadScheme).arg(excerpt_debug(s)),
        ));
    }
    let body = &s[scheme_end + 3..];
    let lowered = scheme.to_ascii_lowercase();
    let row = SHAREABLE
        .iter()
        .chain(IMPORT_ONLY)
        .find(|row| row.scheme == lowered.as_str());
    let mut ignored = Vec::new();
    let profile = match row {
        Some(row) => (row.parse)(body, &mut ignored)?,
        None => {
            return Err(LinkError::Unsupported(
                Diag::new(Key::LinkUnsupportedScheme).arg(excerpt(&lowered)),
            ));
        }
    };
    validate_profile(&profile)?;
    Ok(ParsedLink { profile, ignored })
}

/// Parse a paste/subscription blob: one link per line; blank lines and
/// `#comment` lines are skipped. The whole blob is bounded by
/// [`MAX_BULK_LEN`]; an oversized blob yields one `Malformed` error entry.
pub fn parse_bulk(text: &str) -> Vec<Result<ParsedLink, LinkError>> {
    if text.len() > MAX_BULK_LEN {
        return vec![Err(malformed(
            Diag::new(Key::LinkSubscriptionTooLarge)
                .arg(text.len())
                .arg(MAX_BULK_LEN),
        ))];
    }
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(parse_link)
        .collect()
}

/// Cancellable bulk parse for worker threads: `cancel` is polled between
/// lines, so a UI cancel stops parsing promptly on large pastes. Partial
/// results are discarded (`None`) once cancelled. The [`MAX_BULK_LEN`]
/// aggregate and [`MAX_LINK_LEN`] per-line caps are enforced exactly as in
/// [`parse_bulk`].
pub fn parse_bulk_cancellable(
    text: &str,
    cancel: &AtomicBool,
) -> Option<Vec<Result<ParsedLink, LinkError>>> {
    if text.len() > MAX_BULK_LEN {
        return Some(vec![Err(malformed(
            Diag::new(Key::LinkSubscriptionTooLarge)
                .arg(text.len())
                .arg(MAX_BULK_LEN),
        ))]);
    }
    let mut parsed = Vec::new();
    for line in text.lines() {
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        parsed.push(parse_link(line));
    }
    Some(parsed)
}

/// Export a profile to its share link. `Unsupported` for the non-shareable
/// protocols (socks/http/wireguard/freedom/blackhole/dns/loopback/hysteria).
pub fn to_link(profile: &ServerProfile) -> Result<String, LinkError> {
    // The editor intentionally retains inactive transport and security drafts.
    // They are not effective outbound state, so share export mirrors the wire
    // boundary before validating or checking representability.
    let mut canonical = profile.clone();
    canonical
        .outbound
        .stream
        .retain_selected_stream_blocks_for_wire();

    validate_profile(&canonical)?;
    validate_exportable(&canonical)?;
    // The share set decides before any renderer runs; the match below only
    // picks the renderer for a protocol the grammar names.
    let protocol = canonical.outbound.settings.protocol();
    if !shareable(protocol) {
        return Err(unsupported_protocol(protocol));
    }
    let link = match &canonical.outbound.settings {
        ProtocolSettings::Vless(settings) => vless_link(&canonical, settings),
        ProtocolSettings::Vmess(settings) => vmess_link(&canonical, settings),
        ProtocolSettings::Trojan(settings) => trojan_link(&canonical, settings),
        ProtocolSettings::Shadowsocks(settings) => ss_link(&canonical, settings),
        // Refused above by the share set; a total match keeps this refusal
        // site rather than a second message.
        other => Err(unsupported_protocol(other.protocol())),
    }?;

    // Keep this final structural guard even though the field-specific checks
    // above produce better errors. It prevents newly added model fields from
    // becoming silent share-link drops before this adapter is updated.
    let roundtrip = parse_link(&link)?;
    if canonical.name != roundtrip.name {
        return Err(lossy("profile.name", Key::LinkLossyProfileName));
    }
    if canonical.outbound.to_wire("share") != roundtrip.outbound.to_wire("share") {
        return Err(lossy("profile", Key::LinkLossyProfileRoundtrip));
    }
    Ok(link)
}

/// Render `s` as a QR code (EC level M) with the required four-module quiet
/// zone. Returns `None` when the input exceeds QR capacity.
pub fn qr_color_image(s: &str) -> Option<egui::ColorImage> {
    let code =
        qrcode::QrCode::with_error_correction_level(s.as_bytes(), qrcode::EcLevel::M).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    const QUIET: usize = 4;
    let modules = width + QUIET * 2;
    let scale = (256 / modules).max(1);
    let px = modules * scale;
    let mut img = egui::ColorImage::new([px, px], vec![egui::Color32::WHITE; px * px]);
    for y in 0..width {
        for x in 0..width {
            if colors[y * width + x] == qrcode::Color::Dark {
                let ox = (x + QUIET) * scale;
                let oy = (y + QUIET) * scale;
                for dy in 0..scale {
                    for dx in 0..scale {
                        img.pixels[(oy + dy) * px + (ox + dx)] = egui::Color32::BLACK;
                    }
                }
            }
        }
    }
    Some(img)
}

// ---------- tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::inbound::DNS_OUTBOUND_TAG;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn assert_profile_eq(a: &ServerProfile, b: &ServerProfile) {
        assert_eq!(a.name, b.name, "name mismatch");
        assert_eq!(
            serde_json::to_value(&a.outbound).unwrap(),
            serde_json::to_value(&b.outbound).unwrap(),
            "outbound mismatch"
        );
    }

    /// parse → export → reparse must be stable, and the canonical form must
    /// be a fixpoint.
    fn round_trip(s: &str) -> (ServerProfile, String) {
        let p1 = parse_link(s).unwrap_or_else(|e| panic!("parse {}: {e}", redact(s)));
        let s2 = to_link(&p1).unwrap_or_else(|e| panic!("export {}: {e}", redact(s)));
        let p2 = parse_link(&s2).unwrap_or_else(|e| panic!("reparse {}: {e}", redact(&s2)));
        assert_profile_eq(&p1, &p2);
        let s3 = to_link(&p2).unwrap();
        assert_eq!(s2, s3, "canonical form not stable for {}", redact(s));
        (p2.profile, s3)
    }

    fn vmess_json(v: Value) -> String {
        format!(
            "vmess://{}",
            STANDARD.encode(serde_json::to_vec(&v).unwrap())
        )
    }

    /// A valid `wg://` link: the model pass needs a 32-byte key pair and a
    /// peer endpoint.
    fn wireguard_link() -> String {
        let secret = URL_SAFE_NO_PAD.encode([1_u8; 32]);
        let public = URL_SAFE_NO_PAD.encode([2_u8; 32]);
        format!(
            "wg://198.51.100.9:51820?private_key={secret}&public_key={public}&local_address=10.0.0.2%2F32#WG"
        )
    }

    fn reality_public_key() -> String {
        URL_SAFE_NO_PAD.encode([7_u8; 32])
    }

    fn reality_mldsa65_verify() -> String {
        URL_SAFE_NO_PAD.encode([9_u8; 1952])
    }

    // ----- vless -----

    #[test]
    fn vless_reality_full() {
        let link = format!(
            "vless://{UUID}@reality.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=rL5c2g3K9yZ8xN1vQ7wE0tYuIoPaSdFgHjKlZxCvBnM&sid=0123abcd&spx=%2F&type=tcp#Reality%20Edge"
        );
        let (p, canonical) = round_trip(&link);
        assert_eq!(p.name, "Reality Edge");
        let ProtocolSettings::Vless(v) = &p.outbound.settings else {
            panic!("not vless")
        };
        assert_eq!(v.id, UUID);
        assert_eq!(v.port, 443);
        assert_eq!(v.flow, "xtls-rprx-vision");
        assert_eq!(v.encryption, "none");
        let r = p.outbound.stream.reality_settings.as_ref().unwrap();
        assert_eq!(r.server_name, "www.microsoft.com");
        assert_eq!(r.fingerprint, "chrome");
        assert_eq!(r.password, "rL5c2g3K9yZ8xN1vQ7wE0tYuIoPaSdFgHjKlZxCvBnM");
        assert_eq!(r.short_id, "0123abcd");
        assert_eq!(r.spider_x, "/");
        assert!(canonical.contains("spx=%2F"));
        assert!(canonical.contains("security=reality"));
    }

    /// The editor's REALITY fingerprint option list is trimmed; the share
    /// grammar still accepts every other canonical name a link may carry.
    #[test]
    fn reality_import_accepts_fingerprints_outside_the_editor_options() {
        let public_key = reality_public_key();
        for fingerprint in ["ios", "edge", "qq"] {
            let link = format!(
                "vless://{UUID}@reality.example.com:443?security=reality&sni=www.microsoft.com&fp={fingerprint}&pbk={public_key}&type=tcp#Trim"
            );
            let (profile, canonical) = round_trip(&link);
            let reality = profile.outbound.stream.reality_settings.as_ref().unwrap();
            assert_eq!(reality.fingerprint, fingerprint);
            assert!(
                canonical.contains(&format!("fp={fingerprint}")),
                "the exported link must keep {fingerprint:?}: {canonical}"
            );
        }
    }

    #[test]
    fn reality_without_sni_materializes_endpoint_host_and_canonicalizes() {
        let public_key = reality_public_key();
        let link = format!(
            "vless://{UUID}@fallback.example.com:443?security=reality&fp=chrome&pbk={public_key}&type=tcp#Fallback"
        );
        let (profile, canonical) = round_trip(&link);
        let reality = profile.outbound.stream.reality_settings.as_ref().unwrap();
        assert_eq!(reality.server_name, "fallback.example.com");
        assert!(
            canonical.contains("sni=fallback.example.com"),
            "{canonical:?}"
        );
    }

    /// Warning findings never refuse import/export validation —
    /// only Severity::Error findings gate `validate_profile`. The same
    /// profile with a blocking finding still refuses.
    #[test]
    fn warning_findings_do_not_block_import_export_validation() {
        let mut profile = ServerProfile::new("vision+mux", OutboundModel::new(Protocol::Vless));
        {
            let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
                unreachable!()
            };
            settings.address = "example.com".into();
            settings.port = 443;
            settings.id = UUID.into();
            settings.flow = "xtls-rprx-vision".into();
            settings.encryption = "none".into();
        }
        let _ = profile.outbound.stream.select_security(Security::Tls);
        profile.outbound.mux.enabled = true;
        profile.outbound.mux.concurrency = Some(8);
        validate_profile(&profile).expect("vision+mux warnings must not refuse import/export");

        // A real Severity::Error finding on the same profile still refuses.
        profile
            .outbound
            .stream
            .tls_settings
            .as_mut()
            .unwrap()
            .master_key_log = "C:\\keys.log".into();
        assert!(
            matches!(
                validate_profile(&profile),
                Err(LinkError::InvalidModel { issue, .. })
                    if validation_issue_message(&issue, Language::En).contains("masterKeyLog")
            ),
            "Error findings must keep gating validate_profile"
        );
    }

    /// A REALITY serverName that is a UUID imports —
    /// the finding is ServerNameImplausible (Severity::Warning), advisory
    /// only (the xray run -test report is the gate that catches it).
    #[test]
    fn uuid_reality_server_name_imports_with_a_warning() {
        let public_key = reality_public_key();
        let link = format!(
            "vless://{UUID}@reality.example.com:443?encryption=none&security=reality&sni=9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d&fp=chrome&pbk={public_key}&type=tcp#UUID-SNI"
        );
        let profile = parse_link(&link).expect("an implausible serverName may only warn");
        let reality = profile.outbound.stream.reality_settings.as_ref().unwrap();
        assert_eq!(reality.server_name, "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d");
        // The import must surface the advisory finding through the model pass
        // — and through the seam the import logs it with, which must hand the
        // finding over without refusing the profile.
        let advisories =
            profile_advisories(&profile).expect("an advisory finding must not refuse the import");
        assert!(
            advisories.iter().any(|issue| {
                issue.code == crate::model::validation::ValidationCode::ServerNameImplausible
                    && issue.severity == crate::model::validation::Severity::Warning
            }),
            "{advisories:#?}"
        );
    }

    #[test]
    fn vless_reality_pqv_and_alias() {
        let pbk = reality_public_key();
        let pqv = reality_mldsa65_verify();
        let link = format!(
            "vless://{UUID}@pq.example.com:443?security=reality&sni=x.com&fp=chrome&pbk={pbk}&pqv={pqv}&spx=%2F#PQ"
        );
        let (p, canonical) = round_trip(&link);
        let r = p.outbound.stream.reality_settings.as_ref().unwrap();
        assert_eq!(r.mldsa65_verify, pqv);
        assert!(canonical.contains("pqv="));

        // Legacy alias imports but canonical export uses `pqv`.
        let link2 = format!(
            "vless://{UUID}@pq.example.com:443?security=reality&sni=x.com&fp=chrome&pbk={pbk}&mldsa65Verify={pqv}#PQ"
        );
        let p2 = parse_link(&link2).unwrap();
        assert_eq!(
            p2.outbound
                .stream
                .reality_settings
                .as_ref()
                .unwrap()
                .mldsa65_verify,
            pqv
        );
    }

    #[test]
    fn vless_ws_tls() {
        let link = format!(
            "vless://{UUID}@cdn.example.com:443?security=tls&sni=cdn.example.com&fp=firefox&alpn=h2%2Chttp%2F1.1&type=ws&host=cdn.example.com&path=%2Fapi%2Fv1#WS%20CDN"
        );
        let (p, canonical) = round_trip(&link);
        let w = p.outbound.stream.ws_settings.as_ref().unwrap();
        assert_eq!(w.host, "cdn.example.com");
        assert_eq!(w.path, "/api/v1");
        let t = p.outbound.stream.tls_settings.as_ref().unwrap();
        assert_eq!(t.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(t.fingerprint, "firefox");
        assert!(canonical.contains("alpn=h2%2Chttp%2F1.1"));
    }

    #[test]
    fn vless_xhttp_mode_extra() {
        let extra = pct_encode(r#"{"xPaddingBytes":"100-1000","noGRPCHeader":true}"#);
        let link = format!(
            "vless://{UUID}@x.example.com:8443?security=tls&sni=x.example.com&type=xhttp&path=%2Fxhttp&mode=stream-one&extra={extra}#XHTTP"
        );
        let (p, canonical) = round_trip(&link);
        let x = p.outbound.stream.xhttp_settings.as_ref().unwrap();
        assert_eq!(x.path, "/xhttp");
        assert_eq!(x.mode, "stream-one");
        assert_eq!(x.no_grpc_header, Some(true));
        assert!(x.x_padding_bytes.is_some());
        assert!(canonical.contains("extra="));
    }

    #[test]
    fn xhttp_extra_download_master_key_log_is_rejected() {
        // Crafted link: the xhttp `extra` sets a nested download stream whose
        // TLS settings carry masterKeyLog — an attacker-chosen file write.
        let tls_extra = pct_encode(
            r#"{"downloadSettings":{"security":"tls","tlsSettings":{"masterKeyLog":"C:\\xray-keys.log"}}}"#,
        );
        let link = format!(
            "vless://{UUID}@x.example.com:443?security=tls&sni=x.example.com&type=xhttp&extra={tls_extra}#X"
        );
        match parse_link(&link) {
            Err(LinkError::InvalidModel { issue, .. }) => {
                let message = validation_issue_message(&issue, Language::En);
                assert!(
                    message.contains("masterKeyLog"),
                    "message must name masterKeyLog: {message:?}"
                );
            }
            other => panic!(
                "expected Malformed for nested TLS masterKeyLog, got {}",
                outcome_shape(&other)
            ),
        }

        // Reality variant of the same attack.
        let reality_extra = pct_encode(
            r#"{"downloadSettings":{"security":"reality","realitySettings":{"masterKeyLog":"C:\\xray-keys.log"}}}"#,
        );
        let link = format!(
            "vless://{UUID}@x.example.com:443?security=tls&sni=x.example.com&type=xhttp&extra={reality_extra}#X"
        );
        match parse_link(&link) {
            Err(LinkError::InvalidModel { issue, .. }) => {
                let message = validation_issue_message(&issue, Language::En);
                assert!(
                    message.contains("masterKeyLog"),
                    "message must name masterKeyLog: {message:?}"
                );
            }
            other => panic!(
                "expected Malformed for nested REALITY masterKeyLog, got {}",
                outcome_shape(&other)
            ),
        }
    }

    #[test]
    fn xhttp_extra_download_without_master_key_log_imports_unchanged() {
        // A nested download stream with TLS settings but no masterKeyLog must
        // still import — valid links are unaffected by the new rule.
        let extra = pct_encode(
            r#"{"downloadSettings":{"security":"tls","tlsSettings":{"serverName":"cdn.example.com","fingerprint":"chrome"}}}"#,
        );
        let link = format!(
            "vless://{UUID}@x.example.com:443?security=tls&sni=x.example.com&type=xhttp&path=%2F&extra={extra}#XHTTP-DL"
        );
        let profile = parse_link(&link).unwrap_or_else(|e| panic!("parse: {e}"));
        let x = profile
            .outbound
            .stream
            .xhttp_settings
            .as_ref()
            .expect("xhttp settings present");
        let download = x
            .download_settings
            .as_deref()
            .expect("download settings present");
        assert_eq!(download.security, Security::Tls);
        let tls = download
            .tls_settings
            .as_ref()
            .expect("tls settings present");
        assert_eq!(tls.server_name, "cdn.example.com");
        assert_eq!(tls.fingerprint, "chrome");
        assert!(tls.master_key_log.is_empty());
    }
    #[test]
    fn xhttp_extra_download_allow_insecure_is_rejected() {
        // Crafted link: the xhttp `extra` carries a removed TLS field inside
        // the nested download stream. `allowInsecure` has no modeled field,
        // so it lands in TlsModel's flattened `extra` map and must fail
        // validation naming the removed key.
        let tls_extra = pct_encode(
            r#"{"downloadSettings":{"security":"tls","tlsSettings":{"allowInsecure":true}}}"#,
        );
        let link = format!(
            "vless://{UUID}@x.example.com:443?security=tls&sni=x.example.com&type=xhttp&extra={tls_extra}#X"
        );
        match parse_link(&link) {
            Err(LinkError::InvalidModel { issue, .. }) => {
                let message = validation_issue_message(&issue, Language::En);
                assert!(
                    message.contains("allowInsecure"),
                    "message must name allowInsecure: {message:?}"
                );
            }
            other => panic!(
                "expected Malformed for nested TLS allowInsecure, got {}",
                outcome_shape(&other)
            ),
        }

        // `allowInsecure: false` is the Go zero value — Xray runs it fine, so
        // the link stays valid and the flag is preserved in the flattened map.
        let false_extra = pct_encode(
            r#"{"downloadSettings":{"security":"tls","tlsSettings":{"allowInsecure":false}}}"#,
        );
        let link = format!(
            "vless://{UUID}@x.example.com:443?security=tls&sni=x.example.com&type=xhttp&extra={false_extra}#X"
        );
        let profile =
            parse_link(&link).unwrap_or_else(|e| panic!("parse false allowInsecure: {e}"));
        let x = profile
            .outbound
            .stream
            .xhttp_settings
            .as_ref()
            .expect("xhttp settings present");
        let download = x
            .download_settings
            .as_deref()
            .expect("download settings present");
        let tls = download
            .tls_settings
            .as_ref()
            .expect("tls settings present");
        assert_eq!(tls.extra.get("allowInsecure"), Some(&Value::Bool(false)));
    }

    #[test]
    fn xhttp_extra_parse_error_never_echoes_the_full_value() {
        // A hostile `extra` value that fails XhttpSettings deserialization
        // must not inflate the error with the whole payload.
        let huge = "x".repeat(200_000);
        let extra = format!(r#"{{"downloadSettings":"{huge}"}}"#);
        let link = format!(
            "vless://{UUID}@h.example.com:443?type=xhttp&extra={}#Huge",
            pct_encode(&extra)
        );
        match parse_link(&link) {
            Err(LinkError::Malformed(message)) => {
                let message = message.text(Language::En);
                assert!(
                    message.len() < 100,
                    "xhttp extra error must stay bounded, got {} chars: {message:?}",
                    message.len()
                );
                assert!(
                    !message.contains(&huge),
                    "must not embed the payload: {message:?}"
                );
                assert!(
                    message.contains("XHTTP extra value is not valid JSON"),
                    "{message:?}"
                );
            }
            other => panic!(
                "expected malformed xhttp extra, got {}",
                outcome_shape(&other)
            ),
        }
    }

    #[test]
    fn vmess_bad_json_error_never_inflates_with_payload() {
        // A hostile legacy-vmess body that fails JSON parsing must not
        // inflate the error text with the payload.
        let huge = "x".repeat(200_000);
        let body = format!(r#"{{"v":"2","port":"{huge}""#); // truncated JSON
        let link = format!("vmess://{}", STANDARD.encode(body.as_bytes()));
        match parse_link(&link) {
            Err(LinkError::Malformed(message)) => {
                let message = message.text(Language::En);
                assert!(
                    message.len() < 100,
                    "vmess JSON error must stay bounded, got {} chars: {message:?}",
                    message.len()
                );
                assert!(
                    !message.contains(&huge),
                    "must not embed the payload: {message:?}"
                );
                assert!(
                    message.contains("vmess link does not carry valid JSON"),
                    "{message:?}"
                );
            }
            other => panic!(
                "expected malformed vmess JSON, got {}",
                outcome_shape(&other)
            ),
        }
    }

    #[test]
    fn legacy_vmess_ps_name_is_sanitized_like_a_fragment() {
        // `ps` is attacker-controlled JSON: control characters must not
        // reach the persisted profile name (LINK-002), and an over-long name
        // must be rejected — exactly like the `#fragment` path.
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "evil\nname\u{0}x", "add": "a.example.com", "port": "443",
            "id": UUID, "net": "tcp", "tls": ""
        }));
        let (profile, _) = round_trip(&link);
        assert_eq!(
            profile.name, "evilnamex",
            "control characters must be stripped"
        );

        let overlong = "p".repeat(MAX_PROFILE_NAME_LEN + 1);
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": overlong, "add": "a.example.com", "port": "443",
            "id": UUID, "net": "tcp", "tls": ""
        }));
        match parse_link(&link) {
            Err(LinkError::Malformed(message)) => {
                let message = message.text(Language::En);
                assert!(message.contains("exceeds"), "{message:?}");
                assert!(
                    !message.contains("pppppp"),
                    "must not echo the name into the error: {message:?}"
                );
            }
            other => panic!(
                "expected over-long ps rejection, got {}",
                outcome_shape(&other)
            ),
        }
    }

    #[test]
    fn vless_grpc_multi() {
        let link = format!(
            "vless://{UUID}@g.example.com:443?security=tls&type=grpc&serviceName=GunService&mode=multi&authority=g.example.com#GRPC"
        );
        let (p, _) = round_trip(&link);
        let g = p.outbound.stream.grpc_settings.as_ref().unwrap();
        assert_eq!(g.service_name, "GunService");
        assert_eq!(g.authority, "g.example.com");
        assert_eq!(g.multi_mode, Some(true));
    }

    #[test]
    fn official_fields_that_explicitly_allow_empty_values_canonicalize_to_omission() {
        let link = format!(
            "vless://{UUID}@g.example.com:443?flow=&security=tls&ech=&pcs=&vcn=&type=grpc&serviceName=svc&authority=#Empty"
        );
        let (_, canonical) = round_trip(&link);
        for omitted in ["flow=", "ech=", "pcs=", "vcn=", "authority="] {
            assert!(!canonical.contains(omitted), "{canonical:?}");
        }
    }

    #[test]
    fn vless_kcp_mtu_and_tti_round_trip() {
        let link = format!("vless://{UUID}@kcp.local:29666?type=kcp&mtu=1400&tti=30#KCP");
        let (profile, canonical) = round_trip(&link);
        let kcp = profile.outbound.stream.kcp_settings.as_ref().unwrap();
        assert_eq!(kcp.mtu, Some(1400));
        assert_eq!(kcp.tti, Some(30));
        assert!(canonical.contains("type=kcp"));
        assert!(canonical.contains("mtu=1400"));
        assert!(canonical.contains("tti=30"));
    }

    #[test]
    fn finalmask_links_reject_unknown_and_invalid_known_masks() {
        let unknown = pct_encode(r#"{"udp":[{"type":"future-udp","settings":{"opaque":true}}]}"#);
        match parse_link(&format!(
            "vless://{UUID}@router.local:443?encryption=none&fm={unknown}#Unknown"
        )) {
            Err(LinkError::InvalidModel { issue, .. }) => {
                let message = validation_issue_message(&issue, Language::En);
                assert!(message.contains("finalmask.udp[0]"), "{message:?}");
                assert!(message.contains("future-udp"), "{message:?}");
            }
            other => panic!(
                "expected unknown finalmask rejection, got {}",
                outcome_shape(&other)
            ),
        }

        let invalid =
            pct_encode(r#"{"tcp":[{"type":"fragment","settings":{"packets":"0","length":0}}]}"#);
        match parse_link(&format!(
            "vless://{UUID}@router.local:443?encryption=none&fm={invalid}#Invalid"
        )) {
            Err(LinkError::InvalidModel { issue, .. }) => {
                let message = validation_issue_message(&issue, Language::En);
                assert!(message.contains("finalmask.tcp[0]"), "{message:?}");
                assert!(message.contains("packet number cannot be 0"), "{message:?}");
            }
            other => panic!(
                "expected invalid finalmask rejection, got {}",
                outcome_shape(&other)
            ),
        }
    }

    #[test]
    fn vless_plain_tcp_private_endpoint() {
        let link = format!("vless://{UUID}@router.local:80?encryption=none#Plain");
        let (p, canonical) = round_trip(&link);
        assert_eq!(p.outbound.stream.security, Security::None);
        assert_eq!(p.outbound.stream.network, Network::Raw);
        assert_eq!(
            canonical,
            format!("vless://{UUID}@router.local:80?encryption=none#Plain")
        );
    }

    #[test]
    fn public_plaintext_vless_and_trojan_endpoints_are_rejected() {
        for (link, expected) in [
            (
                format!("vless://{UUID}@plain.example.com:80?encryption=none#Plain"),
                "public VLESS endpoints require TLS/REALITY or non-none VLESS encryption",
            ),
            (
                "trojan://password@trojan.example.com:443?security=none#Plain".to_string(),
                "public Trojan endpoints require TLS or REALITY",
            ),
        ] {
            match parse_link(&link) {
                Err(LinkError::InvalidModel { issue, .. }) => {
                    let message = validation_issue_message(&issue, Language::En);
                    assert_eq!(message, expected, "{}", redact(&link));
                }
                other => panic!(
                    "expected public plaintext rejection for {}, got {}",
                    redact(&link),
                    outcome_shape(&other)
                ),
            }
        }
    }

    #[test]
    fn vless_mlkem_encryption_round_trips_valid_core_key_material() {
        let key = URL_SAFE_NO_PAD.encode([5_u8; 32]);
        // A bare key and a key behind the core's minimal valid padding
        // prefix (100-35-35) both round-trip verbatim.
        for encryption in [
            format!("mlkem768x25519plus.native.1rtt.{key}"),
            format!("mlkem768x25519plus.native.1rtt.100-35-35.{key}"),
        ] {
            let link = format!("vless://{UUID}@pq.example.com:443?encryption={encryption}#PQ");
            let (profile, canonical) = round_trip(&link);
            let ProtocolSettings::Vless(settings) = &profile.outbound.settings else {
                panic!("not vless")
            };
            assert_eq!(settings.encryption, encryption);
            assert!(canonical.contains(&format!("encryption={encryption}")));
        }
    }

    #[test]
    fn raw_http_camouflage_query_maps_into_raw_settings() {
        // A client emits raw HTTP camouflage as `type=tcp&headerType=http` plus
        // host/path; the model carries the same block the legacy VMess JSON
        // path builds.
        let link = format!(
            "vless://{UUID}@camo.local:8080?encryption=none&type=tcp&headerType=http&host=cdn.example.com&path=%2Fcamo"
        );
        let parsed = parse_link(&link).unwrap();
        assert!(parsed.ignored.is_empty());
        let header = parsed
            .outbound
            .stream
            .raw_settings
            .as_ref()
            .and_then(|settings| settings.header.as_ref())
            .expect("the camouflage maps into rawSettings");
        assert_eq!(header.r#type, "http");
        let request = header.request.as_ref().expect("http carries a request");
        assert_eq!(request.path, vec!["/camo".to_string()]);
        assert_eq!(
            request.headers["Host"],
            Value::String("cdn.example.com".into())
        );
    }

    #[test]
    fn raw_header_type_none_is_a_silent_no_op() {
        // Every `type=tcp` link a client emits carries `headerType=none`; it
        // is the absence of camouflage, so it neither sets anything nor joins
        // the dropped-parameter report.
        let parsed = parse_link(&format!(
            "vless://{UUID}@plain.local:443?encryption=none&type=tcp&headerType=none"
        ))
        .unwrap();
        assert!(parsed.ignored.is_empty());
        assert!(parsed.outbound.stream.raw_settings.is_none());
    }

    #[test]
    fn vless_finalmask_fm() {
        let fm = pct_encode(r#"{"udp":[{"type":"salamander","password":"pw"}]}"#);
        let link = format!("vless://{UUID}@fm.local:443?fm={fm}#FM");
        let (p, canonical) = round_trip(&link);
        let f = p.outbound.stream.finalmask.as_ref().unwrap();
        assert_eq!(f.udp.len(), 1);
        assert!(canonical.contains("fm="));
    }

    // ----- vmess -----

    #[test]
    fn vmess_ws_tls_full() {
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "VM WS", "add": "cdn.example.com", "port": "443",
            "id": UUID, "aid": "0", "scy": "auto", "net": "ws", "type": "",
            "host": "cdn.example.com", "path": "/ws", "tls": "tls",
            "sni": "cdn.example.com", "alpn": "h2,http/1.1", "fp": "chrome"
        }));
        let (p, canonical) = round_trip(&link);
        assert_eq!(p.name, "VM WS");
        let ProtocolSettings::Vmess(v) = &p.outbound.settings else {
            panic!("not vmess")
        };
        assert_eq!(v.security, "auto");
        assert_eq!(v.port, 443);
        let w = p.outbound.stream.ws_settings.as_ref().unwrap();
        assert_eq!(
            (w.host.as_str(), w.path.as_str()),
            ("cdn.example.com", "/ws")
        );
        let t = p.outbound.stream.tls_settings.as_ref().unwrap();
        assert_eq!(t.alpn.len(), 2);
        assert_eq!(t.fingerprint, "chrome");
        assert!(canonical.starts_with(&format!("vmess://{UUID}@cdn.example.com:443?")));
        assert!(canonical.contains("type=ws"));
        assert!(!canonical.contains("eyJ"));
    }

    #[test]
    fn vmess_tcp_plain_numeric_port() {
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "TCP", "add": "tcp.example.com", "port": 3389,
            "id": UUID, "aid": 0, "net": "tcp", "tls": ""
        }));
        let (p, _) = round_trip(&link);
        let ProtocolSettings::Vmess(v) = &p.outbound.settings else {
            panic!("not vmess")
        };
        assert_eq!(v.port, 3389);
        assert_eq!(v.security, "auto");
        assert_eq!(p.outbound.stream.security, Security::None);
        assert_eq!(p.outbound.stream.network, Network::Raw);
    }

    /// The legacy Base64-JSON form's `net` carries the same transport
    /// vocabulary as the URL grammar's `type` (infra/conf/transport_internet.go:16),
    /// so upstream's canonical `raw` imports the RAW transport instead of
    /// failing as an unknown net.
    #[test]
    fn vmess_legacy_net_raw_imports_the_raw_transport() {
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "RAW", "add": "raw.example.com", "port": "443",
            "id": UUID, "aid": "0", "net": "raw", "tls": ""
        }));
        let (profile, _) = round_trip(&link);
        assert_eq!(profile.outbound.stream.network, Network::Raw);
    }

    #[test]
    fn vmess_official_none_encryption_normalizes_to_auto_and_omits_it() {
        // #716 permits `none`, but current Xray maps that JSON string through
        // VMessAccount.Build's default branch to SecurityType_AUTO.
        let link = format!("vmess://{UUID}@none.example.com:443?encryption=none#Alias");
        let (profile, canonical) = round_trip(&link);
        let ProtocolSettings::Vmess(settings) = &profile.outbound.settings else {
            panic!("not vmess")
        };
        assert_eq!(settings.security, "auto");
        assert_eq!(
            canonical,
            format!("vmess://{UUID}@none.example.com:443#Alias")
        );
    }

    #[test]
    fn legacy_vmess_none_cipher_normalizes_to_url_auto() {
        let legacy = vmess_json(serde_json::json!({
            "v": "2", "ps": "Legacy alias", "add": "legacy.example.com", "port": "443",
            "id": UUID, "aid": "0", "scy": "none", "net": "tcp", "tls": ""
        }));
        let (profile, canonical) = round_trip(&legacy);
        let ProtocolSettings::Vmess(settings) = &profile.outbound.settings else {
            panic!("not vmess")
        };
        assert_eq!(settings.security, "auto");
        assert_eq!(
            canonical,
            format!("vmess://{UUID}@legacy.example.com:443#Legacy%20alias")
        );
    }

    #[test]
    fn vmess_tcp_http_camo_multi() {
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "CAMO", "add": "c.example.com", "port": "80",
            "id": UUID, "net": "tcp", "type": "http",
            "host": "a.com,b.com", "path": "/p1,/p2", "tls": ""
        }));
        let p = parse_link(&link).unwrap();
        let req = p
            .outbound
            .stream
            .raw_settings
            .as_ref()
            .unwrap()
            .header
            .as_ref()
            .unwrap()
            .request
            .as_ref()
            .unwrap();
        assert_eq!(req.path, vec!["/p1".to_string(), "/p2".to_string()]);
        assert_eq!(
            req.headers.get("Host").unwrap(),
            &Value::Array(vec!["a.com".into(), "b.com".into()])
        );
        assert!(matches!(to_link(&p), Err(LinkError::Lossy(_))));
    }

    #[test]
    fn vmess_grpc_multi() {
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "G", "add": "g.example.com", "port": "443",
            "id": UUID, "net": "grpc", "type": "multi",
            "host": "auth.example.com", "path": "svc", "tls": "tls", "sni": "g.example.com"
        }));
        let (p, _) = round_trip(&link);
        let g = p.outbound.stream.grpc_settings.as_ref().unwrap();
        assert_eq!(g.service_name, "svc");
        assert_eq!(g.authority, "auth.example.com");
        assert_eq!(g.multi_mode, Some(true));
    }

    #[test]
    fn vmess_legacy_kcp_seed_and_header_are_rejected() {
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "K", "add": "k.example.com", "port": "1234",
            "id": UUID, "net": "kcp", "type": "wechat-video", "path": "seedvalue", "tls": ""
        }));
        expect_unsupported(&link);
    }

    #[test]
    fn vmess_splithttp_alias_imports_and_exports_official_url() {
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "X", "add": "x.example.com", "port": "443",
            "id": UUID, "net": "splithttp", "type": "stream-up", "host": "x.example.com", "path": "/x", "tls": "tls"
        }));
        let (p, canonical) = round_trip(&link);
        assert_eq!(p.outbound.stream.network, Network::Xhttp);
        assert!(canonical.starts_with(&format!("vmess://{UUID}@x.example.com:443?")));
        assert!(canonical.contains("type=xhttp"));
        assert!(canonical.contains("mode=stream-up"));
        assert!(!canonical.contains("splithttp"));
    }

    #[test]
    fn vmess_alter_id_unsupported() {
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "old", "add": "a.com", "port": "443",
            "id": UUID, "aid": "5", "net": "tcp", "tls": ""
        }));
        match parse_link(&link) {
            Err(LinkError::Unsupported(m)) => assert!(m.text(Language::En).contains("alterId")),
            other => panic!("expected Unsupported, got {}", outcome_shape(&other)),
        }
    }

    #[test]
    fn vmess_legacy_unknown_field_is_rejected() {
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "unknown", "add": "a.com", "port": "443",
            "id": UUID, "net": "tcp", "tls": "", "packetEncoding": "xudp"
        }));
        match parse_link(&link) {
            Err(LinkError::Unsupported(message)) => {
                let message = message.text(Language::En);
                assert!(message.contains("packetEncoding"));
            }
            other => panic!("expected Unsupported, got {}", outcome_shape(&other)),
        }
    }

    #[test]
    fn vmess_legacy_wrong_field_type_is_rejected_instead_of_defaulted() {
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "bad", "add": "a.com", "port": "443",
            "id": UUID, "net": {"silently": "tcp"}, "tls": ""
        }));
        expect_malformed(&link);
    }

    #[test]
    fn vmess_official_url_form_round_trips_transport_and_security() {
        let link = format!(
            "vmess://{UUID}@vm.example.com:443?encryption=chacha20-poly1305&security=tls&sni=cdn.example.com&fp=chrome&alpn=h2%2Chttp%2F1.1&type=xhttp&host=cdn.example.com&path=%2Fvm&mode=stream-up#Official"
        );
        let (profile, canonical) = round_trip(&link);
        let ProtocolSettings::Vmess(settings) = &profile.outbound.settings else {
            panic!("not vmess")
        };
        assert_eq!(settings.security, "chacha20-poly1305");
        assert_eq!(profile.outbound.stream.network, Network::Xhttp);
        assert_eq!(profile.outbound.stream.security, Security::Tls);
        assert_eq!(
            profile
                .outbound
                .stream
                .tls_settings
                .as_ref()
                .unwrap()
                .server_name,
            "cdn.example.com"
        );
        assert!(canonical.starts_with(&format!("vmess://{UUID}@vm.example.com:443?")));
        assert!(canonical.contains("encryption=chacha20-poly1305"));
        assert!(canonical.contains("type=xhttp"));
    }

    /// The RAW transport's spec spelling is `tcp`; upstream's config parser
    /// accepts `raw` too (infra/conf/transport_internet.go:16), and provider
    /// links carry it. Import names the same row for both, and canonical
    /// output carries no `type` token at all.
    #[test]
    fn raw_transport_alias_imports_and_exports_without_a_type_token() {
        let public_key = reality_public_key();
        let link = format!(
            "vless://{UUID}@jp.example.com:42299?encryption=none&flow=xtls-rprx-vision&type=raw&security=reality&sni=swdist.apple.com&fp=ios&pbk={public_key}&sid=48495f#JP06"
        );
        let (profile, canonical) = round_trip(&link);
        assert_eq!(profile.outbound.stream.network, Network::Raw);
        assert_eq!(profile.outbound.stream.security, Security::Reality);
        assert!(!canonical.contains("type="), "{canonical}");
    }

    /// Every upstream alias imports its transport, and canonical output
    /// writes the spec spelling — `kcp`, `ws`, `xhttp` — never the alias.
    #[test]
    fn url_transport_aliases_canonicalize_to_the_spec_spelling() {
        for (token, network, canonical_token) in [
            ("mkcp", Network::Kcp, "kcp"),
            ("websocket", Network::Ws, "ws"),
            ("splithttp", Network::Xhttp, "xhttp"),
        ] {
            let link = format!("vmess://{UUID}@{token}.example.com:443?type={token}");
            let (profile, canonical) = round_trip(&link);
            assert_eq!(profile.outbound.stream.network, network, "{token}");
            // The exact `type` value, not a substring: `type=websocket`
            // also contains `type=ws`.
            let query = canonical
                .split_once('?')
                .expect("the exported link carries a query")
                .1
                .split('#')
                .next()
                .expect("str::split always yields one piece");
            assert_eq!(
                parse_query(query).unwrap().get("type"),
                Some(canonical_token),
                "{token} must export {canonical_token:?}: {canonical}"
            );
        }
    }

    /// Every `type` token the grammar accepts must name the row's network
    /// through the model's own alias set ([`Network::parse`], the config
    /// loader's vocabulary): a token the loader does not know, or one mapped
    /// to a different transport, fails here instead of drifting silently.
    #[test]
    fn transport_type_tokens_agree_with_the_model_alias_set() {
        for spec in TRANSPORTS {
            let tokens = spec
                .type_string
                .iter()
                .copied()
                .chain(spec.type_aliases.iter().copied());
            for token in tokens {
                assert_eq!(
                    Network::parse(token),
                    Some(spec.network),
                    "the grammar accepts {token:?} for {}",
                    spec.path
                );
            }
        }
    }

    #[test]
    fn vmess_official_url_transports_round_trip() {
        let cases = [
            (
                format!("vmess://{UUID}@raw.example.com:80?type=tcp#RAW"),
                Network::Raw,
            ),
            (
                format!(
                    "vmess://{UUID}@ws.example.com:443?type=ws&host=cdn.example.com&path=%2Fsocket#WS"
                ),
                Network::Ws,
            ),
            (
                format!(
                    "vmess://{UUID}@grpc.example.com:443?type=grpc&serviceName=Broccoli%20Service&authority=grpc.example.com&mode=multi#GRPC"
                ),
                Network::Grpc,
            ),
            (
                format!(
                    "vmess://{UUID}@up.example.com:443?type=httpupgrade&host=up.example.com&path=%2Fupgrade#HTTPUpgrade"
                ),
                Network::Httpupgrade,
            ),
        ];
        for (link, network) in cases {
            let (profile, canonical) = round_trip(&link);
            assert_eq!(profile.outbound.stream.network, network, "{link}");
            assert!(
                canonical.starts_with(&format!("vmess://{UUID}@")),
                "{canonical}"
            );
        }
    }

    #[test]
    fn official_url_transport_paths_use_the_specified_slash_default() {
        for (transport, network) in [
            ("ws", Network::Ws),
            ("httpupgrade", Network::Httpupgrade),
            ("xhttp", Network::Xhttp),
        ] {
            let link = format!("vmess://{UUID}@default.example.com:443?type={transport}");
            let (profile, canonical) = round_trip(&link);
            assert_eq!(profile.outbound.stream.network, network);
            let path = match network {
                Network::Ws => &profile.outbound.stream.ws_settings.as_ref().unwrap().path,
                Network::Httpupgrade => {
                    &profile
                        .outbound
                        .stream
                        .httpupgrade_settings
                        .as_ref()
                        .unwrap()
                        .path
                }
                Network::Xhttp => {
                    &profile
                        .outbound
                        .stream
                        .xhttp_settings
                        .as_ref()
                        .unwrap()
                        .path
                }
                _ => unreachable!(),
            };
            assert_eq!(path, "/");
            assert!(canonical.contains("path=%2F"), "{canonical:?}");
        }
    }

    #[test]
    fn vmess_official_reality_and_percent_encoded_label_round_trip() {
        let public_key = reality_public_key();
        let link = format!(
            "vmess://{UUID}@reality.example.com:443?security=reality&sni=target.example.com&fp=chrome&pbk={public_key}&sid=0123abcd&spx=%2Fsearch%3Fq%3Dbroccoli&type=tcp#Tokyo%20%2B%20%E6%9D%B1%E4%BA%AC"
        );
        let (profile, canonical) = round_trip(&link);
        assert_eq!(profile.name, "Tokyo + 東京");
        assert_eq!(profile.outbound.stream.security, Security::Reality);
        assert_eq!(profile.outbound.stream.network, Network::Raw);
        let reality = profile.outbound.stream.reality_settings.as_ref().unwrap();
        assert_eq!(reality.password, public_key);
        assert_eq!(reality.spider_x, "/search?q=broccoli");
        assert!(canonical.ends_with("#Tokyo%20%2B%20%E6%9D%B1%E4%BA%AC"));
    }

    // ----- trojan -----

    #[test]
    fn trojan_default_tls_name_with_spaces() {
        let (p, canonical) = round_trip("trojan://p4ssw0rd@trojan.example.com:443#Trojan%20One");
        assert_eq!(p.name, "Trojan One");
        let ProtocolSettings::Trojan(t) = &p.outbound.settings else {
            panic!("not trojan")
        };
        assert_eq!(t.password, "p4ssw0rd");
        assert_eq!(p.outbound.stream.security, Security::Tls);
        assert!(p.outbound.stream.tls_settings.is_some());
        assert!(canonical.contains("security=tls"));
        assert!(canonical.ends_with("#Trojan%20One"));
    }

    #[test]
    fn trojan_encoded_password_security_none_private_endpoint() {
        let (p, _) = round_trip(
            "trojan://p%40ss%3Aword@router.local:8443?security=none&type=ws&host=h.com&path=%2F#pw",
        );
        let ProtocolSettings::Trojan(t) = &p.outbound.settings else {
            panic!("not trojan")
        };
        assert_eq!(t.password, "p@ss:word");
        assert_eq!(p.outbound.stream.security, Security::None);
        let w = p.outbound.stream.ws_settings.as_ref().unwrap();
        assert_eq!(w.path, "/");
        // explicit security=none survives (trojan default is tls)
        let s2 = to_link(&p).unwrap();
        assert!(s2.contains("security=none"));
        assert!(s2.contains("p%40ss%3Aword"));
    }

    #[test]
    fn trojan_reality() {
        let public_key = reality_public_key();
        let (p, _) = round_trip(&format!(
            "trojan://pw@tr.example.com:443?security=reality&sni=yahoo.com&fp=chrome&pbk={public_key}&sid=abcd&spx=%2F#TR"
        ));
        let r = p.outbound.stream.reality_settings.as_ref().unwrap();
        assert_eq!(r.password, public_key);
        assert_eq!(r.short_id, "abcd");
        assert_eq!(r.spider_x, "/");
    }

    #[test]
    fn insecure_switches_are_ignored_with_a_report() {
        // `allowInsecure` / `insecure` have no Xray field (the certificate pin
        // replaces them). Import keeps verification on, keeps the model
        // default, and reports the drop.
        let parsed = parse_link("trojan://pw@ai.example.com:443?allowInsecure=1&sni=x.com#AI")
            .expect("an insecure request must not refuse the link");
        assert_eq!(parsed.ignored, vec!["allowInsecure".to_string()]);
        let tls = parsed.outbound.stream.tls_settings.as_ref().unwrap();
        assert_eq!(tls.server_name, "x.com");
        assert!(tls.pinned_peer_cert_sha256.is_empty());

        // A switch spelling its off value is the default already: silent.
        let parsed =
            parse_link("trojan://pw@ai.example.com:443?allowInsecure=0&sni=x.com#AI").unwrap();
        assert!(parsed.ignored.is_empty());
    }

    #[test]
    fn trojan_grpc_gun_normalized() {
        let (p, canonical) =
            round_trip("trojan://pw@tg.example.com:443?type=grpc&serviceName=svc&mode=gun#G");
        let g = p.outbound.stream.grpc_settings.as_ref().unwrap();
        assert_eq!(g.multi_mode, None); // gun == default
        assert!(!canonical.contains("mode="));
    }

    #[test]
    fn trojan_xhttp() {
        let (p, _) = round_trip(
            "trojan://pw@tx.example.com:443?security=tls&type=xhttp&path=%2Fx&mode=packet-up#X",
        );
        let x = p.outbound.stream.xhttp_settings.as_ref().unwrap();
        assert_eq!(x.mode, "packet-up");
        assert_eq!(x.path, "/x");
    }

    // ----- ss -----

    #[test]
    fn ss_base64_userinfo() {
        let ui = URL_SAFE_NO_PAD.encode("aes-128-gcm:pass1234");
        let link = format!("ss://{ui}@ss1.example.com:8388#SS%20One");
        let (p, canonical) = round_trip(&link);
        assert_eq!(p.name, "SS One");
        let ProtocolSettings::Shadowsocks(s) = &p.outbound.settings else {
            panic!("not ss")
        };
        assert_eq!(s.method, "aes-128-gcm");
        assert_eq!(s.password, "pass1234");
        assert_eq!(canonical, link);
    }

    #[test]
    fn ss_legacy_whole_base64() {
        let legacy = URL_SAFE_NO_PAD.encode("aes-256-gcm:p@ssw0rd@ss2.example.com:8388#LegacyTag");
        let link = format!("ss://{legacy}");
        let (p, canonical) = round_trip(&link);
        assert_eq!(p.name, "LegacyTag");
        let ProtocolSettings::Shadowsocks(s) = &p.outbound.settings else {
            panic!("not ss")
        };
        assert_eq!(s.method, "aes-256-gcm");
        assert_eq!(s.password, "p@ssw0rd");
        assert_eq!(s.address, "ss2.example.com");
        // canonical re-export is the SIP002 userinfo form
        assert!(canonical.starts_with("ss://"));
        assert!(canonical.contains("@ss2.example.com:8388#LegacyTag"));
    }

    #[test]
    fn ss_legacy_base64_trailing_slash_round_trips() {
        // Legacy whole-URI payloads use standard base64, whose alphabet
        // includes '/'; a payload can legitimately end with one. The parser
        // must not mistake it for the SIP002 separator slash (LINK-003):
        // any unconditional trailing-'/' strip truncates the payload and
        // silently decodes to different bytes. The payload below encodes to
        // a trailing '/' (asserted), so the link exercises that case.
        let payload = "aes-128-gcm:password@slash.example.com:8388#Tag?";
        let legacy = STANDARD_NO_PAD.encode(payload);
        assert!(
            legacy.ends_with('/'),
            "test payload must encode to a trailing '/'"
        );
        let link = format!("ss://{legacy}");
        let (p, canonical) = round_trip(&link);
        assert_eq!(p.name, "Tag?");
        let ProtocolSettings::Shadowsocks(s) = &p.outbound.settings else {
            panic!("not ss")
        };
        assert_eq!(s.method, "aes-128-gcm");
        assert_eq!(s.password, "password");
        assert_eq!(s.address, "slash.example.com");
        assert_eq!(s.port, 8388);
        // canonical re-export is the SIP002 userinfo form
        assert!(canonical.starts_with("ss://"));
        assert!(canonical.contains("@slash.example.com:8388#Tag%3F"));
    }

    #[test]
    fn ss_plain_userinfo() {
        let (p, _) =
            round_trip("ss://chacha20-ietf-poly1305:pl%40inpass@ss3.example.com:8389#Plain");
        let ProtocolSettings::Shadowsocks(s) = &p.outbound.settings else {
            panic!("not ss")
        };
        assert_eq!(s.method, "chacha20-ietf-poly1305");
        assert_eq!(s.password, "pl@inpass");
    }

    #[test]
    fn ss_plugin_is_rejected() {
        let ui = URL_SAFE_NO_PAD.encode("aes-128-gcm:pw");
        let link = format!(
            "ss://{ui}@ss4.example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#Plugin"
        );
        expect_unsupported(&link);
    }

    #[test]
    fn ss_2022_method() {
        // The core reads a 2022 key with `base64.StdEncoding`, so the padding
        // is part of the accepted form.
        let key = STANDARD.encode([3_u8; 16]);
        let ui = URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-128-gcm:{key}"));
        let link = format!("ss://{ui}@ss5.example.com:8388#SS2022");
        let (p, _) = round_trip(&link);
        let ProtocolSettings::Shadowsocks(s) = &p.outbound.settings else {
            panic!("not ss")
        };
        assert_eq!(s.method, "2022-blake3-aes-128-gcm");
        assert_eq!(s.password, key);
    }

    #[test]
    fn ss_ipv6_host() {
        let ui = URL_SAFE_NO_PAD.encode("aes-128-gcm:pw");
        let link = format!("ss://{ui}@[2001:db8::1]:8388#V6");
        let (p, canonical) = round_trip(&link);
        let ProtocolSettings::Shadowsocks(s) = &p.outbound.settings else {
            panic!("not ss")
        };
        assert_eq!(s.address, "2001:db8::1");
        assert!(canonical.contains("@[2001:db8::1]:8388"));
    }

    #[test]
    fn ss_userinfo_trailing_slash_parses() {
        // SIP002 userinfo@host links may carry a trailing '/' (plugin links
        // are `…@host:port/?plugin=…`); there it is a separator, never part
        // of the authority (LINK-003 regression guard).
        let ui = URL_SAFE_NO_PAD.encode("aes-128-gcm:pass1234");
        let link = format!("ss://{ui}@ss-slash.example.com:8388/");
        let (p, canonical) = round_trip(&link);
        let ProtocolSettings::Shadowsocks(s) = &p.outbound.settings else {
            panic!("not ss")
        };
        assert_eq!(s.address, "ss-slash.example.com");
        assert_eq!(s.port, 8388);
        assert_eq!(p.name, "ss-slash.example.com");
        assert_eq!(
            canonical,
            format!("ss://{ui}@ss-slash.example.com:8388#ss-slash.example.com")
        );
    }

    #[test]
    fn fragment_control_chars_are_filtered_from_name() {
        // %0A/%0D/%00/%1B must never reach the stored profile name — names
        // are drawn verbatim every frame by the dashboard/server list and
        // interpolated into generator validation text (LINK-002).
        let vless = format!("vless://{UUID}@ctl.local:443?encryption=none#Safe%0AName%0D%00%1B");
        let (p, canonical) = round_trip(&vless);
        assert_eq!(p.name, "SafeName");
        assert_eq!(
            canonical,
            format!("vless://{UUID}@ctl.local:443?encryption=none#SafeName")
        );

        let ui = URL_SAFE_NO_PAD.encode("aes-128-gcm:pw");
        let ss = format!("ss://{ui}@ctl2.example.com:8388#SS%0A%1BName");
        let (p, canonical) = round_trip(&ss);
        assert_eq!(p.name, "SSName");
        assert_eq!(canonical, format!("ss://{ui}@ctl2.example.com:8388#SSName"));

        // A fragment that filters down to nothing falls back to the host
        // default instead of storing an empty/control-only name.
        let p = parse_link(&format!(
            "vless://{UUID}@ctl3.local:443?encryption=none#%00%0D%1B",
        ))
        .unwrap();
        assert_eq!(p.name, "ctl3.local");
    }

    #[test]
    fn overlong_fragment_name_is_rejected() {
        // A multi-MB fragment would otherwise be persisted in servers.json
        // and laid out every frame; the decoded name is capped at import on
        // both fragment import paths (LINK-002).
        let long = "x".repeat(MAX_PROFILE_NAME_LEN + 1);
        match parse_link(&format!(
            "vless://{UUID}@long.local:443?encryption=none#{long}"
        )) {
            Err(LinkError::Malformed(msg)) => {
                let msg = msg.text(Language::En);
                assert!(msg.contains("profile name exceeds"));
            }
            other => panic!("expected Malformed, got {}", outcome_shape(&other)),
        }
        let ui = URL_SAFE_NO_PAD.encode("aes-128-gcm:pw");
        match parse_link(&format!("ss://{ui}@long2.example.com:8388#{long}")) {
            Err(LinkError::Malformed(_)) => {}
            other => panic!("expected Malformed, got {}", outcome_shape(&other)),
        }
        // Exactly at the cap is still accepted.
        let ok = "y".repeat(MAX_PROFILE_NAME_LEN);
        let p = parse_link(&format!(
            "vless://{UUID}@cap.local:443?encryption=none#{ok}"
        ))
        .unwrap();
        assert_eq!(p.name, ok);
    }

    #[test]
    fn b64_decode_any_rejects_oversized_and_foreign_alphabet_input() {
        // > 1 MiB input is rejected by the length precheck before any engine
        // allocates a decode buffer, even when every byte is decodable.
        let oversized = "A".repeat(MAX_B64_INPUT_LEN + 1);
        assert_eq!(b64_decode_any(&oversized), None);

        // Characters outside every engine alphabet skip all four decode
        // passes without allocating a buffer; results match the engines.
        assert_eq!(b64_decode_any("abc def"), None);
        assert_eq!(b64_decode_any("abc|def"), None);
    }

    #[test]
    fn oversized_link_payload_is_malformed() {
        // End-to-end: the legacy whole-URI base64 form feeds b64_decode_any;
        // an oversized body is rejected as Malformed without decoding.
        let body = STANDARD.encode(vec![0_u8; MAX_B64_INPUT_LEN]);
        expect_malformed(&format!("vmess://{body}"));
    }

    // ----- import-only schemes -----

    #[test]
    fn socks_accepts_both_userinfo_spellings_and_defaults_the_port() {
        let parsed = parse_link("socks5://alice:s3cr3t@h.example.com#S").unwrap();
        let ProtocolSettings::Socks(settings) = &parsed.outbound.settings else {
            panic!("expected a socks profile");
        };
        assert_eq!(settings.address, "h.example.com");
        assert_eq!(settings.port, 1080);
        assert_eq!(settings.user, "alice");
        assert_eq!(settings.pass, "s3cr3t");

        // The base64 `user:pass` userinfo spelling.
        let userinfo = URL_SAFE_NO_PAD.encode("bob:hunter2");
        let parsed = parse_link(&format!("socks://{userinfo}@h.example.com:1080#S")).unwrap();
        let ProtocolSettings::Socks(settings) = &parsed.outbound.settings else {
            panic!("expected a socks profile");
        };
        assert_eq!(settings.user, "bob");
        assert_eq!(settings.pass, "hunter2");

        // `uot` has no Xray field; the link still imports and reports it.
        let parsed = parse_link("socks5://h.example.com:1080?uot=1#S").unwrap();
        assert_eq!(parsed.ignored, vec!["uot".to_string()]);
    }

    #[test]
    fn http_https_and_headers_map() {
        let parsed = parse_link(
            "https://bob:hunter2@proxy.example.com?headers=X-A,1,X-B,2&path=%2Ftunnel#H",
        )
        .unwrap();
        assert_eq!(parsed.ignored, vec!["path".to_string()]);
        assert_eq!(parsed.outbound.stream.security, Security::Tls);
        let ProtocolSettings::Http(settings) = &parsed.outbound.settings else {
            panic!("expected an http profile");
        };
        assert_eq!(settings.port, 443);
        assert_eq!(settings.headers["X-A"], Value::String("1".into()));
        assert_eq!(settings.headers["X-B"], Value::String("2".into()));

        // Plain `http` keeps its default port and no TLS.
        let plain = parse_link("http://h.example.com#P").unwrap();
        assert_eq!(plain.outbound.stream.security, Security::None);
        assert_eq!(plain.outbound.protocol, Protocol::Http);
        let ProtocolSettings::Http(settings) = &plain.outbound.settings else {
            panic!("expected an http profile");
        };
        assert_eq!(settings.port, 80);

        // An odd name,value list has no pairing.
        expect_malformed("http://h.example.com?headers=only-name#H");

        // `security=none` contradicts the scheme rather than a setting.
        expect_malformed("https://h.example.com?security=none#H");
        // `security=tls` on plain `http` turns TLS on, as the clients do.
        let upgraded = parse_link("http://h.example.com?security=tls&sni=h.example.com#H").unwrap();
        assert_eq!(upgraded.outbound.stream.security, Security::Tls);
    }

    #[test]
    fn wireguard_accepts_both_client_grammars() {
        let secret = URL_SAFE_NO_PAD.encode([1_u8; 32]);
        let public = URL_SAFE_NO_PAD.encode([2_u8; 32]);

        // Private key in a parameter, dash-joined local addresses, plus an
        // AmneziaWG switch with no Xray field.
        let parameter_form = format!(
            "wg://198.51.100.9:2408?private_key={secret}&local_address=10.0.0.2%2F32-2001%3Adb8%3A%3A2%2F128&public_key={public}&reserved=15-62-190&persistent_keepalive_interval=25&use_system_interface=true&jc=4#WG"
        );
        let parsed = parse_link(&parameter_form).unwrap();
        assert_eq!(
            parsed.ignored,
            vec!["use_system_interface".to_string(), "jc".to_string()]
        );
        let ProtocolSettings::Wireguard(settings) = &parsed.outbound.settings else {
            panic!("expected a wireguard profile");
        };
        assert_eq!(settings.secret_key, secret);
        assert_eq!(
            settings.address,
            vec!["10.0.0.2/32".to_string(), "2001:db8::2/128".to_string()]
        );
        assert_eq!(settings.reserved, Some(vec![15, 62, 190]));
        assert_eq!(settings.peers[0].public_key, public);
        assert_eq!(settings.peers[0].endpoint, "198.51.100.9:2408");
        assert_eq!(settings.peers[0].keep_alive, Some(25));

        // Private key in the userinfo, comma-joined addresses, and a DNS entry.
        let userinfo_form = format!(
            "wireguard://{secret}@198.51.100.9:2408?publickey={public}&address=10.0.0.2%2F32&mtu=1280&dns=1.1.1.1#WG2"
        );
        let parsed = parse_link(&userinfo_form).unwrap();
        assert!(parsed.ignored.is_empty());
        let ProtocolSettings::Wireguard(settings) = &parsed.outbound.settings else {
            panic!("expected a wireguard profile");
        };
        assert_eq!(settings.mtu, 1280);
        assert_eq!(settings.remote_dns, vec!["1.1.1.1".to_string()]);

        // Two spellings of one field must not silently pick a winner.
        expect_malformed(&format!(
            "wg://h.example.com:51820?private_key={secret}&privatekey={secret}&public_key={public}&local_address=10.0.0.2%2F32"
        ));
    }

    #[test]
    fn wireguard_refuses_material_the_core_cannot_use() {
        // The model pass owns the key material, so an import reports the
        // same keyed finding the editor and generation gate on — never a
        // profile that only fails at core config load after a clean preview.
        use crate::model::validation::ValidationCode;
        let secret = URL_SAFE_NO_PAD.encode([1_u8; 32]);
        let public = URL_SAFE_NO_PAD.encode([2_u8; 32]);
        expect_invalid_model(
            "wg://h.example.com:51820?private_key=not-a-key&public_key=also-not&local_address=10.0.0.2%2F32",
            ValidationCode::WireguardSecretKeyInvalid,
        );
        expect_invalid_model(
            &format!(
                "wg://h.example.com:51820?private_key={secret}&public_key=not-a-key&local_address=10.0.0.2%2F32"
            ),
            ValidationCode::WireguardPeerPublicKeyRequired,
        );
        expect_invalid_model(
            &format!(
                "wg://h.example.com:51820?private_key={secret}&public_key={public}&local_address=10.0.0.2%2F32&reserved=1-2"
            ),
            ValidationCode::WireguardReservedKeyBytes,
        );
    }

    #[test]
    fn default_port_grammars_still_refuse_a_garbled_bracketed_host() {
        // The import-only schemes supply a default port, so bytes after the
        // closing bracket that are not a port must not be swallowed.
        expect_malformed("socks5://[::1]junk#S");
        expect_malformed("hysteria2://pw@[::1]x#H");

        // A bracketed literal with no port takes the scheme default.
        let parsed = parse_link("socks5://[::1]#S").unwrap();
        let ProtocolSettings::Socks(settings) = &parsed.outbound.settings else {
            panic!("expected a socks profile");
        };
        assert_eq!(settings.address, "::1");
        assert_eq!(settings.port, 1080);
    }

    #[test]
    fn hysteria2_authority_port_range_forms_the_hop_set() {
        // A provider link puts the hop range in the authority; the range's
        // first port becomes the outbound destination and the whole list rides
        // the hop mask.
        let parsed = parse_link(
            "hysteria2://letmein@hop.example.com:20000-30000?security=tls&sni=hop.example.com&allowInsecure=true#Node",
        )
        .unwrap();
        assert_eq!(parsed.ignored, vec!["allowInsecure".to_string()]);
        let ProtocolSettings::Hysteria(settings) = &parsed.outbound.settings else {
            panic!("expected a hysteria profile");
        };
        assert_eq!(settings.port, 20000);
        assert_eq!(
            parsed
                .outbound
                .stream
                .tls_settings
                .as_ref()
                .unwrap()
                .server_name,
            "hop.example.com"
        );
        let finalmask = parsed.outbound.stream.finalmask.as_ref().unwrap();
        let hop = finalmask
            .udp
            .iter()
            .find_map(|mask| match mask {
                FinalmaskUdpMask::Udphop { settings, .. } => Some(settings.as_ref()),
                _ => None,
            })
            .expect("the authority range maps onto the udphop mask");
        assert!(
            matches!(&hop.remote_ports, FinalmaskPortList::Text(ports) if ports == "20000-30000")
        );
        assert_eq!(hop.mode, "perConnRemote");

        // A mixed list keeps every item.
        let parsed = parse_link("hysteria2://pw@h.example.com:20000-30000,443").unwrap();
        let ProtocolSettings::Hysteria(settings) = &parsed.outbound.settings else {
            panic!("expected a hysteria profile");
        };
        assert_eq!(settings.port, 20000);
        let hop = parsed
            .outbound
            .stream
            .finalmask
            .as_ref()
            .unwrap()
            .udp
            .iter()
            .find_map(|mask| match mask {
                FinalmaskUdpMask::Udphop { settings, .. } => Some(settings.as_ref()),
                _ => None,
            })
            .unwrap();
        assert!(
            matches!(&hop.remote_ports, FinalmaskPortList::Text(ports) if ports == "20000-30000,443")
        );
    }

    #[test]
    fn hysteria2_refuses_two_hop_spellings_and_bad_port_lists() {
        expect_malformed("hysteria2://pw@h.example.com:20000-30000?mport=20000-30000");
        expect_malformed("hysteria2://pw@h.example.com:30000-20000");
        expect_malformed("hysteria2://pw@h.example.com?mport=bogus");
        expect_malformed("hysteria2://pw@h.example.com:0");
        // A hop interval names nothing without a hop set.
        expect_unsupported("hysteria2://pw@h.example.com:443?hop_interval=30");
    }

    #[test]
    fn hysteria2_maps_obfs_hop_and_rates() {
        let pin = "a".repeat(64);
        let link = format!(
            "hysteria2://letmein@h.example.com:8443?sni=edge.example.com&alpn=h3&pinSHA256={pin}&obfs=salamander&obfs-password=obfspw&minPacketSize=1000&maxPacketSize=1400&mport=20000-30000%2C443&hop_interval=30&upmbps=100&downmbps=500&disable_chrome_parrot=true#Hy2"
        );
        let parsed = parse_link(&link).unwrap();
        assert!(parsed.ignored.is_empty());
        let ProtocolSettings::Hysteria(settings) = &parsed.outbound.settings else {
            panic!("expected a hysteria profile");
        };
        assert_eq!(settings.address, "h.example.com");
        assert_eq!(settings.port, 8443);
        assert_eq!(settings.version, 2);

        let stream = &parsed.outbound.stream;
        assert_eq!(stream.network, Network::Hysteria);
        assert_eq!(stream.security, Security::Tls);
        assert_eq!(stream.hysteria_settings.as_ref().unwrap().auth, "letmein");
        let tls = stream.tls_settings.as_ref().unwrap();
        assert_eq!(tls.server_name, "edge.example.com");
        assert_eq!(tls.alpn, vec!["h3".to_string()]);
        assert_eq!(tls.pinned_peer_cert_sha256, pin);

        let finalmask = stream.finalmask.as_ref().unwrap();
        let salamander = finalmask
            .udp
            .iter()
            .find_map(|mask| match mask {
                FinalmaskUdpMask::Salamander { settings, .. } => Some(settings),
                _ => None,
            })
            .expect("obfs maps onto the salamander mask");
        assert_eq!(salamander.password, "obfspw");
        assert_eq!(salamander.packet_size, Int32Range::new(1000, 1400));
        let hop = finalmask
            .udp
            .iter()
            .find_map(|mask| match mask {
                FinalmaskUdpMask::Udphop { settings, .. } => Some(settings.as_ref()),
                _ => None,
            })
            .expect("mport maps onto the udphop mask");
        assert!(matches!(
            &hop.remote_ports,
            FinalmaskPortList::Text(ports) if ports == "20000-30000,443"
        ));
        assert_eq!(hop.mode, "intervalRemote");
        assert_eq!(hop.interval, Int32Range::single(30));
        let quic = finalmask.quic_params.as_ref().unwrap();
        assert_eq!(quic.congestion, "force-brutal");
        assert_eq!(quic.brutal_up, "100 mbps");
        assert_eq!(quic.brutal_down, "500 mbps");
        assert_eq!(quic.disable_chrome_parrot, Some(true));
    }

    #[test]
    fn hysteria2_refuses_gecko_realm_and_one_sided_rates() {
        expect_unsupported("hysteria2://pw@h.example.com:443?obfs=gecko&obfs-password=x");
        expect_unsupported("hysteria2+realm://token@h.example.com:443/realm");
        // A packet size only exists for the salamander mask.
        expect_unsupported("hysteria2://pw@h.example.com:443?minPacketSize=1000");
        expect_malformed("hysteria2://pw@h.example.com:443?upmbps=100");
        expect_malformed(&format!(
            "hysteria2://pw@h.example.com:443?pinSHA256={},{}",
            "a".repeat(64),
            "b".repeat(64)
        ));
    }

    #[test]
    fn recognized_compatibility_parameters_are_dropped_and_reported() {
        // A parameter with no effective Xray field imports, keeps the model
        // default, and names itself in the report.
        let parsed = parse_link(&format!(
            "vless://{UUID}@h.example.com:443?encryption=none&security=tls&sni=h.example.com&mux=true&packetEncoding=xudp#M"
        ))
        .unwrap();
        assert_eq!(
            parsed.ignored,
            vec!["mux".to_string(), "packetEncoding".to_string()]
        );
        assert!(parsed.outbound.mux.is_empty());

        // A switch spelling its off value is the default already: silent.
        let parsed = parse_link(&format!(
            "vless://{UUID}@h.example.com:443?encryption=none&security=tls&sni=h.example.com&mux=false#M"
        ))
        .unwrap();
        assert!(parsed.ignored.is_empty());

        // A bare flag is present in the link: it is reported, not assumed off.
        let parsed = parse_link(&format!(
            "vless://{UUID}@h.example.com:443?encryption=none&security=tls&sni=h.example.com&mux#M"
        ))
        .unwrap();
        assert_eq!(parsed.ignored, vec!["mux".to_string()]);

        // A parameter the grammar does not know still refuses the link.
        expect_unsupported(&format!(
            "vless://{UUID}@h.example.com:443?encryption=none&futureTransport=1"
        ));
    }

    #[test]
    fn legacy_vmess_maps_tls_extras_and_drops_insecure() {
        let pin = "a".repeat(64);
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "V", "add": "v.example.com", "port": "443",
            "id": UUID, "aid": "0", "scy": "auto", "net": "tcp", "tls": "tls",
            "sni": "v.example.com", "insecure": "1", "vcn": "v.example.com", "pcs": pin
        }));
        let parsed = parse_link(&link).unwrap();
        assert_eq!(parsed.ignored, vec!["insecure".to_string()]);
        let tls = parsed.outbound.stream.tls_settings.as_ref().unwrap();
        assert_eq!(tls.verify_peer_cert_by_name, "v.example.com");
        assert_eq!(tls.pinned_peer_cert_sha256, pin);

        // `insecure=0` is the default state: nothing was dropped.
        let link = vmess_json(serde_json::json!({
            "v": "2", "ps": "V", "add": "v.example.com", "port": "443",
            "id": UUID, "aid": "0", "net": "tcp", "tls": "tls",
            "sni": "v.example.com", "insecure": "0"
        }));
        let parsed = parse_link(&link).unwrap();
        assert!(parsed.ignored.is_empty());
    }

    // ----- malformed / unsupported -----

    fn expect_malformed(s: &str) {
        match parse_link(s) {
            Err(LinkError::Malformed(_)) => {}
            other => panic!(
                "expected Malformed for {}, got {}",
                redact(s),
                outcome_shape(&other)
            ),
        }
    }

    fn expect_unsupported(s: &str) {
        match parse_link(s) {
            Err(LinkError::Unsupported(_)) => {}
            other => panic!(
                "expected Unsupported for {}, got {}",
                redact(s),
                outcome_shape(&other)
            ),
        }
    }

    fn expect_lossy(profile: &ServerProfile, field: &str) {
        match to_link(profile) {
            Err(LinkError::Lossy(message)) => {
                let message = message.text(Language::En);
                assert!(
                    message.contains(field),
                    "{message:?} did not name {field:?}"
                );
            }
            other => panic!("expected Lossy({field}), got {}", outcome_shape(&other)),
        }
    }

    /// A lossy export with the exact message `key` and `field` render: the
    /// refusal's own key and the block it names are the contract the UI
    /// shows.
    fn expect_lossy_message(profile: &ServerProfile, key: Key, field: &str) {
        match to_link(profile) {
            Err(LinkError::Lossy(message)) => {
                assert_eq!(
                    message.text(Language::En),
                    t_fmt(Language::En, key, &[&field])
                );
            }
            other => panic!(
                "expected Lossy({key:?}, {field:?}), got {}",
                outcome_shape(&other)
            ),
        }
    }

    /// A link the model rules reject: parse surfaces the first `Error`
    /// finding as a keyed `InvalidModel`, never a rendered string.
    fn expect_invalid_model(s: &str, code: crate::model::validation::ValidationCode) {
        match parse_link(s) {
            Err(LinkError::InvalidModel { issue, .. }) if issue.code == code => {}
            other => panic!(
                "expected InvalidModel({code:?}) for {}, got {}",
                redact(s),
                outcome_shape(&other)
            ),
        }
    }

    /// A link with its credential elided: for the URL-shaped engines
    /// everything between the scheme and the first `@` is the account's id or
    /// password, and for the base64-shaped ones the whole body is, so a
    /// diagnostic names the scheme and host without the secret it carries.
    fn redact(link: &str) -> String {
        let Some((scheme, rest)) = link.split_once("://") else {
            return "<link>".to_owned();
        };
        match rest.split_once('@') {
            Some((_, host)) => format!("{scheme}://<id>@{host}"),
            None => format!("{scheme}://<body>"),
        }
    }

    /// The same shape for a parse outcome: a test that matched the error's
    /// variant by pattern still holds the whole `Result`, and its message names
    /// the variant rather than dumping a profile or a link either.
    fn outcome_shape<T>(outcome: &Result<T, LinkError>) -> &'static str {
        match outcome {
            Ok(_) => "Ok(_)",
            Err(error) => error_shape(error),
        }
    }

    /// Which failure came back, as a literal per variant. Everything an error
    /// carries descends from the link its case parsed, and a panic message is a
    /// CI log line, so the tests name the variant and nothing that travelled
    /// with it — the key a payload holds is an identifier, not data, but it is
    /// read out of the same value and stays out of the message all the same.
    fn error_shape(error: &LinkError) -> &'static str {
        match error {
            LinkError::Unsupported(_) => "Unsupported",
            LinkError::Malformed(_) => "Malformed",
            LinkError::Lossy(_) => "Lossy",
            LinkError::InvalidModel { .. } => "InvalidModel",
        }
    }

    #[test]
    fn diagnostics_never_echo_the_credential() {
        // A panic message is a CI log line: the account's id must not travel
        // into it, and the reader still needs to know which link and which
        // failure the case reached.
        assert_eq!(
            redact("vless://7f0a9c4e-0000-0000-0000-000000000000@h.example.com:443?type=ws"),
            "vless://<id>@h.example.com:443?type=ws"
        );
        assert_eq!(redact("vmess://eyJ2IjoiMiJ9"), "vmess://<body>");
        assert_eq!(redact("no scheme here"), "<link>");
        assert_eq!(
            outcome_shape(&parse_link(
                "vless://7f0a9c4e-0000-0000-0000-000000000000@h.example.com:443?security=tls"
            )),
            "Ok(_)"
        );
        let malformed =
            parse_link("vless://7f0a9c4e-0000-0000-0000-000000000000@h.example.com").unwrap_err();
        let shape = error_shape(&malformed);
        assert_eq!(shape, "Malformed");
        assert!(
            !shape.contains("7f0a9c4e"),
            "the shape must not carry the payload: {shape}"
        );
    }

    #[test]
    fn duplicate_decoded_keys_empty_values_and_guna_are_rejected() {
        expect_malformed(&format!(
            "vless://{UUID}@h.example.com:443?security=tls&%73ecurity=reality"
        ));
        expect_malformed(&format!(
            "vmess://{UUID}@h.example.com:443?type=ws&%74ype=grpc"
        ));
        expect_malformed(&format!(
            "vless://{UUID}@h.example.com:443?security=reality&fp=chrome&pbk={}&pqv=AAA&mldsa65Verify=BBB",
            reality_public_key()
        ));
        expect_malformed(&format!("vless://{UUID}@h.example.com:443?security="));
        expect_malformed(&format!("vless://{UUID}@h.example.com:443?type=ws&path="));
        expect_malformed(&format!("vless://{UUID}@h.example.com:443?type=WS"));
        expect_unsupported(&format!(
            "vmess://{UUID}@h.example.com:443?type=grpc&serviceName=svc&mode=guna"
        ));
        expect_unsupported(&format!("vless://{UUID}@h.example.com:443?unknown=value"));
    }

    #[test]
    fn hostile_and_malformed_uri_hosts_are_rejected() {
        for link in [
            format!("vless://{UUID}@example.com:443/evil"),
            format!("vless://{UUID}@bad@host.example:443"),
            format!("vless://{UUID}@täst.example:443"),
            format!("vless://{UUID}@2001:db8::1:443"),
            format!("vless://{UUID}@[example.com]:443"),
            format!("vless://{UUID}@%65xample.com:443"),
            format!("vless://{UUID}@999.1.1.1:443"),
            format!("vless://{UUID}@bad\\host.example:443"),
            format!("vless://{UUID}@0x7f.0.0.1:443"),
        ] {
            expect_malformed(&link);
        }
        let ipv6 = format!("vless://{UUID}@[fd00::1]:443#IPv6");
        let (_, canonical) = round_trip(&ipv6);
        assert!(canonical.contains("@[fd00::1]:443"));
    }

    #[test]
    fn reality_and_vless_core_constraints_are_enforced() {
        let public_key = reality_public_key();
        expect_malformed(&format!(
            "vless://{UUID}@h.example.com:443?security=reality&pbk={public_key}"
        ));
        expect_invalid_model(
            &format!("vless://{UUID}@h.example.com:443?security=reality&fp=chrome"),
            crate::model::validation::ValidationCode::RealityPublicKeyInvalid,
        );
        expect_invalid_model(
            &format!(
                "vless://{UUID}@h.example.com:443?security=reality&fp=chrome&pbk={public_key}&sid=0"
            ),
            crate::model::validation::ValidationCode::RealityShortIdInvalid,
        );
        expect_invalid_model(
            &format!(
                "vless://{UUID}@h.example.com:443?security=reality&fp=chrome&pbk={public_key}&pqv=AAA"
            ),
            crate::model::validation::ValidationCode::RealityMldsa65Invalid,
        );
        expect_invalid_model(
            &format!(
                "vless://{UUID}@h.example.com:443?security=reality&fp=chrome&pbk={public_key}&spx=relative"
            ),
            crate::model::validation::ValidationCode::RealitySpiderXInvalid,
        );
        expect_invalid_model(
            &format!(
                "vless://{UUID}@h.example.com:443?security=reality&fp=chrome&pbk={public_key}&type=ws"
            ),
            crate::model::validation::ValidationCode::RealityRequiresTransport,
        );
        expect_malformed(&format!("vless://{UUID}@h.example.com:443?encryption="));
        expect_malformed(&format!(
            "vless://{UUID}@h.example.com:443?encryption=aes-128-gcm"
        ));
        expect_malformed(&format!(
            "vless://{UUID}@h.example.com:443?encryption=mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAA"
        ));
        // A key part is required: an all-padding value panics the core's
        // parser, and a short token after a key part breaks handler
        // creation.
        expect_malformed(&format!(
            "vless://{UUID}@h.example.com:443?encryption=mlkem768x25519plus.native.1rtt.key"
        ));
        let key = URL_SAFE_NO_PAD.encode([5_u8; 32]);
        expect_malformed(&format!(
            "vless://{UUID}@h.example.com:443?encryption=mlkem768x25519plus.native.1rtt.{key}.ab"
        ));
        expect_malformed(&format!(
            "vless://{UUID}@h.example.com:443?flow=xtls-rprx-vision-splice"
        ));
        expect_invalid_model(
            &format!("vless://{UUID}@h.example.com:443?security=tls&pcs=abcd"),
            crate::model::validation::ValidationCode::PinnedPeerCertSha256Invalid,
        );
    }

    #[test]
    fn vless_vision_requires_tls_or_reality_for_parse_and_export() {
        let plain = format!(
            "vless://{UUID}@router.local:443?encryption=none&flow=xtls-rprx-vision&type=tcp#Plain"
        );
        expect_invalid_model(
            &plain,
            crate::model::validation::ValidationCode::VisionRequiresTlsOrReality,
        );

        let mut manual = parse_link(&format!(
            "vless://{UUID}@router.local:443?encryption=none&type=tcp#Manual"
        ))
        .unwrap();
        let ProtocolSettings::Vless(settings) = &mut manual.outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision".into();
        match to_link(&manual) {
            Err(LinkError::InvalidModel { issue, .. }) => {
                let message = validation_issue_message(&issue, Language::En);
                assert!(message.contains("TLS or REALITY"), "{message:?}");
            }
            other => panic!(
                "expected Vision security rejection, got {}",
                outcome_shape(&other)
            ),
        }

        let tls = format!(
            "vless://{UUID}@router.local:443?encryption=none&flow=xtls-rprx-vision&security=tls&type=tcp#TLS"
        );
        let (tls_profile, _) = round_trip(&tls);
        assert_eq!(tls_profile.outbound.stream.security, Security::Tls);

        let public_key = reality_public_key();
        let reality = format!(
            "vless://{UUID}@router.local:443?encryption=none&flow=xtls-rprx-vision&security=reality&fp=chrome&pbk={public_key}&type=tcp#REALITY"
        );
        let (reality_profile, _) = round_trip(&reality);
        assert_eq!(reality_profile.outbound.stream.security, Security::Reality);
    }

    #[test]
    fn imported_stream_core_invariants_are_enforced() {
        // TLS keeps the public-plaintext rule from firing first, so these two
        // reach the mKCP ranges themselves.
        expect_invalid_model(
            &format!("vless://{UUID}@h.example.com:443?type=kcp&mtu=20&security=tls"),
            crate::model::validation::ValidationCode::KcpRangeInvalid,
        );
        expect_invalid_model(
            &format!("vless://{UUID}@h.example.com:443?type=kcp&tti=9&security=tls"),
            crate::model::validation::ValidationCode::KcpRangeInvalid,
        );
        expect_malformed(&format!("vmess://{UUID}@h.example.com:443?type=grpc"));
        expect_malformed(&format!(
            "vmess://{UUID}@h.example.com:443?security=tls&sni=bad%2Fname"
        ));

        let host_header = pct_encode(r#"{"headers":{"Host":"wrong.example"}}"#);
        expect_malformed(&format!(
            "vmess://{UUID}@h.example.com:443?type=xhttp&extra={host_header}"
        ));
        let disabled_padding = pct_encode(r#"{"xPaddingBytes":"0-1"}"#);
        expect_invalid_model(
            &format!("vmess://{UUID}@h.example.com:443?type=xhttp&extra={disabled_padding}"),
            crate::model::validation::ValidationCode::XhttpPaddingBytesInvalid,
        );
        let reserved = pct_encode(r#"{"path":"/smuggled"}"#);
        expect_malformed(&format!(
            "vmess://{UUID}@h.example.com:443?type=xhttp&extra={reserved}"
        ));
        let recursive = pct_encode(r#"{"downloadSettings":{"network":"raw","security":"none"}}"#);
        expect_invalid_model(
            &format!(
                "vmess://{UUID}@h.example.com:443?type=xhttp&mode=stream-one&extra={recursive}"
            ),
            crate::model::validation::ValidationCode::StreamOneNoDownload,
        );
    }

    #[test]
    fn shadowsocks_cipher_and_password_rules_match_xray() {
        const CLASSIC: &[&str] = &[
            "aes-128-gcm",
            "aead_aes_128_gcm",
            "aes-256-gcm",
            "aead_aes_256_gcm",
            "chacha20-poly1305",
            "aead_chacha20_poly1305",
            "chacha20-ietf-poly1305",
            "xchacha20-poly1305",
            "aead_xchacha20_poly1305",
            "xchacha20-ietf-poly1305",
            "AES-128-GCM",
        ];
        for method in CLASSIC {
            let userinfo = URL_SAFE_NO_PAD.encode(format!("{method}:password"));
            parse_link(&format!("ss://{userinfo}@ss.example.com:8388"))
                .unwrap_or_else(|error| panic!("{method}: {error}"));
        }

        let unsupported = URL_SAFE_NO_PAD.encode("aes-256-cfb:password");
        expect_malformed(&format!("ss://{unsupported}@ss.example.com:8388"));
        let empty_password = URL_SAFE_NO_PAD.encode("aes-128-gcm:");
        expect_malformed(&format!("ss://{empty_password}@ss.example.com:8388"));

        let key16_a = STANDARD.encode([1_u8; 16]);
        let key16_b = STANDARD.encode([2_u8; 16]);
        let aes_multi =
            URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-128-gcm:{key16_a}:{key16_b}"));
        parse_link(&format!("ss://{aes_multi}@ss.example.com:8388")).unwrap();

        // The core decodes a 2022 key with `base64.StdEncoding` and requires
        // at least the method's key size, so an unpadded or short key is
        // refused at import exactly as the core refuses the built config.
        let unpadded16 = STANDARD_NO_PAD.encode([1_u8; 16]);
        let unpadded = URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-128-gcm:{unpadded16}"));
        expect_malformed(&format!("ss://{unpadded}@ss.example.com:8388"));

        let bad_aes = URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-256-gcm:{key16_a}"));
        expect_malformed(&format!("ss://{bad_aes}@ss.example.com:8388"));

        let key32_a = STANDARD.encode([3_u8; 32]);
        let key32_b = STANDARD.encode([4_u8; 32]);
        for method in ["2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"] {
            let valid = URL_SAFE_NO_PAD.encode(format!("{method}:{key32_a}"));
            parse_link(&format!("ss://{valid}@ss.example.com:8388"))
                .unwrap_or_else(|error| panic!("{method}: {error}"));
        }
        let bad_chacha =
            URL_SAFE_NO_PAD.encode(format!("2022-blake3-chacha20-poly1305:{key32_a}:{key32_b}"));
        expect_malformed(&format!("ss://{bad_chacha}@ss.example.com:8388"));

        // A part longer than the method's size loads (the core hashes it down
        // to the method's length), so the import keeps it and the profile
        // carries only the model's advisory finding.
        let long_part = STANDARD.encode([5_u8; 24]);
        let longer = URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-128-gcm:{long_part}"));
        parse_link(&format!("ss://{longer}@ss.example.com:8388"))
            .unwrap_or_else(|error| panic!("a longer 2022 key must import: {error}"));
    }

    #[test]
    fn incomplete_profiles_cannot_export() {
        for protocol in [
            Protocol::Vless,
            Protocol::Vmess,
            Protocol::Trojan,
            Protocol::Shadowsocks,
        ] {
            let profile = ServerProfile::new("incomplete", OutboundModel::new(protocol));
            assert!(
                matches!(to_link(&profile), Err(LinkError::Malformed(_))),
                "{protocol:?}"
            );
        }
    }

    #[test]
    fn export_rejects_each_unrepresentable_state_instead_of_dropping_it() {
        let base = parse_link(&format!(
            "vless://{UUID}@router.local:443?encryption=none#Base"
        ))
        .unwrap();

        // A dial-through chain is local configuration: every share-link
        // grammar stops at the outbound itself. The check names the surviving
        // spelling's wire path.
        let mut profile = base.clone();
        profile.outbound.chain_via("dial-via");
        expect_lossy(&profile, "streamSettings.sockopt.dialerProxy");

        let mut profile = base.clone();
        profile.outbound.send_through = Some("192.0.2.1".into());
        expect_lossy(&profile, "sendThrough");

        let mut profile = base.clone();
        profile.outbound.target_strategy = Some("forceip".into());
        expect_lossy(&profile, "targetStrategy");

        let mut profile = base.clone();
        profile.outbound.mux.enabled = true;
        expect_lossy(&profile, "mux");

        let mut profile = base.clone();
        profile
            .outbound
            .extra
            .insert("unknownEnvelope".into(), Value::Bool(true));
        expect_lossy(&profile, "outbound.extra");

        let mut profile = base.clone();
        profile.outbound.stream.sockopt = Some(crate::model::stream::SockoptModel {
            interface: "Ethernet".into(),
            ..Default::default()
        });
        expect_lossy(&profile, "sockopt");

        let mut profile = base.clone();
        profile.outbound.stream.raw_settings = Some(RawSettings {
            header: Some(RawHeader {
                r#type: "http".into(),
                request: Some(HttpCamouflageRequest {
                    path: vec!["/camouflage".into()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        });
        expect_lossy(&profile, "rawSettings");

        let mut profile =
            parse_link(&format!("vless://{UUID}@ws.local:443?type=ws&path=%2Fws")).unwrap();
        profile
            .outbound
            .stream
            .ws_settings
            .as_mut()
            .unwrap()
            .headers
            .insert("X-Test".into(), Value::String("value".into()));
        expect_lossy(&profile, "wsSettings");

        let mut profile = parse_link(&format!(
            "vless://{UUID}@grpc.local:443?type=grpc&serviceName=svc"
        ))
        .unwrap();
        profile
            .outbound
            .stream
            .grpc_settings
            .as_mut()
            .unwrap()
            .user_agent = Some("custom".into());
        expect_lossy(&profile, "grpcSettings");

        let mut profile =
            parse_link(&format!("vless://{UUID}@tls.example.com:443?security=tls")).unwrap();
        profile
            .outbound
            .stream
            .tls_settings
            .as_mut()
            .unwrap()
            .min_version = "1.3".into();
        expect_lossy(&profile, "tlsSettings");

        let mut profile = base.clone();
        let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
            unreachable!()
        };
        settings.email = "stats@example.com".into();
        expect_lossy(&profile, "settings.email");

        let mut profile = base;
        profile
            .extra
            .insert("subscriptionMeta".into(), Value::Bool(true));
        expect_lossy(&profile, "profile.extra");

        let userinfo = URL_SAFE_NO_PAD.encode("aes-128-gcm:password");
        let mut ss = parse_link(&format!("ss://{userinfo}@ss.example.com:8388#SS")).unwrap();
        ss.outbound.stream.finalmask = Some(
            serde_json::from_value(serde_json::json!({
                "udp": [{"type": "salamander", "settings": {"password": "pw"}}]
            }))
            .unwrap(),
        );
        expect_lossy(&ss, "streamSettings");
    }

    #[test]
    fn export_refusals_name_the_transport_block_and_their_own_reason() {
        // A congestion knob and a header map have no share-link spelling:
        // each refusal names the block it sits in under its own key.
        let mut kcp = parse_link(&format!(
            "vless://{UUID}@kcp.local:443?type=kcp&mtu=1400#KCP"
        ))
        .unwrap();
        kcp.outbound
            .stream
            .kcp_settings
            .as_mut()
            .unwrap()
            .uplink_capacity = Some(1_000);
        expect_lossy_message(&kcp, Key::LinkLossyKcp, "streamSettings.kcpSettings");

        let mut upgrade = parse_link(&format!(
            "vless://{UUID}@upgrade.local:443?type=httpupgrade&path=%2Fup#UP"
        ))
        .unwrap();
        upgrade
            .outbound
            .stream
            .httpupgrade_settings
            .as_mut()
            .unwrap()
            .headers
            .insert("X-Test".into(), Value::String("value".into()));
        expect_lossy_message(
            &upgrade,
            Key::LinkLossyHttpupgrade,
            "streamSettings.httpupgradeSettings",
        );
    }

    #[test]
    fn export_ignores_inactive_invalid_transport_drafts_without_leaking_them() {
        let mut profile = parse_link(&format!(
            "vless://{UUID}@grpc.example.com:443?security=tls&type=grpc&serviceName=active-svc#Active"
        ))
        .unwrap();
        let mut stale_headers = Map::new();
        stale_headers.insert("X-Invalid".into(), Value::Number(1.into()));
        profile.outbound.stream.ws_settings = Some(WsSettings {
            host: "stale.example".into(),
            path: "/stale-ws".into(),
            headers: stale_headers,
            ..Default::default()
        });

        let link = to_link(&profile).expect("inactive WebSocket draft is not wire state");
        assert!(link.contains("type=grpc"));
        assert!(link.contains("serviceName=active-svc"));
        assert!(!link.contains("stale"), "{}", redact(&link));
        assert!(
            profile.outbound.stream.ws_settings.is_some(),
            "export must canonicalize a clone, not destroy the editor draft"
        );

        let reparsed = parse_link(&link).unwrap();
        assert_eq!(reparsed.outbound.stream.network, Network::Grpc);
        assert!(reparsed.outbound.stream.ws_settings.is_none());
    }

    #[test]
    fn export_ignores_inactive_security_drafts_without_leaking_them() {
        let mut profile = parse_link(&format!(
            "vless://{UUID}@tls.example.com:443?security=tls&sni=active.example.com&fp=chrome#TLS"
        ))
        .unwrap();
        profile.outbound.stream.reality_settings = Some(RealityModel {
            server_name: "inactive-reality.example.com".into(),
            show: Some(true),
            master_key_log: "inactive-reality-key-log".into(),
            ..Default::default()
        });
        let inactive_snapshot =
            serde_json::to_value(profile.outbound.stream.reality_settings.as_ref().unwrap())
                .unwrap();

        let link = to_link(&profile).expect("inactive REALITY draft is not wire state");
        assert!(!link.contains("inactive-reality"), "{}", redact(&link));

        let reparsed = parse_link(&link).unwrap();
        assert_eq!(reparsed.outbound.stream.security, Security::Tls);
        assert!(reparsed.outbound.stream.tls_settings.is_some());
        assert!(reparsed.outbound.stream.reality_settings.is_none());
        assert_eq!(
            serde_json::to_value(profile.outbound.stream.reality_settings.as_ref().unwrap())
                .unwrap(),
            inactive_snapshot,
            "export must canonicalize a clone, not destroy the editor draft"
        );
    }

    #[test]
    fn malformed_inputs() {
        expect_malformed("");
        expect_malformed("not a link");
        expect_malformed("vless://");
        expect_malformed("vless://not-a-uuid@h.example.com:443");
        expect_malformed(&format!("vless://{UUID}@h.example.com"));
        expect_malformed(&format!("vless://{UUID}@h.example.com:0"));
        expect_malformed(&format!("vless://{UUID}@h.example.com:99999"));
        expect_malformed(&format!("vless://{UUID}@h.example.com:443?type=bogus"));
        // #716 §2 keeps parameter names and constant strings case-sensitive:
        // the transport aliases import in lowercase only.
        expect_malformed(&format!("vless://{UUID}@h.example.com:443?type=RAW"));
        expect_malformed(&format!("vless://{UUID}@h.example.com:443?flow=vision"));
        expect_malformed(&format!("vless://{UUID}@h.example.com:443?x=1&x=2"));
        expect_invalid_model(
            &format!(
                "vless://{UUID}@h.example.com:443?security=reality&type=ws&fp=chrome&pbk={}",
                reality_public_key()
            ),
            crate::model::validation::ValidationCode::RealityRequiresTransport,
        );
        expect_invalid_model(
            &format!(
                "vless://{UUID}@h.example.com:443?security=reality&fp=unsafe&pbk={}",
                reality_public_key()
            ),
            crate::model::validation::ValidationCode::RealityFingerprintUnsupported,
        );
        expect_invalid_model(
            &format!("vless://{UUID}@h.example.com:443?security=reality&fp=chrome&pbk=AAA"),
            crate::model::validation::ValidationCode::RealityPublicKeyInvalid,
        );
        expect_invalid_model(
            &format!(
                "vless://{UUID}@h.example.com:443?security=reality&fp=chrome&pbk={}&sid=xyz",
                reality_public_key()
            ),
            crate::model::validation::ValidationCode::RealityShortIdInvalid,
        );
        expect_invalid_model(
            &format!("vless://{UUID}@h.example.com:443?type=grpc"),
            crate::model::validation::ValidationCode::PublicVlessRequiresTlsOrEncryption,
        );
        expect_malformed("vmess://###not-base64###");
        expect_malformed(&format!("vmess://{}", STANDARD.encode(b"not json")));
        expect_malformed(&vmess_json(serde_json::json!({"ps": "x"}))); // no add/port/id
        expect_malformed(&vmess_json(serde_json::json!({
            "add": "a.com", "port": "abc", "id": UUID
        })));
        expect_malformed("trojan://@h.example.com:443");
        expect_malformed("ss://");
        expect_malformed("ss://aes-128-gcm@h.example.com:8388"); // no ':' in userinfo
        expect_malformed("ss://bmV0aG9kOnB3@h.example.com:notaport");
        expect_malformed(&format!("vless://{UUID}@h.example.com:443#bad%zz"));
    }
    #[test]
    fn unsupported_inputs() {
        expect_unsupported("socks4://u:p@h.example.com:1080");
        expect_unsupported("socks4a://u:p@h.example.com:1080");
        expect_unsupported("hysteria://pw@h.example.com:443");
        expect_unsupported(&format!("vless://{UUID}@h.example.com:443?security=xtls"));
        expect_unsupported(&format!("vless://{UUID}@h.example.com:443?type=http"));
        expect_unsupported(&format!("vless://{UUID}@h.example.com:443?type=quic"));
        expect_malformed(&format!(
            "vless://{UUID}@h.example.com:443?type=tcp&headerType=bogus"
        ));
    }

    #[test]
    fn to_link_refuses_the_import_only_protocols() {
        // The import grammar names these protocols; export renders none of
        // them. Hysteria refuses through its transport (the row spells no
        // `type`) before the protocol-level check, exactly as it did before
        // the hysteria2 link existed.
        let cases = [
            (
                parse_link("socks5://u:p@h.example.com:1080")
                    .unwrap()
                    .profile,
                t_fmt(Language::En, Key::LinkUnsupportedProtocol, &[&"socks"]),
            ),
            (
                parse_link("http://h.example.com:8080").unwrap().profile,
                t_fmt(Language::En, Key::LinkUnsupportedProtocol, &[&"http"]),
            ),
            (
                parse_link("hysteria2://pw@h.example.com:443")
                    .unwrap()
                    .profile,
                t_fmt(Language::En, Key::LinkUnsupportedHysteria, &[]),
            ),
            (
                parse_link(&wireguard_link()).unwrap().profile,
                t_fmt(Language::En, Key::LinkUnsupportedProtocol, &[&"wireguard"]),
            ),
        ];
        for (profile, expected) in cases {
            match to_link(&profile) {
                Err(LinkError::Unsupported(message)) => {
                    assert_eq!(message.text(Language::En), expected);
                }
                other => panic!(
                    "expected Unsupported({expected:?}), got {}",
                    outcome_shape(&other)
                ),
            }
        }
    }

    #[test]
    fn hysteria_has_no_share_grammar_in_either_direction() {
        // The grammar spells no `type` for hysteria: import reports the value
        // as an unknown transport, and export refuses the live model network
        // with its own message.
        expect_malformed(&format!("vless://{UUID}@h.example.com:443?type=hysteria"));

        let mut profile = parse_link(&format!(
            "vless://{UUID}@tls.local:443?security=tls&sni=tls.local#Hysteria"
        ))
        .unwrap();
        profile.outbound.stream.network = Network::Hysteria;
        profile.outbound.stream.hysteria_settings =
            Some(crate::model::stream::HysteriaTransport::default());
        match to_link(&profile) {
            Err(LinkError::Unsupported(message)) => assert_eq!(
                message.text(Language::En),
                t_fmt(Language::En, Key::LinkUnsupportedHysteria, &[])
            ),
            other => panic!(
                "expected Unsupported(Hysteria), got {}",
                outcome_shape(&other)
            ),
        }
    }

    // ----- bulk -----

    #[test]
    fn bulk_skips_blanks_and_comments() {
        let ui = URL_SAFE_NO_PAD.encode("aes-128-gcm:pw");
        let text = format!(
            "# subscription comment\n\n   \nvless://{UUID}@a.local:443?encryption=none#A\nss://{ui}@b.example.com:8388#B\nnot a link\n"
        );
        let res = parse_bulk(&text);
        assert_eq!(res.len(), 3);
        assert!(res[0].is_ok());
        assert!(res[1].is_ok());
        assert!(matches!(res[2], Err(LinkError::Malformed(_))));
    }

    // ----- qr -----

    #[test]
    fn qr_renders_with_a_full_four_module_quiet_zone() {
        let payload = "vless://x@y:443";
        let code =
            qrcode::QrCode::with_error_correction_level(payload.as_bytes(), qrcode::EcLevel::M)
                .unwrap();
        let width = code.width();
        let modules = width + 8;
        let scale = (256 / modules).max(1);
        let quiet_pixels = 4 * scale;

        let img = qr_color_image(payload).expect("short input must fit");
        assert_eq!(img.size, [modules * scale, modules * scale]);
        assert!(img.pixels.contains(&egui::Color32::BLACK));
        let side = img.size[0];
        for y in 0..side {
            for x in 0..quiet_pixels {
                assert_eq!(img.pixels[y * side + x], egui::Color32::WHITE);
                assert_eq!(img.pixels[y * side + side - 1 - x], egui::Color32::WHITE);
            }
        }
        for y in 0..quiet_pixels {
            for x in 0..side {
                assert_eq!(img.pixels[y * side + x], egui::Color32::WHITE);
                assert_eq!(img.pixels[(side - 1 - y) * side + x], egui::Color32::WHITE);
            }
        }
        // The top-left finder starts at module (0, 0), immediately after the
        // four-module margin. This prevents a larger pixel margin from hiding
        // an undersized module margin in the assertion above.
        assert_eq!(
            img.pixels[quiet_pixels * side + quiet_pixels],
            egui::Color32::BLACK
        );
        assert_eq!(
            img.pixels[quiet_pixels * side + side - quiet_pixels - 1],
            egui::Color32::BLACK
        );
        assert_eq!(
            img.pixels[(side - quiet_pixels - 1) * side + quiet_pixels],
            egui::Color32::BLACK
        );
    }

    #[test]
    fn qr_byte_capacity_boundary_is_exact() {
        // Version 40-M carries 2331 bytes in byte mode, including mode/count
        // overhead. Lowercase `x` forces byte mode rather than alphanumeric.
        assert!(qr_color_image(&"x".repeat(2331)).is_some());
        assert!(qr_color_image(&"x".repeat(2332)).is_none());
    }

    // ----- gen smoke: parsed profiles feed the config generator -----

    #[test]
    fn parsed_profiles_generate() {
        let ui = URL_SAFE_NO_PAD.encode("aes-128-gcm:pw");
        let public_key = reality_public_key();
        let links = [
            format!(
                "vless://{UUID}@r.example.com:443?security=reality&sni=x.com&fp=chrome&pbk={public_key}&sid=01&spx=%2F&type=tcp#R"
            ),
            vmess_json(serde_json::json!({
                "v": "2", "ps": "V", "add": "v.example.com", "port": "443",
                "id": UUID, "net": "ws", "host": "h.com", "path": "/ws", "tls": "tls"
            })),
            "trojan://pw@t.example.com:443#T".to_string(),
            format!("ss://{ui}@s.example.com:8388#S"),
        ];
        let mut servers = crate::model::ServersFile::default();
        for link in &links {
            servers.profiles.push(parse_link(link).unwrap().profile);
        }
        let cfg = crate::r#gen::generate(&servers, &crate::model::Settings::default())
            .expect("generate config");
        let outbounds = cfg["outbounds"].as_array().expect("outbounds array");
        // 4 servers + built-in direct/block + dns-out (seeded DNS module)
        assert_eq!(outbounds.len(), 7);
        for outbound in &outbounds[..4] {
            assert!(outbound["tag"].as_str().unwrap().starts_with("srv-"));
        }
        assert_eq!(outbounds[4]["tag"], "direct");
        assert_eq!(outbounds[5]["tag"], "block");
        assert_eq!(outbounds[6]["tag"], DNS_OUTBOUND_TAG);
    }

    // ----- input-size caps and error redaction -----

    #[test]
    fn parse_link_rejects_overlong_line_before_parsing() {
        let payload = "a".repeat(MAX_LINK_LEN + 1);
        let link = format!("vless://{payload}:443");
        match parse_link(&link) {
            Err(LinkError::Malformed(message)) => {
                let message = message.text(Language::En);
                assert!(
                    message.contains("link is too long"),
                    "message must name the cap: {message:?}"
                );
                assert!(
                    !message.contains(&payload),
                    "error must not echo the raw input: {message:?}"
                );
            }
            other => panic!("expected too-long rejection, got {}", outcome_shape(&other)),
        }
    }

    #[test]
    fn parse_bulk_rejects_overlong_single_line_but_keeps_valid_lines() {
        let long = format!("vless://{}:443", "b".repeat(MAX_LINK_LEN));
        let text = format!(
            "vless://{UUID}@ok.local:443?encryption=none#Ok\n\
             {long}\n\
             vless://{UUID}@ok2.local:443?encryption=none#Ok2\n"
        );
        let parsed = parse_bulk(&text);
        assert_eq!(parsed.len(), 3, "all three lines must yield a result");
        assert!(parsed[0].is_ok(), "short line before the long one");
        match &parsed[1] {
            Err(LinkError::Malformed(message)) => {
                let message = message.text(Language::En);
                assert!(
                    message.contains("link is too long"),
                    "message must name the cap: {message:?}"
                );
                assert!(!message.contains(&long), "error must not echo the line");
            }
            other => panic!("expected too-long rejection, got {}", outcome_shape(other)),
        }
        assert!(parsed[2].is_ok(), "short line after the long one");
    }

    #[test]
    fn parse_bulk_rejects_oversized_blob_wholesale() {
        let text = "x".repeat(MAX_BULK_LEN + 1);
        let parsed = parse_bulk(&text);
        assert_eq!(parsed.len(), 1, "one wholesale error entry");
        match &parsed[0] {
            Err(LinkError::Malformed(message)) => {
                let message = message.text(Language::En);
                assert!(
                    message.contains("text is too large"),
                    "message must name the cap: {message:?}"
                );
                assert!(!message.contains(&text), "error must not echo the blob");
            }
            other => panic!("expected too-large rejection, got {}", outcome_shape(other)),
        }
    }

    #[test]
    fn parse_bulk_cancellable_worker_delivers_via_channel() {
        let text = format!(
            "vless://{UUID}@a.local:443?encryption=none#A\n\
             # comment line\n\
             \n\
             vless://{UUID}@b.local:443?encryption=none#B\n"
        );
        let cancel = AtomicBool::new(false);
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let parsed = parse_bulk_cancellable(&text, &cancel);
            let _ = tx.send(parsed);
        });
        let parsed = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("worker result must arrive via the channel");
        handle.join().expect("worker thread must join");
        let parsed = parsed.expect("cancel flag was never set");
        assert_eq!(parsed.len(), 2, "comments and blank lines are skipped");
        assert!(parsed.iter().all(|result| result.is_ok()));
    }

    #[test]
    fn parse_bulk_cancellable_returns_none_when_cancel_is_preset() {
        let cancel = AtomicBool::new(true);
        assert!(
            parse_bulk_cancellable("vless://anything.local:443", &cancel).is_none(),
            "preset cancel must discard the parse"
        );
    }

    #[test]
    fn parse_bulk_cancellable_stops_when_cancelled_mid_run() {
        // Enough lines that the worker cannot finish before the flag is set:
        // the cooperative check between lines must return `None`.
        let line = "vless://{UUID}@c.local:443?encryption=none#C\n";
        let mut text = String::new();
        for _ in 0..50_000 {
            text.push_str(line);
        }
        assert!(
            text.len() <= MAX_BULK_LEN,
            "fixture must stay under the bulk cap"
        );
        let cancel = AtomicBool::new(false);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let parsed = parse_bulk_cancellable(&text, &cancel);
                let _ = tx.send(parsed);
            });
            // Set the flag from the test thread while the worker is
            // mid-parse: the per-line cooperative check must return `None`.
            cancel.store(true, Ordering::Relaxed);
        });
        let parsed = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("worker result must arrive via the channel");
        assert!(
            parsed.is_none(),
            "cancelled parse must discard partial results"
        );
    }

    #[test]
    fn parse_errors_never_echo_full_raw_input() {
        let payload = "A".repeat(100_000);
        let cases = [
            // No scheme at all.
            payload.clone(),
            // Scheme starts with a digit → "bad scheme".
            format!("1{payload}://host"),
            // Long but structurally valid scheme → Unsupported, bounded.
            format!("{payload}://host"),
            // Over-long host inside an otherwise valid link.
            format!("vless://{payload}:443"),
            // Over-long percent-encoded component.
            format!("vless://{UUID}@h.example.com:443?path={payload}"),
        ];
        for input in &cases {
            let error = match parse_link(input) {
                Ok(_) => panic!("fixture must be rejected: {input:.64}…"),
                Err(error) => error.text(Language::En),
            };
            assert!(
                !error.contains(&payload),
                "error must not embed the raw input: {error:?}"
            );
            assert!(
                error.len() < payload.len(),
                "error ({}) must be strictly smaller than the raw input ({}): {error:?}",
                error.len(),
                payload.len()
            );
        }
    }

    /// The fingerprint grammar predicates must track the canonical model
    /// table (src/model/fingerprint.rs): adding one fingerprint there lands
    /// in TLS and REALITY import alike. Expectations derive from the table's
    /// own context split, never from a duplicated literal list.
    #[test]
    fn fingerprint_grammar_matches_the_canonical_fingerprint_table() {
        use crate::model::fingerprint::{FINGERPRINTS, VALIDATION_ONLY_FINGERPRINTS};
        for &name in FINGERPRINTS {
            // TLS import accepts the editor-visible subset verbatim.
            assert_eq!(
                supported_tls_fingerprint(name),
                !VALIDATION_ONLY_FINGERPRINTS.contains(&name),
                "TLS grammar mismatch for {name:?}"
            );
            // REALITY import additionally rejects the three names its
            // grammar never carries: empty, unsafe, hellogolang.
            assert_eq!(
                supported_reality_fingerprint(name),
                !VALIDATION_ONLY_FINGERPRINTS.contains(&name)
                    && !matches!(name, "" | "unsafe" | "hellogolang"),
                "REALITY grammar mismatch for {name:?}"
            );
        }
        // Wire-only names (validation-only by definition) stay un-importable.
        for &name in VALIDATION_ONLY_FINGERPRINTS {
            assert!(
                !supported_tls_fingerprint(name),
                "{name:?} importable as TLS"
            );
            assert!(
                !supported_reality_fingerprint(name),
                "{name:?} importable as REALITY"
            );
        }
        // Case sensitivity is grammar behavior: mixed-case names never match.
        assert!(!supported_tls_fingerprint("Chrome"));
        assert!(!supported_reality_fingerprint("Chrome"));
    }

    /// End-to-end: a share link whose `fm` parameter feeds a
    /// model-validation code with a ~1 MiB attacker string must fail import
    /// with a bounded message. The excerpting happens once, at code
    /// construction in the model layer, so the import-error surface (what the
    /// UI/log renders) never sees the full value.
    #[test]
    fn hostile_megabyte_finalmask_values_yield_bounded_import_errors() {
        // Unknown UDP mask discriminator — the largest attacker string that
        // fits inside the 1 MiB wire cap.
        let hostile = "u".repeat(MAX_LINK_LEN - 512);
        let fm = format!(r#"{{"udp":[{{"type":"{hostile}","settings":{{}}}}]}}"#);
        let link = format!(
            "vless://{UUID}@router.local:443?encryption=none&fm={}#X",
            pct_encode(&fm)
        );
        assert!(link.len() <= MAX_LINK_LEN, "fixture must fit the wire cap");
        match parse_link(&link) {
            Err(error @ LinkError::InvalidModel { .. }) => {
                assert_eq!(
                    error.text(Language::En),
                    format!(
                        "The finalmask settings are invalid: finalmask.udp[0]: unsupported future \
                         UDP mask discriminator Some(\"{}\u{2026}\"). The raw value \
                         is preserved",
                        &hostile[..MAX_ERROR_EXCERPT_CHARS]
                    )
                );
            }
            other => panic!("expected bounded Malformed, got {}", outcome_shape(&other)),
        }

        // Invalid port-list text item — the Debug-quoted embed path.
        let hostile = "a".repeat(MAX_LINK_LEN - 512);
        let fm = format!(
            r#"{{"udp":[{{"type":"udphop","settings":{{"mode":"intervalLocal","interval":"5-10","remotePorts":"1-5,{hostile}"}}}}]}}"#
        );
        let link = format!(
            "vless://{UUID}@router.local:443?encryption=none&fm={}#X",
            pct_encode(&fm)
        );
        assert!(link.len() <= MAX_LINK_LEN, "fixture must fit the wire cap");
        match parse_link(&link) {
            Err(error @ LinkError::InvalidModel { .. }) => {
                assert_eq!(
                    error.text(Language::En),
                    format!(
                        "The finalmask settings are invalid: \
                         finalmask.udp[0].settings.remotePorts: \
                         \"{}\u{2026}\" is not a port, port range, or env:NAME entry",
                        &hostile[..MAX_ERROR_EXCERPT_CHARS]
                    )
                );
            }
            other => panic!("expected bounded Malformed, got {}", outcome_shape(&other)),
        }
    }

    #[test]
    fn error_text_renders_through_the_locale_table() {
        let malformed = LinkError::Malformed(Diag::new(Key::LinkHostMissing).arg("vless"));
        assert_eq!(
            malformed.text(Language::En),
            t_fmt(Language::En, Key::LinkHostMissing, &[&"vless"])
        );
        assert_eq!(malformed.to_string(), malformed.text(Language::En));

        let unsupported =
            LinkError::Unsupported(Diag::new(Key::LinkUnsupportedQueryField).arg("x"));
        assert_eq!(
            unsupported.text(Language::En),
            t_fmt(Language::En, Key::LinkUnsupportedQueryField, &[&"x"])
        );

        let lossy = LinkError::Lossy(Diag::new(Key::LinkLossyMux).arg("mux"));
        assert_eq!(
            lossy.text(Language::En),
            t_fmt(Language::En, Key::LinkLossyMux, &[&"mux"])
        );
    }

    #[test]
    fn invalid_model_text_renders_the_finding_and_the_prefix() {
        let issue = ValidationIssue {
            code: crate::model::validation::ValidationCode::StreamOneNoDownload,
            path: Some("stream.xhttpSettings".into()),
            severity: crate::model::validation::Severity::Error,
        };
        let bare = LinkError::InvalidModel {
            prefix: None,
            issue: Box::new(issue.clone()),
        };
        assert_eq!(
            bare.text(Language::En),
            validation_issue_message(&issue, Language::En)
        );

        let prefixed = LinkError::InvalidModel {
            prefix: Some(Key::LinkFinalmaskInvalid),
            issue: Box::new(issue.clone()),
        };
        assert_eq!(
            prefixed.text(Language::En),
            t_fmt(
                Language::En,
                Key::LinkFinalmaskInvalid,
                &[&validation_issue_message(&issue, Language::En)],
            )
        );
        assert_eq!(prefixed.to_string(), prefixed.text(Language::En));
    }
}
