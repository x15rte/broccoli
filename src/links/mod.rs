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
//! Inputs that name removed or unrepresentable behavior are rejected, never
//! dropped or normalized:
//! - `allowInsecure`, mKCP `seed` / `headerType`, Trojan `flow`, SIP002
//!   `plugin=`, VMess `aid > 0`, `security=xtls`, and removed transports.
//! - gRPC `mode=guna`, which Xray's boolean `multiMode` cannot express.
//! - URL fields that are unknown, duplicated after percent-decoding, empty
//!   when #716 forbids emptiness, or valid only for a different transport or
//!   security mode.
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

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::diag::Diag;
use crate::i18n::{Key, t_fmt, validation_issue_message};
use crate::model::outbound::{
    OutboundModel, Protocol, ProtocolSettings, ShadowsocksSettings, TrojanSettings, VlessSettings,
    VmessSettings, vless_encryption_supported,
};
use crate::model::servers::ServerProfile;
use crate::model::settings::Language;
use crate::model::stream::{
    FinalmaskModel, GrpcSettings, HttpCamouflageRequest, HttpupgradeSettings, KcpSettings, Network,
    RawHeader, RawSettings, RealityModel, Security, StreamModel, TlsModel, WsSettings,
    XhttpSettings,
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

/// Parse `host:port` / `[v6]:port`. Returns host without brackets.
fn parse_host_port(hp: &str, scheme: &str) -> Result<(String, u16), LinkError> {
    let (host, port_s) = if let Some(rest) = hp.strip_prefix('[') {
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
        let port_s = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| malformed(Diag::new(Key::LinkPortMissing).arg(scheme)))?;
        (host.to_string(), port_s)
    } else {
        if hp.contains('[') || hp.contains(']') {
            return Err(malformed(Diag::new(Key::LinkHostBracketed).arg(scheme)));
        }
        let (h, p) = hp
            .rsplit_once(':')
            .ok_or_else(|| malformed(Diag::new(Key::LinkPortMissing).arg(scheme)))?;
        if h.contains(':') {
            return Err(malformed(
                Diag::new(Key::LinkHostIpv6Unbracketed).arg(scheme),
            ));
        }
        (h.to_string(), p)
    };
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

fn validate_url_query(q: &Query, proto: Protocol) -> Result<(), LinkError> {
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
            "allowInsecure" => {
                return Err(LinkError::Unsupported(Diag::new(
                    Key::LinkUnsupportedAllowInsecure,
                )));
            }
            "seed" | "headerType" => {
                return Err(LinkError::Unsupported(
                    Diag::new(Key::LinkUnsupportedField).arg(key),
                ));
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
            .find(|spec| spec.type_string == Some(other))
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

const RAW: TransportSpec = TransportSpec {
    network: Network::Raw,
    path: "streamSettings.rawSettings",
    type_string: Some(DEFAULT_TYPE),
    fields: &[],
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
    parse: fn(&str) -> Result<ServerProfile, LinkError>,
}

/// The share grammar's supported set, one row per shareable protocol: the
/// schemes `parse_link` accepts and the protocols `to_link` renders. Any other
/// protocol is refused with [`unsupported_protocol`].
const SHAREABLE: &[Shareable] = &[
    Shareable {
        scheme: "vless",
        protocol: Protocol::Vless,
        parse: |body| parse_url_style(body, Protocol::Vless),
    },
    Shareable {
        scheme: "vmess",
        protocol: Protocol::Vmess,
        parse: parse_vmess_body,
    },
    Shareable {
        scheme: "trojan",
        protocol: Protocol::Trojan,
        parse: |body| parse_url_style(body, Protocol::Trojan),
    },
    Shareable {
        scheme: "ss",
        protocol: Protocol::Shadowsocks,
        parse: parse_ss,
    },
];

/// #716 names the VMess URL form when the body carries a userinfo, and the
/// obsolete whole-body Base64-JSON form otherwise.
fn parse_vmess_body(body: &str) -> Result<ServerProfile, LinkError> {
    if body.contains('@') {
        parse_url_style(body, Protocol::Vmess)
    } else {
        parse_legacy_vmess(body)
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

fn parse_url_style(body: &str, proto: Protocol) -> Result<ServerProfile, LinkError> {
    let scheme = proto.as_str();
    let (auth, query, frag) = split_link(body);
    let (userinfo, hp) = auth
        .split_once('@')
        .ok_or_else(|| malformed(Diag::new(Key::LinkUserinfoMissing).arg(scheme)))?;
    if hp.contains('@') {
        return Err(malformed(Diag::new(Key::LinkUserinfoAt).arg(scheme)));
    }
    let user = pct_decode(userinfo)?;
    let (host, port) = parse_host_port(hp, scheme)?;
    let q = parse_query(query)?;
    validate_url_query(&q, proto)?;
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

fn parse_legacy_vmess(body: &str) -> Result<ServerProfile, LinkError> {
    let raw = b64_decode_any(body).ok_or_else(|| malformed(Diag::new(Key::LinkVmessBase64)))?;
    let v: Value = serde_json::from_slice(&raw)
        .map_err(|e| malformed(Diag::new(Key::LinkVmessJson).arg(excerpt(&e.to_string()))))?;
    let o = v
        .as_object()
        .ok_or_else(|| malformed(Diag::new(Key::LinkVmessObject)))?;
    const LEGACY_FIELDS: &[&str] = &[
        "v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni",
        "alpn", "fp",
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

    let net = get("net");
    let typ = get("type");
    let host = get("host");
    let path = get("path");
    match net.to_ascii_lowercase().as_str() {
        "" | "tcp" => {
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

fn parse_ss(body: &str) -> Result<ServerProfile, LinkError> {
    let (rest, frag0) = match body.find('#') {
        Some(i) => (&body[..i], &body[i + 1..]),
        None => (body, ""),
    };
    let (rest, raw_query) = match rest.find('?') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    let query = parse_query(raw_query)?;
    // Any query field makes the link unsupported; the first key decides the
    // message (SIP002 plugins have their own diagnostic).
    if let Some((key, _)) = query.0.first() {
        if key == "plugin" {
            return Err(LinkError::Unsupported(Diag::new(
                Key::LinkUnsupportedSsPlugin,
            )));
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
            // The grammar spells no `type` for this transport, so a profile
            // that names it cannot cross the import/export boundary either:
            // the row's own check states the refusal.
            transport_spec(Network::Hysteria).spelling()?;
        }
    }
    if let Some(finalmask) = stream.finalmask.as_ref() {
        validate_finalmask(finalmask)?;
    }
    Ok(())
}

fn validate_2022_key(method: &str, password: &str) -> bool {
    let key_len = match method {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => 32,
        _ => return true,
    };
    if method == "2022-blake3-chacha20-poly1305" && password.contains(':') {
        return false;
    }
    password.split(':').all(|key| {
        STANDARD
            .decode(key)
            .or_else(|_| STANDARD_NO_PAD.decode(key))
            .is_ok_and(|decoded| decoded.len() == key_len)
    })
}

/// Pure, side-effect-free validation for imported/shareable profiles.
///
/// This mirrors the local Xray configuration builders' required fields and
/// cross-field invariants. Callers that persist an imported profile should
/// additionally run the generated scratch config through `xray run -test`.
pub fn validate_profile(profile: &ServerProfile) -> Result<(), LinkError> {
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
            if !validate_2022_key(&settings.method, &settings.password) {
                return Err(malformed(Diag::new(Key::LinkSsKeyMaterial)));
            }
        }
        other => return Err(unsupported_protocol(other.protocol())),
    }

    // Model validation pass: protocol, stream, and transport-security
    // invariants in one sweep (no short-circuit). The verdict's first
    // blocking finding blocks the import/export; its advisory findings are
    // the profile that is xray-legal and imports fine. Remaining #716
    // grammar checks run below.
    if let Some(issue) = validate_outbound(&profile.outbound).into_first_blocking() {
        return Err(LinkError::InvalidModel {
            prefix: None,
            issue: Box::new(issue),
        });
    }

    validate_stream_core(&profile.outbound.stream)
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
/// `#fragment`, else the server host).
pub fn parse_link(s: &str) -> Result<ServerProfile, LinkError> {
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
    let profile = match SHAREABLE.iter().find(|row| row.scheme == lowered.as_str()) {
        Some(row) => (row.parse)(body),
        None => Err(LinkError::Unsupported(
            Diag::new(Key::LinkUnsupportedScheme).arg(excerpt(&lowered)),
        )),
    }?;
    validate_profile(&profile)?;
    Ok(profile)
}

/// Parse a paste/subscription blob: one link per line; blank lines and
/// `#comment` lines are skipped. The whole blob is bounded by
/// [`MAX_BULK_LEN`]; an oversized blob yields one `Malformed` error entry.
pub fn parse_bulk(text: &str) -> Vec<Result<ServerProfile, LinkError>> {
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
) -> Option<Vec<Result<ServerProfile, LinkError>>> {
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
        (p2, s3)
    }

    fn vmess_json(v: Value) -> String {
        format!(
            "vmess://{}",
            STANDARD.encode(serde_json::to_vec(&v).unwrap())
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
        // The import must surface the advisory finding through the model pass.
        let issues = crate::model::validation::validate_outbound(&profile.outbound);
        assert!(
            issues.iter().any(|issue| {
                issue.code == crate::model::validation::ValidationCode::ServerNameImplausible
                    && issue.severity == crate::model::validation::Severity::Warning
            }),
            "{issues:#?}"
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
    fn vless_tcp_http_camo_query_is_rejected() {
        expect_unsupported(&format!(
            "vless://{UUID}@camo.example.com:8080?type=tcp&headerType=http&host=cdn.example.com&path=%2Fcamo"
        ));
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
    fn trojan_allow_insecure_is_rejected() {
        expect_unsupported("trojan://pw@ai.example.com:443?allowInsecure=1&sni=x.com#AI");
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
        let key = STANDARD_NO_PAD.encode([3_u8; 16]);
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

        let key16_a = STANDARD_NO_PAD.encode([1_u8; 16]);
        let key16_b = STANDARD.encode([2_u8; 16]);
        let aes_multi =
            URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-128-gcm:{key16_a}:{key16_b}"));
        parse_link(&format!("ss://{aes_multi}@ss.example.com:8388")).unwrap();

        let bad_aes = URL_SAFE_NO_PAD.encode(format!("2022-blake3-aes-256-gcm:{key16_a}"));
        expect_malformed(&format!("ss://{bad_aes}@ss.example.com:8388"));

        let key32_a = STANDARD_NO_PAD.encode([3_u8; 32]);
        let key32_b = STANDARD_NO_PAD.encode([4_u8; 32]);
        for method in ["2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"] {
            let valid = URL_SAFE_NO_PAD.encode(format!("{method}:{key32_a}"));
            parse_link(&format!("ss://{valid}@ss.example.com:8388"))
                .unwrap_or_else(|error| panic!("{method}: {error}"));
        }
        let bad_chacha =
            URL_SAFE_NO_PAD.encode(format!("2022-blake3-chacha20-poly1305:{key32_a}:{key32_b}"));
        expect_malformed(&format!("ss://{bad_chacha}@ss.example.com:8388"));
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
        expect_unsupported("http://example.com");
        expect_unsupported("hy2://pw@h.example.com:443");
        expect_unsupported("socks5://u:p@h.example.com:1080");
        expect_unsupported(&format!("vless://{UUID}@h.example.com:443?security=xtls"));
        expect_unsupported(&format!("vless://{UUID}@h.example.com:443?type=http"));
        expect_unsupported(&format!("vless://{UUID}@h.example.com:443?type=quic"));
        expect_unsupported(&format!(
            "vless://{UUID}@h.example.com:443?type=tcp&headerType=bogus"
        ));
    }

    #[test]
    fn to_link_unsupported_protocols() {
        let p = ServerProfile::new("x", OutboundModel::new(Protocol::Wireguard));
        match to_link(&p) {
            Err(LinkError::Unsupported(_)) => {}
            other => panic!("expected Unsupported, got {}", outcome_shape(&other)),
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
            servers.profiles.push(parse_link(link).unwrap());
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
