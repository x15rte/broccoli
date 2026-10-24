//! Validation rules of the stream scope.
//!
//! Split out of [`crate::model::validation`]; that module holds the taxonomy
//! and the vocabulary more than one scope reads.

use super::outbound::{validate_masque_stream, validate_xdrive_stream};
use super::{
    ValidationCode, ValidationIssue, Verdict, excerpt, excerpt_debug, extra_has_key, extra_key_set,
    is_vision_flow, issue, warning,
};
use crate::model::outbound::{OutboundModel, ProtocolSettings};
use crate::model::stream::{
    FinalmaskFilter, FinalmaskModel, FinalmaskPortList, FinalmaskQuicParams, FinalmaskRawValue,
    FinalmaskSudoku, FinalmaskTcpMask, FinalmaskTransform, FinalmaskUdpMask, FinalmaskXdnsDomain,
    FinalmaskXmc, MAX_XHTTP_DOWNLOAD_DEPTH, Network, Security, SockoptModel, StreamModel, TlsModel,
    XmuxConfig,
};
use crate::model::{
    Int32Range, fold_eq, fold_lower, go_std_base64_decode, go_std_base64_decodes, parse_range_go,
    vocabulary_holds,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

/// Predicate shared with the editor's targeted-inline hints: true when a
/// TLS/REALITY `serverName` cannot plausibly be a hostname or IP
/// literal — canonical UUID (8-4-4-4-12 hex, case-insensitive), exactly 32
/// hex characters, or any character that can never appear in a DNS name or
/// IP literal (anything outside ASCII alphanumerics, `-._:`, and Unicode
/// alphanumerics). IP literals (v4/v6), punycode and raw-unicode IDN forms,
/// single labels, and underscore labels never warn; empty is out of scope
/// (no editor-side rule covers it — the xray `run -test` report does).
pub fn server_name_implausible(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    // Canonical 8-4-4-4-12 UUID (hex is case-insensitive). Byte positions
    // 8/13/18/23 must hold the dashes; non-ASCII bytes fail hexdigit, so a
    // multibyte string of the same byte length cannot slip through.
    let uuid_shaped = value.len() == 36
        && value.as_bytes().iter().enumerate().all(|(i, &byte)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        });
    // Bare 32-hex value.
    let bare_32_hex = value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    uuid_shaped
        || bare_32_hex
        || value
            .chars()
            .any(|c| !(c.is_alphanumeric() || matches!(c, '-' | '.' | '_' | ':')))
}

// ---------- protocol-settings vocabulary ----------
//
// Every predicate here mirrors the share-link import grammar (the
// `validate_profile` whitelists in `crate::links`) and the Xray conf
// builders they cite, so the model seam, the import grammar, and the
// editor never disagree about a value's acceptability. Keep the two
// mirrors in lockstep: same literals, same comparisons. The VLESS
// encryption rule is not mirrored but shared: `vless_encryption_supported`
// lives in `super::outbound`, and the model pass, the import grammar, and
// the editor validator all call it. The UUID rule is shared the same way:
// `is_canonical_uuid` below is its one definition, and the import grammar,
// the finalmask validator, and the editor validator call it.

/// True when a VLESS `flow` is acceptable on the wire —
/// empty (the default) or one of the two vision (XRV) variants. Xray's conf
/// build rejects every other flow (conf/vless.go).
pub(super) fn vless_flow_supported(flow: &str) -> bool {
    flow.is_empty() || is_vision_flow(flow)
}

/// The VMess `settings.security` vocabulary: the ciphers the core's account
/// build reads after it lowercases the value (infra/conf/vmess.go:27-36).
/// The editor combo and the share-link grammar both read this list.
pub const VMESS_SECURITY_OPTIONS: &[&str] = &["auto", "aes-128-gcm", "chacha20-poly1305"];

/// True when a VMess `settings.security` is one the core reads: the empty zero
/// value or one of [`VMESS_SECURITY_OPTIONS`], under [`vocabulary_holds`]. A
/// value outside the set is not refused — the core maps it onto `auto` — so
/// the rule wired to this predicate warns instead of gating.
pub fn vmess_security_supported(security: &str) -> bool {
    security.is_empty() || vocabulary_holds(VMESS_SECURITY_OPTIONS, security)
}

/// The AEAD method vocabulary: the canonical spellings, then the legacy
/// aliases Xray's `cipherFromString` folds onto them (each alias sits beside
/// the canonical name it names). Compared under the core's own fold, which
/// lowercases the value before its switch (infra/conf/shadowsocks.go:18); the
/// 2022 names are a separate, exact list in the core.
const SS_AEAD_METHODS: &[&str] = &[
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
];

/// The Shadowsocks-2022 method names. `GetCipherMethod` lowercases the whole
/// value before its map lookup (`proxy/shadowsocks_2022/cipher.go:24-30`), so
/// a case variant is the same method the core builds.
const SS_METHODS_2022: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

/// The Shadowsocks method vocabulary the editors offer and the share links
/// spell, in display order: the four canonical AEAD methods, then the 2022
/// methods. Spelled element-wise from the two accepted lists, so the offered
/// set can never hold a method the rule refuses (the legacy alias spellings
/// are accepted but never offered).
pub const SS_METHOD_OPTIONS: &[&str] = &[
    SS_AEAD_METHODS[0],
    SS_AEAD_METHODS[2],
    SS_AEAD_METHODS[6],
    SS_AEAD_METHODS[9],
    SS_METHODS_2022[0],
    SS_METHODS_2022[1],
    SS_METHODS_2022[2],
];

/// True when a Shadowsocks `method` is in Xray's
/// accepted vocabulary — the AEAD methods and their legacy alias spellings
/// (`cipherFromString`) plus the 2022 method names. Every spelling folds
/// case-insensitively, exactly as the core folds it before its own lookup
/// (`infra/conf/shadowsocks.go:17` and
/// `proxy/shadowsocks_2022/cipher.go:24`). Legacy *stream* ciphers (e.g.
/// `aes-256-cfb`) and anything else fall through to the unknown-cipher load
/// error and are unsupported. The share-link grammar calls this predicate
/// instead of re-listing the methods.
pub fn shadowsocks_method_supported(method: &str) -> bool {
    vocabulary_holds(SS_AEAD_METHODS, method) || vocabulary_holds(SS_METHODS_2022, method)
}

/// The key size one Shadowsocks-2022 method uses, or `None` for a method that
/// is not a 2022 method (the core then treats the password as an opaque legacy
/// key). The name folds like the core's own lookup.
fn shadowsocks_2022_key_length(method: &str) -> Option<usize> {
    if fold_eq(method, "2022-blake3-aes-128-gcm") {
        Some(16)
    } else if fold_eq(method, "2022-blake3-aes-256-gcm")
        || fold_eq(method, "2022-blake3-chacha20-poly1305")
    {
        Some(32)
    } else {
        None
    }
}

/// True when `password` carries key material the rewritten core's
/// Shadowsocks-2022 client builds — the question the share-link grammar asks
/// before it imports a profile, and the rule the outbound pass uses. `None`
/// from [`shadowsocks_2022_key_length`] (a non-2022 method) and an empty
/// password (the required-value rule owns that state) are usable here.
///
/// The core parses the password as a colon-separated PSK list (`ParsePSKList`
/// in `proxy/shadowsocks_2022/kdf.go`), and each part through `ParseKey`: it
/// decodes the part as standard base64 and falls back to the raw bytes when
/// the decode fails, then requires the decoded length to equal the method's
/// key size exactly. The ChaCha20 method accepts one part only
/// (`outbound.go`). So a wrong-length key — base64 or raw — is refused, and a
/// right-length key in either form is accepted.
pub fn shadowsocks_2022_key_usable(method: &str, password: &str) -> bool {
    let Some(key_len) = shadowsocks_2022_key_length(method) else {
        return true;
    };
    if password.is_empty() {
        return true;
    }
    if fold_eq(method, "2022-blake3-chacha20-poly1305") && password.contains(':') {
        return false;
    }
    password
        .split(':')
        .all(|part| match go_std_base64_decode(part) {
            Some(decoded) => decoded.len() == key_len,
            // Go falls back to `[]byte(key)` when the decode fails, so the raw
            // UTF-8 byte length is what the key-size check then reads.
            None => part.len() == key_len,
        })
}

/// The UUID format policy, one definition: true when an id is a canonical
/// UUID under `uuid::Uuid::parse_str`. Xray itself sha1-maps 1-30-char
/// strings to a deterministic v5 UUID (common/uuid/uuid.go) and accepts
/// 32-36-char hex forms, so only a true UUID dials the configured account.
/// The import grammar's `check_uuid`, the finalmask XMC validator, and the
/// editor's UUID field validator all call this predicate, each keeping only
/// its own message channel.
pub(crate) fn is_canonical_uuid(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok()
}

// ---------- transport-security formats ----------
//
// Single-source predicates for the TLS/REALITY security-format rules. The
// share-link import grammar
// (`validate_reality` / `validate_tls` in `crate::links`) delegates its
// shape checks to these predicates and the editor's keygen guards call
// them, so import, model, and editor can never disagree about a value's
// acceptability. Fingerprint vocabulary lives in `crate::model::fingerprint`
// (the canonical tables); this module only consumes its predicates.

/// Predicate shared with the share-link grammar's pbk check and the editor's
/// derive guard: true when the REALITY client `publicKey` (stored in the
/// profile's `password` field, the upstream alias) is an unpadded base64url
/// string decoding to exactly 32 bytes. Empty is invalid
/// — Xray's conf build refuses an empty key (`empty "password"`) and the
/// import grammar requires it.
pub fn reality_public_key_valid(value: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(value)
        .is_ok_and(|decoded| decoded.len() == 32)
}

/// mKCP hard load bound (shared with the share-link grammar's kcp check):
/// true when `mtu` satisfies Xray's KCPConfig.Build floor of 21
/// (infra/conf/transport_method.go: "Mtu must be at least 21").
pub fn kcp_mtu_hard_ok(mtu: u32) -> bool {
    mtu >= 21
}

/// mKCP hard load bound (shared with the share-link grammar's kcp check):
/// true when `tti` lies within Xray's KCPConfig.Build window [10, 1000]
/// (infra/conf/transport_method.go: "invalid mKCP TTI").
pub fn kcp_tti_hard_ok(tti: u32) -> bool {
    (10..=1000).contains(&tti)
}

/// XHTTP load bound (shared with the share-link grammar's xhttp check):
/// true when `serverMaxHeaderBytes` is non-negative —
/// SplitHTTPConfig.Build refuses negatives (infra/conf/transport_method.go).
pub fn server_max_header_bytes_ok(value: i32) -> bool {
    value >= 0
}

/// Predicate shared with the share-link grammar's sid check:
/// true when the REALITY `shortId` is empty (the default) or an even-length
/// hex value of at most 16 characters — the exact set Xray hex-decodes into
/// its 8-byte short id without error (conf/transport_security.go; Go's
/// hex.Decode rejects odd-length and non-hex input).
pub fn reality_short_id_valid(value: &str) -> bool {
    value.is_empty()
        || (value.len() <= 16
            && value.len().is_multiple_of(2)
            && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

/// Predicate shared with the share-link grammar's spx check:
/// true when the REALITY `spiderX` is empty (Xray defaults it to `/`) or a
/// URL path beginning with `/` with no control characters — the shape Xray's
/// conf build accepts and its query rewriter can parse
/// (conf/transport_security.go client branch).
pub fn reality_spider_x_valid(value: &str) -> bool {
    value.is_empty()
        || (value.starts_with('/')
            && !value.bytes().any(|byte| byte.is_ascii_control())
            && url::Url::parse(&format!("https://reality.invalid{value}")).is_ok())
}

/// Predicate shared with the share-link grammar's pqv check and the editor's
/// keygen guard: true when the REALITY `mldsa65Verify` is
/// empty (no post-quantum verification key) or an unpadded base64url string
/// decoding to the 1952-byte ML-DSA-65 public key
/// (conf/transport_security.go client branch).
pub fn reality_mldsa65_verify_valid(value: &str) -> bool {
    value.is_empty()
        || URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|decoded| decoded.len() == 1952)
}

/// Predicate shared with the share-link grammar's pcs check:
/// true when `pinnedPeerCertSha256` is empty or every comma-separated entry
/// (whitespace-trimmed, colons stripped) is exactly 64 hex digits — 32
/// bytes of SHA-256 fingerprint, the shape Xray's conf build decodes
/// (conf/transport_security.go).
pub fn pinned_peer_cert_sha256_valid(value: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .filter(|pin| !pin.is_empty())
        .all(|pin| {
            let compact = pin.replace(':', "");
            compact.len() == 64 && compact.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

/// The TLS version vocabulary Xray's transport layer maps onto a concrete
/// TLS version (transport/internet/tls/config.go switches); every other
/// string is accepted by the conf loader but silently dropped, leaving the
/// Go defaults in place. Empty is the field's wire default rather than a
/// version — the rules that judge a version check emptiness themselves — so
/// it is not an entry here; the version combos add their own empty display
/// entry.
pub const TLS_VERSION_OPTIONS: &[&str] = &["1.0", "1.1", "1.2", "1.3"];

/// True when `version` names one of [`TLS_VERSION_OPTIONS`].
pub fn tls_version_supported(version: &str) -> bool {
    TLS_VERSION_OPTIONS.contains(&version)
}

/// Monotonic rank of one wire TLS version in {1.0, 1.1, 1.2, 1.3} — the
/// shared ordering predicate for the in-range min > max rule. Out-of-range
/// strings rank None (they are `TlsVersionRangeInvalid`'s business).
pub fn tls_version_rank(version: &str) -> Option<u8> {
    match version {
        "1.0" => Some(10),
        "1.1" => Some(11),
        "1.2" => Some(12),
        "1.3" => Some(13),
        _ => None,
    }
}

// ---------- stream/sockopt/strategy enum surfaces ----------
//
// The XHTTP predicates below are the single definition of each vocabulary /
// cross-field rule, shared with the share-link xhttp grammar
// (`crate::links::validate_xhttp`) so the import seam and the model seam
// cannot drift (the `is_vision_flow` pattern). The upstream
// mirror is Xray's SplitHTTPConfig.Build (infra/conf/transport_method.go:
// 317-459): every non-`""` value outside the sets below is refused at Xray
// conf load, and `""` is always the wire default of the field it feeds.

/// The XHTTP `mode` vocabulary: empty (wire default `auto`) or one of the
/// four modes. Xray's conf build rejects every other string ("unsupported
/// mode"). The editor's mode combo aliases this list.
pub const XHTTP_MODE_OPTIONS: &[&str] = &["", "auto", "packet-up", "stream-up", "stream-one"];

/// True when an XHTTP `mode` is one Xray accepts — empty (wire default
/// `auto`) or one of the four modes.
pub fn xhttp_mode_supported(mode: &str) -> bool {
    XHTTP_MODE_OPTIONS.contains(&mode)
}

/// The `xPaddingPlacement` vocabulary: empty (wire default `queryInHeader`)
/// or one of the four placements Xray accepts.
pub const X_PADDING_PLACEMENT_OPTIONS: &[&str] =
    &["", "cookie", "header", "query", "queryInHeader"];

/// True when an `xPaddingPlacement` is one of
/// [`X_PADDING_PLACEMENT_OPTIONS`].
pub fn xpadding_placement_supported(placement: &str) -> bool {
    X_PADDING_PLACEMENT_OPTIONS.contains(&placement)
}

/// The `xPaddingMethod` vocabulary: empty (wire default `repeat-x`) or one
/// of the two methods Xray accepts.
pub const XPADDING_METHOD_OPTIONS: &[&str] = &["", "repeat-x", "tokenish"];

/// True when an `xPaddingMethod` is one of [`XPADDING_METHOD_OPTIONS`].
pub fn xpadding_method_supported(method: &str) -> bool {
    XPADDING_METHOD_OPTIONS.contains(&method)
}

/// The `uplinkDataPlacement` vocabulary: empty (wire default `auto`) or one
/// of the four placements Xray accepts.
pub const UPLINK_DATA_PLACEMENT_OPTIONS: &[&str] = &["", "auto", "body", "cookie", "header"];

/// The placements only the `packet-up` form accepts: a cookie or a header
/// carries the upload in a request with its own headers, which only that form
/// sends. [`uplink_placement_mode_supported`] refuses exactly these off
/// `packet-up`; [`UPLINK_STREAM_PLACEMENT_OPTIONS`] is the vocabulary minus
/// them, and the three lists sit here together so the pair cannot drift.
const UPLINK_PACKET_UP_ONLY_PLACEMENTS: [&str; 2] = ["cookie", "header"];

/// The placements a `stream-up`/`stream-one` `uplinkDataPlacement` accepts —
/// the editor combos' options off `packet-up`.
pub const UPLINK_STREAM_PLACEMENT_OPTIONS: [&str; 3] = ["", "auto", "body"];

/// True when an `uplinkDataPlacement` is one of
/// [`UPLINK_DATA_PLACEMENT_OPTIONS`].
pub fn uplink_data_placement_supported(placement: &str) -> bool {
    UPLINK_DATA_PLACEMENT_OPTIONS.contains(&placement)
}

/// The `sessionIDPlacement` vocabulary: empty (wire default `path`) plus the
/// four placements Xray accepts.
pub const SESSION_ID_PLACEMENT_OPTIONS: &[&str] = &["", "path", "cookie", "header", "query"];

/// True when a `sessionIDPlacement` is one of
/// [`SESSION_ID_PLACEMENT_OPTIONS`].
pub fn session_id_placement_supported(placement: &str) -> bool {
    SESSION_ID_PLACEMENT_OPTIONS.contains(&placement)
}

/// `seqPlacement` uses exactly the sessionID placement vocabulary upstream;
/// one list and one predicate.
pub const SEQ_PLACEMENT_OPTIONS: &[&str] = SESSION_ID_PLACEMENT_OPTIONS;

/// True when a `seqPlacement` is one of [`SEQ_PLACEMENT_OPTIONS`].
pub fn seq_placement_supported(placement: &str) -> bool {
    SEQ_PLACEMENT_OPTIONS.contains(&placement)
}

/// True when an `xPaddingBytes` range is acceptable —
/// absent or zero (padding off) or a range with both bounds positive. Xray
/// refuses any other shape ("xPaddingBytes cannot be disabled").
pub fn xpadding_bytes_supported(range: Option<Int32Range>) -> bool {
    !range.is_some_and(|range| {
        (range.from != 0 || range.to != 0) && (range.from <= 0 || range.to <= 0)
    })
}

/// Cross-field predicates: Xray supports cookie/header upload
/// placement and the GET upload method only in `packet-up` mode. Empty mode
/// means `auto` on the wire, so `mode != "packet-up"` is the exact refusal
/// condition in both seams (compare the raw string exactly like upstream's
/// build does).
pub fn uplink_placement_mode_supported(placement: &str, mode: &str) -> bool {
    !UPLINK_PACKET_UP_ONLY_PLACEMENTS.contains(&placement) || mode == "packet-up"
}

/// Cross-field predicate: `uplinkHTTPMethod` GET only in
/// `packet-up` mode (empty method = the wire default `POST`; Xray compares
/// the uppercased method, hence the case-insensitive GET test).
pub fn uplink_http_method_mode_supported(method: &str, mode: &str) -> bool {
    !method.eq_ignore_ascii_case("GET") || mode == "packet-up"
}

/// A transport's xmux `maxConnections` and `maxConcurrency` are mutually
/// exclusive while both are in use, on every transport whose conf build
/// reads the block. Xray compares the ranges' upper bounds (`To > 0`), so a
/// range whose `to` is 0 is the "not in use" wire shape in both seams.
pub fn xmux_limits_conflict(xmux: Option<&XmuxConfig>) -> bool {
    xmux.is_some_and(|xmux| {
        xmux.max_connections.is_some_and(|range| range.to > 0)
            && xmux.max_concurrency.is_some_and(|range| range.to > 0)
    })
}

/// Predicate shared with the xhttp grammar: true when an ASCII
/// `sessionIDTable` of `table.len()` characters with a `sessionIDLength`
/// range from `range.from` to `range.to` can open Xray's required 2^31 key
/// combinations (the key space is the count of table strings of every
/// length in the range). Mirrors Xray's `roomSize` comparison in
/// SplitHTTPConfig.Build — reversed ranges, `from ≤ 0`, and non-ASCII
/// tables all fail here exactly like upstream.
pub(crate) fn range_has_session_room(table: &str, range: crate::model::Int32Range) -> bool {
    if range.from <= 0 || range.to < range.from || !table.is_ascii() {
        return false;
    }
    let table_len = match table {
        "ALPHABET" | "alphabet" => 26,
        "Alphabet" => 52,
        "BASE36" | "base36" => 36,
        "Base62" => 62,
        "HEX" | "hex" => 16,
        "number" => 10,
        custom => custom.len(),
    };
    if table_len < 2 {
        return false;
    }
    // The smallest possible base is two, so any term with exponent 31 or
    // greater already reaches Xray's required 2^31 key space.
    if range.from >= 31 {
        return true;
    }
    let base = table_len.min(u64::MAX as usize) as u64;
    let required = 2_u64 << 30;
    let mut power = 1_u64;
    let mut total = 0_u64;
    for exponent in 1..=range.to.min(64) {
        power = power.saturating_mul(base);
        if exponent >= range.from {
            total = total.saturating_add(power);
            if total >= required {
                return true;
            }
        }
    }
    false
}

/// Sockopt `tproxy` vocabulary — the three values Xray accepts, shared with
/// the warning predicate below so the accepted set and the check can never
/// disagree. `off` is the explicit spelling of Xray's default
/// (SocketConfig_Off) and is honored as-is; `tproxy` and `redirect` are the
/// two active modes (infra/conf/transport_sockopt.go). The structured editor
/// renders no widget for this field (its Linux-only readers are the only
/// consumers), so the vocabulary is reachable only through a hand-edited
/// profile or the raw config override.
pub const TPROXY_MODES: &[&str] = &["off", "redirect", "tproxy"];

/// The target-domain-strategy vocabulary: every value Xray's outbound
/// `targetStrategy` switch and freedom `domainStrategy` switch accept
/// (infra/conf/xray.go OutboundDetectorConfig.Build and conf/freedom.go read
/// the same word list). Comparison folds case — Xray lowercases the value
/// before switching — and empty is the wire default (`asis`), which the
/// rules that judge a strategy check themselves. The strategy combos alias
/// this list.
pub const TARGET_STRATEGY_OPTIONS: &[&str] = &[
    "AsIs",
    "UseIP",
    "UseIPv4",
    "UseIPv6",
    "UseIPv4v6",
    "UseIPv6v4",
    "ForceIP",
    "ForceIPv4",
    "ForceIPv6",
    "ForceIPv6v4",
    "ForceIPv4v6",
];

/// True when `target_strategy` names one of Xray's
/// outbound target domain strategies, under [`vocabulary_holds`] — Xray
/// lowercases the value before its switch (infra/conf/xray.go
/// OutboundDetectorConfig Build). Empty stays legal (the wire default
/// `asis`).
pub(super) fn target_strategy_supported(strategy: &str) -> bool {
    vocabulary_holds(TARGET_STRATEGY_OPTIONS, strategy)
}

/// True when a freedom `domainStrategy`
/// value names one of the strategies Xray's FreedomConfig.Build switch
/// accepts — the very same word list as the outbound `targetStrategy`
/// rule, compared the same case-insensitive way (Xray lowercases before
/// switching, conf/freedom.go). Empty is separately legal (the wire
/// default `asis`).
pub(super) fn freedom_domain_strategy_supported(strategy: &str) -> bool {
    target_strategy_supported(strategy)
}

/// The TLS settings findings Xray's `TLSConfig.Build` applies whatever the
/// surface: the `serverName` advisory, the removed `masterKeyLog` and
/// `allowInsecure` keys, the fingerprint vocabulary, the certificate pin,
/// and the version strings. `path` is the settings block's wire path
/// (`stream.tlsSettings`, or a resolver's `...resolvers[i].tlsConfig`), so
/// the same rule reports under the block the user edited.
fn validate_tls_settings(tls: &TlsModel, path: &str, issues: &mut Vec<ValidationIssue>) {
    // Advisory: a serverName that can never be a real SNI (UUID-shaped or
    // impossible characters) always fails the handshake, yet Xray accepts the
    // config — warn, never gate. Empty is out of scope.
    if server_name_implausible(&tls.server_name) {
        issues.push(warning(
            ValidationCode::ServerNameImplausible,
            Some(format!("{path}.serverName")),
        ));
    }
    // `masterKeyLog` makes Xray create/append an attacker-chosen file and
    // log TLS session keys to it — refused on import (the share-link
    // export already rejects it as outside #716). serde binds only the
    // exact-case `masterKeyLog` to the model field; a case variant lands
    // in the flattened `extra` map, is still flattened verbatim into the
    // generated config, and Go's case-insensitive JSON unmarshal sets
    // MasterKeyLog regardless — so the extra map is scanned
    // case-insensitively too.
    if !tls.master_key_log.is_empty()
        || tls
            .extra
            .keys()
            .any(|key| key.eq_ignore_ascii_case("masterKeyLog"))
    {
        issues.push(issue(
            ValidationCode::MasterKeyLogNotSupported,
            Some(format!("{path}.masterKeyLog")),
        ));
    }
    // `allowInsecure` is a removed Xray TLS field (not modeled), so a
    // carried value lands in the flattened `extra` map and must be
    // refused. `false` is the Go zero value — Xray runs it fine; any
    // other value (`true`, strings, numbers) either hard-fails
    // TLSConfig.Build (PrintRemovedFeatureError) or Xray's JSON
    // unmarshal into `AllowInsecure bool`. Go's unmarshal matches field
    // names case-insensitively, so every key case must be scanned.
    if tls.extra.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("allowInsecure")
            && !matches!(value, Value::Bool(false) | Value::Null)
    }) {
        issues.push(issue(
            ValidationCode::TlsAllowInsecureRemoved,
            Some(format!("{path}.allowInsecure")),
        ));
    }
    // The fingerprint vocabulary is the canonical table in
    // `crate::model::fingerprint` — TLS accepts the full wire vocabulary
    // (`unsafe`/`hellogolang` included).
    if !crate::model::fingerprint::wire_validation_supported(&tls.fingerprint) {
        issues.push(issue(
            ValidationCode::TlsFingerprintUnsupported,
            Some(format!("{path}.fingerprint")),
        ));
    }
    if !pinned_peer_cert_sha256_valid(&tls.pinned_peer_cert_sha256) {
        issues.push(issue(
            ValidationCode::PinnedPeerCertSha256Invalid,
            Some(format!("{path}.pinnedPeerCertSha256")),
        ));
    }
    // Configuration warning: Xray accepts any string here
    // but the version switches in tls/config.go leave unrecognized
    // values at the Go default — the configured cap/floor silently
    // never applies. The in-range min > max inversion is a separate
    // runtime-class rule and is NOT coded here.
    for (version, field) in [
        (&tls.min_version, "minVersion"),
        (&tls.max_version, "maxVersion"),
    ] {
        if !version.is_empty() && !tls_version_supported(version) {
            issues.push(warning(
                ValidationCode::TlsVersionRangeInvalid,
                Some(format!("{path}.{field}")),
            ));
        }
    }
    // In-range min > max inversion:
    // both versions are valid {1.0..1.3} but the range is inverted.
    // Live repro 2026-09-06 on Xray 26.7.28: `run -test` accepts the
    // pair and the wire negotiates TLS 1.3 — the client version
    // pins never apply (a maxVersion-only "1.2" probe also
    // negotiates 1.3, and a minVersion-only "1.3" probe accepts
    // 1.2), so the config silently never behaves as written —
    // configuration warning (Severity::Warning).
    if let (Some(min), Some(max)) = (
        tls_version_rank(&tls.min_version),
        tls_version_rank(&tls.max_version),
    ) && min > max
    {
        issues.push(warning(
            ValidationCode::TlsMinExceedsMax,
            Some(path.to_string()),
        ));
    }
}

/// The TLS settings rules Xray applies only when the block is actually
/// selected: the `fromMitm` ALPN shape and the certificate rows. The stream
/// takes them when `security` is TLS; a DoH resolver always does.
fn validate_tls_connection_settings(tls: &TlsModel, path: &str, issues: &mut Vec<ValidationIssue>) {
    // `fromMitm` beside another ALPN name: Xray's conf build refuses
    // the list (infra/conf/transport_security.go: only one element is
    // allowed in "alpn" when using "fromMitm" in it).
    if tls.alpn.len() > 1 && tls.alpn.iter().any(|value| value == "fromMitm") {
        issues.push(issue(
            ValidationCode::TlsFromMitmAlpnShort,
            Some(format!("{path}.alpn")),
        ));
    }
    // A certificate row with neither a file nor inline PEM lines has
    // no key material to load (infra/conf: both file and bytes are
    // empty). Both tests are trimmed: a whitespace-only path names no
    // readable file and a blank-only line list parses no certificate,
    // so the row has nothing to load. The path names the row so the
    // finding points at the entry the user has to fill in.
    for (index, certificate) in tls.certificates.iter().enumerate() {
        if certificate.certificate_file.trim().is_empty()
            && certificate
                .certificate
                .iter()
                .all(|line| line.trim().is_empty())
        {
            issues.push(issue(
                ValidationCode::TlsCertificateRequired,
                Some(format!("{path}.certificates[{index}]")),
            ));
        }
    }
}

/// Validate a stream model, recursing over every modeled XHTTP download
/// stream. Mirrors the old `StreamModel::validation_errors` visit logic.
pub fn validate_stream(s: &StreamModel) -> Verdict {
    fn visit(stream: &StreamModel, depth: usize, issues: &mut Vec<ValidationIssue>) {
        if depth > MAX_XHTTP_DOWNLOAD_DEPTH {
            issues.push(issue(ValidationCode::XhttpDepthExceeded, None));
            return;
        }
        if !stream.carries_transport_block()
            && let Some(key) = crate::model::stream::transport_settings_key(stream.network)
        {
            issues.push(issue(
                ValidationCode::TransportSettingsMissing(stream.network),
                Some(format!("stream.{key}")),
            ));
        }
        // Every headers map reaches Xray's `map[string]string` fields, and a
        // non-string value (a hand-edited state file, or an extra-map key kept
        // verbatim from one) makes the generated document unloadable. The
        // share-link grammar refuses the same value on import, so the state
        // load is the only way in — and generation must refuse it with a
        // message that names the rule instead of spending a core start on it.
        if let Some((headers, path)) = stream.transport_headers()
            && headers.values().any(|value| !value.is_string())
        {
            issues.push(issue(
                ValidationCode::HeaderValuesNotStrings(stream.network),
                Some(path.into()),
            ));
        }
        if stream.network == Network::Hysteria {
            if stream.security != Security::Tls {
                issues.push(issue(
                    ValidationCode::HysteriaTransportRequiresTls,
                    Some("stream.security".into()),
                ));
            }
            if stream
                .hysteria_settings
                .as_ref()
                .is_some_and(|settings| settings.version != 2)
            {
                issues.push(issue(
                    ValidationCode::HysteriaTransportVersion,
                    Some("stream.hysteriaSettings.version".into()),
                ));
            }
        }
        validate_masque_stream(stream, issues);
        validate_xdrive_stream(stream, issues);
        if stream.security == Security::Reality && !stream.network.supports_reality() {
            issues.push(issue(
                ValidationCode::RealityRequiresTransport,
                Some("stream.security".into()),
            ));
        }
        if stream.security == Security::Reality && stream.reality_settings.is_none() {
            issues.push(issue(
                ValidationCode::RealitySettingsMissing,
                Some("stream.realitySettings".into()),
            ));
        }
        if stream.security == Security::Tls && stream.tls_settings.is_none() {
            issues.push(issue(
                ValidationCode::TlsSettingsMissing,
                Some("stream.tlsSettings".into()),
            ));
        }
        // The TLS settings rules, shared by the outbound `stream.tlsSettings`
        // block and the DoH resolver's nested `tlsConfig` in an `xdns` mask:
        // both carry the same `TlsModel`, and the core applies one
        // `TLSConfig.Build` rule set to both, so the path prefix is the only
        // difference. A resolver always speaks TLS, so it takes the
        // connection rules unconditionally; the stream takes them only when
        // `security` selects TLS (the wire pass drops the block otherwise).
        if let Some(tls) = stream.tls_settings.as_ref() {
            validate_tls_settings(tls, "stream.tlsSettings", issues);
            if stream.security == Security::Tls {
                validate_tls_connection_settings(tls, "stream.tlsSettings", issues);
            }
        }
        if let Some(reality) = stream.reality_settings.as_ref()
            && server_name_implausible(&reality.server_name)
        {
            issues.push(warning(
                ValidationCode::ServerNameImplausible,
                Some("stream.realitySettings.serverName".into()),
            ));
        }
        if let Some(reality) = stream.reality_settings.as_ref()
            && (!reality.master_key_log.is_empty()
                || reality
                    .extra
                    .keys()
                    .any(|key| key.eq_ignore_ascii_case("masterKeyLog")))
        {
            issues.push(issue(
                ValidationCode::MasterKeyLogNotSupported,
                Some("stream.realitySettings.masterKeyLog".into()),
            ));
        }
        // Extra-passthrough scans — transport-level extras: the same
        // flatten-map mechanics as the masterKeyLog/allowInsecure scans above,
        // over the kcp/hysteria/reality settings blocks. Removed-feature keys
        // are Error; accepted-then-ignored keys are Warning
        // (Severity::Warning). JSON `null` is the Go zero shape and stays
        // silent on the keys whose upstream check tests a non-nil pointer.
        if let Some(kcp) = stream.kcp_settings.as_ref() {
            // mKCP `seed`/`header` — KCPConfig.Build refuses a set
            // seed or header object with PrintRemovedFeatureError naming
            // the finalmask UDP masks as the migration
            // (conf/transport_method.go).
            for (wire_key, path) in [
                ("seed", "stream.kcpSettings.seed"),
                ("header", "stream.kcpSettings.header"),
            ] {
                if extra_key_set(&kcp.extra, wire_key) {
                    issues.push(issue(
                        ValidationCode::KcpSeedHeaderRemoved,
                        Some(path.into()),
                    ));
                }
            }
            // `headerType` never was an Xray JSON key (the old camouflage
            // object is `header`; `headerType` exists only in share links),
            // so Xray's unmarshal silently ignores it — advisory only.
            if extra_has_key(&kcp.extra, "headerType") {
                issues.push(warning(
                    ValidationCode::KcpHeaderTypeIgnored,
                    Some("stream.kcpSettings.headerType".into()),
                ));
            }
        }
        if let Some(hysteria) = stream.hysteria_settings.as_ref() {
            // Hysteria `congestion`/`up`/`down`/`udphop` — HysteriaConfig
            // still parses the legacy QUIC knobs, logs an upstream warning
            // ("congestion & up & down & udphop move to finalmask/quicParams")
            // and discards them (conf/transport_method.go); the config
            // loads and runs without the knobs — advisory.
            for (wire_key, path) in [
                ("congestion", "stream.hysteriaSettings.congestion"),
                ("up", "stream.hysteriaSettings.up"),
                ("down", "stream.hysteriaSettings.down"),
                ("udphop", "stream.hysteriaSettings.udphop"),
            ] {
                if extra_key_set(&hysteria.extra, wire_key) {
                    issues.push(warning(
                        ValidationCode::HysteriaQuicKnobsMoved,
                        Some(path.into()),
                    ));
                }
            }
        }
        if let Some(reality) = stream.reality_settings.as_ref() {
            // REALITY server-form keys (dest, target, privateKey,
            // serverNames, shortIds, mldsa65Seed) carried on a client
            // profile: a client REALITY build never reads them, and a set
            // dest/target flips REALITYConfig.Build onto the server branch
            // (conf/transport_security.go), so an outbound carrying them
            // cannot behave as a client. They are carried verbatim and the
            // config loads — advisory (a profile may deliberately hold
            // server-form material for tooling).
            for wire_key in [
                "dest",
                "target",
                "privateKey",
                "serverNames",
                "shortIds",
                "mldsa65Seed",
            ] {
                // JSON null is the Go zero value — nothing is carried and
                // the dest/target server-branch flip never triggers, so
                // only non-null presence warns (extra_key_set, matching
                // the other removed-feature rows' Go-zero semantics).
                if extra_key_set(&reality.extra, wire_key) {
                    issues.push(warning(
                        ValidationCode::RealityServerFormKeysInert,
                        Some(format!("stream.realitySettings.{wire_key}")),
                    ));
                }
            }
        }
        // REALITY client formats: the fingerprint vocabulary and the
        // key/SPX shapes. All Error findings mirror Xray conf-load rejections
        // (conf/transport_security.go), so they gate save/apply exactly like
        // an import refusal. Fingerprint vocabulary is the canonical table in
        // `crate::model::fingerprint`; REALITY excludes exactly
        // `unsafe`/`hellogolang`.
        if let Some(reality) = stream.reality_settings.as_ref() {
            if !crate::model::fingerprint::reality_wire_supported(&reality.fingerprint) {
                issues.push(issue(
                    ValidationCode::RealityFingerprintUnsupported,
                    Some("stream.realitySettings.fingerprint".into()),
                ));
            } else if crate::model::fingerprint::reality_fingerprint_outside_known_good(
                &reality.fingerprint,
            ) {
                // The wire accepts the name and Xray runs it, but upstream's
                // REALITY scenarios exercise only the known-good three, so
                // the stored value is an untested shape rather than a broken
                // one — advisory (Severity::Warning), never a gate.
                issues.push(warning(
                    ValidationCode::RealityFingerprintUntested(excerpt(&reality.fingerprint)),
                    Some("stream.realitySettings.fingerprint".into()),
                ));
            }
            if !reality_public_key_valid(&reality.password) {
                issues.push(issue(
                    ValidationCode::RealityPublicKeyInvalid,
                    Some("stream.realitySettings.publicKey".into()),
                ));
            }
            if !reality_short_id_valid(&reality.short_id) {
                issues.push(issue(
                    ValidationCode::RealityShortIdInvalid,
                    Some("stream.realitySettings.shortId".into()),
                ));
            }
            if !reality_spider_x_valid(&reality.spider_x) {
                issues.push(issue(
                    ValidationCode::RealitySpiderXInvalid,
                    Some("stream.realitySettings.spiderX".into()),
                ));
            }
            if !reality_mldsa65_verify_valid(&reality.mldsa65_verify) {
                issues.push(issue(
                    ValidationCode::RealityMldsa65Invalid,
                    Some("stream.realitySettings.mldsa65Verify".into()),
                ));
            }
        }
        if let Some(sockopt) = &stream.sockopt {
            issues.extend(validate_sockopt(sockopt, "stream.sockopt"));
        }
        if let Some(ech_sockopt) = ech_sockopt_emitted(stream) {
            issues.extend(validate_sockopt(
                ech_sockopt,
                "stream.tlsSettings.echSockopt",
            ));
        }
        if let Some(finalmask) = &stream.finalmask {
            issues.extend(validate_finalmask(finalmask));
            finalmask_outbound_filter_advisories(finalmask, issues);
        }
        // XHTTP enum vocabularies and cross-field rules: every value below is
        // refused by Xray's SplitHTTPConfig Build at config load
        // (infra/conf/transport_method.go:317-459) and
        // by the share-link xhttp grammar on import — the predicates are the
        // single source shared with `crate::links::validate_xhttp`, so the
        // import seam and this pass decide identically on every value.
        // Findings ride the settings block whenever one is present (the TLS
        // block convention); the recursion below re-visits nested XHTTP
        // download blocks with the same checks.
        if let Some(xhttp) = stream.xhttp_settings.as_ref() {
            if !xhttp_mode_supported(&xhttp.mode) {
                issues.push(issue(
                    ValidationCode::XhttpModeUnsupported,
                    Some("stream.xhttpSettings.mode".into()),
                ));
            }
            if !xpadding_bytes_supported(xhttp.x_padding_bytes) {
                issues.push(issue(
                    ValidationCode::XhttpPaddingBytesInvalid,
                    Some("stream.xhttpSettings.xPaddingBytes".into()),
                ));
            }
            if !xpadding_placement_supported(&xhttp.x_padding_placement) {
                issues.push(issue(
                    ValidationCode::XhttpPaddingPlacementInvalid,
                    Some("stream.xhttpSettings.xPaddingPlacement".into()),
                ));
            }
            if !xpadding_method_supported(&xhttp.x_padding_method) {
                issues.push(issue(
                    ValidationCode::XhttpPaddingMethodInvalid,
                    Some("stream.xhttpSettings.xPaddingMethod".into()),
                ));
            }
            if !uplink_data_placement_supported(&xhttp.uplink_data_placement) {
                issues.push(issue(
                    ValidationCode::XhttpUplinkDataPlacementInvalid,
                    Some("stream.xhttpSettings.uplinkDataPlacement".into()),
                ));
            }
            if !uplink_placement_mode_supported(&xhttp.uplink_data_placement, &xhttp.mode) {
                issues.push(issue(
                    ValidationCode::XhttpUplinkDataPlacementRequiresPacketUp,
                    Some("stream.xhttpSettings.uplinkDataPlacement".into()),
                ));
            }
            if !uplink_http_method_mode_supported(&xhttp.uplink_http_method, &xhttp.mode) {
                issues.push(issue(
                    ValidationCode::XhttpUplinkHttpMethodRequiresPacketUp,
                    Some("stream.xhttpSettings.uplinkHTTPMethod".into()),
                ));
            }
            if !session_id_placement_supported(&xhttp.session_id_placement) {
                issues.push(issue(
                    ValidationCode::XhttpSessionIdPlacementInvalid,
                    Some("stream.xhttpSettings.sessionIDPlacement".into()),
                ));
            }
            if !seq_placement_supported(&xhttp.seq_placement) {
                issues.push(issue(
                    ValidationCode::XhttpSeqPlacementInvalid,
                    Some("stream.xhttpSettings.seqPlacement".into()),
                ));
            }
            if !xhttp.session_id_table.is_empty() {
                match xhttp.session_id_length {
                    None => issues.push(issue(
                        ValidationCode::XhttpSessionIdLengthRequired,
                        Some("stream.xhttpSettings.sessionIDLength".into()),
                    )),
                    Some(range) if !range_has_session_room(&xhttp.session_id_table, range) => {
                        issues.push(issue(
                            ValidationCode::XhttpSessionIdTableInvalid,
                            Some("stream.xhttpSettings.sessionIDTable".into()),
                        ));
                    }
                    _ => {}
                }
            }
            if xmux_limits_conflict(xhttp.xmux.as_ref()) {
                issues.push(issue(
                    ValidationCode::XmuxLimitsExclusive,
                    Some("stream.xhttpSettings.xmux".into()),
                ));
            }
            // Negative serverMaxHeaderBytes is refused by
            // SplitHTTPConfig.Build at load (infra/conf/transport_method.go)
            // and by the import grammar — the model closes the state path
            // (Error tier, shared server_max_header_bytes_ok predicate).
            if xhttp
                .server_max_header_bytes
                .is_some_and(|value| !server_max_header_bytes_ok(value))
            {
                issues.push(issue(
                    ValidationCode::XhttpServerMaxHeaderBytesInvalid,
                    Some("stream.xhttpSettings.serverMaxHeaderBytes".into()),
                ));
            }
            // Extra-passthrough shadowing:
            // an `xhttpSettings.extra` key naming a modeled xhttp setting
            // overrides it — serde flatten emits the extra value over the
            // typed field on export, and Xray's SplitHTTPConfig.Build
            // (infra/conf/transport_method.go) replaces the whole outer
            // object with the nested `extra` object except host/path/mode.
            // Live repro 2026-09-06 on Xray 26.7.28: outer
            // `xPaddingMethod: "tokenish"` + extra
            // `xPaddingMethod: "bogus"` refuses at load ("unsupported
            // padding method: bogus") while the same config without the
            // extra key loads — the edited value never reaches Xray.
            // Configuration warning (class E, Severity::Warning); the carried
            // key names the offender. The list is
            // the camelCase serde surface of `XhttpSettings`.
            for wire_key in [
                "host",
                "path",
                "mode",
                "headers",
                "uplinkHTTPMethod",
                "uplinkDataPlacement",
                "uplinkDataKey",
                "uplinkChunkSize",
                "xPaddingBytes",
                "xPaddingObfsMode",
                "xPaddingKey",
                "xPaddingHeader",
                "xPaddingPlacement",
                "xPaddingMethod",
                "sessionIDPlacement",
                "sessionIDKey",
                "sessionIDTable",
                "sessionIDLength",
                "seqPlacement",
                "seqKey",
                "noGRPCHeader",
                "noSSEHeader",
                "scMaxEachPostBytes",
                "scMinPostsIntervalMs",
                "scMaxBufferedPosts",
                "scStreamUpServerSecs",
                "serverMaxHeaderBytes",
                "xmux",
                "downloadSettings",
            ] {
                if extra_has_key(&xhttp.extra, wire_key) {
                    issues.push(warning(
                        ValidationCode::XhttpExtraShadowsSettings(wire_key.to_string()),
                        Some(format!("stream.xhttpSettings.{wire_key}")),
                    ));
                }
            }
            if xhttp.mode == "stream-one" && xhttp.download_settings.is_some() {
                issues.push(issue(
                    ValidationCode::StreamOneNoDownload,
                    Some("stream.xhttpSettings.downloadSettings".into()),
                ));
            }
            if let Some(download) = xhttp.download_settings.as_deref() {
                visit(download, depth + 1, issues);
            }
        }
        // mKCP configuration ranges: Xray's
        // KCPConfig.Build load-refuses mtu < 21 and tti outside [10, 1000]
        // (infra/conf/transport_method.go) — Error tier below, sharing the
        // import grammar's hard bounds (kcp_mtu_hard_ok /
        // kcp_tti_hard_ok). The docs (mkcp.md) merely recommend
        // mtu 576-1460 / tti 10-100, so values Xray accepts outside that
        // band stay a docs-soft Warning.
        if let Some(kcp) = stream.kcp_settings.as_ref() {
            if kcp.mtu.is_some_and(|mtu| !kcp_mtu_hard_ok(mtu)) {
                issues.push(issue(
                    ValidationCode::KcpRangeInvalid,
                    Some("stream.kcpSettings.mtu".into()),
                ));
            } else if kcp.mtu.is_some_and(|mtu| !(576..=1460).contains(&mtu)) {
                issues.push(warning(
                    ValidationCode::KcpRangeSoft,
                    Some("stream.kcpSettings.mtu".into()),
                ));
            }
            if kcp.tti.is_some_and(|tti| !kcp_tti_hard_ok(tti)) {
                issues.push(issue(
                    ValidationCode::KcpRangeInvalid,
                    Some("stream.kcpSettings.tti".into()),
                ));
            } else if kcp.tti.is_some_and(|tti| !(10..=100).contains(&tti)) {
                issues.push(warning(
                    ValidationCode::KcpRangeSoft,
                    Some("stream.kcpSettings.tti".into()),
                ));
            }
        }
        // gRPC negative-clamp configuration warnings (Severity::Warning):
        // Xray clamps negative
        // idle_timeout / health_check_timeout / initial_windows_size to zero
        // at conf build (infra/conf/transport_method.go GRPCConfig.Build).
        // Zero itself is intentional on every knob — the keepalive params
        // and the initial-window option are attached only for `> 0` values
        // (grpc dial.go), so 0 means "disabled / Xray's default window" —
        // only negatives are a silent reinterpretation of the user's value.
        if let Some(grpc) = stream.grpc_settings.as_ref() {
            for (knob, path) in [
                (&grpc.idle_timeout, "stream.grpcSettings.idle_timeout"),
                (
                    &grpc.health_check_timeout,
                    "stream.grpcSettings.health_check_timeout",
                ),
                (
                    &grpc.initial_windows_size,
                    "stream.grpcSettings.initial_windows_size",
                ),
            ] {
                if knob.is_some_and(|seconds| seconds < 0) {
                    issues.push(warning(
                        ValidationCode::GrpcNegativeClamp,
                        Some(path.into()),
                    ));
                }
            }
        }
    }

    let mut issues = Vec::new();
    visit(s, 0, &mut issues);
    Verdict::from_issues(issues)
}

/// The sockopt `domainStrategy` vocabulary: the empty wire default plus the
/// same word list the outbound `targetStrategy` rule reads
/// (infra/conf/transport_sockopt.go hands the value to the dial's resolver).
/// The sockopt combo aliases this list.
pub const SOCKOPT_DOMAIN_STRATEGY_OPTIONS: &[&str] = &[
    "",
    "AsIs",
    "UseIP",
    "UseIPv4",
    "UseIPv6",
    "UseIPv4v6",
    "UseIPv6v4",
    "ForceIP",
    "ForceIPv4",
    "ForceIPv6",
    "ForceIPv4v6",
    "ForceIPv6v4",
];

/// True when a sockopt `domainStrategy` is one of
/// [`SOCKOPT_DOMAIN_STRATEGY_OPTIONS`], under [`vocabulary_holds`].
pub fn sockopt_domain_strategy_supported(strategy: &str) -> bool {
    vocabulary_holds(SOCKOPT_DOMAIN_STRATEGY_OPTIONS, strategy)
}

/// The sockopt `addressPortStrategy` vocabulary: the empty wire default plus
/// the SRV/TXT lookup orders Xray's dialer reads
/// (infra/conf/transport_sockopt.go). The sockopt combo aliases this list.
pub const SOCKOPT_ADDRESS_PORT_STRATEGY_OPTIONS: &[&str] = &[
    "",
    "none",
    "srvportonly",
    "srvaddressonly",
    "srvportandaddress",
    "txtportonly",
    "txtaddressonly",
    "txtportandaddress",
];

/// True when a sockopt `addressPortStrategy` is one of
/// [`SOCKOPT_ADDRESS_PORT_STRATEGY_OPTIONS`], under [`vocabulary_holds`].
pub fn sockopt_address_port_strategy_supported(strategy: &str) -> bool {
    vocabulary_holds(SOCKOPT_ADDRESS_PORT_STRATEGY_OPTIONS, strategy)
}

/// The stream's ECH sockopt block, when it reaches the wire: Xray reads
/// `tlsSettings.echSockopt` under TLS only, so a block stored under any other
/// security is never emitted and never judged. The one gate for both the
/// model sweep and the editor's inline ECH verdict, so a stored block is
/// either checked in both places or in neither.
pub fn ech_sockopt_emitted(stream: &StreamModel) -> Option<&SockoptModel> {
    if stream.security != Security::Tls {
        return None;
    }
    stream.tls_settings.as_ref()?.ech_sockopt.as_ref()
}

/// Validate one sockopt block. `prefix` is the wire path prefix that scopes
/// every field finding (e.g. `"stream.sockopt"`).
pub fn validate_sockopt(s: &SockoptModel, prefix: &str) -> Verdict {
    let mut issues = Vec::new();
    if !sockopt_domain_strategy_supported(&s.domain_strategy) {
        issues.push(issue(
            ValidationCode::SockoptDomainStrategyInvalid,
            Some(format!("{prefix}.domainStrategy")),
        ));
    }
    if !sockopt_address_port_strategy_supported(&s.address_port_strategy) {
        issues.push(issue(
            ValidationCode::SockoptAddressPortStrategyInvalid,
            Some(format!("{prefix}.addressPortStrategy")),
        ));
    }
    if s.tcp_fast_open
        .as_ref()
        .is_some_and(|value| !value.is_boolean() && !value.is_number())
    {
        issues.push(issue(
            ValidationCode::SockoptTcpFastOpenType,
            Some(format!("{prefix}.tcpFastOpen")),
        ));
    }
    let idle = s.tcp_keep_alive_idle.unwrap_or_default();
    let interval = s.tcp_keep_alive_interval.unwrap_or_default();
    // Direct sign comparison, not `idle.wrapping_mul(interval) < 0`: the
    // product overflows for large magnitudes, so 86400 * 86400 wrapped
    // negative and rejected valid same-sign keepalives while large
    // opposite-sign pairs wrapped positive and slipped through. A `0`
    // default (missing field) must keep pairing with any value as
    // same-sign, matching the old `0 * x == 0` behavior, so both values
    // must be strictly nonzero for their signs to conflict.
    if (idle < 0 && interval > 0) || (idle > 0 && interval < 0) {
        issues.push(issue(
            ValidationCode::SockoptKeepaliveSigns,
            Some(format!("{prefix}.tcpKeepAliveIdle")),
        ));
    }
    if s.custom_sockopt
        .iter()
        .any(|custom| custom.opt.trim().is_empty())
    {
        issues.push(issue(
            ValidationCode::SockoptCustomOptRequired,
            Some(format!("{prefix}.customSockopt")),
        ));
    }
    if s.custom_sockopt
        .iter()
        .any(|custom| !matches!(custom.r#type.as_str(), "int" | "str"))
    {
        issues.push(issue(
            ValidationCode::SockoptCustomTypeInvalid,
            Some(format!("{prefix}.customSockopt")),
        ));
    }
    // Tproxy configuration warning (Severity::Warning): Xray
    // lowercases `tproxy` and maps everything outside {tproxy, redirect} —
    // a typo included, `off` being the explicit spelling of the Off default
    // that is honored as-is — onto SocketConfig_Off without a word
    // (infra/conf/transport_sockopt.go), so a misspelled mode runs without
    // transparency. Advisory: the config loads and the wire works, the
    // value silently never applies. The vocabulary is the shared
    // [`TPROXY_MODES`] list; the field has no widget any more, so a value
    // this flags came from a hand-edited profile or the raw config override.
    if s.tproxy
        .as_deref()
        .is_some_and(|value| !value.is_empty() && !vocabulary_holds(TPROXY_MODES, value))
    {
        issues.push(warning(
            ValidationCode::SockoptTproxySilentOff,
            Some(format!("{prefix}.tproxy")),
        ));
    }
    Verdict::from_issues(issues)
}

// ---------- finalmask ----------

fn finalmask_range_bounds(value: Int32Range) -> (i32, i32) {
    if value.from <= value.to {
        (value.from, value.to)
    } else {
        (value.to, value.from)
    }
}

/// Validate one finalmask block. Paths are wire paths suitable for inline UI
/// and share-link diagnostics; they mirror the rejections of the current Xray
/// finalmask loader and QUIC parameter builder.
pub fn validate_finalmask(fm: &FinalmaskModel) -> Verdict {
    let mut issues = Vec::new();
    for (index, mask) in fm.tcp.iter().enumerate() {
        finalmask_validate_tcp_mask(index, mask, &mut issues);
    }
    finalmask_validate_udp_order(&fm.udp, &mut issues);
    for (index, mask) in fm.udp.iter().enumerate() {
        finalmask_validate_udp_mask(index, mask, &mut issues);
    }
    if let Some(quic) = &fm.quic_params {
        finalmask_validate_quic_params("finalmask.quicParams", quic, &mut issues);
    }
    Verdict::from_issues(issues)
}

/// One finding per `filter` mask an outbound carries: the loader builds it,
/// but only a listener consults it, so the profile starts with the mask inert.
/// A warning — the configuration loads and runs exactly as without it.
fn finalmask_outbound_filter_advisories(fm: &FinalmaskModel, issues: &mut Vec<ValidationIssue>) {
    for (index, mask) in fm.tcp.iter().enumerate() {
        if matches!(mask, FinalmaskTcpMask::Filter { .. }) {
            issues.push(warning(
                ValidationCode::FinalmaskFilterOnOutbound,
                Some(format!("finalmask.tcp[{index}]")),
            ));
        }
    }
    for (index, mask) in fm.udp.iter().enumerate() {
        if matches!(mask, FinalmaskUdpMask::Filter { .. }) {
            issues.push(warning(
                ValidationCode::FinalmaskFilterOnOutbound,
                Some(format!("finalmask.udp[{index}]")),
            ));
        }
    }
}

/// Check one `filter` settings object. `ParseIPRules` runs over both lists at
/// build time (`infra/conf/transport_finalmask.go:105-115`), so one malformed
/// rule aborts the whole configuration — on a listener and on a dial alike.
fn finalmask_validate_filter(
    path: &str,
    settings: &FinalmaskFilter,
    issues: &mut Vec<ValidationIssue>,
) {
    for (key, rules) in [
        ("blockedSourceIPs", &settings.blocked_source_ips),
        ("allowedSourceIPs", &settings.allowed_source_ips),
    ] {
        for (index, rule) in rules.iter().enumerate() {
            if !super::ip_rule_valid(rule) {
                issues.push(issue(
                    ValidationCode::FinalmaskFilterIpRuleInvalid(excerpt(rule)),
                    Some(format!("{path}.{key}[{index}]")),
                ));
            }
        }
    }
}

/// Gate the UDP mask positions the wrap refuses. `NewFinalMask` reverses both
/// mask slices at construction and the wrap then runs forward
/// (`transport/internet/finalmask/finalmask.go:44-46`), so the JSON list's
/// last entry is the outermost wrap. A mask that declares `HandleDial` or
/// `HandleListen` owns the outbound's own socket and must be that outermost
/// wrap — the core refuses any other index with `incorrect index: %d %T`
/// (`finalmask.go:149-152` for `HandleDial`, `:218-221` for `HandleListen`).
/// `udphop` declares `HandleDial` (`.../udphop/config.go:9`) and `xicmp`
/// declares both (`.../xicmp/config.go:10-12`), so each belongs at the end of
/// the list; no other UDP mask type, and no TCP mask type, is pinned. The
/// core enforces this only while it wraps a connection, so the config build
/// accepts a misordered chain and every dial fails; the app gates it instead.
fn finalmask_validate_udp_order(masks: &[FinalmaskUdpMask], issues: &mut Vec<ValidationIssue>) {
    let Some(last) = masks.len().checked_sub(1) else {
        return;
    };
    for (index, mask) in masks.iter().enumerate() {
        match mask {
            FinalmaskUdpMask::Xicmp { .. } | FinalmaskUdpMask::Udphop { .. } if index != last => {
                issues.push(issue(
                    ValidationCode::FinalmaskUdpMaskNotLast(
                        mask.known_type()
                            .expect("the match arm only admits known mask types")
                            .into(),
                    ),
                    Some(format!("finalmask.udp[{index}]")),
                ));
            }
            _ => {}
        }
    }
}

/// True when a `udphop` UDP mask selects an interval mode
/// (`intervalLocal` or `intervalRemote`, comma-combinable and
/// case-insensitive) over a well-formed `mode` set. Each hop moves or
/// re-rolls the outbound's socket, unlike the per-connection `perConnRemote`
/// roll.
pub(super) fn finalmask_udp_hop_interval_mode(stream: &StreamModel) -> bool {
    stream
        .finalmask
        .as_ref()
        .is_some_and(|finalmask| finalmask.udp.iter().any(finalmask_udphop_selects_interval))
}

/// True when the transport can run an interval hop: hysteria2 and the
/// splithttp HTTP/3 mode carry a QUIC connection that migrates, and the
/// WireGuard outbound reads the mask from its stream settings and wraps its
/// own packet conn, which follows endpoint changes
/// (`proxy/wireguard/client.go:309-310`).
///
/// Splithttp dials HTTP/3 — and only that branch applies the mask manager
/// (`transport/internet/splithttp/dialer.go:216`) — when its TLS ALPN is
/// exactly `["h3"]`: REALITY forces HTTP/2 and a stream without TLS falls
/// back to HTTP/1.1 (`.../splithttp/dialer.go:82-99`). Other transports
/// either never wrap the mask list or cannot move a live connection, so an
/// interval hop cannot run there.
pub(super) fn hop_transport_migrates_connections(outbound: &OutboundModel) -> bool {
    if matches!(&outbound.settings, ProtocolSettings::Wireguard(_)) {
        return true;
    }
    match outbound.stream.network {
        Network::Hysteria => true,
        Network::Xhttp => tls_alpn_is_h3(&outbound.stream),
        _ => false,
    }
}

/// True when TLS selected the QUIC transport the way the core reads it: the
/// security mode is `tls` and the ALPN list is exactly `["h3"]`. XHTTP's h3
/// branch (`transport/internet/splithttp/dialer.go:82-99`) and xdrive's h3
/// form (`infra/conf/transport_internet.go:108-115`) both detect it this way;
/// no other spelling — a longer list, a mixed case, a REALITY block — selects
/// it.
pub(super) fn tls_alpn_is_h3(stream: &StreamModel) -> bool {
    stream.security == Security::Tls
        && stream
            .tls_settings
            .as_ref()
            .is_some_and(|tls| tls.alpn == ["h3"])
}

fn finalmask_valid_var_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return true;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

/// One matched `<key arg>` token of a `noise` `exp` expression: the key name,
/// the argument text (empty when the token carried none), and the byte offset
/// just past the closing `>`.
struct NoiseExpToken<'a> {
    key: &'a str,
    arg: &'a str,
    end: usize,
}

/// Match one `noise` `exp` token anchored at the `<` at `open`, with the
/// pinned core's regex `<\\s*([a-z]+)(?:\\s+([^>]*?))?\\s*>`
/// (`infra/conf/transport_finalmask.go:362`): optional whitespace, a
/// lowercase key, an optional whitespace-prefixed argument that stops before
/// the first `>` (trailing whitespace excluded by the lazy group), optional
/// whitespace, and the closing `>`. `None` when no token starts here.
fn match_noise_exp_token(expression: &str, open: usize) -> Option<NoiseExpToken<'_>> {
    let bytes = expression.as_bytes();
    let mut i = open + 1;
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    let key_start = i;
    while i < bytes.len() && bytes[i].is_ascii_lowercase() {
        i += 1;
    }
    if i == key_start {
        return None;
    }
    let key = &expression[key_start..i];
    if i < bytes.len() && bytes[i] == b'>' {
        return Some(NoiseExpToken {
            key,
            arg: "",
            end: i + 1,
        });
    }
    if i >= bytes.len() || !bytes[i].is_ascii_whitespace() {
        return None;
    }
    // `\s+` is greedy; the argument then runs to the smallest index whose
    // suffix up to the first `>` is whitespace.
    let mut j = i;
    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
        j += 1;
    }
    let close = j + expression[j..].find('>')?;
    let mut arg_end = close;
    while arg_end > j && bytes[arg_end - 1].is_ascii_whitespace() {
        arg_end -= 1;
    }
    Some(NoiseExpToken {
        key,
        arg: &expression[j..arg_end],
        end: close + 1,
    })
}

/// The verdict of one `noise` `exp` `packet` value, mirroring the mask
/// build: a JSON string is parsed as the token mini-language, JSON `null` is
/// Go's zero string (an empty expression), and anything else — the field
/// absent included — fails the string unmarshal
/// (`infra/conf/transport_finalmask.go:318-326`).
fn finalmask_validate_noise_exp(packet: &FinalmaskRawValue) -> Result<(), ValidationCode> {
    match packet.value() {
        None => Err(ValidationCode::FinalmaskNoiseExpPacketNotString),
        Some(Value::String(expression)) => finalmask_validate_noise_exp_expression(expression),
        Some(Value::Null) => Err(ValidationCode::FinalmaskNoiseExpEmpty),
        Some(_) => Err(ValidationCode::FinalmaskNoiseExpPacketNotString),
    }
}

/// Parse one `noise` `exp` expression the way `parseNoiseExp` does
/// (`infra/conf/transport_finalmask.go:364-391`): tokens matched left to
/// right, only whitespace allowed between and after them, at least one token
/// required, and every token built by [`build_noise_exp_segment`].
fn finalmask_validate_noise_exp_expression(expression: &str) -> Result<(), ValidationCode> {
    let mut last = 0usize;
    let mut cursor = 0usize;
    let mut segments = 0usize;
    while cursor < expression.len() {
        let Some(open) = expression[cursor..].find('<').map(|offset| cursor + offset) else {
            break;
        };
        let Some(token) = match_noise_exp_token(expression, open) else {
            cursor = open + 1;
            continue;
        };
        if !expression[last..open].trim().is_empty() {
            return Err(ValidationCode::FinalmaskNoiseExpTrailingText(excerpt(
                expression[last..open].trim(),
            )));
        }
        build_noise_exp_segment(&token)?;
        segments += 1;
        last = token.end;
        cursor = token.end;
    }
    if !expression[last..].trim().is_empty() {
        return Err(ValidationCode::FinalmaskNoiseExpTrailingText(excerpt(
            expression[last..].trim(),
        )));
    }
    if segments == 0 {
        return Err(ValidationCode::FinalmaskNoiseExpEmpty);
    }
    Ok(())
}

/// The finding for one `noise` `exp` expression string, for the editor's
/// inline verdict: `None` when the mask build accepts the expression. The
/// string half of [`finalmask_validate_noise_exp`], the verdict the packet
/// carries when its value is a JSON string.
pub fn noise_exp_finding(expression: &str) -> Option<ValidationCode> {
    finalmask_validate_noise_exp_expression(expression).err()
}

/// The finding for one whole `noise` `exp` `packet` value, for the editor's
/// inline verdict: `None` when the mask build accepts it. The same verdict
/// the pass stores for the packet, so a loaded value the editor cannot read
/// as a string still renders the rule that refused it.
pub fn noise_exp_packet_finding(packet: &FinalmaskRawValue) -> Option<ValidationCode> {
    finalmask_validate_noise_exp(packet).err()
}

/// Build one `noise` `exp` token the way `buildNoiseSegment` does
/// (`infra/conf/transport_finalmask.go:393-434`): `<b HEX>` is a byte
/// literal, `<r|rc|rd SIZE>` a sized random segment, `<t>`/`<c>`/`<n>` a
/// no-argument segment, and anything else an unknown token.
fn build_noise_exp_segment(token: &NoiseExpToken<'_>) -> Result<(), ValidationCode> {
    let size_segment = || {
        if token.arg.is_empty() {
            return Err(ValidationCode::FinalmaskNoiseExpMissingSize(
                token.key.to_owned(),
            ));
        }
        match parse_range_go(token.arg) {
            Some((from, to)) if from >= 0 && to >= from && to <= 65535 => Ok(()),
            _ => Err(ValidationCode::FinalmaskNoiseExpSizeInvalid(excerpt(
                token.arg,
            ))),
        }
    };
    match token.key {
        "b" => {
            // `strings.Fields` + `Join` drops every whitespace run, then the
            // optional `0x`/`0X` prefix is stripped before the hex decode.
            let joined: String = token.arg.split_whitespace().collect();
            let hex = joined.strip_prefix("0x").unwrap_or(&joined);
            let hex = hex.strip_prefix("0X").unwrap_or(hex);
            if hex.is_empty()
                || !hex.len().is_multiple_of(2)
                || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                let named = if token.arg.is_empty() {
                    token.key.to_owned()
                } else {
                    excerpt(token.arg)
                };
                return Err(ValidationCode::FinalmaskNoiseExpBytesInvalid(named));
            }
            Ok(())
        }
        "r" | "rc" | "rd" => size_segment(),
        "t" | "c" | "n" => {
            if token.arg.is_empty() {
                Ok(())
            } else {
                Err(ValidationCode::FinalmaskNoiseExpArgumentNotAllowed(
                    token.key.to_owned(),
                ))
            }
        }
        other => Err(ValidationCode::FinalmaskNoiseExpUnknownToken(
            other.to_owned(),
        )),
    }
}

fn finalmask_validate_bytes(
    path: &str,
    encoding: &str,
    raw: &FinalmaskRawValue,
    issues: &mut Vec<ValidationIssue>,
) {
    // `PraseByteSlice` folds the spelling with `strings.ToLower`
    // (`infra/conf/transport_finalmask.go:35`); no accepted value carries an
    // `i` or a `k` — the two letters where Go's simple fold and an ASCII fold
    // part ways — so this compares exactly, not by ASCII accident.
    let kind = fold_lower(encoding);
    let Some(value) = raw.value() else {
        if !matches!(&*kind, "" | "array") {
            issues.push(issue(
                ValidationCode::FinalmaskBytesValueRequired(excerpt(&kind)),
                Some(path.to_string()),
            ));
        }
        return;
    };
    match &*kind {
        "" | "array" => {
            // `json.Unmarshal` into `[]byte` reads a number array or a base64
            // string, and `null` clears the field — the core accepts all
            // three.
            let valid = match value {
                Value::Null => true,
                Value::Array(values) => values.iter().all(|value| {
                    // A `null` element is the zero byte: Go's decoder leaves
                    // the element's value alone and reports no error.
                    value.is_null() || value.as_u64().is_some_and(|byte| byte <= u8::MAX as u64)
                }),
                Value::String(text) => go_std_base64_decodes(text),
                _ => false,
            };
            if !valid {
                issues.push(issue(
                    ValidationCode::FinalmaskArrayByteSyntax,
                    Some(path.to_string()),
                ));
            }
        }
        "str" => {
            if !(value.is_string() || value.is_null()) {
                issues.push(issue(
                    ValidationCode::FinalmaskStrByteSyntax,
                    Some(path.to_string()),
                ));
            }
        }
        "hex" => {
            let valid = match value {
                Value::Null => true,
                Value::String(text) => {
                    text.len().is_multiple_of(2)
                        && text.bytes().all(|byte| byte.is_ascii_hexdigit())
                }
                _ => false,
            };
            if !valid {
                issues.push(issue(
                    ValidationCode::FinalmaskHexByteSyntax,
                    Some(path.to_string()),
                ));
            }
        }
        "base64" => {
            let valid = match value {
                Value::Null => true,
                Value::String(text) => go_std_base64_decodes(text),
                _ => false,
            };
            if !valid {
                issues.push(issue(
                    ValidationCode::FinalmaskBase64ByteSyntax,
                    Some(path.to_string()),
                ));
            }
        }
        _ => issues.push(issue(
            ValidationCode::FinalmaskUnknownByteSyntax(excerpt_debug(encoding)),
            Some(path.to_string()),
        )),
    }
}

fn finalmask_validate_transform(
    path: &str,
    transform: &FinalmaskTransform,
    issues: &mut Vec<ValidationIssue>,
) {
    if transform.op.is_empty() {
        issues.push(issue(
            ValidationCode::FinalmaskTransformOpRequired,
            Some(format!("{path}.op")),
        ));
    }
    if transform.args.is_empty() {
        issues.push(issue(
            ValidationCode::FinalmaskTransformArgRequired,
            Some(format!("{path}.args")),
        ));
    }
    for (index, arg) in transform.args.iter().enumerate() {
        let arg_path = format!("{path}.args[{index}]");
        let count = usize::from(!arg.bytes.is_absent())
            + usize::from(arg.u64.is_some())
            + usize::from(!arg.reuse.is_empty())
            + usize::from(!arg.metadata.is_empty())
            + usize::from(arg.transform.is_some());
        if count != 1 {
            issues.push(issue(
                ValidationCode::FinalmaskTransformArgExclusive,
                Some(arg_path.clone()),
            ));
        }
        if !arg.bytes.is_absent() {
            finalmask_validate_bytes(
                &format!("{arg_path}.bytes"),
                &arg.encoding,
                &arg.bytes,
                issues,
            );
        }
        if !finalmask_valid_var_name(&arg.reuse) {
            issues.push(issue(
                ValidationCode::FinalmaskVarNameInvalid,
                Some(format!("{arg_path}.reuse")),
            ));
        }
        if let Some(nested) = &arg.transform {
            finalmask_validate_transform(&format!("{arg_path}.transform"), nested, issues);
        }
    }
}

/// Read-only view of the finalmask header-custom item fields shared by the
/// TCP and UDP item structs, so validation can accept either.
trait FinalmaskCustomItem {
    fn capture(&self) -> &str;
    fn packet(&self) -> &FinalmaskRawValue;
    fn rand(&self) -> i32;
    fn rand_range(&self) -> Option<Int32Range>;
    fn encoding(&self) -> &str;
    fn reuse(&self) -> &str;
    fn transform(&self) -> Option<&FinalmaskTransform>;
}

impl FinalmaskCustomItem for crate::model::stream::FinalmaskTcpItem {
    fn capture(&self) -> &str {
        &self.capture
    }
    fn packet(&self) -> &FinalmaskRawValue {
        &self.packet
    }
    fn rand(&self) -> i32 {
        self.rand
    }
    fn rand_range(&self) -> Option<Int32Range> {
        self.rand_range
    }
    fn encoding(&self) -> &str {
        &self.encoding
    }
    fn reuse(&self) -> &str {
        &self.reuse
    }
    fn transform(&self) -> Option<&FinalmaskTransform> {
        self.transform.as_ref()
    }
}

impl FinalmaskCustomItem for crate::model::stream::FinalmaskUdpItem {
    fn capture(&self) -> &str {
        &self.capture
    }
    fn packet(&self) -> &FinalmaskRawValue {
        &self.packet
    }
    fn rand(&self) -> i32 {
        self.rand
    }
    fn rand_range(&self) -> Option<Int32Range> {
        self.rand_range
    }
    fn encoding(&self) -> &str {
        &self.encoding
    }
    fn reuse(&self) -> &str {
        &self.reuse
    }
    fn transform(&self) -> Option<&FinalmaskTransform> {
        self.transform.as_ref()
    }
}

fn finalmask_validate_custom_item(
    path: &str,
    item: &impl FinalmaskCustomItem,
    issues: &mut Vec<ValidationIssue>,
) {
    let capture = item.capture();
    let packet = item.packet();
    let rand = item.rand();
    let rand_range = item.rand_range();
    let encoding = item.encoding();
    let reuse = item.reuse();
    let transform = item.transform();
    if !finalmask_valid_var_name(capture) {
        issues.push(issue(
            ValidationCode::FinalmaskVarNameInvalid,
            Some(format!("{path}.capture")),
        ));
    }
    if !finalmask_valid_var_name(reuse) {
        issues.push(issue(
            ValidationCode::FinalmaskVarNameInvalid,
            Some(format!("{path}.reuse")),
        ));
    }
    let count = usize::from(!packet.is_absent())
        + usize::from(rand > 0)
        + usize::from(!reuse.is_empty())
        + usize::from(transform.is_some());
    if count > 1 || (count == 0 && !capture.is_empty()) {
        issues.push(issue(
            ValidationCode::FinalmaskCustomItemExclusive,
            Some(path.to_string()),
        ));
    }
    if let Some(range) = rand_range {
        let (from, to) = finalmask_range_bounds(range);
        if from < 0 || to > 255 {
            issues.push(issue(
                ValidationCode::FinalmaskRandRangeInvalid,
                Some(format!("{path}.randRange")),
            ));
        }
    }
    finalmask_validate_bytes(&format!("{path}.packet"), encoding, packet, issues);
    if let Some(transform) = transform {
        finalmask_validate_transform(&format!("{path}.transform"), transform, issues);
    }
}

fn finalmask_validate_sudoku(_path: &str, _settings: &FinalmaskSudoku) {
    // Xray deliberately accepts every value and applies current-field-over-
    // legacy-field precedence during Build.
}

fn finalmask_validate_xmc(path: &str, settings: &FinalmaskXmc, issues: &mut Vec<ValidationIssue>) {
    if settings.profiles.is_empty() {
        issues.push(issue(
            ValidationCode::FinalmaskXmcProfilesRequired,
            Some(format!("{path}.profiles")),
        ));
    }
    if settings.password.is_empty() {
        issues.push(issue(
            ValidationCode::FinalmaskXmcPasswordRequired,
            Some(format!("{path}.password")),
        ));
    }
    for (index, profile) in settings.profiles.iter().enumerate() {
        let profile_path = format!("{path}.profiles[{index}]");
        let username = profile.username.as_bytes();
        if !(3..=16).contains(&username.len())
            || !username
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            issues.push(issue(
                ValidationCode::FinalmaskXmcUsernameInvalid,
                Some(format!("{profile_path}.username")),
            ));
        }
        if !is_canonical_uuid(&profile.uuid) {
            issues.push(issue(
                ValidationCode::FinalmaskXmcUuidInvalid,
                Some(format!("{profile_path}.uuid")),
            ));
        }
        if profile.textures_value.is_empty() || profile.textures_signature.is_empty() {
            issues.push(issue(
                ValidationCode::FinalmaskXmcTexturesRequired,
                Some(profile_path),
            ));
        }
    }
}

/// QUIC `brutalUp`/`brutalDown` bandwidth → bytes per second.
///
/// `Ok(None)` is Xray's unset shape: blank input or an explicit zero (the
/// too-small rule's own message names `0/empty` as legal), which leaves the
/// QUIC parameter at its default. `Ok(Some(bytes))` is a positive bit rate
/// truncated to whole bytes, so a sub-byte rate (`"5bps"`, a bare `"1"`)
/// yields `Some(0)` — a value that can never work, reported by the caller as
/// too small instead of being read as unset.
fn finalmask_parse_bandwidth_bps(value: &str) -> Result<Option<u64>, ValidationCode> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let index = value
        .char_indices()
        .find_map(|(index, ch)| (!(ch.is_ascii_digit() || ch == '.')).then_some(index))
        .unwrap_or(value.len());
    let number: f64 = value[..index]
        .parse()
        .map_err(|_| ValidationCode::FinalmaskQuicBandwidthSyntax)?;
    if !number.is_finite() || number < 0.0 {
        return Err(ValidationCode::FinalmaskQuicBandwidthNonFinite);
    }
    // The core lowercases each unit with Go's simple fold before its own match
    // (transport_method.go:697), so a Kelvin-sign `k` is a kilobyte here too.
    // The value keeps its spelling for the message.
    let unit = value[index..].trim();
    let multiplier = if unit.is_empty() || fold_eq(unit, "b") || fold_eq(unit, "bps") {
        1_u64
    } else if fold_eq(unit, "k") || fold_eq(unit, "kb") || fold_eq(unit, "kbps") {
        1024
    } else if fold_eq(unit, "m") || fold_eq(unit, "mb") || fold_eq(unit, "mbps") {
        1024 * 1024
    } else if fold_eq(unit, "g") || fold_eq(unit, "gb") || fold_eq(unit, "gbps") {
        1024 * 1024 * 1024
    } else if fold_eq(unit, "t") || fold_eq(unit, "tb") || fold_eq(unit, "tbps") {
        1024_u64 * 1024 * 1024 * 1024
    } else {
        return Err(ValidationCode::FinalmaskQuicBandwidthUnitInvalid(excerpt(
            unit,
        )));
    };
    let bits = number * multiplier as f64;
    if bits > u64::MAX as f64 {
        return Err(ValidationCode::FinalmaskQuicBandwidthTooLarge);
    }
    if bits == 0.0 {
        return Ok(None);
    }
    Ok(Some(bits as u64 / 8))
}

fn finalmask_validate_port_list(
    path: &str,
    ports: &FinalmaskPortList,
    issues: &mut Vec<ValidationIssue>,
) {
    match ports {
        FinalmaskPortList::Number(port) => {
            if *port > u16::MAX as u32 {
                issues.push(issue(
                    ValidationCode::FinalmaskPortNumberRange,
                    Some(path.to_string()),
                ));
            }
        }
        FinalmaskPortList::Text(text) => {
            for item in text
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
            {
                if let Some(environment) = item.strip_prefix("env:") {
                    if environment.is_empty() {
                        issues.push(issue(
                            ValidationCode::FinalmaskPortEnvNameRequired,
                            Some(path.to_string()),
                        ));
                    }
                    continue;
                }
                let valid_port = |part: &str| {
                    part.parse::<u32>()
                        .is_ok_and(|port| port <= u16::MAX as u32)
                };
                let valid = match item.split_once('-') {
                    Some((from, to)) => valid_port(from) && valid_port(to) && !to.contains('-'),
                    None => valid_port(item),
                };
                if !valid {
                    issues.push(issue(
                        ValidationCode::FinalmaskPortListInvalid(excerpt_debug(item)),
                        Some(path.to_string()),
                    ));
                }
            }
        }
    }
}

fn finalmask_validate_quic_params(
    path: &str,
    quic: &FinalmaskQuicParams,
    issues: &mut Vec<ValidationIssue>,
) {
    // `strings.ToLower` on the wire (`infra/conf/transport_internet.go:250`);
    // the vocabulary carries no `i` or `k`, so the primitive folds it exactly
    // rather than by an ASCII accident a future value would break.
    let congestion = fold_lower(&quic.congestion);
    if !matches!(
        &*congestion,
        "" | "brutal" | "reno" | "bbr" | "force-brutal"
    ) {
        issues.push(issue(
            ValidationCode::FinalmaskQuicCongestionInvalid,
            Some(format!("{path}.congestion")),
        ));
    }
    if !(quic.bbr_profile.is_empty()
        || vocabulary_holds(
            &["conservative", "standard", "aggressive"],
            &quic.bbr_profile,
        ))
    {
        issues.push(issue(
            ValidationCode::FinalmaskQuicBbrProfileInvalid,
            Some(format!("{path}.bbrProfile")),
        ));
    }
    // An unset (blank/explicit-zero) bandwidth reports nothing; a positive
    // rate below the 64 KiB/s floor — including one that truncates below a
    // single byte per second — reports the too-small rule. `force-brutal`
    // additionally needs an upload rate at all, but only when the value
    // itself parsed: a syntax/unit finding already names the field, so the
    // derived rule must not double-report the same path.
    let mut up_parse_failed = false;
    let up = match finalmask_parse_bandwidth_bps(&quic.brutal_up) {
        Ok(Some(value)) => {
            if value < 65_536 {
                issues.push(issue(
                    ValidationCode::FinalmaskQuicBandwidthTooSmall,
                    Some(format!("{path}.brutalUp")),
                ));
            }
            Some(value)
        }
        Ok(None) => None,
        Err(code) => {
            issues.push(issue(code, Some(format!("{path}.brutalUp"))));
            up_parse_failed = true;
            None
        }
    };
    match finalmask_parse_bandwidth_bps(&quic.brutal_down) {
        Ok(Some(value)) if value < 65_536 => issues.push(issue(
            ValidationCode::FinalmaskQuicBandwidthTooSmall,
            Some(format!("{path}.brutalDown")),
        )),
        Err(code) => issues.push(issue(code, Some(format!("{path}.brutalDown")))),
        _ => {}
    }
    if congestion == "force-brutal" && up.is_none() && !up_parse_failed {
        issues.push(issue(
            ValidationCode::FinalmaskQuicForceBrutalNeedsUp,
            Some(format!("{path}.brutalUp")),
        ));
    }
    if quic.retired_udp_hop.is_some() {
        // The retired `quicParams.udpHop` key left this mark behind: the
        // core ignores the key and the hop would die silently, so the user is
        // told to rebuild it as a `udphop` UDP mask. Nothing is migrated —
        // the raw value stays for the settings file and the generated
        // document never carries it. Carries no path: the key is a
        // settings-file fact, not a field of the generated document.
        issues.push(warning(ValidationCode::FinalmaskQuicHopMoved, None));
    }
    for (name, value) in [
        ("initStreamReceiveWindow", quic.init_stream_receive_window),
        ("maxStreamReceiveWindow", quic.max_stream_receive_window),
        (
            "initConnectionReceiveWindow",
            quic.init_connection_receive_window,
        ),
        (
            "maxConnectionReceiveWindow",
            quic.max_connection_receive_window,
        ),
    ] {
        if value.is_some_and(|value| value > 0 && value < 16_384) {
            issues.push(issue(
                ValidationCode::FinalmaskQuicReceiveWindowTooSmall,
                Some(format!("{path}.{name}")),
            ));
        }
    }
    if quic
        .max_idle_timeout
        .is_some_and(|value| value != 0 && !(4..=120).contains(&value))
    {
        issues.push(issue(
            ValidationCode::FinalmaskQuicMaxIdleTimeoutInvalid,
            Some(format!("{path}.maxIdleTimeout")),
        ));
    }
    if quic
        .keep_alive_period
        .is_some_and(|value| value != 0 && !(2..=60).contains(&value))
    {
        issues.push(issue(
            ValidationCode::FinalmaskQuicKeepAlivePeriodInvalid,
            Some(format!("{path}.keepAlivePeriod")),
        ));
    }
    if quic
        .max_incoming_streams
        .is_some_and(|value| value != 0 && value < 8)
    {
        issues.push(issue(
            ValidationCode::FinalmaskQuicMaxIncomingStreamsInvalid,
            Some(format!("{path}.maxIncomingStreams")),
        ));
    }
}

fn finalmask_validate_tcp_mask(
    index: usize,
    mask: &FinalmaskTcpMask,
    issues: &mut Vec<ValidationIssue>,
) {
    let path = format!("finalmask.tcp[{index}]");
    match mask {
        FinalmaskTcpMask::Filter { settings, .. } => {
            finalmask_validate_filter(&format!("{path}.settings"), settings, issues);
        }
        FinalmaskTcpMask::HeaderCustom { settings, .. } => {
            for (group_name, groups) in [
                ("clients", &settings.clients),
                ("servers", &settings.servers),
                ("errors", &settings.errors),
            ] {
                for (sequence_index, sequence) in groups.iter().enumerate() {
                    for (item_index, item) in sequence.iter().enumerate() {
                        finalmask_validate_custom_item(
                            &format!(
                                "{path}.settings.{group_name}[{sequence_index}][{item_index}]"
                            ),
                            item,
                            issues,
                        );
                    }
                }
            }
        }
        FinalmaskTcpMask::Fragment { settings, .. } => {
            if !settings.packets.is_empty() && !fold_eq(&settings.packets, "tlshello") {
                match Int32Range::parse(&settings.packets) {
                    Some(range) if range.from != 0 => {}
                    Some(_) => issues.push(issue(
                        ValidationCode::FinalmaskPacketsFirstNotZero,
                        Some(format!("{path}.settings.packets")),
                    )),
                    None => issues.push(issue(
                        ValidationCode::FinalmaskPacketsSyntax,
                        Some(format!("{path}.settings.packets")),
                    )),
                }
            }
            let last = settings.lengths.last().copied().unwrap_or(settings.length);
            if finalmask_range_bounds(last).0 == 0 {
                issues.push(issue(
                    ValidationCode::FinalmaskLengthsStartAboveZero,
                    Some(format!("{path}.settings.lengths")),
                ));
            }
        }
        FinalmaskTcpMask::Sudoku { settings, .. } => {
            finalmask_validate_sudoku(&format!("{path}.settings"), settings);
        }
        FinalmaskTcpMask::Xmc { settings, .. } => {
            finalmask_validate_xmc(&format!("{path}.settings"), settings, issues);
        }
        FinalmaskTcpMask::Unknown(raw) => issues.push(issue(
            ValidationCode::FinalmaskUnknownTcpMask(
                raw.get("type").and_then(Value::as_str).map(excerpt),
            ),
            Some(path),
        )),
    }
}

fn finalmask_valid_split_host_port(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix('[') {
        return rest.find(']').is_some_and(|close| {
            rest.get(close + 1..)
                .is_some_and(|suffix| suffix.starts_with(':'))
        });
    }
    value.matches(':').count() == 1
}

/// The scheme an `xdns` resolver address selects, mirroring the mask build
/// (`infra/conf/transport_finalmask.go:903-923`): an address without `://` is
/// read as `udp://<address>` (port 53 when the address carries none), while
/// a spelled scheme must be `tcp`, `udp`, or `https`. `None` when the core
/// refuses the address for its scheme.
fn finalmask_xdns_addr_scheme(value: &str) -> Option<&'static str> {
    match value.split_once("://") {
        Some((scheme, authority)) => match &*fold_lower(scheme) {
            "tcp" => finalmask_xdns_host_authority(authority).then_some("tcp"),
            "udp" => finalmask_xdns_host_authority(authority).then_some("udp"),
            "https" => finalmask_xdns_https_authority(authority).then_some("https"),
            _ => None,
        },
        None => finalmask_xdns_host_authority(value).then_some("udp"),
    }
}

/// The scheme an address spells when it carries `://` at all, whatever the
/// core thinks of it.
fn finalmask_xdns_addr_scheme_word(value: &str) -> Option<&str> {
    value
        .split_once("://")
        .map(|(scheme, _)| scheme)
        .filter(|scheme| !scheme.is_empty())
}

/// True for the authority Go's URL parser hands the mask build: the part
/// before the first `/`, `?`, `#`, with any userinfo dropped. A bracketed
/// IPv6 host or a host without a colon may carry a numeric port; a missing
/// port takes the core's 53.
fn finalmask_xdns_host_authority(authority: &str) -> bool {
    let authority = authority.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or("");
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return false;
        };
        if host.is_empty() {
            return false;
        }
        return match tail.strip_prefix(':') {
            None => tail.is_empty(),
            Some(port) => port.parse::<u16>().is_ok_and(|port| port != 0),
        };
    }
    match authority.split_once(':') {
        None => !authority.is_empty() && !authority.contains(['[', ']']),
        Some((host, port)) => {
            !host.is_empty()
                && !host.contains(['[', ']', ':'])
                && port.parse::<u16>().is_ok_and(|port| port != 0)
        }
    }
}

/// True for a DoH URL the mask build accepts: a non-empty host after the
/// scheme, with the path and query passed through to the HTTP client.
fn finalmask_xdns_https_authority(authority: &str) -> bool {
    let authority = authority.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or("");
    if authority.is_empty() || authority.chars().any(char::is_whitespace) {
        return false;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return false;
        };
        return !host.is_empty()
            && match tail.strip_prefix(':') {
                None => tail.is_empty(),
                Some(port) => port.parse::<u16>().is_ok_and(|port| port != 0),
            };
    }
    match authority.split_once(':') {
        None => true,
        Some((host, port)) => !host.is_empty() && port.parse::<u16>().is_ok_and(|port| port != 0),
    }
}

/// Whether one `xdns` domain's limits leave the room its name needs. The
/// loader substitutes a zero `lenLimit` with 255 and a zero `labelLimit` with
/// 63 before it builds the domain
/// (`infra/conf/transport_finalmask.go:858-863`); the build then refuses a
/// `lenLimit` below the wire length of the name plus one, and a derived label
/// capacity below 17 bytes
/// (`transport/internet/finalmask/xdns/domain.go:112-128`). The name's wire
/// length is its bytes plus the trailing root dot, exactly the `uint8(len)`
/// the core's `dnsmessage.NewName(name + ".")` records
/// (`transport/internet/finalmask/xdns/domain.go:112-115`). `None` when a
/// limit is outside its own range: the core refuses that first, and the
/// caller reports it instead.
fn finalmask_xdns_capacity_refused(name: &str, domain: &FinalmaskXdnsDomain) -> bool {
    if !(0..=255).contains(&domain.len_limit) || !(0..=63).contains(&domain.label_limit) {
        return false;
    }
    let len_limit = if domain.len_limit == 0 {
        255
    } else {
        domain.len_limit
    };
    let label_limit = if domain.label_limit == 0 {
        63
    } else {
        domain.label_limit
    };
    let name_len = name.len() as i32 + 1;
    if len_limit < name_len + 1 {
        return true;
    }
    let room = len_limit - name_len - 1;
    let label = label_limit + 1;
    let mut total = (room / label) * label_limit;
    let left = room % label;
    if left > 1 {
        total += left - 1;
    }
    // `base32.StdEncoding.WithPadding(NoPadding).DecodedLen(total)`, the
    // capacity table `NewDomain` indexes (`domain.go:47-53`, `:126-128`):
    // `total/8*5 + total%8*5/8`, which is the floor of five eighths.
    total * 5 / 8 < 17
}

fn finalmask_validate_udp_mask(
    index: usize,
    mask: &FinalmaskUdpMask,
    issues: &mut Vec<ValidationIssue>,
) {
    let path = format!("finalmask.udp[{index}]");
    match mask {
        FinalmaskUdpMask::Filter { settings, .. } => {
            finalmask_validate_filter(&format!("{path}.settings"), settings, issues);
        }
        FinalmaskUdpMask::HeaderCustom { settings, .. } => {
            if !matches!(settings.mode.as_str(), "" | "prefix" | "standalone") {
                issues.push(issue(
                    ValidationCode::FinalmaskUdpHeaderModeInvalid,
                    Some(format!("{path}.settings.mode")),
                ));
            }
            for (group_name, items) in [("client", &settings.client), ("server", &settings.server)]
            {
                for (item_index, item) in items.iter().enumerate() {
                    finalmask_validate_custom_item(
                        &format!("{path}.settings.{group_name}[{item_index}]"),
                        item,
                        issues,
                    );
                }
            }
        }
        FinalmaskUdpMask::MkcpLegacy { settings, .. } => {
            if !(settings.header.is_empty()
                || vocabulary_holds(
                    &["dns", "dtls", "srtp", "utp", "wechat", "wireguard"],
                    &settings.header,
                ))
            {
                issues.push(issue(
                    ValidationCode::FinalmaskMkcpHeaderInvalid,
                    Some(format!("{path}.settings.header")),
                ));
            }
        }
        FinalmaskUdpMask::Noise { settings, .. } => {
            for code in super::settings::noise_script_issues(
                settings.script.as_deref(),
                settings.noise.len(),
            ) {
                issues.push(issue(code, Some(format!("{path}.settings.script"))));
            }
            for (item_index, item) in settings.noise.iter().enumerate() {
                let item_path = format!("{path}.settings.noise[{item_index}]");
                if !item.packet.is_absent() && finalmask_range_bounds(item.rand).1 > 0 {
                    issues.push(issue(
                        ValidationCode::FinalmaskNoisePacketExclusive,
                        Some(item_path.clone()),
                    ));
                }
                // `type: "exp"` (folded, `infra/conf/transport_finalmask.go:318`)
                // takes the packet as a string holding the token mini-language;
                // the core returns before it reads `randRange`, so the other
                // checks below apply to the legacy byte-encoding types only.
                if fold_eq(&item.encoding, "exp") {
                    if let Err(code) = finalmask_validate_noise_exp(&item.packet) {
                        issues.push(issue(code, Some(format!("{item_path}.packet"))));
                    }
                    continue;
                }
                if let Some(range) = item.rand_range {
                    let (from, to) = finalmask_range_bounds(range);
                    if from < 0 || to > 255 {
                        issues.push(issue(
                            ValidationCode::FinalmaskRandRangeInvalid,
                            Some(format!("{item_path}.randRange")),
                        ));
                    }
                }
                finalmask_validate_bytes(
                    &format!("{item_path}.packet"),
                    &item.encoding,
                    &item.packet,
                    issues,
                );
            }
        }
        FinalmaskUdpMask::Salamander { settings, .. } => {
            let (from, to) = finalmask_range_bounds(settings.packet_size);
            if to > 0 && (from <= 0 || to > 2048) {
                issues.push(issue(
                    ValidationCode::FinalmaskSalamanderPacketSize,
                    Some(format!("{path}.settings.packetSize")),
                ));
            }
        }
        FinalmaskUdpMask::Sudoku { settings, .. } => {
            finalmask_validate_sudoku(&format!("{path}.settings"), settings);
        }
        FinalmaskUdpMask::Xdns { settings, .. } => {
            if settings.retired_shape {
                issues.push(warning(
                    ValidationCode::FinalmaskXdnsShapeRetired,
                    Some(format!("{path}.settings")),
                ));
            }
            // The mask build emits one domain per name and one resolver per
            // address (`infra/conf/transport_finalmask.go`), so either list
            // with no row hands `NewClient` the empty list it refuses before
            // it reads any entry (`transport/internet/finalmask/xdns/client.go`).
            // The per-row findings below cannot see a list with no rows.
            if settings.domains.is_empty() {
                issues.push(issue(
                    ValidationCode::FinalmaskXdnsDomainsEmpty,
                    Some(format!("{path}.settings.domains")),
                ));
            }
            if settings.resolvers.is_empty() {
                issues.push(issue(
                    ValidationCode::FinalmaskXdnsResolversEmpty,
                    Some(format!("{path}.settings.resolvers")),
                ));
            }
            for (domain_index, domain) in settings.domains.iter().enumerate() {
                let entry_path = format!("{path}.settings.domains[{domain_index}]");
                if domain.types.is_empty()
                    || domain
                        .types
                        .iter()
                        .any(|record_type| !matches!(record_type, 1 | 5 | 16 | 28))
                {
                    issues.push(issue(
                        ValidationCode::FinalmaskXdnsDomainTypesInvalid,
                        Some(format!("{entry_path}.types")),
                    ));
                }
                for (name_index, name) in domain.names.iter().enumerate() {
                    let name_path = format!("{entry_path}.names[{name_index}]");
                    if name.contains("..") {
                        issues.push(issue(
                            ValidationCode::FinalmaskXdnsDomainNameInvalid,
                            Some(name_path),
                        ));
                    } else if finalmask_xdns_capacity_refused(name, domain) {
                        issues.push(issue(
                            ValidationCode::FinalmaskXdnsDomainCapacityInvalid,
                            Some(name_path),
                        ));
                    }
                }
                if !(0..=255).contains(&domain.len_limit) {
                    issues.push(issue(
                        ValidationCode::FinalmaskXdnsDomainLimitInvalid,
                        Some(format!("{entry_path}.lenLimit")),
                    ));
                }
                if !(0..=63).contains(&domain.label_limit) {
                    issues.push(issue(
                        ValidationCode::FinalmaskXdnsDomainLimitInvalid,
                        Some(format!("{entry_path}.labelLimit")),
                    ));
                }
                if domain.edns0 != 0 && !(512..=4096).contains(&domain.edns0) {
                    issues.push(issue(
                        ValidationCode::FinalmaskXdnsDomainLimitInvalid,
                        Some(format!("{entry_path}.edns0")),
                    ));
                }
            }
            for (resolver_index, resolver) in settings.resolvers.iter().enumerate() {
                let entry_path = format!("{path}.settings.resolvers[{resolver_index}]");
                if resolver.addrs.is_empty() {
                    issues.push(issue(
                        ValidationCode::FinalmaskXdnsResolverAddrsEmpty,
                        Some(format!("{entry_path}.addrs")),
                    ));
                }
                for (addr_index, addr) in resolver.addrs.iter().enumerate() {
                    let addr_path = format!("{entry_path}.addrs[{addr_index}]");
                    match finalmask_xdns_addr_scheme(addr) {
                        Some("https") if resolver.tls_config.is_none() => {
                            issues.push(issue(
                                ValidationCode::FinalmaskXdnsHttpsRequiresTls,
                                Some(addr_path),
                            ));
                        }
                        Some(_) => {}
                        None => match finalmask_xdns_addr_scheme_word(addr) {
                            Some(scheme) => issues.push(issue(
                                ValidationCode::FinalmaskXdnsAddrSchemeUnknown(scheme.to_string()),
                                Some(addr_path),
                            )),
                            None => issues.push(issue(
                                ValidationCode::FinalmaskXdnsResolverAddrInvalid,
                                Some(addr_path),
                            )),
                        },
                    }
                }
                if resolver.worker < 0 {
                    issues.push(issue(
                        ValidationCode::FinalmaskXdnsWorkerInvalid,
                        Some(format!("{entry_path}.worker")),
                    ));
                }
                // A resolver's nested `tlsConfig` is the same `TlsModel` the
                // outbound carries, built by the same `TLSConfig.Build`, so
                // it takes the same rules under its own path. DoH speaks TLS
                // unconditionally, so the connection rules apply as well.
                if let Some(tls) = resolver.tls_config.as_ref() {
                    let tls_path = format!("{entry_path}.tlsConfig");
                    validate_tls_settings(tls, &tls_path, issues);
                    validate_tls_connection_settings(tls, &tls_path, issues);
                }
                if let Some(quic) = resolver.quic_config.as_ref() {
                    finalmask_validate_quic_params(
                        &format!("{entry_path}.quicConfig"),
                        quic,
                        issues,
                    );
                }
            }
            if !(0..=3).contains(&settings.extra_poll) {
                issues.push(issue(
                    ValidationCode::FinalmaskXdnsExtraPollInvalid,
                    Some(format!("{path}.settings.extraPoll")),
                ));
            }
        }
        FinalmaskUdpMask::Xicmp { settings, .. } => {
            for (ip_index, ip) in settings.ips.iter().enumerate() {
                if ip.parse::<std::net::IpAddr>().is_err() {
                    issues.push(issue(
                        ValidationCode::FinalmaskXicmpIpInvalid,
                        Some(format!("{path}.settings.ips[{ip_index}]")),
                    ));
                }
            }
        }
        FinalmaskUdpMask::Realm { settings, .. } => {
            match url::Url::parse(&settings.url) {
                Ok(url) => {
                    if !matches!(url.scheme(), "realm" | "realm+http") {
                        issues.push(issue(
                            ValidationCode::FinalmaskRealmScheme,
                            Some(format!("{path}.settings.url")),
                        ));
                    }
                    if url.host_str().is_none_or(str::is_empty) {
                        issues.push(issue(
                            ValidationCode::FinalmaskRealmHostRequired,
                            Some(format!("{path}.settings.url")),
                        ));
                    }
                    if url.username().is_empty() {
                        issues.push(issue(
                            ValidationCode::FinalmaskRealmTokenBeforeAt,
                            Some(format!("{path}.settings.url")),
                        ));
                    }
                    if url.path().trim_start_matches('/').is_empty() {
                        issues.push(issue(
                            ValidationCode::FinalmaskRealmIdInPath,
                            Some(format!("{path}.settings.url")),
                        ));
                    }
                }
                Err(error) => issues.push(issue(
                    ValidationCode::FinalmaskRealmUrlSyntax(excerpt(&error.to_string())),
                    Some(format!("{path}.settings.url")),
                )),
            }
            if settings.stun_servers.is_empty() {
                issues.push(issue(
                    ValidationCode::FinalmaskRealmStunRequired,
                    Some(format!("{path}.settings.stunServers")),
                ));
            }
            for (server_index, server) in settings.stun_servers.iter().enumerate() {
                if !finalmask_valid_split_host_port(server) {
                    issues.push(issue(
                        ValidationCode::FinalmaskRealmStunFormat,
                        Some(format!("{path}.settings.stunServers[{server_index}]")),
                    ));
                }
            }
            if let Some(tls) = &settings.tls_config {
                finalmask_validate_realm_tls(&format!("{path}.settings.tlsConfig"), tls, issues);
            }
        }
        FinalmaskUdpMask::Udphop { settings, .. } => {
            finalmask_validate_udphop(&format!("{path}.settings"), settings, issues);
        }
        FinalmaskUdpMask::Unknown(raw) => issues.push(issue(
            ValidationCode::FinalmaskUnknownUdpMask(
                raw.get("type").and_then(Value::as_str).map(excerpt),
            ),
            Some(path),
        )),
    }
}

/// One `udphop` `mode` name, matched the way the mask build matches it:
/// split on `,`, lowercased, never trimmed
/// (`infra/conf/transport_finalmask.go:925-940`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum FinalmaskUdpHopMode {
    IntervalLocal,
    IntervalRemote,
    PerConnRemote,
}

/// Classify one component of a `udphop` mask's `mode` value. `None` when the
/// component is outside the three names — the mask build refuses that shape
/// at config load, so the mode gate reports it and the interval-hop advisory
/// stays silent for it rather than adding a second message for one value.
fn finalmask_udphop_mode(component: &str) -> Option<FinalmaskUdpHopMode> {
    if fold_eq(component, "intervallocal") {
        Some(FinalmaskUdpHopMode::IntervalLocal)
    } else if fold_eq(component, "intervalremote") {
        Some(FinalmaskUdpHopMode::IntervalRemote)
    } else if fold_eq(component, "perconnremote") {
        Some(FinalmaskUdpHopMode::PerConnRemote)
    } else {
        None
    }
}

/// True when one `udphop` mask selects an interval mode over a well-formed
/// `mode` set. Each interval hop moves or re-rolls the outbound's socket,
/// unlike the per-connection `perConnRemote` roll, so only a transport that
/// moves a live connection runs it.
fn finalmask_udphop_selects_interval(mask: &FinalmaskUdpMask) -> bool {
    let FinalmaskUdpMask::Udphop { settings, .. } = mask else {
        return false;
    };
    let mut interval = false;
    for component in settings.mode.split(',') {
        match finalmask_udphop_mode(component) {
            // An invalid component is the mode gate's load error; the
            // advisory never speaks for a mode set the profile cannot use.
            None => return false,
            Some(FinalmaskUdpHopMode::IntervalLocal | FinalmaskUdpHopMode::IntervalRemote) => {
                interval = true;
            }
            Some(FinalmaskUdpHopMode::PerConnRemote) => {}
        }
    }
    interval
}

/// Validate one `udphop` UDP mask's settings against the mask build and the
/// wrap-time checks (`infra/conf/transport_finalmask.go:911-965` and
/// `transport/internet/finalmask/udphop/conn.go:71-73`).
fn finalmask_validate_udphop(
    path: &str,
    settings: &crate::model::stream::FinalmaskUdpHop,
    issues: &mut Vec<ValidationIssue>,
) {
    // The build splits on ',' and refuses every component outside the three
    // names, case-insensitively and without trimming each split part
    // (`strings.Split` + `strings.ToLower`,
    // `infra/conf/transport_finalmask.go:925-940`), so a whitespace-carrying
    // component is refused too — the pinned core exits with `invalid mode
    // intervalRemote` for `"intervalLocal, intervalRemote"`. An empty mode
    // splits to one empty component and is refused as well.
    if settings
        .mode
        .split(',')
        .any(|component| finalmask_udphop_mode(component).is_none())
    {
        issues.push(issue(
            ValidationCode::FinalmaskUdpHopModeInvalid,
            Some(format!("{path}.mode")),
        ));
    }
    // The build replaces a fully unset `0/0` range with its own `30/30`
    // default, so the key is optional and the core picks the period; any
    // other shape with an endpoint below 5 seconds is refused — the load
    // check reads `From` (`infra/conf/transport_finalmask.go:1098-1104`) and
    // the wrap refuses either endpoint below 5 at dial
    // (`udphop/conn.go:56-58`), so both bounds must clear the floor.
    let (from, to) = finalmask_range_bounds(settings.interval);
    if (from != 0 || to != 0) && (from < 5 || to < 5) {
        issues.push(issue(
            ValidationCode::FinalmaskUdpHopIntervalTooSmall,
            Some(format!("{path}.interval")),
        ));
    }
    finalmask_validate_port_list(
        &format!("{path}.remotePorts"),
        &settings.remote_ports,
        issues,
    );
    for (index, entry) in settings.remote_ips.iter().enumerate() {
        if crate::model::stream::finalmask_udphop_remote_ip(entry).is_none() {
            issues.push(issue(
                ValidationCode::FinalmaskUdpHopIpInvalid,
                Some(format!("{path}.remoteIPs[{index}]")),
            ));
        }
    }
    if settings.sockopt.is_some() {
        // The retired `sockopt` key left this mark behind: the mask build
        // dropped the field and the core ignores the unknown key, so the
        // per-hop socket options never take effect. The value stays for the
        // settings file and is stripped from the generated document.
        issues.push(warning(
            ValidationCode::FinalmaskUdpHopSockoptRetired,
            Some(format!("{path}.sockopt")),
        ));
    }
}

fn finalmask_validate_realm_tls(
    path: &str,
    tls: &crate::model::stream::FinalmaskRealmTls,
    issues: &mut Vec<ValidationIssue>,
) {
    if tls.allow_insecure == Some(true) {
        issues.push(issue(
            ValidationCode::FinalmaskRealmAllowInsecureRemoved,
            Some(format!("{path}.allowInsecure")),
        ));
    }
    // Canonical fingerprint vocabulary (src/model/fingerprint.rs): the full
    // table. The historical inline allow-list lowercased the value before
    // matching; `wire_validation_supported` keeps that ASCII-case tolerance.
    if !crate::model::fingerprint::wire_validation_supported(&tls.fingerprint) {
        issues.push(issue(
            ValidationCode::FinalmaskRealmFingerprintUnknown,
            Some(format!("{path}.fingerprint")),
        ));
    }
    if tls.alpn.len() > 1 && tls.alpn.iter().any(|alpn| alpn == "fromMitm") {
        issues.push(issue(
            ValidationCode::FinalmaskRealmAlpnFromMitm,
            Some(format!("{path}.alpn")),
        ));
    }
    for (certificate_index, certificate) in tls.certificates.iter().enumerate() {
        if certificate.certificate_file.is_empty()
            && certificate.certificate.iter().all(String::is_empty)
        {
            issues.push(issue(
                ValidationCode::FinalmaskRealmCertRequired,
                Some(format!("{path}.certificates[{certificate_index}]")),
            ));
        }
    }
    if !tls.ech_server_keys.is_empty() && !go_std_base64_decodes(&tls.ech_server_keys) {
        issues.push(issue(
            ValidationCode::FinalmaskRealmEchKeysBase64,
            Some(format!("{path}.echServerKeys")),
        ));
    }
    if let Some(sockopt) = &tls.ech_sockopt {
        issues.extend(validate_sockopt(sockopt, &format!("{path}.echSockopt")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::stream::{CustomSockopt, GrpcSettings, KcpSettings, XhttpSettings};
    use crate::model::validation::outbound::{
        dns_out_action_supported, freedom_final_rule_supported, sniffing_dest_override_supported,
    };
    use crate::model::validation::tests::codes;
    use crate::model::validation::{Severity, VISION_FLOW_OPTIONS};
    use serde_json::{Map, json};
    /// Every published field vocabulary and the predicate that judges it
    /// agree: the predicate accepts each entry of the list, and refuses the
    /// near-misses the list does not hold (a case variant of a case-sensitive
    /// vocabulary, a spelling with stray whitespace, a value one step past
    /// the set). A combo that offers a value its own rule refuses, or a rule
    /// that drifts off its list, reds here.
    #[test]
    fn field_vocabularies_and_their_predicates_agree() {
        fn couples(options: &[&str], accepts: impl Fn(&str) -> bool, refused: &[&str]) {
            assert!(
                !options.is_empty(),
                "a published vocabulary must hold the values it offers"
            );
            for entry in options {
                assert!(
                    accepts(entry),
                    "{entry:?} is in its vocabulary and refused by its predicate"
                );
            }
            for neighbour in refused {
                assert!(
                    !accepts(neighbour),
                    "{neighbour:?} is outside the vocabulary and must be refused"
                );
            }
        }

        couples(
            TARGET_STRATEGY_OPTIONS,
            target_strategy_supported,
            &["ForceIPv6v4 ", "asis+", "bogus"],
        );
        couples(
            SOCKOPT_DOMAIN_STRATEGY_OPTIONS,
            sockopt_domain_strategy_supported,
            &["asis+", "bogus"],
        );
        couples(
            SOCKOPT_ADDRESS_PORT_STRATEGY_OPTIONS,
            sockopt_address_port_strategy_supported,
            &["srvportonly ", "txtportandaddress!", "bogus"],
        );
        couples(
            SS_METHOD_OPTIONS,
            shadowsocks_method_supported,
            &["", "aes-128-gcm ", "2022-blake3-bogus", "bogus"],
        );
        couples(
            XHTTP_MODE_OPTIONS,
            xhttp_mode_supported,
            &["packet_up", "stream-one-plus", "bogus"],
        );
        couples(
            X_PADDING_PLACEMENT_OPTIONS,
            xpadding_placement_supported,
            &["queryinheader", "body", "bogus"],
        );
        couples(
            XPADDING_METHOD_OPTIONS,
            xpadding_method_supported,
            &["repeatx", "cookie", "bogus"],
        );
        couples(
            UPLINK_DATA_PLACEMENT_OPTIONS,
            uplink_data_placement_supported,
            &["path", "body ", "bogus"],
        );
        couples(
            SESSION_ID_PLACEMENT_OPTIONS,
            session_id_placement_supported,
            &["body", "query ", "bogus"],
        );
        couples(
            SEQ_PLACEMENT_OPTIONS,
            seq_placement_supported,
            &["body", "query ", "bogus"],
        );
        couples(
            TLS_VERSION_OPTIONS,
            tls_version_supported,
            &["", "1.4", "TLSv1.3", "bogus"],
        );
        couples(
            VMESS_SECURITY_OPTIONS,
            vmess_security_supported,
            &["auto ", "aes128-gcm", "bogus"],
        );
        couples(
            VISION_FLOW_OPTIONS,
            is_vision_flow,
            &["", "xtls-rprx-vision-udp444", "bogus"],
        );
    }

    /// The uplink placement lists partition the vocabulary: every advertised
    /// placement is accepted in some mode, and the two mode subsets are
    /// disjoint and cover it — so the editor's off-`packet-up` combo and the
    /// rule that refuses the rest cannot drift.
    #[test]
    fn uplink_placement_subsets_partition_the_vocabulary() {
        for placement in UPLINK_DATA_PLACEMENT_OPTIONS {
            assert!(
                uplink_placement_mode_supported(placement, "packet-up"),
                "{placement:?} must be accepted in packet-up"
            );
        }
        for placement in UPLINK_STREAM_PLACEMENT_OPTIONS {
            assert!(
                uplink_placement_mode_supported(placement, "stream-up"),
                "{placement:?} is advertised off packet-up and refused there"
            );
            assert!(
                UPLINK_DATA_PLACEMENT_OPTIONS.contains(&placement),
                "{placement:?} is not in the vocabulary"
            );
        }
        for placement in UPLINK_PACKET_UP_ONLY_PLACEMENTS {
            assert!(
                !uplink_placement_mode_supported(placement, "stream-up"),
                "{placement:?} is packet-up-only and accepted off it"
            );
            assert!(
                UPLINK_DATA_PLACEMENT_OPTIONS.contains(&placement),
                "{placement:?} is not in the vocabulary"
            );
        }
        assert_eq!(
            UPLINK_STREAM_PLACEMENT_OPTIONS.len() + UPLINK_PACKET_UP_ONLY_PLACEMENTS.len(),
            UPLINK_DATA_PLACEMENT_OPTIONS.len(),
            "the two mode subsets must cover the vocabulary exactly"
        );
    }

    /// The findings one `header-custom` client item with `encoding` and
    /// `packet` draws from the finalmask pass.
    fn mask_codes(encoding: &str, packet: serde_json::Value) -> Vec<ValidationCode> {
        let model: FinalmaskModel = serde_json::from_value(json!({
            "tcp": [{
                "type": "header-custom",
                "settings": {"clients": [[{"type": encoding, "packet": packet}]]},
            }],
        }))
        .expect("fixture is valid finalmask JSON");
        codes(&validate_finalmask(&model).into_issues())
    }

    /// Each mask byte encoding routes to its own shape check, mirroring
    /// `PraseByteSlice` (`infra/conf/transport_finalmask.go`): `""`/`array`
    /// takes a JSON byte array or a base64 string, `str` a JSON string, `hex`
    /// Go's `hex.DecodeString`, and `base64` Go's non-strict `StdEncoding`.
    /// The decoder's own quirks (`=` padding, trailing bits, `\r`/`\n`) are
    /// pinned by `go_std_base64_decodes_matches_the_cores_decoder`, and the
    /// pinned v26.10.21 binary loads every accepted row below (`xray run -test`
    /// exits 0) while it exits 23 on every gated one.
    #[test]
    fn finalmask_byte_encodings_route_each_encoding_to_its_shape_check() {
        let gated = [
            (
                "base64",
                json!("AA"),
                ValidationCode::FinalmaskBase64ByteSyntax,
            ),
            ("hex", json!("A"), ValidationCode::FinalmaskHexByteSyntax),
            ("str", json!(7), ValidationCode::FinalmaskStrByteSyntax),
            (
                "array",
                json!([256]),
                ValidationCode::FinalmaskArrayByteSyntax,
            ),
            ("array", json!(7), ValidationCode::FinalmaskArrayByteSyntax),
        ];
        let buildable = [
            (
                "base64",
                json!("AA=="),
                ValidationCode::FinalmaskBase64ByteSyntax,
            ),
            ("hex", json!("AA"), ValidationCode::FinalmaskHexByteSyntax),
            (
                "str",
                json!("anything"),
                ValidationCode::FinalmaskStrByteSyntax,
            ),
            (
                "array",
                json!([1, 2]),
                ValidationCode::FinalmaskArrayByteSyntax,
            ),
            // `json.Unmarshal` into `[]byte` also reads a base64 string, and
            // `null` is the zero value every known encoding takes.
            (
                "array",
                json!("AA=="),
                ValidationCode::FinalmaskArrayByteSyntax,
            ),
            (
                "array",
                json!(null),
                ValidationCode::FinalmaskArrayByteSyntax,
            ),
            ("str", json!(null), ValidationCode::FinalmaskStrByteSyntax),
            ("hex", json!(null), ValidationCode::FinalmaskHexByteSyntax),
            (
                "base64",
                json!(null),
                ValidationCode::FinalmaskBase64ByteSyntax,
            ),
            ("", json!(null), ValidationCode::FinalmaskArrayByteSyntax),
        ];
        for (encoding, packet, code) in buildable {
            let codes = mask_codes(encoding, packet.clone());
            assert!(
                !codes.contains(&code),
                "{encoding} {packet:?} must stay buildable: {codes:?}"
            );
        }
        for (encoding, packet, code) in gated {
            let codes = mask_codes(encoding, packet.clone());
            assert!(
                codes.contains(&code),
                "{encoding} {packet:?} must gate: {codes:?}"
            );
        }

        // An unknown encoding fails the build whatever the payload carries —
        // `null` included, where every known encoding's `null` is its zero
        // value.
        for packet in [json!(null), json!("AA=="), json!([1]), json!("")] {
            let codes = mask_codes("zzz", packet.clone());
            assert!(
                codes
                    .iter()
                    .any(|code| matches!(code, ValidationCode::FinalmaskUnknownByteSyntax(_))),
                "zzz {packet:?} must gate: {codes:?}"
            );
        }

        // The decoder's own shapes pin the routing: a strict engine or an
        // array-only check fails these, and the pinned binary accepts them.
        for (encoding, packet, code) in [
            (
                "base64",
                json!("AB=="),
                ValidationCode::FinalmaskBase64ByteSyntax,
            ),
            (
                "base64",
                json!("A\nA=="),
                ValidationCode::FinalmaskBase64ByteSyntax,
            ),
            (
                "array",
                json!("A\nA=="),
                ValidationCode::FinalmaskArrayByteSyntax,
            ),
            (
                "array",
                json!([null]),
                ValidationCode::FinalmaskArrayByteSyntax,
            ),
            (
                "array",
                json!([1, null, 2]),
                ValidationCode::FinalmaskArrayByteSyntax,
            ),
        ] {
            let codes = mask_codes(encoding, packet.clone());
            assert!(
                !codes.contains(&code),
                "{encoding} {packet:?} must stay buildable: {codes:?}"
            );
        }
        for (encoding, packet, code) in [
            (
                "base64",
                json!("AA="),
                ValidationCode::FinalmaskBase64ByteSyntax,
            ),
            (
                "array",
                json!(["x"]),
                ValidationCode::FinalmaskArrayByteSyntax,
            ),
            (
                "array",
                json!([null, 256]),
                ValidationCode::FinalmaskArrayByteSyntax,
            ),
        ] {
            let codes = mask_codes(encoding, packet.clone());
            assert!(
                codes.contains(&code),
                "{encoding} {packet:?} must gate: {codes:?}"
            );
        }
    }

    /// The realm `echServerKeys` decode is the same Go `StdEncoding` the mask
    /// byte encodings use — `infra/conf/transport_security.go` reads the field
    /// with `base64.StdEncoding.DecodeString` — so a payload with non-zero
    /// trailing bits or interior `\r`/`\n` loads on the pinned v26.10.21 binary
    /// while a padding violation exits 23. The decoder's own rows live in
    /// `go_std_base64_decodes_matches_the_cores_decoder`; this pins that the
    /// rule routes through it.
    #[test]
    fn finalmask_realm_ech_keys_decode_like_the_core() {
        fn realm_codes(value: &str) -> Vec<ValidationCode> {
            let model: FinalmaskModel = serde_json::from_value(json!({
                "udp": [{
                    "type": "realm",
                    "settings": {
                        "url": "realm://token@realm.example/id",
                        "tlsConfig": {"echServerKeys": value},
                    },
                }],
            }))
            .expect("fixture is valid finalmask JSON");
            codes(&validate_finalmask(&model).into_issues())
        }

        for value in ["", "AA==", "AB==", "A\nA==", "AA==\r\n"] {
            let codes = realm_codes(value);
            assert!(
                !codes.contains(&ValidationCode::FinalmaskRealmEchKeysBase64),
                "{value:?} must stay buildable: {codes:?}"
            );
        }
        for value in ["AA", "A A==", "AA==="] {
            let codes = realm_codes(value);
            assert!(
                codes.contains(&ValidationCode::FinalmaskRealmEchKeysBase64),
                "{value:?} must gate: {codes:?}"
            );
        }
    }

    /// The nested mask vocabularies fold like the core: it lowercases the mKCP
    /// `header` (`infra/conf/transport_finalmask.go:746`) and the QUIC
    /// `bbrProfile` (`:1219`) before matching, and the pinned v26.10.21
    /// binary loads each folded spelling below (`run -test` exits 0) — so
    /// neither may gate.
    #[test]
    fn finalmask_vocabularies_fold_like_the_core() {
        let folded: FinalmaskModel = serde_json::from_value(json!({
            "udp": [{"type": "mkcp-legacy", "settings": {"header": "w\u{130}reguard"}}],
            "quicParams": {"bbrProfile": "conservat\u{130}ve"}
        }))
        .expect("fixture is valid finalmask JSON");
        let issues = validate_finalmask(&folded);
        assert!(issues.is_empty(), "{issues:#?}");

        let outside: FinalmaskModel = serde_json::from_value(json!({
            "udp": [{"type": "mkcp-legacy", "settings": {"header": "zzz"}}],
            "quicParams": {"bbrProfile": "conservative!"}
        }))
        .expect("fixture is valid finalmask JSON");
        assert_eq!(
            codes(&validate_finalmask(&outside)),
            vec![
                ValidationCode::FinalmaskMkcpHeaderInvalid,
                ValidationCode::FinalmaskQuicBbrProfileInvalid,
            ],
            "{:#?}",
            validate_finalmask(&outside)
        );
    }

    /// The `filter` mask's two rule lists take the routing IP-rule grammar:
    /// plain addresses, CIDR prefixes, `geoip:` tags, and `ext:` rules pass;
    /// a malformed entry blocks with its list path.
    #[test]
    fn finalmask_filter_rules_mirror_the_core_parser() {
        fn filter_model(blocked: serde_json::Value, allowed: serde_json::Value) -> FinalmaskModel {
            serde_json::from_value(json!({
                "tcp": [{"type": "filter", "settings": {
                    "blockedSourceIPs": blocked,
                    "allowedSourceIPs": allowed
                }}]
            }))
            .expect("fixture is valid finalmask JSON")
        }

        for rule in [
            "1.2.3.4",
            " 1.2.3.4 ",
            "[::1]",
            "1.2.3.4/",
            "1.2.3.4/24",
            "::1/128",
            "!geoip:private",
            "geoip:private",
            "geoip:!private",
            "ext:geoip.dat:cn",
            "ext-ip:geoip.dat:cn",
            "!!10.0.0.0/8",
        ] {
            let issues = validate_finalmask(&filter_model(json!([rule]), json!([])));
            assert!(issues.is_empty(), "{rule:?} must pass: {issues:#?}");
        }

        for rule in [
            "",
            "!",
            "host.example",
            "1.2.3.4/33",
            "::1/129",
            "1.2.3.4/ 24",
            "1.2.3.4/24/8",
            "1.2.3.4%eth0",
            "10.0.0.0/8 ",
            "geoip:",
            "ext:",
            "ext:geoip.dat",
            "ext::cn",
            "ext:geoip.dat:",
        ] {
            let issues = validate_finalmask(&filter_model(json!([rule]), json!([])));
            assert_eq!(
                codes(&issues),
                vec![ValidationCode::FinalmaskFilterIpRuleInvalid(excerpt(rule))],
                "{rule:?} must be refused: {issues:#?}"
            );
        }

        let model = filter_model(json!(["nope"]), json!(["also-nope"]));
        let issues = validate_finalmask(&model);
        assert_eq!(
            issues
                .iter()
                .map(|issue| (issue.code.clone(), issue.path.clone()))
                .collect::<Vec<_>>(),
            vec![
                (
                    ValidationCode::FinalmaskFilterIpRuleInvalid(excerpt("nope")),
                    Some("finalmask.tcp[0].settings.blockedSourceIPs[0]".into())
                ),
                (
                    ValidationCode::FinalmaskFilterIpRuleInvalid(excerpt("also-nope")),
                    Some("finalmask.tcp[0].settings.allowedSourceIPs[0]".into())
                ),
            ],
            "{issues:#?}"
        );
    }

    /// A `filter` mask on an outbound builds (so a malformed rule still
    /// blocks), but no dial reads it: the stream pass turns the mask itself
    /// into an advisory instead of an unknown discriminator.
    #[test]
    fn finalmask_filter_on_an_outbound_is_an_advisory() {
        let stream: StreamModel = serde_json::from_value(json!({
            "network": "raw",
            "finalmask": {
                "tcp": [{"type": "filter", "settings": {"blockedSourceIPs": ["geoip:private"]}}],
                "udp": [{"type": "filter", "settings": {"allowedSourceIPs": ["10.0.0.0/8"]}}]
            }
        }))
        .expect("fixture is a valid stream");
        let verdict = validate_stream(&stream);
        assert!(!verdict.has_blocking(), "{verdict:#?}");
        assert_eq!(
            verdict
                .advisory()
                .map(|issue| (issue.code.clone(), issue.path.clone()))
                .collect::<Vec<_>>(),
            vec![
                (
                    ValidationCode::FinalmaskFilterOnOutbound,
                    Some("finalmask.tcp[0]".into())
                ),
                (
                    ValidationCode::FinalmaskFilterOnOutbound,
                    Some("finalmask.udp[0]".into())
                ),
            ],
            "{verdict:#?}"
        );
    }

    /// The fold the vocabularies use is Go's, not ASCII case-insensitivity:
    /// the pinned v26.10.21 binary accepts each dotted-`İ`/Kelvin spelling below
    /// (`run -test` exits 0), so a predicate that refuses one gates a profile
    /// the core runs. The point the ASCII fold misses is that `İ` folds to
    /// the same `i` an ASCII `I` does.
    #[test]
    fn vocabularies_fold_unicode_like_go_lower() {
        type Predicate = fn(&str) -> bool;
        // One row per predicate and the spelling only Go's fold reaches: `İ`
        // (U+0130) folds to `i`, the Kelvin sign (U+212A) to `k`. The pinned
        // v26.10.21 binary loads every value below (`run -test` exits 0).
        let rows: &[(Predicate, &str)] = &[
            (target_strategy_supported, "Force\u{130}P"),
            (sockopt_domain_strategy_supported, "Use\u{130}P"),
            (dns_out_action_supported, "h\u{130}jack"),
            (freedom_final_rule_supported, "bloc\u{212a}"),
            (sniffing_dest_override_supported, "qu\u{130}c"),
            (shadowsocks_method_supported, "chacha20-\u{130}etf-poly1305"),
        ];
        for (accepts, value) in rows {
            assert!(accepts(value), "{value:?} must fold like the core does");
        }

        // The 2022 method names fold too: `GetCipherMethod` lowercases the
        // whole string before its map lookup (proxy/shadowsocks_2022/cipher.go),
        // so a Kelvin `k` reaches the canonical method.
        assert!(shadowsocks_method_supported(
            "2022-bla\u{212a}e3-aes-128-gcm"
        ));

        // The nested mask vocabularies the same fold reaches.
        assert!(matches!(
            finalmask_udphop_mode("\u{130}ntervalLocal"),
            Some(FinalmaskUdpHopMode::IntervalLocal)
        ));
        assert!(finalmask_udphop_mode("perconnremote\u{130}").is_none());
        assert_eq!(
            finalmask_parse_bandwidth_bps("1024 \u{212a}bps"),
            Ok(Some(131_072))
        );

        // The tproxy vocabulary's core side maps by the same fold; `redirect`
        // is its only spelling an `İ` can stand in for, and the observable
        // half is that a folded spelling draws no warning while its near-miss
        // does.
        let sockopt = |tproxy: &str| SockoptModel {
            tproxy: Some(tproxy.to_owned()),
            ..Default::default()
        };
        assert!(
            validate_sockopt(&sockopt("red\u{130}rect"), "stream.sockopt")
                .advisory()
                .next()
                .is_none(),
            "a folded tproxy spelling is one the core maps"
        );
        assert!(
            validate_sockopt(&sockopt("red\u{130}rected"), "stream.sockopt")
                .advisory()
                .next()
                .is_some(),
            "a spelling outside the vocabulary still warns"
        );
    }

    #[test]
    fn finalmask_issues_carry_wire_paths_and_parameters() {
        let fm: FinalmaskModel = serde_json::from_value(json!({
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
                {"type": "xdns", "settings": {
                    "resolvers": [{"addrs": ["quic://1.1.1.1:53"]}]
                }},
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
        let issues = validate_finalmask(&fm);
        for (code, path) in [
            (
                ValidationCode::FinalmaskPacketsFirstNotZero,
                "finalmask.tcp[0].settings.packets",
            ),
            (
                ValidationCode::FinalmaskXmcUsernameInvalid,
                "finalmask.tcp[1].settings.profiles[0].username",
            ),
            (
                ValidationCode::FinalmaskNoisePacketExclusive,
                "finalmask.udp[0].settings.noise[0]",
            ),
            (
                ValidationCode::FinalmaskSalamanderPacketSize,
                "finalmask.udp[1].settings.packetSize",
            ),
            (
                ValidationCode::FinalmaskXdnsAddrSchemeUnknown("quic".into()),
                "finalmask.udp[2].settings.resolvers[0].addrs[0]",
            ),
            (
                ValidationCode::FinalmaskXicmpIpInvalid,
                "finalmask.udp[3].settings.ips[0]",
            ),
            (
                ValidationCode::FinalmaskRealmScheme,
                "finalmask.udp[4].settings.url",
            ),
            (
                ValidationCode::FinalmaskUdpHopModeInvalid,
                "finalmask.udp[5].settings.mode",
            ),
            (
                ValidationCode::FinalmaskUdpHopIntervalTooSmall,
                "finalmask.udp[5].settings.interval",
            ),
            (
                ValidationCode::FinalmaskPortNumberRange,
                "finalmask.udp[5].settings.remotePorts",
            ),
            (
                ValidationCode::FinalmaskUdpHopIpInvalid,
                "finalmask.udp[5].settings.remoteIPs[0]",
            ),
            (
                ValidationCode::FinalmaskQuicBandwidthTooSmall,
                "finalmask.quicParams.brutalUp",
            ),
            (
                ValidationCode::FinalmaskQuicBbrProfileInvalid,
                "finalmask.quicParams.bbrProfile",
            ),
            (
                ValidationCode::FinalmaskQuicReceiveWindowTooSmall,
                "finalmask.quicParams.initStreamReceiveWindow",
            ),
            (
                ValidationCode::FinalmaskQuicMaxIdleTimeoutInvalid,
                "finalmask.quicParams.maxIdleTimeout",
            ),
            (
                ValidationCode::FinalmaskQuicKeepAlivePeriodInvalid,
                "finalmask.quicParams.keepAlivePeriod",
            ),
            (
                ValidationCode::FinalmaskQuicMaxIncomingStreamsInvalid,
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

    /// Every `xdns` rule the core refuses at build time reports the offending
    /// entry and field: an empty or unknown record type, a name holding two
    /// dots, a length limit or `edns0` outside its range, limits that leave
    /// too little room for the name and the encoded payload, an unknown
    /// address scheme, a malformed address, an `https` address without TLS, a
    /// negative worker, and an `extraPoll` outside 0 through 3.
    #[test]
    fn finalmask_xdns_rules_mirror_the_core() {
        let fm: FinalmaskModel = serde_json::from_value(json!({
            "udp": [{"type": "xdns", "settings": {
                "domains": [
                    {"names": ["a.example"], "types": [], "lenLimit": 256},
                    {"names": ["b.example"], "types": [2]},
                    {"names": ["c.example"], "types": [1], "labelLimit": 64},
                    {"names": ["d.example"], "types": [1], "edns0": 100},
                    {"names": ["ok.example", "second.example"], "types": [1, 5, 16, 28],
                     "lenLimit": 255, "labelLimit": 63, "edns0": 512},
                    {"names": ["a..b", "a.example"], "types": [1]},
                    {"names": ["tunnel.example.com"], "types": [1], "lenLimit": 3},
                    {"names": ["a"], "types": [1], "lenLimit": 3},
                    {"names": ["tight.example"], "types": [1], "lenLimit": 20, "labelLimit": 63},
                    {"names": ["a"], "types": [1], "lenLimit": 32, "labelLimit": 63},
                    {"names": ["a"], "types": [1], "lenLimit": 31, "labelLimit": 63}
                ],
                "resolvers": [
                    {"addrs": ["quic://1.1.1.1:53"]},
                    {"addrs": ["1.1.1.1:notaport"]},
                    {"addrs": [""]},
                    {"addrs": ["[2001:db8::1]:53", "h.example", "UDP://1.1.1.1:53"]},
                    {"addrs": ["https://dns.example/dns-query"]},
                    {"addrs": ["https://dns.example/dns-query"], "tlsConfig": {}},
                    {"addrs": ["1.1.1.1"], "worker": -1}
                ],
                "extraPoll": 4
            }}]
        }))
        .unwrap();
        let issues = validate_finalmask(&fm);
        for (code, path) in [
            (
                ValidationCode::FinalmaskXdnsDomainTypesInvalid,
                "finalmask.udp[0].settings.domains[0].types",
            ),
            (
                ValidationCode::FinalmaskXdnsDomainLimitInvalid,
                "finalmask.udp[0].settings.domains[0].lenLimit",
            ),
            (
                ValidationCode::FinalmaskXdnsDomainTypesInvalid,
                "finalmask.udp[0].settings.domains[1].types",
            ),
            (
                ValidationCode::FinalmaskXdnsDomainLimitInvalid,
                "finalmask.udp[0].settings.domains[2].labelLimit",
            ),
            (
                ValidationCode::FinalmaskXdnsDomainLimitInvalid,
                "finalmask.udp[0].settings.domains[3].edns0",
            ),
            (
                ValidationCode::FinalmaskXdnsDomainNameInvalid,
                "finalmask.udp[0].settings.domains[5].names[0]",
            ),
            (
                ValidationCode::FinalmaskXdnsDomainCapacityInvalid,
                "finalmask.udp[0].settings.domains[6].names[0]",
            ),
            (
                ValidationCode::FinalmaskXdnsDomainCapacityInvalid,
                "finalmask.udp[0].settings.domains[7].names[0]",
            ),
            (
                ValidationCode::FinalmaskXdnsDomainCapacityInvalid,
                "finalmask.udp[0].settings.domains[8].names[0]",
            ),
            (
                ValidationCode::FinalmaskXdnsDomainCapacityInvalid,
                "finalmask.udp[0].settings.domains[10].names[0]",
            ),
            (
                ValidationCode::FinalmaskXdnsAddrSchemeUnknown("quic".into()),
                "finalmask.udp[0].settings.resolvers[0].addrs[0]",
            ),
            (
                ValidationCode::FinalmaskXdnsResolverAddrInvalid,
                "finalmask.udp[0].settings.resolvers[1].addrs[0]",
            ),
            (
                ValidationCode::FinalmaskXdnsResolverAddrInvalid,
                "finalmask.udp[0].settings.resolvers[2].addrs[0]",
            ),
            (
                ValidationCode::FinalmaskXdnsHttpsRequiresTls,
                "finalmask.udp[0].settings.resolvers[4].addrs[0]",
            ),
            (
                ValidationCode::FinalmaskXdnsWorkerInvalid,
                "finalmask.udp[0].settings.resolvers[6].worker",
            ),
            (
                ValidationCode::FinalmaskXdnsExtraPollInvalid,
                "finalmask.udp[0].settings.extraPoll",
            ),
        ] {
            assert!(
                issues
                    .iter()
                    .any(|issue| issue.code == code && issue.path.as_deref() == Some(path)),
                "missing {code:?} at {path:?} in {issues:#?}"
            );
        }
        // The in-range domains, the capacity boundary that clears the core's
        // 17-byte floor, the folded bracketed-IPv6 and bare-host addresses,
        // and the DoH address carrying TLS report nothing.
        assert!(
            !issues
                .iter()
                .any(|issue| issue
                    .path
                    .as_deref()
                    .is_some_and(|path| path.contains("domains[4]")
                        || path.contains("domains[9]")
                        || path.contains("resolvers[3]")
                        || path.contains("resolvers[5]"))),
            "{issues:#?}"
        );
    }

    /// The resolver's own `quicConfig` goes through the same QUIC rule set as
    /// the mask-level block, under the resolver's path; a resolver that
    /// carries TLS satisfies the DoH rule.
    #[test]
    fn finalmask_xdns_resolver_quic_params_validate_under_the_resolver() {
        let fm: FinalmaskModel = serde_json::from_value(json!({
            "udp": [{"type": "xdns", "settings": {"resolvers": [
                {
                    "addrs": ["https://dns.example/dns-query"],
                    "tlsConfig": {"alpn": ["h3"]},
                    "quicConfig": {
                        "congestion": "force-brutal",
                        "initStreamReceiveWindow": 1,
                        "maxIdleTimeout": 3,
                        "keepAlivePeriod": 61,
                        "maxIncomingStreams": 7
                    }
                },
                {
                    "addrs": ["https://dns.example/dns-query"],
                    "tlsConfig": {"alpn": ["h3"]},
                    "quicConfig": {
                        "congestion": "force-brutal",
                        "brutalUp": "100 mbps",
                        "initStreamReceiveWindow": 16384,
                        "maxIdleTimeout": 30,
                        "keepAlivePeriod": 10,
                        "maxIncomingStreams": 8
                    }
                }
            ]}}]
        }))
        .expect("fixture is valid finalmask JSON");
        let issues = validate_finalmask(&fm);
        let root = "finalmask.udp[0].settings.resolvers[0].quicConfig";
        for (code, field) in [
            (ValidationCode::FinalmaskQuicForceBrutalNeedsUp, "brutalUp"),
            (
                ValidationCode::FinalmaskQuicReceiveWindowTooSmall,
                "initStreamReceiveWindow",
            ),
            (
                ValidationCode::FinalmaskQuicMaxIdleTimeoutInvalid,
                "maxIdleTimeout",
            ),
            (
                ValidationCode::FinalmaskQuicKeepAlivePeriodInvalid,
                "keepAlivePeriod",
            ),
            (
                ValidationCode::FinalmaskQuicMaxIncomingStreamsInvalid,
                "maxIncomingStreams",
            ),
        ] {
            let path = format!("{root}.{field}");
            assert!(
                issues
                    .iter()
                    .any(|issue| issue.code == code && issue.path.as_deref() == Some(&path)),
                "missing {code:?} at {path:?} in {issues:#?}"
            );
        }
        // The configured TLS block satisfies the DoH rule, and the second
        // resolver's complete parameters report nothing.
        assert!(
            !issues
                .iter()
                .any(|issue| issue.code == ValidationCode::FinalmaskXdnsHttpsRequiresTls),
            "{issues:#?}"
        );
        assert!(
            !issues.iter().any(|issue| issue
                .path
                .as_deref()
                .is_some_and(|path| path.contains("resolvers[1]"))),
            "{issues:#?}"
        );
    }

    /// A resolver's nested `tlsConfig` is the outbound TLS block in another
    /// place, built by the same `TLSConfig.Build`, so every rule that gates
    /// an outbound TLS block gates it too — under the resolver's own path.
    /// `masterKeyLog` in particular must not survive import and reach the
    /// core, which would write session keys to the chosen file.
    #[test]
    fn finalmask_xdns_resolver_tls_config_takes_the_stream_tls_rules() {
        let fm: FinalmaskModel = serde_json::from_value(json!({
            "udp": [{"type": "xdns", "settings": {"resolvers": [
                {
                    "addrs": ["https://dns.example/dns-query"],
                    "tlsConfig": {"masterKeyLog": "keys.log"}
                },
                {
                    "addrs": ["https://dns.example/dns-query"],
                    "tlsConfig": {
                        "fingerprint": "bogus",
                        "pinnedPeerCertSha256": "zz",
                        "alpn": ["fromMitm", "h2"]
                    }
                },
                {
                    "addrs": ["https://dns.example/dns-query"],
                    "tlsConfig": {"serverName": "dns.example"}
                }
            ]}}]
        }))
        .expect("fixture is valid finalmask JSON");
        let issues = validate_finalmask(&fm);
        let root = "finalmask.udp[0].settings.resolvers";
        for (code, path) in [
            (
                ValidationCode::MasterKeyLogNotSupported,
                format!("{root}[0].tlsConfig.masterKeyLog"),
            ),
            (
                ValidationCode::TlsFingerprintUnsupported,
                format!("{root}[1].tlsConfig.fingerprint"),
            ),
            (
                ValidationCode::PinnedPeerCertSha256Invalid,
                format!("{root}[1].tlsConfig.pinnedPeerCertSha256"),
            ),
            (
                ValidationCode::TlsFromMitmAlpnShort,
                format!("{root}[1].tlsConfig.alpn"),
            ),
        ] {
            assert!(
                issues
                    .iter()
                    .any(|issue| issue.code == code && issue.path.as_deref() == Some(&path)),
                "missing {code:?} at {path:?} in {issues:#?}"
            );
        }
        assert!(
            !issues.iter().any(|issue| issue
                .path
                .as_deref()
                .is_some_and(|path| path.contains("resolvers[2]"))),
            "a clean DoH resolver must pass: {issues:#?}"
        );

        // The same rules reach the outbound gate, which is what the editor
        // and the share-link importer call.
        let mut outbound =
            crate::model::outbound::OutboundModel::new(crate::model::outbound::Protocol::Vless);
        outbound.stream.finalmask = Some(fm);
        let gate = crate::model::validation::validate_outbound(&outbound);
        assert!(
            gate.iter().any(
                |issue| issue.code == ValidationCode::MasterKeyLogNotSupported
                    && issue.path.as_deref()
                        == Some("finalmask.udp[0].settings.resolvers[0].tlsConfig.masterKeyLog")
            ),
            "the apply gate must refuse the resolver's masterKeyLog: {gate:#?}"
        );
    }

    /// A resolver row with no address contributes nothing to the built
    /// resolver list, and a mask whose rows all lack addresses hands the
    /// client an empty list it refuses at creation. The row is the unit the
    /// editor creates and the user fills in, so an empty one blocks with its
    /// own path.
    #[test]
    fn finalmask_xdns_resolver_without_addresses_blocks_the_model_gate() {
        let fm: FinalmaskModel = serde_json::from_value(json!({
            "udp": [{"type": "xdns", "settings": {"resolvers": [
                {"addrs": []},
                {"addrs": ["1.1.1.1"]}
            ]}}]
        }))
        .expect("fixture is valid finalmask JSON");
        let issues = validate_finalmask(&fm);
        assert!(
            issues.iter().any(|issue| issue.code
                == ValidationCode::FinalmaskXdnsResolverAddrsEmpty
                && issue.path.as_deref() == Some("finalmask.udp[0].settings.resolvers[0].addrs")),
            "the empty resolver row must block at its own path: {issues:#?}"
        );
        assert!(
            !issues.iter().any(|issue| issue
                .path
                .as_deref()
                .is_some_and(|path| path.contains("resolvers[1]"))),
            "a resolver with an address must not fire: {issues:#?}"
        );

        let mut outbound =
            crate::model::outbound::OutboundModel::new(crate::model::outbound::Protocol::Vless);
        outbound.stream.finalmask = Some(fm);
        let gate = crate::model::validation::validate_outbound(&outbound);
        assert!(
            gate.iter().any(
                |issue| issue.code == ValidationCode::FinalmaskXdnsResolverAddrsEmpty
                    && issue.path.as_deref()
                        == Some("finalmask.udp[0].settings.resolvers[0].addrs")
            ),
            "the apply gate must refuse the empty resolver row: {gate:#?}"
        );
    }

    /// `NewClient` refuses a mask whose built domain list or resolver list is
    /// empty before it reads any entry
    /// (`transport/internet/finalmask/xdns/client.go`), and the per-row
    /// findings cannot see a list with no rows. Each list reports at its own
    /// path, so the model pass and the apply gate refuse the same state.
    #[test]
    fn finalmask_xdns_empty_lists_block_both_gates() {
        let empty: FinalmaskModel = serde_json::from_value(json!({
            "udp": [{"type": "xdns", "settings": {}}]
        }))
        .expect("fixture is valid finalmask JSON");
        let issues = validate_finalmask(&empty);
        for (code, path) in [
            (
                ValidationCode::FinalmaskXdnsDomainsEmpty,
                "finalmask.udp[0].settings.domains",
            ),
            (
                ValidationCode::FinalmaskXdnsResolversEmpty,
                "finalmask.udp[0].settings.resolvers",
            ),
        ] {
            assert!(
                issues
                    .iter()
                    .any(|issue| issue.code == code && issue.path.as_deref() == Some(path)),
                "missing {code:?} at {path:?} in {issues:#?}"
            );
        }

        // A populated list does not hide the other list's empty state.
        let domains_only: FinalmaskModel = serde_json::from_value(json!({
            "udp": [{"type": "xdns", "settings": {"domains": [
                {"names": ["a.example"], "types": [1]}
            ]}}]
        }))
        .expect("fixture is valid finalmask JSON");
        let issues = validate_finalmask(&domains_only);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == ValidationCode::FinalmaskXdnsResolversEmpty),
            "{issues:#?}"
        );
        assert!(
            !issues
                .iter()
                .any(|issue| issue.code == ValidationCode::FinalmaskXdnsDomainsEmpty),
            "{issues:#?}"
        );

        // Selecting the xdns type in the mask editor builds the default
        // settings, whose lists hold no rows; the apply gate refuses that
        // exact state. A mask with one row in each list reports neither.
        let brand_new = FinalmaskUdpMask::from_known_type("xdns")
            .expect("the mask editor offers the xdns type");
        let mut outbound =
            crate::model::outbound::OutboundModel::new(crate::model::outbound::Protocol::Vless);
        outbound.stream.finalmask = Some(FinalmaskModel {
            udp: vec![brand_new],
            ..Default::default()
        });
        let gate = crate::model::validation::validate_outbound(&outbound);
        for code in [
            ValidationCode::FinalmaskXdnsDomainsEmpty,
            ValidationCode::FinalmaskXdnsResolversEmpty,
        ] {
            assert!(
                gate.iter().any(|issue| issue.code == code),
                "the apply gate must refuse a brand-new xdns mask ({code:?}): {gate:#?}"
            );
        }

        let populated: FinalmaskModel = serde_json::from_value(json!({
            "udp": [{"type": "xdns", "settings": {
                "domains": [{"names": ["a.example"], "types": [1]}],
                "resolvers": [{"addrs": ["1.1.1.1"]}]
            }}]
        }))
        .expect("fixture is valid finalmask JSON");
        outbound.stream.finalmask = Some(populated);
        let gate = crate::model::validation::validate_outbound(&outbound);
        for code in [
            ValidationCode::FinalmaskXdnsDomainsEmpty,
            ValidationCode::FinalmaskXdnsResolversEmpty,
        ] {
            assert!(
                !gate.iter().any(|issue| issue.code == code),
                "a populated xdns mask must pass ({code:?}): {gate:#?}"
            );
        }
    }

    /// Sub-byte bandwidths are values, not unset: a positive bit rate that
    /// truncates below one byte per second reports the too-small rule (blank
    /// input and an explicit zero stay the unset shape the rule's own message
    /// names), and an unparsable `brutalUp` reports only its own rule instead
    /// of doubling with the derived force-brutal requirement.
    #[test]
    fn quic_bandwidth_rounding_reports_sub_byte_values() {
        let issues_for = |congestion: &str, brutal_up: &str| {
            let fm: FinalmaskModel = serde_json::from_value(json!({
                "quicParams": {"congestion": congestion, "brutalUp": brutal_up}
            }))
            .expect("fixture is valid finalmask JSON");
            validate_finalmask(&fm)
        };

        for value in ["5bps", "1", "7 b"] {
            let issues = issues_for("brutal", value);
            assert_eq!(
                codes(&issues),
                vec![ValidationCode::FinalmaskQuicBandwidthTooSmall],
                "brutalUp {value:?} must report the too-small rule: {issues:#?}"
            );
            assert_eq!(
                issues[0].path.as_deref(),
                Some("finalmask.quicParams.brutalUp")
            );
        }
        for value in ["", "  ", "0", "0bps", "0.0 kbps", "0.0 \u{212a}bps"] {
            let issues = issues_for("brutal", value);
            assert!(
                codes(&issues).is_empty(),
                "brutalUp {value:?} is the unset shape: {issues:#?}"
            );
        }

        assert_eq!(
            codes(&issues_for("force-brutal", "")),
            vec![ValidationCode::FinalmaskQuicForceBrutalNeedsUp],
            "force-brutal still requires an upload rate"
        );
        let refused = issues_for("force-brutal", "1 zap");
        assert_eq!(
            codes(&refused),
            vec![ValidationCode::FinalmaskQuicBandwidthUnitInvalid(
                "zap".into()
            )],
            "one unparsable value must not double-report: {refused:#?}"
        );
    }

    /// The `udphop` mask gates what the mask build and the wrap refuse: a
    /// mode outside the three names (empty included). An unset interval is
    /// legal — the core substitutes its own `30/30` default and the key is
    /// omitted — while any other shape with an endpoint below 5 seconds is
    /// refused. The editor's fresh mask and every accepted spelling stay
    /// clean.
    #[test]
    fn udphop_mask_gates_the_mode_set_and_the_five_second_floor() {
        let codes_for = |settings: &str| {
            let fm: FinalmaskModel = serde_json::from_str(&format!(
                r#"{{"udp":[{{"type":"udphop","settings":{settings}}}]}}"#
            ))
            .expect("fixture is valid finalmask JSON");
            codes(&validate_finalmask(&fm))
        };

        for settings in [
            // An unset interval and the explicit zero range are the same
            // shape: the core substitutes its own default.
            r#"{"mode":"perConnRemote"}"#,
            r#"{"mode":"perConnRemote","interval":0}"#,
            r#"{"mode":"perConnRemote","interval":"0-0"}"#,
            r#"{"mode":"perConnRemote","interval":"5-10"}"#,
            r#"{"mode":"intervalLocal,intervalRemote","interval":"5-5"}"#,
            r#"{"mode":"INTERVALREMOTE,INTERVALLOCAL","interval":"5-30"}"#,
            r#"{"mode":"perConnRemote","interval":"30-60"}"#,
        ] {
            assert!(
                codes_for(settings).is_empty(),
                "{settings} must be legal: {:#?}",
                codes_for(settings)
            );
        }

        // The core lowercases but never trims, so a space around a component
        // is a load error, exactly like an unknown name.
        for mode in [
            "",
            "banana",
            "intervalLocal,banana",
            "perConnLocal",
            "intervalLocal, intervalRemote",
            " intervalLocal",
            "intervalLocal ",
        ] {
            let found = codes_for(&format!(r#"{{"mode":"{mode}","interval":"5-10"}}"#));
            assert_eq!(
                found,
                vec![ValidationCode::FinalmaskUdpHopModeInvalid],
                "mode {mode:?}"
            );
        }

        // Any shape with an endpoint below 5 seconds is refused: 1 through 4,
        // a zero bound beside a non-zero one, and a reversed range whose low
        // end sits below the floor.
        for interval in [
            json!(4),
            json!("2-10"),
            json!("5-4"),
            json!("0-10"),
            json!("5-0"),
            json!("-1-10"),
        ] {
            let found = codes_for(&format!(
                r#"{{"mode":"perConnRemote","interval":{interval}}}"#
            ));
            assert_eq!(
                found,
                vec![ValidationCode::FinalmaskUdpHopIntervalTooSmall],
                "interval {interval}"
            );
        }

        // A `remoteIPs` entry that parses as neither an address nor a prefix
        // is refused at build time, one finding per entry. An IPv6 zone is
        // legal in both forms — Go's ParseAddr keeps it and both
        // ParsePrefix and PrefixFrom strip it again, and a form that fails
        // the prefix parse falls through to the address parse (verified
        // against the pinned core: `fe80::1%eth0`, `2001:db8::1%en0`,
        // `fe80::1%eth0/64`, `fe80::1%eth0%more`, and
        // `fe80::1%eth0/64%x` all load) — while an empty zone, a zone on
        // IPv4, an out-of-range bit count, and a padded entry do not.
        assert_eq!(
            codes_for(
                r#"{"mode":"perConnRemote","interval":"5-10","remoteIPs":["203.0.113.10","nope","2001:db8::/129","fe80::1%","1.2.3.4%eth0"," fe80::1","fe80::1/ 64"]}"#
            ),
            vec![
                ValidationCode::FinalmaskUdpHopIpInvalid,
                ValidationCode::FinalmaskUdpHopIpInvalid,
                ValidationCode::FinalmaskUdpHopIpInvalid,
                ValidationCode::FinalmaskUdpHopIpInvalid,
                ValidationCode::FinalmaskUdpHopIpInvalid,
                ValidationCode::FinalmaskUdpHopIpInvalid,
            ]
        );
        assert!(
            codes_for(
                r#"{"mode":"perConnRemote","interval":"5-10","remoteIPs":["203.0.113.10","2001:db8::/48","::1","fe80::1%eth0","2001:db8::1%en0","fe80::1%eth0/64","fe80::1%eth0%more","fe80::1%eth0/64%x"]}"#
            )
            .is_empty()
        );
    }

    /// The `noise` `type: "exp"` packet mini-language, row by row from the
    /// pinned v26.10.21 binary: every accepted expression loads there and every
    /// refused row exits with the message the rule names.
    #[test]
    fn noise_exp_packet_grammar_matches_the_core() {
        let codes_for = |item: serde_json::Value| {
            let fm: FinalmaskModel = serde_json::from_value(json!({
                "udp": [{"type": "noise", "settings": {"noise": [item]}}]
            }))
            .expect("fixture is valid finalmask JSON");
            codes(&validate_finalmask(&fm))
        };
        let accepted = |packet: &str| {
            let found = codes_for(json!({"type": "exp", "packet": packet}));
            assert!(
                found.is_empty(),
                "packet {packet:?} must be legal: {found:?}"
            );
        };
        let refused = |item: serde_json::Value, expected: ValidationCode| {
            let found = codes_for(item.clone());
            assert_eq!(found, vec![expected], "item {item}");
        };

        // The whole token set, in the pinned core's spelling, with spaces the
        // regex tolerates around and inside a token.
        accepted("<b 0x00ff><r 4-8><rc 1-2><rd 1><t><c><n>");
        accepted("  <r 4-8 >  <t> ");
        accepted("<r 0>");
        accepted("<rc 65535>");
        accepted("<b 00>");
        accepted("<b 0Xff>");
        accepted("<t>");

        // `type` folds case-insensitively, so an upper-cased spelling is the
        // same token set.
        let found = codes_for(json!({"type": "EXP", "packet": "<t>"}));
        assert!(found.is_empty(), "{found:?}");

        // Empty: no token at all.
        refused(
            json!({"type": "exp", "packet": ""}),
            ValidationCode::FinalmaskNoiseExpEmpty,
        );
        refused(
            json!({"type": "exp", "packet": "   "}),
            ValidationCode::FinalmaskNoiseExpEmpty,
        );
        refused(
            json!({"type": "exp", "packet": null}),
            ValidationCode::FinalmaskNoiseExpEmpty,
        );

        // Trailing text: text the pattern cannot absorb, before or after a
        // token, names the text.
        refused(
            json!({"type": "exp", "packet": "x<r 4>"}),
            ValidationCode::FinalmaskNoiseExpTrailingText("x".into()),
        );
        refused(
            json!({"type": "exp", "packet": "<r 4>x"}),
            ValidationCode::FinalmaskNoiseExpTrailingText("x".into()),
        );
        refused(
            json!({"type": "exp", "packet": "<R 4>"}),
            ValidationCode::FinalmaskNoiseExpTrailingText("<R 4>".into()),
        );

        // Unknown token, named.
        refused(
            json!({"type": "exp", "packet": "<z 4>"}),
            ValidationCode::FinalmaskNoiseExpUnknownToken("z".into()),
        );
        refused(
            json!({"type": "exp", "packet": "<rb 4>"}),
            ValidationCode::FinalmaskNoiseExpUnknownToken("rb".into()),
        );

        // Missing size, named.
        refused(
            json!({"type": "exp", "packet": "<r>"}),
            ValidationCode::FinalmaskNoiseExpMissingSize("r".into()),
        );
        refused(
            json!({"type": "exp", "packet": "<rd >"}),
            ValidationCode::FinalmaskNoiseExpMissingSize("rd".into()),
        );

        // Out-of-range and unparsable sizes.
        refused(
            json!({"type": "exp", "packet": "<r 70000>"}),
            ValidationCode::FinalmaskNoiseExpSizeInvalid("70000".into()),
        );
        refused(
            json!({"type": "exp", "packet": "<r -1-10>"}),
            ValidationCode::FinalmaskNoiseExpSizeInvalid("-1-10".into()),
        );
        refused(
            json!({"type": "exp", "packet": "<r 8-4>"}),
            ValidationCode::FinalmaskNoiseExpSizeInvalid("8-4".into()),
        );
        refused(
            json!({"type": "exp", "packet": "<r 4 - 8>"}),
            ValidationCode::FinalmaskNoiseExpSizeInvalid("4 - 8".into()),
        );

        // Byte literals: empty, odd, and non-hex.
        refused(
            json!({"type": "exp", "packet": "<b>"}),
            ValidationCode::FinalmaskNoiseExpBytesInvalid("b".into()),
        );
        refused(
            json!({"type": "exp", "packet": "<b 0>"}),
            ValidationCode::FinalmaskNoiseExpBytesInvalid("0".into()),
        );
        refused(
            json!({"type": "exp", "packet": "<b zz>"}),
            ValidationCode::FinalmaskNoiseExpBytesInvalid("zz".into()),
        );

        // A no-argument token carrying one.
        refused(
            json!({"type": "exp", "packet": "<t 4>"}),
            ValidationCode::FinalmaskNoiseExpArgumentNotAllowed("t".into()),
        );
        refused(
            json!({"type": "exp", "packet": "<c 4>"}),
            ValidationCode::FinalmaskNoiseExpArgumentNotAllowed("c".into()),
        );

        // The packet must be a JSON string; absent is the unmarshal failure.
        refused(
            json!({"type": "exp"}),
            ValidationCode::FinalmaskNoiseExpPacketNotString,
        );
        refused(
            json!({"type": "exp", "packet": 5}),
            ValidationCode::FinalmaskNoiseExpPacketNotString,
        );

        // The one refusal carries the wire path of the packet field.
        let fm: FinalmaskModel = serde_json::from_value(json!({
            "udp": [{"type": "noise", "settings": {"noise": [
                {"type": "exp", "packet": "<t>"},
                {"type": "exp", "packet": "<z>"}
            ]}}]
        }))
        .unwrap();
        let issues = validate_finalmask(&fm);
        assert_eq!(issues.len(), 1, "{issues:#?}");
        assert_eq!(
            issues[0].path.as_deref(),
            Some("finalmask.udp[0].settings.noise[1].packet")
        );
    }

    /// A noise mask's `script` is exclusive with its `noise` items: the
    /// core's build returns the script path only when the item list is empty
    /// and refuses the pair (`infra/conf/transport_finalmask.go`,
    /// `NoiseMask.Build`). The path itself carries the shared Lua rules, so a
    /// blank or non-`.lua` path gates on its own.
    #[test]
    fn noise_script_gates_the_pair_and_the_path_shape() {
        let codes_for = |settings: serde_json::Value| {
            let fm: FinalmaskModel =
                serde_json::from_value(json!({"udp": [{"type": "noise", "settings": settings}]}))
                    .expect("fixture is valid finalmask JSON");
            validate_finalmask(&fm)
                .into_iter()
                .map(|issue| (issue.code, issue.path, issue.severity))
                .collect::<Vec<_>>()
        };

        assert_eq!(
            codes_for(json!({
                "script": "/tmp/noise.lua",
                "noise": [{"type": "hex", "packet": "00"}]
            })),
            vec![(
                ValidationCode::FinalmaskNoiseScriptConflict,
                Some("finalmask.udp[0].settings.script".into()),
                Severity::Error,
            )]
        );
        assert!(
            codes_for(json!({"script": "/tmp/noise.lua", "noise": []})).is_empty(),
            "a script alone is the script arm the core builds"
        );
        assert!(
            codes_for(json!({"noise": [{"type": "hex", "packet": "00"}]})).is_empty(),
            "items alone are the settings arm"
        );
        assert_eq!(
            codes_for(json!({"script": ""})),
            vec![(
                ValidationCode::LuaScriptPathRequired,
                Some("finalmask.udp[0].settings.script".into()),
                Severity::Error,
            )],
            "a blank path never resolves"
        );
        assert_eq!(
            codes_for(json!({"script": "/tmp/noise.txt"})),
            vec![(
                ValidationCode::LuaScriptPathNotLua,
                Some("finalmask.udp[0].settings.script".into()),
                Severity::Error,
            )]
        );
    }

    /// The UDP mask wrap pins only the masks that own the outbound's own
    /// socket to the last list entry. `NewFinalMask` reverses both mask slices
    /// at construction and wraps forward
    /// (`transport/internet/finalmask/finalmask.go:44-46`), and only a mask
    /// that declares `HandleDial` or `HandleListen` is position-bound —
    /// `udphop` declares `HandleDial` and `xicmp` both, so the core refuses
    /// any other index with `incorrect index` at dial. No other mask type is
    /// pinned: `realm`, `sudoku` and the unconstrained types wrap in any
    /// order. A misplaced pinned entry gates with its path and the required
    /// end, and the editor's move operation repairs it.
    #[test]
    fn udp_mask_order_gates_the_self_dialing_masks_only() {
        let order_findings = |list: &str| -> Vec<ValidationIssue> {
            let fm: FinalmaskModel = serde_json::from_str(&format!(r#"{{"udp":{list}}}"#))
                .expect("fixture is valid finalmask JSON");
            validate_finalmask(&fm)
                .into_iter()
                .filter(|issue| matches!(issue.code, ValidationCode::FinalmaskUdpMaskNotLast(_)))
                .collect()
        };
        let paths = |findings: &[ValidationIssue]| -> Vec<Option<String>> {
            findings.iter().map(|issue| issue.path.clone()).collect()
        };

        const SALAMANDER: &str = r#"{"type":"salamander","settings":{"password":"pw"}}"#;
        const HEADER: &str = r#"{"type":"header-custom","settings":{}}"#;
        const SUDOKU: &str = r#"{"type":"sudoku","settings":{"password":"pw"}}"#;
        const REALM: &str = r#"{"type":"realm","settings":{"url":"realm://token@203.0.113.10:443/id","stunServers":["stun.example.com:3478"]}}"#;
        const XICMP: &str = r#"{"type":"xicmp","settings":{"ips":["192.0.2.1"]}}"#;
        const UDPHOP: &str =
            r#"{"type":"udphop","settings":{"mode":"perConnRemote","interval":"5-10"}}"#;

        // Single-entry chains fill the pinned slot for every type.
        for mask in [SALAMANDER, HEADER, SUDOKU, REALM, XICMP, UDPHOP] {
            assert!(
                order_findings(&format!("[{mask}]")).is_empty(),
                "a single-entry chain is legal for {mask}"
            );
        }

        // A pinned type at the last entry, with unconstrained masks around it,
        // stays clean.
        for chain in [
            format!("[{SUDOKU},{UDPHOP}]"),
            format!("[{REALM},{XICMP}]"),
            format!("[{SUDOKU},{SALAMANDER},{UDPHOP}]"),
            format!("[{HEADER},{REALM},{XICMP}]"),
        ] {
            assert!(
                order_findings(&chain).is_empty(),
                "chain {chain} is correctly ordered"
            );
        }

        // The masks with no position marker wrap in any order.
        for chain in [
            format!("[{REALM},{SUDOKU}]"),
            format!("[{SUDOKU},{REALM}]"),
            format!("[{SUDOKU},{SALAMANDER}]"),
            format!("[{SALAMANDER},{HEADER}]"),
            format!("[{HEADER},{SALAMANDER},{HEADER}]"),
        ] {
            assert!(
                order_findings(&chain).is_empty(),
                "chain {chain} has no pinned type"
            );
        }

        // Each pinned type misordered at each non-last position.
        for (mask, name) in [(XICMP, "xicmp"), (UDPHOP, "udphop")] {
            let chain = format!("[{mask},{SALAMANDER}]");
            let found = order_findings(&chain);
            assert_eq!(
                codes(&found),
                vec![ValidationCode::FinalmaskUdpMaskNotLast(name.into())],
                "chain {chain}"
            );
            assert_eq!(paths(&found), vec![Some("finalmask.udp[0]".to_string())]);

            let chain = format!("[{SALAMANDER},{mask},{HEADER}]");
            let found = order_findings(&chain);
            assert_eq!(
                codes(&found),
                vec![ValidationCode::FinalmaskUdpMaskNotLast(name.into())],
                "chain {chain}"
            );
            assert_eq!(paths(&found), vec![Some("finalmask.udp[1]".to_string())]);
        }

        // A pinned type directly before the end reports on its own entry.
        let found = order_findings(&format!("[{SALAMANDER},{UDPHOP},{REALM}]"));
        assert_eq!(
            codes(&found),
            vec![ValidationCode::FinalmaskUdpMaskNotLast("udphop".into())],
            "{found:#?}"
        );
        assert!(found.iter().all(|issue| issue.severity == Severity::Error));

        // The editor's move buttons swap neighbouring entries: one move turns
        // a misplaced pinned type into the legal shape.
        let mut fm: FinalmaskModel =
            serde_json::from_str(&format!(r#"{{"udp":[{UDPHOP},{SALAMANDER}]}}"#))
                .expect("fixture is valid finalmask JSON");
        assert!(!validate_finalmask(&fm).is_empty());
        fm.udp.swap(0, 1);
        assert!(
            validate_finalmask(&fm)
                .iter()
                .all(|issue| !matches!(issue.code, ValidationCode::FinalmaskUdpMaskNotLast(_))),
            "one move must repair the chain"
        );
    }

    /// The realm TLS allow-list is the canonical fingerprint vocabulary
    /// (src/model/fingerprint.rs): adding a fingerprint there must land in
    /// this validation context too, with the same ASCII-case tolerance the
    /// historical lowercased allow-list had. The wire-only names are part of
    /// this context's set even though the editor and links reject them.
    #[test]
    fn realm_tls_accepts_the_canonical_fingerprint_table_case_insensitively() {
        use crate::model::fingerprint::{FINGERPRINTS, VALIDATION_ONLY_FINGERPRINTS};
        use crate::model::stream::FinalmaskRealmTls;
        for &name in FINGERPRINTS.iter().chain(VALIDATION_ONLY_FINGERPRINTS) {
            for fingerprint in [name.to_owned(), name.to_ascii_uppercase()] {
                let mut issues = Vec::new();
                finalmask_validate_realm_tls(
                    "finalmask.udp[0].settings.tlsConfig",
                    &FinalmaskRealmTls {
                        fingerprint,
                        ..Default::default()
                    },
                    &mut issues,
                );
                assert!(
                    !issues.iter().any(|issue| {
                        issue.code == ValidationCode::FinalmaskRealmFingerprintUnknown
                    }),
                    "realm TLS validation rejects {name:?}: {issues:#?}"
                );
            }
        }
        // A name outside the table still reports the Unknown code.
        let mut issues = Vec::new();
        finalmask_validate_realm_tls(
            "finalmask.udp[0].settings.tlsConfig",
            &FinalmaskRealmTls {
                fingerprint: "hellobroccoli_3000".into(),
                ..Default::default()
            },
            &mut issues,
        );
        assert_eq!(
            codes(&issues),
            vec![ValidationCode::FinalmaskRealmFingerprintUnknown]
        );
    }

    #[test]
    fn sockopt_validation_reports_each_rule_code() {
        let sockopt = SockoptModel {
            domain_strategy: "future-strategy".into(),
            tcp_fast_open: Some(json!("not bool or number")),
            tcp_keep_alive_idle: Some(-1),
            tcp_keep_alive_interval: Some(30),
            custom_sockopt: vec![CustomSockopt {
                opt: String::new(),
                r#type: "future".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let issues = validate_sockopt(&sockopt, "stream.sockopt");
        let found = codes(&issues);
        for code in [
            ValidationCode::SockoptDomainStrategyInvalid,
            ValidationCode::SockoptTcpFastOpenType,
            ValidationCode::SockoptKeepaliveSigns,
            ValidationCode::SockoptCustomOptRequired,
            ValidationCode::SockoptCustomTypeInvalid,
        ] {
            assert!(found.contains(&code), "missing {code:?} in {found:#?}");
        }
    }

    // ---- stream/sockopt/strategy enum surfaces ----

    fn xhttp_stream(settings: XhttpSettings) -> StreamModel {
        StreamModel {
            network: crate::model::stream::Network::Xhttp,
            xhttp_settings: Some(settings),
            ..Default::default()
        }
    }

    /// Every xhttp code of the enum surface, in fire order.
    fn xhttp_codes(issues: &[ValidationIssue]) -> Vec<ValidationCode> {
        issues
            .iter()
            .map(|issue| issue.code.clone())
            .filter(|code| {
                matches!(
                    code,
                    ValidationCode::XhttpModeUnsupported
                        | ValidationCode::XhttpPaddingBytesInvalid
                        | ValidationCode::XhttpPaddingPlacementInvalid
                        | ValidationCode::XhttpPaddingMethodInvalid
                        | ValidationCode::XhttpUplinkDataPlacementInvalid
                        | ValidationCode::XhttpUplinkDataPlacementRequiresPacketUp
                        | ValidationCode::XhttpUplinkHttpMethodRequiresPacketUp
                        | ValidationCode::XhttpSessionIdPlacementInvalid
                        | ValidationCode::XhttpSeqPlacementInvalid
                        | ValidationCode::XhttpSessionIdLengthRequired
                        | ValidationCode::XhttpSessionIdTableInvalid
                        | ValidationCode::XmuxLimitsExclusive
                        | ValidationCode::StreamOneNoDownload
                )
            })
            .collect()
    }

    #[test]
    fn xhttp_canonical_settings_fire_no_xhttp_code() {
        let canonical = XhttpSettings {
            mode: "packet-up".into(),
            x_padding_bytes: Some(Int32Range::new(100, 200)),
            x_padding_placement: "cookie".into(),
            x_padding_method: "tokenish".into(),
            uplink_data_placement: "cookie".into(),
            uplink_http_method: "GET".into(),
            session_id_placement: "query".into(),
            session_id_table: "ALPHABET".into(),
            session_id_length: Some(Int32Range::new(31, 31)),
            seq_placement: "header".into(),
            xmux: Some(XmuxConfig {
                max_concurrency: Some(Int32Range::single(8)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&xhttp_stream(canonical));
        assert!(
            xhttp_codes(&issues).is_empty(),
            "canonical xhttp state must be silent: {issues:#?}"
        );
        // stream-one with a download is the pre-existing rule; unchanged.
        let stream_one = XhttpSettings {
            mode: "stream-one".into(),
            ..Default::default()
        };
        assert!(xhttp_codes(&validate_stream(&xhttp_stream(stream_one))).is_empty());
    }

    #[test]
    fn xhttp_vocabulary_refusals_fire_per_field_with_wire_paths() {
        let hostile = XhttpSettings {
            mode: "quic".into(),
            x_padding_placement: "body".into(),
            x_padding_method: "aes".into(),
            uplink_data_placement: "path".into(),
            session_id_placement: "auto".into(),
            seq_placement: "auto".into(),
            ..Default::default()
        };
        let issues = validate_stream(&xhttp_stream(hostile));
        let found = xhttp_codes(&issues);
        for code in [
            ValidationCode::XhttpModeUnsupported,
            ValidationCode::XhttpPaddingPlacementInvalid,
            ValidationCode::XhttpPaddingMethodInvalid,
            ValidationCode::XhttpUplinkDataPlacementInvalid,
            ValidationCode::XhttpSessionIdPlacementInvalid,
            ValidationCode::XhttpSeqPlacementInvalid,
        ] {
            assert!(found.contains(&code), "missing {code:?} in {found:#?}");
            let finding = issues
                .iter()
                .find(|issue| issue.code == code)
                .expect("issue present");
            assert_eq!(finding.severity, Severity::Error);
        }
        assert_eq!(issues[0].path.as_deref(), Some("stream.xhttpSettings.mode"));
        assert_eq!(
            issues.len(),
            6,
            "exactly the six vocab refusals: {issues:#?}"
        );
    }

    #[test]
    fn xhttp_cross_field_and_bounds_rules_fire_with_wire_paths() {
        // stream-up mode with cookie placement, GET method, a negative
        // xPaddingBytes range, a both-set xmux, and an insufficient
        // sessionIDTable pair.
        let hostile = XhttpSettings {
            mode: "stream-up".into(),
            x_padding_bytes: Some(Int32Range::new(-1, 100)),
            uplink_data_placement: "cookie".into(),
            uplink_http_method: "get".into(),
            session_id_table: "AB".into(),
            session_id_length: Some(Int32Range::new(2, 2)),
            xmux: Some(XmuxConfig {
                max_concurrency: Some(Int32Range::single(8)),
                max_connections: Some(Int32Range::single(3)),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&xhttp_stream(hostile));
        let found = xhttp_codes(&issues);
        for code in [
            ValidationCode::XhttpPaddingBytesInvalid,
            ValidationCode::XhttpUplinkDataPlacementRequiresPacketUp,
            ValidationCode::XhttpUplinkHttpMethodRequiresPacketUp,
            ValidationCode::XhttpSessionIdTableInvalid,
            ValidationCode::XmuxLimitsExclusive,
        ] {
            assert!(found.contains(&code), "missing {code:?} in {found:#?}");
        }
        // Every finding is Error tier (Xray refuses these at conf load).
        for issue in &issues {
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
        }
        let paths: Vec<Option<&str>> = issues.iter().map(|issue| issue.path.as_deref()).collect();
        for path in [
            Some("stream.xhttpSettings.xPaddingBytes"),
            Some("stream.xhttpSettings.uplinkDataPlacement"),
            Some("stream.xhttpSettings.uplinkHTTPMethod"),
            Some("stream.xhttpSettings.sessionIDTable"),
            Some("stream.xhttpSettings.xmux"),
        ] {
            assert!(paths.contains(&path), "missing path {path:?} in {paths:?}");
        }
    }

    #[test]
    fn xhttp_placement_and_get_are_legal_in_packet_up_and_placements_fold_in_ascii_room() {
        // The same values are canonical in packet-up mode.
        let packet_up = XhttpSettings {
            mode: "packet-up".into(),
            uplink_data_placement: "cookie".into(),
            uplink_http_method: "GET".into(),
            ..Default::default()
        };
        assert!(xhttp_codes(&validate_stream(&xhttp_stream(packet_up))).is_empty());

        // A zero xPaddingBytes range is the "padding off" shape — legal.
        let zero_padding = XhttpSettings {
            mode: "auto".into(),
            x_padding_bytes: Some(Int32Range::single(0)),
            ..Default::default()
        };
        assert!(xhttp_codes(&validate_stream(&xhttp_stream(zero_padding))).is_empty());

        // sessionIDLength from ≥ 31 opens 2^31 combinations for any ASCII
        // table of at least two characters; a non-ASCII table cannot.
        let big_room = XhttpSettings {
            session_id_table: "xy".into(),
            session_id_length: Some(Int32Range::new(31, 40)),
            ..Default::default()
        };
        assert!(xhttp_codes(&validate_stream(&xhttp_stream(big_room))).is_empty());
        let non_ascii = XhttpSettings {
            session_id_table: "表x".into(),
            session_id_length: Some(Int32Range::new(31, 31)),
            ..Default::default()
        };
        assert!(
            xhttp_codes(&validate_stream(&xhttp_stream(non_ascii)))
                .contains(&ValidationCode::XhttpSessionIdTableInvalid)
        );
        // from ≤ 0 is refused by the same room predicate.
        let zero_from = XhttpSettings {
            session_id_table: "AB".into(),
            session_id_length: Some(Int32Range::new(0, 31)),
            ..Default::default()
        };
        assert!(
            xhttp_codes(&validate_stream(&xhttp_stream(zero_from)))
                .contains(&ValidationCode::XhttpSessionIdTableInvalid)
        );
    }

    #[test]
    fn xhttp_session_table_without_length_is_refused() {
        let issues = validate_stream(&xhttp_stream(XhttpSettings {
            session_id_table: "ABCD".into(),
            ..Default::default()
        }));
        let finding = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::XhttpSessionIdLengthRequired)
            .expect("table without length is refused");
        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(
            finding.path.as_deref(),
            Some("stream.xhttpSettings.sessionIDLength")
        );
    }

    #[test]
    fn xhttp_download_settings_are_revalidated_recursively() {
        let top = XhttpSettings {
            download_settings: Some(Box::new(xhttp_stream(XhttpSettings {
                mode: "fragment".into(),
                ..Default::default()
            }))),
            ..Default::default()
        };
        let issues = validate_stream(&xhttp_stream(top));
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == ValidationCode::XhttpModeUnsupported)
        );
    }

    #[test]
    fn kcp_outside_documented_range_warns_without_blocking() {
        // Canonical values inside the documented band stay silent.
        let canonical = KcpSettings {
            mtu: Some(1350),
            tti: Some(50),
            ..Default::default()
        };
        assert!(
            validate_stream(&StreamModel {
                network: crate::model::stream::Network::Kcp,
                kcp_settings: Some(canonical),
                ..Default::default()
            })
            .is_empty()
        );

        // Values outside the documented band warn (docs-soft advisory):
        // Xray still loads and runs them. Values outside Xray's hard load
        // bounds (mtu < 21, tti outside 10..=1000) are the Error tier —
        // covered by `kcp_outside_hard_load_bounds_errors` below.
        let cases: [(Option<u32>, Option<u32>, &str); 4] = [
            (Some(100), None, "stream.kcpSettings.mtu"), // below the docs band, above the import floor
            (Some(1500), None, "stream.kcpSettings.mtu"),
            (Some(576), None, ""),
            (None, Some(500), "stream.kcpSettings.tti"), // inside Xray's 10..=1000 load window
        ];
        for (mtu, tti, path) in cases {
            let issues = validate_stream(&StreamModel {
                network: crate::model::stream::Network::Kcp,
                kcp_settings: Some(KcpSettings {
                    mtu,
                    tti,
                    ..Default::default()
                }),
                ..Default::default()
            });
            let findings: Vec<&ValidationIssue> = issues
                .iter()
                .filter(|issue| issue.code == ValidationCode::KcpRangeSoft)
                .collect();
            if path.is_empty() {
                assert!(findings.is_empty(), "mtu 576 is in range: {issues:#?}");
            } else {
                assert_eq!(findings.len(), 1, "{issues:#?}");
                assert_eq!(findings[0].severity, Severity::Warning, "{:?}", findings[0]);
                assert_eq!(findings[0].path.as_deref(), Some(path));
            }
        }
        // Both knobs out of range warn twice.
        let both = validate_stream(&StreamModel {
            network: crate::model::stream::Network::Kcp,
            kcp_settings: Some(KcpSettings {
                mtu: Some(100),
                tti: Some(500),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_eq!(
            both.iter()
                .filter(|issue| issue.code == ValidationCode::KcpRangeSoft)
                .count(),
            2
        );
    }

    #[test]
    fn kcp_outside_hard_load_bounds_errors_and_never_soft_warns() {
        // Xray's KCPConfig.Build load-refuses mtu < 21 and tti outside
        // [10, 1000] (infra/conf/transport_method.go) — the model's Error
        // tier, matching the import grammar.
        let cases: [(Option<u32>, Option<u32>, &str); 3] = [
            (Some(20), None, "stream.kcpSettings.mtu"),
            (None, Some(5), "stream.kcpSettings.tti"),
            (None, Some(1001), "stream.kcpSettings.tti"),
        ];
        for (mtu, tti, path) in cases {
            let issues = validate_stream(&StreamModel {
                network: crate::model::stream::Network::Kcp,
                kcp_settings: Some(KcpSettings {
                    mtu,
                    tti,
                    ..Default::default()
                }),
                ..Default::default()
            });
            assert_eq!(issues.len(), 1, "{issues:#?}");
            assert_eq!(issues[0].code, ValidationCode::KcpRangeInvalid);
            assert_eq!(issues[0].severity, Severity::Error, "{:?}", issues[0]);
            assert_eq!(issues[0].path.as_deref(), Some(path));
        }
        // The hard-refused band never double-reports the docs warning.
        let both_issues = validate_stream(&StreamModel {
            network: crate::model::stream::Network::Kcp,
            kcp_settings: Some(KcpSettings {
                mtu: Some(20),
                tti: Some(5),
                ..Default::default()
            }),
            ..Default::default()
        });
        assert_eq!(both_issues.len(), 2, "{both_issues:#?}");
        assert!(
            both_issues
                .iter()
                .all(|issue| issue.code == ValidationCode::KcpRangeInvalid)
        );
    }

    #[test]
    fn xhttp_negative_server_max_header_bytes_errors() {
        // SplitHTTPConfig.Build load-refuses negatives, mirrored by the
        // import grammar.
        let settings = XhttpSettings {
            server_max_header_bytes: Some(-1),
            ..Default::default()
        };
        let issues = validate_stream(&xhttp_stream(settings));
        assert_eq!(issues.len(), 1, "{issues:#?}");
        assert_eq!(
            issues[0].code,
            ValidationCode::XhttpServerMaxHeaderBytesInvalid
        );
        assert_eq!(issues[0].severity, Severity::Error, "{:?}", issues[0]);
        assert_eq!(
            issues[0].path.as_deref(),
            Some("stream.xhttpSettings.serverMaxHeaderBytes")
        );
        // Zero (the Go default) and positive values stay silent.
        assert!(
            validate_stream(&xhttp_stream(XhttpSettings {
                server_max_header_bytes: Some(0),
                ..Default::default()
            }))
            .is_empty()
        );
        assert!(
            validate_stream(&xhttp_stream(XhttpSettings {
                server_max_header_bytes: Some(4096),
                ..Default::default()
            }))
            .is_empty()
        );
    }

    #[test]
    fn grpc_negative_knobs_warn_and_zero_is_intentional() {
        let settings = GrpcSettings {
            idle_timeout: Some(-1),
            health_check_timeout: Some(0),
            initial_windows_size: Some(-1000),
            ..Default::default()
        };
        let issues = validate_stream(&StreamModel {
            network: crate::model::stream::Network::Grpc,
            grpc_settings: Some(settings),
            ..Default::default()
        });
        let findings: Vec<&ValidationIssue> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::GrpcNegativeClamp)
            .collect();
        assert_eq!(findings.len(), 2, "{issues:#?}");
        for finding in &findings {
            assert_eq!(finding.severity, Severity::Warning);
        }
        let paths: Vec<Option<&str>> = findings.iter().map(|issue| issue.path.as_deref()).collect();
        assert!(paths.contains(&Some("stream.grpcSettings.idle_timeout")));
        assert!(paths.contains(&Some("stream.grpcSettings.initial_windows_size")));

        // Zero (disabled / Xray default) and positive values never warn.
        let zeroed = GrpcSettings {
            idle_timeout: Some(0),
            health_check_timeout: Some(0),
            initial_windows_size: Some(0),
            ..Default::default()
        };
        assert!(
            validate_stream(&StreamModel {
                network: crate::model::stream::Network::Grpc,
                grpc_settings: Some(zeroed),
                ..Default::default()
            })
            .is_empty()
        );
        let positive = GrpcSettings {
            idle_timeout: Some(60),
            health_check_timeout: Some(10),
            initial_windows_size: Some(1_048_576),
            ..Default::default()
        };
        assert!(
            validate_stream(&StreamModel {
                network: crate::model::stream::Network::Grpc,
                grpc_settings: Some(positive),
                ..Default::default()
            })
            .is_empty()
        );
    }

    #[test]
    fn sockopt_tproxy_silently_off_warns_only_outside_the_accepted_vocab() {
        // The accepted vocabulary — off included (the explicit spelling
        // of Xray's Off default, honored as-is) — never warns; casing is
        // tolerated because Xray lowercases the value.
        for tproxy in [
            None,
            Some(String::new()),
            Some("off".into()),
            Some("OFF".into()),
            Some("tproxy".into()),
            Some("TProxy".into()),
            Some("redirect".into()),
        ] {
            let issues = validate_sockopt(
                &SockoptModel {
                    tproxy: tproxy.clone(),
                    ..Default::default()
                },
                "stream.sockopt",
            );
            assert!(
                issues
                    .iter()
                    .all(|issue| issue.code != ValidationCode::SockoptTproxySilentOff),
                "{tproxy:?}: {issues:#?}"
            );
        }
        for typo in ["tpory", "redirected", "enabled", "off "] {
            let issues = validate_sockopt(
                &SockoptModel {
                    tproxy: Some(typo.to_string()),
                    ..Default::default()
                },
                "stream.sockopt",
            );
            let finding = issues
                .iter()
                .find(|issue| issue.code == ValidationCode::SockoptTproxySilentOff)
                .expect("typo warns");
            assert_eq!(finding.severity, Severity::Warning);
            assert_eq!(finding.path.as_deref(), Some("stream.sockopt.tproxy"));
        }
        // The prefix scopes the ECH-DNS sockopt block the same way.
        let ech = validate_sockopt(
            &SockoptModel {
                tproxy: Some("tpory".into()),
                ..Default::default()
            },
            "stream.tlsSettings.echSockopt",
        );
        assert_eq!(
            ech[0].path.as_deref(),
            Some("stream.tlsSettings.echSockopt.tproxy")
        );
    }

    #[test]
    fn download_depth_exceeds_safety_depth() {
        let mut stream = crate::model::stream::StreamModel::default();
        let mut current = &mut stream;
        for _ in 0..=MAX_XHTTP_DOWNLOAD_DEPTH {
            current.network = Network::Xhttp;
            let settings = current
                .xhttp_settings
                .get_or_insert_with(crate::model::stream::XhttpSettings::default);
            current = settings
                .download_settings
                .get_or_insert_with(|| Box::new(StreamModel::default()))
                .as_mut();
        }
        let issues = validate_stream(&stream);
        assert!(codes(&issues).contains(&ValidationCode::XhttpDepthExceeded));
    }

    #[test]
    fn master_key_log_is_rejected_in_tls_and_reality() {
        // TLS variant: non-empty tlsSettings.masterKeyLog is refused.
        let tls_stream = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                master_key_log: "C:\\xray-keys.log".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&tls_stream);
        assert_eq!(
            issues,
            vec![issue(
                ValidationCode::MasterKeyLogNotSupported,
                Some("stream.tlsSettings.masterKeyLog".into()),
            )]
        );

        // Reality variant: non-empty realitySettings.masterKeyLog is refused.
        let reality_stream = StreamModel {
            security: Security::Reality,
            reality_settings: Some(crate::model::stream::RealityModel {
                master_key_log: "C:\\xray-keys.log".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&reality_stream);
        assert_eq!(
            issues,
            vec![
                // Security refusals report before the format rules
                // (same block): masterKeyLog first, then the empty public
                // key (itself refused by Xray's REALITY client build).
                issue(
                    ValidationCode::MasterKeyLogNotSupported,
                    Some("stream.realitySettings.masterKeyLog".into()),
                ),
                issue(
                    ValidationCode::RealityPublicKeyInvalid,
                    Some("stream.realitySettings.publicKey".into()),
                ),
            ]
        );

        // The visit recursion must reach a nested xhttp download stream too.
        let mut parent = StreamModel {
            network: Network::Xhttp,
            ..Default::default()
        };
        let download = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                master_key_log: "C:\\keys.log".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        parent.xhttp_settings = Some(crate::model::stream::XhttpSettings {
            download_settings: Some(Box::new(download)),
            ..Default::default()
        });
        let issues = validate_stream(&parent);
        assert!(codes(&issues).contains(&ValidationCode::MasterKeyLogNotSupported));
    }

    #[test]
    fn tls_allow_insecure_is_rejected_unless_false() {
        // `tlsSettings.allowInsecure` was removed by Xray: `true` hard-fails
        // TLSConfig.Build (PrintRemovedFeatureError) and a non-bool value fails
        // Xray's `allowInsecure bool` JSON unmarshal — both land in the TlsModel
        // `extra` flatten map and must be refused on validation.
        let mut stream = StreamModel::default();
        stream.security = Security::Tls;
        stream.tls_settings = Some(crate::model::stream::TlsModel {
            extra: json!({"allowInsecure": true}).as_object().unwrap().clone(),
            ..Default::default()
        });
        let issues = validate_stream(&stream);
        assert_eq!(
            issues,
            vec![issue(
                ValidationCode::TlsAllowInsecureRemoved,
                Some("stream.tlsSettings.allowInsecure".into()),
            )]
        );

        // A non-boolean value would break Xray's bool unmarshal at startup —
        // refused the same way.
        let string_stream = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                extra: json!({"allowInsecure": "true"})
                    .as_object()
                    .unwrap()
                    .clone(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&string_stream);
        assert!(codes(&issues).contains(&ValidationCode::TlsAllowInsecureRemoved));

        // `false` is the Go zero value — Xray runs it fine, so it stays valid.
        let false_stream = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                extra: json!({"allowInsecure": false}).as_object().unwrap().clone(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&false_stream);
        assert!(issues.is_empty(), "{issues:?}");

        // The visit recursion must reach a nested xhttp download stream too.
        let mut parent = StreamModel {
            network: Network::Xhttp,
            ..Default::default()
        };
        let download = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                extra: json!({"allowInsecure": true}).as_object().unwrap().clone(),
                ..Default::default()
            }),
            ..Default::default()
        };
        parent.xhttp_settings = Some(crate::model::stream::XhttpSettings {
            download_settings: Some(Box::new(download)),
            ..Default::default()
        });
        let issues = validate_stream(&parent);
        assert!(codes(&issues).contains(&ValidationCode::TlsAllowInsecureRemoved));
    }

    #[test]
    fn master_key_log_case_variants_in_extra_are_rejected() {
        // serde binds only the exact-case `masterKeyLog` to the model field; a
        // case variant lands in the flattened `extra` map, is still flattened
        // verbatim into the generated config, and Go's case-insensitive JSON
        // unmarshal sets MasterKeyLog regardless — so the attacker-chosen
        // file write survives unless the validator scans `extra`
        // case-insensitively.
        for key in [
            "masterkeylog",
            "MASTERKEYLOG",
            "MasterKeyLog",
            "mAsTeRkEyLoG",
        ] {
            let tls_stream = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    extra: std::iter::once((key.to_string(), json!("C:\\xray-keys.log"))).collect(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&tls_stream);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::MasterKeyLogNotSupported,
                    Some("stream.tlsSettings.masterKeyLog".into()),
                )],
                "tls extra key {key:?} must be rejected like the exact-case field"
            );

            let reality_stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(crate::model::stream::RealityModel {
                    extra: std::iter::once((key.to_string(), json!("C:\\xray-keys.log"))).collect(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&reality_stream);
            assert_eq!(
                issues,
                vec![
                    // Security refusals report before the format
                    // rules: masterKeyLog first, then the empty public key.
                    issue(
                        ValidationCode::MasterKeyLogNotSupported,
                        Some("stream.realitySettings.masterKeyLog".into()),
                    ),
                    issue(
                        ValidationCode::RealityPublicKeyInvalid,
                        Some("stream.realitySettings.publicKey".into()),
                    ),
                ],
                "reality extra key {key:?} must be rejected like the exact-case field"
            );
        }
    }

    #[test]
    fn allow_insecure_case_variants_in_extra_are_rejected() {
        // Go's JSON unmarshal matches field names case-insensitively, so a
        // case variant of `allowInsecure` still sets AllowInsecure in the
        // generated config and Xray's TLSConfig.Build hard-fails with
        // PrintRemovedFeatureError — the validator must scan `extra`
        // case-insensitively.
        for key in [
            "allowinsecure",
            "ALLOWINSECURE",
            "AllowInsecure",
            "allowInSecure",
        ] {
            let mut stream = StreamModel::default();
            stream.security = Security::Tls;
            stream.tls_settings = Some(crate::model::stream::TlsModel {
                extra: std::iter::once((key.to_string(), json!(true))).collect(),
                ..Default::default()
            });
            let issues = validate_stream(&stream);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::TlsAllowInsecureRemoved,
                    Some("stream.tlsSettings.allowInsecure".into()),
                )],
                "tls extra key {key:?} with true must be rejected"
            );
        }
        // `false`/`null` are the Go zero value — Xray runs them fine, so they
        // stay valid regardless of the key's case.
        for key in ["allowinsecure", "allowInSecure"] {
            let false_stream = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    extra: std::iter::once((key.to_string(), json!(false))).collect(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&false_stream);
            assert!(
                issues.is_empty(),
                "allowInsecure=false ({key:?}) must stay valid: {issues:?}"
            );

            let null_stream = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    extra: std::iter::once((key.to_string(), Value::Null)).collect(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&null_stream);
            assert!(
                issues.is_empty(),
                "allowInsecure=null ({key:?}) must stay valid: {issues:?}"
            );
        }
    }

    fn kcp_extra_stream(extra: Map<String, Value>) -> StreamModel {
        StreamModel {
            network: Network::Kcp,
            kcp_settings: Some(KcpSettings {
                extra,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn kcp_seed_and_header_extras_are_refused_and_header_type_warns() {
        // KCPConfig.Build refuses a set `seed` or `header` object
        // with PrintRemovedFeatureError (conf/transport_method.go). Both
        // wire keys, any case, fire the removal Error with per-key paths.
        for (key, path, value) in [
            ("seed", "stream.kcpSettings.seed", json!("s3cret")),
            ("SEED", "stream.kcpSettings.seed", json!("s3cret")),
            (
                "header",
                "stream.kcpSettings.header",
                json!({"type": "dtls"}),
            ),
            (
                "Header",
                "stream.kcpSettings.header",
                json!({"type": "utp"}),
            ),
        ] {
            let stream = kcp_extra_stream(std::iter::once((key.to_string(), value)).collect());
            let issues = validate_stream(&stream);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::KcpSeedHeaderRemoved,
                    Some(path.into())
                )],
                "extra key {key:?} must refuse like the removed feature"
            );
        }
        // JSON null is the Go zero shape (nil pointer / nil RawMessage) and
        // stays silent for both keys.
        for key in ["seed", "header"] {
            let stream =
                kcp_extra_stream(std::iter::once((key.to_string(), Value::Null)).collect());
            assert!(
                validate_stream(&stream).is_empty(),
                "null {key:?} must stay valid"
            );
        }
        // `headerType` never was an Xray JSON key — Xray's unmarshal
        // silently ignores it, so the model warns (Severity::Warning).
        // [Clone-corrected note: the removed-feature citation covers the
        // `header`/`seed` wire keys only; the clone has no `headerType`
        // field anywhere.]
        for key in ["headerType", "HEADERTYPE"] {
            let stream =
                kcp_extra_stream(std::iter::once((key.to_string(), json!("dtls"))).collect());
            let issues = validate_stream(&stream);
            assert_eq!(
                issues,
                vec![warning(
                    ValidationCode::KcpHeaderTypeIgnored,
                    Some("stream.kcpSettings.headerType".into()),
                )],
                "extra key {key:?} must warn exactly once"
            );
        }
        // seed + headerType together: the removal Error and the advisory
        // both render, in scan order.
        let stream = kcp_extra_stream(
            [
                ("seed".to_string(), json!("s3cret")),
                ("headerType".to_string(), json!("dtls")),
            ]
            .into_iter()
            .collect(),
        );
        let issues = validate_stream(&stream);
        assert_eq!(
            codes(&issues),
            vec![
                ValidationCode::KcpSeedHeaderRemoved,
                ValidationCode::KcpHeaderTypeIgnored,
            ]
        );
        // A canonical mKCP block with no extras stays clean.
        assert!(validate_stream(&kcp_extra_stream(Map::new())).is_empty());
    }

    #[test]
    fn reality_server_form_extra_keys_warn_on_client_profiles() {
        // Server-form keys carried on a client REALITY block are
        // never read by the client build, and a set dest/target flips
        // REALITYConfig.Build onto the server branch
        // (conf/transport_security.go) — carried verbatim, so the model
        // warns (advisory; refusal could false-positive on tooling that
        // deliberately carries server-form material).
        let quiet = || StreamModel {
            security: Security::Reality,
            reality_settings: Some(crate::model::stream::RealityModel {
                server_name: "fallback.example.com".into(),
                fingerprint: "chrome".into(),
                password: URL_SAFE_NO_PAD.encode([7_u8; 32]),
                ..Default::default()
            }),
            ..Default::default()
        };
        for (key, path) in [
            ("dest", "stream.realitySettings.dest"),
            ("target", "stream.realitySettings.target"),
            ("privateKey", "stream.realitySettings.privateKey"),
            ("serverNames", "stream.realitySettings.serverNames"),
            ("shortIds", "stream.realitySettings.shortIds"),
            ("mldsa65Seed", "stream.realitySettings.mldsa65Seed"),
        ] {
            let mut stream = quiet();
            stream
                .reality_settings
                .as_mut()
                .unwrap()
                .extra
                .insert(key.to_string(), json!("x"));
            let issues = validate_stream(&stream);
            assert_eq!(
                issues,
                vec![warning(
                    ValidationCode::RealityServerFormKeysInert,
                    Some(path.into()),
                )],
                "server-form key {key:?} must warn exactly once"
            );
        }
        // Case variants bind the same REALITYConfig fields (Go's
        // case-insensitive unmarshal), so they warn identically.
        let mut stream = quiet();
        stream
            .reality_settings
            .as_mut()
            .unwrap()
            .extra
            .insert("DEST".into(), json!("1.2.3.4:443"));
        let issues = validate_stream(&stream);
        assert_eq!(
            issues,
            vec![warning(
                ValidationCode::RealityServerFormKeysInert,
                Some("stream.realitySettings.dest".into()),
            )]
        );
        // A canonical client REALITY block without server-form keys stays
        // silent.
        assert!(validate_stream(&quiet()).is_empty());

        // JSON-null server-form keys are the Go zero value — nothing is
        // carried and the dest/target server-branch flip never triggers,
        // so they must not warn (extra_key_set semantics).
        let mut stream = quiet();
        stream
            .reality_settings
            .as_mut()
            .unwrap()
            .extra
            .insert("dest".into(), Value::Null);
        stream
            .reality_settings
            .as_mut()
            .unwrap()
            .extra
            .insert("privateKey".into(), Value::Null);
        assert!(
            validate_stream(&stream).is_empty(),
            "{:#?}",
            validate_stream(&stream)
        );
    }

    /// Every parameterized code carries the bounded excerpt
    /// form of the hostile source value at construction — never the full
    /// attacker string — so the rendered issue message stays small end to end
    /// and no render site needs its own truncation.
    #[test]
    fn hostile_finalmask_values_reach_codes_and_messages_only_as_excerpts() {
        use crate::i18n::validation_issue_message;
        use crate::model::settings::Language;

        let hostile = "u".repeat(65_536);
        let excerpted = format!("{}…", &hostile[..crate::links::MAX_ERROR_EXCERPT_CHARS]);
        let quoted = format!("\"{excerpted}\"");
        let fm: FinalmaskModel = serde_json::from_str(&format!(
            r#"{{"tcp":[{{"type":"{hostile}","settings":{{}}}}],
                "udp":[
                    {{"type":"{hostile}","settings":{{}}}},
                    {{"type":"noise","settings":{{"noise":[
                        {{"type":"{hostile}","packet":"00"}},
                        {{"type":"{hostile}"}}
                    ]}}}},
                    {{"type":"udphop","settings":{{"mode":"intervalLocal","interval":"5-10",
                        "remotePorts":"1-5,{hostile}"}}}},
                    {{"type":"realm","settings":{{"url":"no-scheme-host","stunServers":["h:1"]}}}}
                ],
                "quicParams":{{"congestion":"bbr","brutalUp":"1 {hostile}"}}}}"#
        ))
        .expect("fixture is valid finalmask JSON");
        let issues = validate_finalmask(&fm);
        // The chain is deliberately misordered (`udphop` sits before the last,
        // `realm`, entry), so the order gate reports `udphop` between the TCP
        // findings and the UDP per-mask findings; every entry still renders
        // bounded.
        assert_eq!(issues.len(), 8, "{issues:#?}");

        let payloads = [
            Some(&excerpted), // FinalmaskUnknownTcpMask
            None,             // FinalmaskUdpMaskNotLast (the chain is misordered)
            Some(&excerpted), // FinalmaskUnknownUdpMask
            Some(&quoted),    // FinalmaskUnknownByteSyntax
            Some(&excerpted), // FinalmaskBytesValueRequired
            Some(&quoted),    // FinalmaskPortListInvalid
            None,             // FinalmaskRealmUrlSyntax (url crate error text)
            Some(&excerpted), // FinalmaskQuicBandwidthUnitInvalid
        ];
        for (issue, expected) in issues.iter().zip(payloads) {
            let message = validation_issue_message(issue, Language::En);
            assert!(
                message.len() < 1024,
                "rendered message must stay bounded: {message:?}"
            );
            assert!(
                !message.contains(&hostile),
                "message must not embed the full hostile value: {message:?}"
            );
            match (&issue.code, expected) {
                (
                    ValidationCode::FinalmaskUnknownTcpMask(Some(payload))
                    | ValidationCode::FinalmaskUnknownUdpMask(Some(payload))
                    | ValidationCode::FinalmaskBytesValueRequired(payload)
                    | ValidationCode::FinalmaskUnknownByteSyntax(payload)
                    | ValidationCode::FinalmaskQuicBandwidthUnitInvalid(payload)
                    | ValidationCode::FinalmaskPortListInvalid(payload),
                    Some(expected),
                ) => assert_eq!(payload, expected, "{issue:?}"),
                (ValidationCode::FinalmaskUdpMaskNotLast(name), None) => {
                    assert_eq!(name, "udphop", "{issue:?}")
                }
                (ValidationCode::FinalmaskRealmUrlSyntax(payload), None) => assert!(
                    payload.len() < 256
                        && payload.chars().count() <= crate::links::MAX_ERROR_EXCERPT_CHARS + 1,
                    "realm parse-error payload must stay bounded: {payload:?}"
                ),
                (code, _) => panic!("unexpected issue {code:?}"),
            }
        }
    }

    /// Regression pins for the excerpt cut-over: short values render
    /// byte-identical messages to the pre-excerpt behavior, because the
    /// excerpt helper is identity below the bound.
    #[test]
    fn short_values_render_byte_identical_messages() {
        use crate::i18n::validation_issue_message;
        use crate::model::settings::Language;
        let render = |json: &str| {
            let fm: FinalmaskModel =
                serde_json::from_str(json).expect("fixture is valid finalmask JSON");
            let issues = validate_finalmask(&fm);
            assert_eq!(issues.len(), 1, "{issues:#?}");
            validation_issue_message(&issues[0], Language::En)
        };

        assert_eq!(
            render(
                r#"{"udp":[{"type":"udphop","settings":{"mode":"intervalLocal","interval":"5-10","remotePorts":"1-5,oops"}}]}"#
            ),
            "finalmask.udp[0].settings.remotePorts: \"oops\" is not a port, port \
             range, or env:NAME entry"
        );
        assert_eq!(
            render(r#"{"quicParams":{"congestion":"bbr","brutalUp":"1 zap"}}"#),
            "finalmask.quicParams.brutalUp: unsupported unit zap. Use bps, \
             kbps, mbps, gbps, or tbps"
        );
        assert_eq!(
            render(
                r#"{"udp":[{"type":"noise","settings":{"noise":[{"type":"future","packet":"00"}]}}]}"#
            ),
            "finalmask.udp[0].settings.noise[0].packet: unknown byte syntax \
             \"future\". Choose array, str, hex, or base64"
        );
        assert_eq!(
            render(r#"{"udp":[{"type":"future-udp","settings":{}}]}"#),
            "finalmask.udp[0]: unsupported future UDP mask discriminator \
             Some(\"future-udp\"). The raw value is preserved"
        );
    }

    #[test]
    fn server_name_implausible_shapes_warn_on_tls_and_reality_blocks() {
        for server_name in [
            "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
            // UUID hex is case-insensitive.
            "9B1DEB4D-3B7D-4BAD-9BDD-2B0D7B3DCB6D",
            "b10a8db164e0754105b7a99be72e3fe5",
            "a b",
            "https://x",
            "x/y",
            "exa🙂mple.com",
        ] {
            let tls_stream = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    server_name: server_name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&tls_stream);
            let finding = issues
                .iter()
                .find(|issue| issue.code == ValidationCode::ServerNameImplausible);
            assert!(
                finding.is_some(),
                "TLS serverName {server_name:?} must warn: {issues:#?}"
            );
            assert_eq!(
                finding.unwrap().path.as_deref(),
                Some("stream.tlsSettings.serverName")
            );

            let reality_stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(crate::model::stream::RealityModel {
                    server_name: server_name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&reality_stream);
            let finding = issues
                .iter()
                .find(|issue| issue.code == ValidationCode::ServerNameImplausible);
            assert!(
                finding.is_some(),
                "REALITY serverName {server_name:?} must warn: {issues:#?}"
            );
            assert_eq!(
                finding.unwrap().path.as_deref(),
                Some("stream.realitySettings.serverName")
            );
        }
    }

    #[test]
    fn plausible_server_names_never_warn() {
        for server_name in [
            "",
            "fts.rbxcdn.com",
            "xn--bcher-kva.example",
            "例え.jp",
            "192.168.1.1",
            "2001:db8::1",
            "my_host.local",
            "router",
            "example.com",
            "8-4-4-4-12",
        ] {
            let tls_stream = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    server_name: server_name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(
                !validate_stream(&tls_stream)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::ServerNameImplausible),
                "TLS serverName {server_name:?} must not warn"
            );
            let reality_stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(crate::model::stream::RealityModel {
                    server_name: server_name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(
                !validate_stream(&reality_stream)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::ServerNameImplausible),
                "REALITY serverName {server_name:?} must not warn"
            );
        }
    }

    // ---------- TLS/REALITY security-format rules ----------
    //
    // Tests beside the existing pins:
    // each code fires on a crafted block with its wire path and severity,
    // and is absent on the canonical value. Sources: Xray conf-load
    // rejections (conf/transport_security.go) — Errors gate exactly like an
    // import refusal — and the class-E version-string drop (tls/config.go),
    // which warns. Fingerprint expectations derive from the canonical table
    // in `crate::model::fingerprint`, never from a duplicated literal list.

    fn reality_base() -> crate::model::stream::RealityModel {
        // Canonical REALITY essentials: everything the client branch of
        // Xray's conf build accepts, with the optional formats empty.
        crate::model::stream::RealityModel {
            fingerprint: "chrome".into(),
            password: URL_SAFE_NO_PAD.encode([7_u8; 32]),
            ..Default::default()
        }
    }

    fn reality_base_with_fingerprint(fingerprint: &str) -> crate::model::stream::RealityModel {
        crate::model::stream::RealityModel {
            fingerprint: fingerprint.into(),
            ..reality_base()
        }
    }

    fn finding_with_code(
        issues: &[ValidationIssue],
        code: ValidationCode,
    ) -> Option<&ValidationIssue> {
        issues.iter().find(|issue| issue.code == code)
    }

    #[test]
    fn canonical_tls_and_reality_blocks_never_fire() {
        let tls = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                fingerprint: "randomizedalpn".into(), // wire-only name: legal
                pinned_peer_cert_sha256: "01ab".repeat(16),
                min_version: "1.2".into(),
                max_version: "1.3".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            validate_stream(&tls).is_empty(),
            "{:?}",
            validate_stream(&tls)
        );

        let reality = StreamModel {
            security: Security::Reality,
            reality_settings: Some(crate::model::stream::RealityModel {
                fingerprint: "chrome".into(),
                password: URL_SAFE_NO_PAD.encode([7_u8; 32]),
                short_id: "0123abcd".into(),
                spider_x: "/search?q=broccoli".into(),
                mldsa65_verify: URL_SAFE_NO_PAD.encode([9_u8; 1952]),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            validate_stream(&reality).is_empty(),
            "{:?}",
            validate_stream(&reality)
        );
    }

    /// An outbound TLS certificate row that names no file and carries no
    /// non-blank PEM line has no key material for Xray's conf build to load,
    /// which refuses the entry (infra/conf: both file and bytes are empty).
    /// A whitespace-only path opens no file and a blank-only line list parses
    /// no certificate, so both count as absent. The rule fires from the model
    /// pass with the offending row's index — the row the user has to fill in —
    /// and stays silent in a block `security` does not select, which Xray
    /// never reads.
    #[test]
    fn tls_certificate_row_without_material_gates_from_the_model_pass() {
        let tls_stream = |tls: crate::model::stream::TlsModel| StreamModel {
            security: Security::Tls,
            tls_settings: Some(tls),
            ..Default::default()
        };

        let issues = validate_stream(&tls_stream(crate::model::stream::TlsModel {
            certificates: vec![
                crate::model::stream::TlsCert::default(),
                crate::model::stream::TlsCert {
                    certificate_file: "   ".into(),
                    ..Default::default()
                },
                crate::model::stream::TlsCert {
                    certificate: vec!["  ".into(), "\t".into()],
                    ..Default::default()
                },
                crate::model::stream::TlsCert {
                    certificate_file: "c.pem".into(),
                    ..Default::default()
                },
                crate::model::stream::TlsCert {
                    certificate: vec!["-----BEGIN CERTIFICATE-----".into()],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }));
        let certificate = finding_with_code(&issues, ValidationCode::TlsCertificateRequired)
            .unwrap_or_else(|| panic!("an empty certificate row must gate: {issues:#?}"));
        assert_eq!(
            certificate.path.as_deref(),
            Some("stream.tlsSettings.certificates[0]")
        );
        assert_eq!(certificate.severity, Severity::Error);
        assert_eq!(
            issues
                .iter()
                .filter(|issue| issue.code == ValidationCode::TlsCertificateRequired)
                .map(|issue| issue.path.as_deref())
                .collect::<Vec<_>>(),
            [
                Some("stream.tlsSettings.certificates[0]"),
                Some("stream.tlsSettings.certificates[1]"),
                Some("stream.tlsSettings.certificates[2]"),
            ],
            "only the rows without material — blank-only text included — may fire: {issues:#?}"
        );

        // A block under another security selection is inert state (the wire
        // pass drops it and Xray never reads it), so the rule stays silent.
        let mut inert = tls_stream(crate::model::stream::TlsModel {
            certificates: vec![crate::model::stream::TlsCert::default()],
            ..Default::default()
        });
        inert.security = Security::Reality;
        inert.reality_settings = Some(reality_base());
        let issues = validate_stream(&inert);
        assert!(
            !issues
                .iter()
                .any(|issue| issue.code == ValidationCode::TlsCertificateRequired),
            "an unselected TLS block must stay silent: {issues:#?}"
        );
    }

    /// An outbound TLS `alpn` list carrying `fromMitm` beside another name is
    /// refused by Xray's conf build (infra/conf/transport_security.go: only
    /// one element is allowed in "alpn" when using "fromMitm" in it), so the
    /// model pass gates it on the field path; a sole `fromMitm` and any
    /// fromMitm-free list stay valid.
    #[test]
    fn tls_from_mitm_alpn_beside_another_name_gates_from_the_model_pass() {
        let tls_stream = |alpn: &[String]| StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                alpn: alpn.to_vec(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let issues = validate_stream(&tls_stream(&["fromMitm".to_string(), "h2".to_string()]));
        let alpn = finding_with_code(&issues, ValidationCode::TlsFromMitmAlpnShort)
            .unwrap_or_else(|| panic!("fromMitm beside another element must gate: {issues:#?}"));
        assert_eq!(alpn.path.as_deref(), Some("stream.tlsSettings.alpn"));
        assert_eq!(alpn.severity, Severity::Error);

        for alpn in [
            Vec::new(),
            vec!["fromMitm".to_string()],
            vec!["h2".to_string(), "http/1.1".to_string()],
        ] {
            let issues = validate_stream(&tls_stream(&alpn));
            assert!(
                !issues
                    .iter()
                    .any(|issue| issue.code == ValidationCode::TlsFromMitmAlpnShort),
                "a sole fromMitm or a fromMitm-free list must not gate for {alpn:?}: {issues:#?}"
            );
        }
    }

    #[test]
    fn reality_client_format_errors_carry_wire_paths_and_gate() {
        // publicKey: empty, malformed, and wrong-length values all fire on
        // the wire path with Error severity (Xray refuses each at conf load).
        let short_pbk = URL_SAFE_NO_PAD.encode([7_u8; 31]);
        let long_pbk = URL_SAFE_NO_PAD.encode([7_u8; 33]);
        for password in [
            "",
            "AAA",
            "not base64url!",
            short_pbk.as_str(),
            long_pbk.as_str(),
        ] {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(crate::model::stream::RealityModel {
                    password: password.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            let finding = finding_with_code(&issues, ValidationCode::RealityPublicKeyInvalid)
                .expect("password {password:?} must fire RealityPublicKeyInvalid");
            assert_eq!(
                finding.path.as_deref(),
                Some("stream.realitySettings.publicKey")
            );
            assert_eq!(finding.severity, Severity::Error);
        }
        // shortId: odd-length hex, non-hex, and >16 chars fire; empty and
        // even-length ≤16 hex do not.
        for short_id in ["abc", "12zz", "0123456789abcdef0"] {
            let mut reality = reality_base();
            reality.short_id = short_id.into();
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            let finding = finding_with_code(&issues, ValidationCode::RealityShortIdInvalid)
                .expect("shortId {short_id:?} must fire RealityShortIdInvalid");
            assert_eq!(
                finding.path.as_deref(),
                Some("stream.realitySettings.shortId")
            );
            assert_eq!(finding.severity, Severity::Error);
        }
        for short_id in ["", "00", "0123abcd", "ABCDEF0123456789"] {
            let mut reality = reality_base();
            reality.short_id = short_id.into();
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality),
                ..Default::default()
            };
            assert!(
                !validate_stream(&stream)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::RealityShortIdInvalid),
                "shortId {short_id:?} must stay valid"
            );
        }
        // spiderX: anything not starting with '/' fires; empty stays valid.
        for spider_x in ["relative", "/has\ttab", "\u{1}/leading-control"] {
            let mut reality = reality_base();
            reality.spider_x = spider_x.into();
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            let finding = finding_with_code(&issues, ValidationCode::RealitySpiderXInvalid)
                .expect("spiderX {spider_x:?} must fire RealitySpiderXInvalid");
            assert_eq!(
                finding.path.as_deref(),
                Some("stream.realitySettings.spiderX")
            );
            assert_eq!(finding.severity, Severity::Error);
        }
        for spider_x in ["", "/", "/search?q=1", "/a/b/c%20d"] {
            let mut reality = reality_base();
            reality.spider_x = spider_x.into();
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality),
                ..Default::default()
            };
            assert!(
                !validate_stream(&stream)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::RealitySpiderXInvalid),
                "spiderX {spider_x:?} must stay valid"
            );
        }
        // mldsa65Verify: non-empty values that are not base64url of exactly
        // 1952 bytes fire; empty stays valid.
        let short_mldsa = URL_SAFE_NO_PAD.encode([9_u8; 1951]);
        for mldsa65_verify in ["AAA", "not base64url!", short_mldsa.as_str()] {
            let mut reality = reality_base();
            reality.mldsa65_verify = mldsa65_verify.into();
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            let finding = finding_with_code(&issues, ValidationCode::RealityMldsa65Invalid)
                .expect("mldsa65Verify must fire RealityMldsa65Invalid");
            assert_eq!(
                finding.path.as_deref(),
                Some("stream.realitySettings.mldsa65Verify")
            );
            assert_eq!(finding.severity, Severity::Error);
        }
        let mut reality = reality_base();
        reality.mldsa65_verify = URL_SAFE_NO_PAD.encode([9_u8; 1952]);
        let stream = StreamModel {
            security: Security::Reality,
            reality_settings: Some(reality),
            ..Default::default()
        };
        assert!(
            !validate_stream(&stream)
                .iter()
                .any(|issue| issue.code == ValidationCode::RealityMldsa65Invalid)
        );
    }

    #[test]
    fn tls_fingerprint_follows_the_wire_vocabulary() {
        // TLS accepts the full canonical table — editor names, wire-only
        // names, empty, `unsafe`/`hellogolang` (native Go TLS), and any
        // ASCII casing (Xray lowercases before lookup).
        for &name in crate::model::fingerprint::FINGERPRINTS
            .iter()
            .chain(crate::model::fingerprint::VALIDATION_ONLY_FINGERPRINTS)
        {
            let tls = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    fingerprint: name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(
                !validate_stream(&tls)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::TlsFingerprintUnsupported),
                "TLS fingerprint {name:?} is wire-valid and must not fire"
            );
        }
        for name in ["Chrome", "RANDOMIZEDNOALPN"] {
            let tls = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    fingerprint: name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(
                !validate_stream(&tls)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::TlsFingerprintUnsupported),
                "TLS fingerprint {name:?} matches case-insensitively and must not fire"
            );
        }
        // Out-of-vocabulary values are conf-load errors on the wire path.
        for name in ["bogus", "hellofirefox_999", "Chrome2"] {
            let tls = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    fingerprint: name.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&tls);
            let finding = finding_with_code(&issues, ValidationCode::TlsFingerprintUnsupported)
                .expect("TLS fingerprint {name:?} must fire");
            assert_eq!(
                finding.path.as_deref(),
                Some("stream.tlsSettings.fingerprint")
            );
            assert_eq!(finding.severity, Severity::Error);
        }
    }

    #[test]
    fn reality_fingerprint_excludes_exactly_unsafe_and_hellogolang() {
        use crate::model::fingerprint::{FINGERPRINTS, VALIDATION_ONLY_FINGERPRINTS};
        // The full canonical table: only `unsafe` and `hellogolang` fire —
        // empty and wire-only names stay legal (Xray's client build rejects
        // exactly {unsafe, hellogolang} plus unknown names).
        for &name in FINGERPRINTS.iter().chain(VALIDATION_ONLY_FINGERPRINTS) {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality_base_with_fingerprint(name)),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            let expected = matches!(name, "unsafe" | "hellogolang");
            assert_eq!(
                issues
                    .iter()
                    .any(|issue| issue.code == ValidationCode::RealityFingerprintUnsupported),
                expected,
                "REALITY fingerprint {name:?} verdict mismatch: {issues:#?}"
            );
        }
        // The wire exclusion is ASCII case-insensitive (Xray lowercases the
        // fingerprint first); table names in any casing stay accepted.
        for name in ["UNSAFE", "Hellogolang"] {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality_base_with_fingerprint(name)),
                ..Default::default()
            };
            assert!(
                validate_stream(&stream)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::RealityFingerprintUnsupported),
                "REALITY fingerprint {name:?} must fire"
            );
        }
        for name in ["chrome", "randomizedalpn", "Chrome"] {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality_base_with_fingerprint(name)),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            assert!(
                !issues
                    .iter()
                    .any(|issue| issue.code == ValidationCode::RealityFingerprintUnsupported),
                "REALITY fingerprint {name:?} must not fire"
            );
            // A firing value carries the block path and Error severity.
        }
        let stream = StreamModel {
            security: Security::Reality,
            reality_settings: Some(reality_base_with_fingerprint("unsafe")),
            ..Default::default()
        };
        let issues = validate_stream(&stream);
        let finding =
            finding_with_code(&issues, ValidationCode::RealityFingerprintUnsupported).unwrap();
        assert_eq!(
            finding.path.as_deref(),
            Some("stream.realitySettings.fingerprint")
        );
        assert_eq!(finding.severity, Severity::Error);
    }

    /// The REALITY fingerprint advisory: a wire-valid name outside the
    /// known-good set the editor offers warns exactly once on the field
    /// path, the empty default and the three names upstream's REALITY
    /// scenarios exercise stay silent, and an invalid name keeps exactly its
    /// blocking finding with no advisory beside it.
    #[test]
    fn reality_fingerprint_outside_known_good_warns_once_on_the_field_path() {
        let pointer = || Some("stream.realitySettings.fingerprint".to_string());
        for name in [
            "ios",
            "edge",
            "qq",
            "android",
            "randomized",
            "randomizedalpn",
        ] {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality_base_with_fingerprint(name)),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            assert_eq!(
                issues,
                vec![warning(
                    ValidationCode::RealityFingerprintUntested(name.into()),
                    pointer()
                )],
                "REALITY fingerprint {name:?} must warn once: {issues:#?}"
            );
        }
        // The empty default (the uTLS Chrome_Auto preset) and the three
        // names upstream's REALITY scenarios exercise are inside the
        // known-good set; a casing of a known name is the same wire value
        // (Xray lowercases the fingerprint before its checks).
        for name in ["", "chrome", "firefox", "safari", "Chrome", "Firefox"] {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality_base_with_fingerprint(name)),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            assert!(
                issues.is_empty(),
                "REALITY fingerprint {name:?} must not warn: {issues:#?}"
            );
        }
        // `unsafe`, `hellogolang`, and unknown names stay conf-load Errors:
        // exactly the existing finding, never a second advisory.
        for name in ["unsafe", "hellogolang", "bogus"] {
            let stream = StreamModel {
                security: Security::Reality,
                reality_settings: Some(reality_base_with_fingerprint(name)),
                ..Default::default()
            };
            let issues = validate_stream(&stream);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::RealityFingerprintUnsupported,
                    pointer()
                )],
                "REALITY fingerprint {name:?} must keep exactly its Error: {issues:#?}"
            );
        }
    }

    #[test]
    fn pcs_rule_covers_the_whole_entry_grammar() {
        // Canonical: empty, one 64-hex pin, colon-separated OpenSSL form,
        // multiple pins with whitespace, uppercase hex — all clean. Empty
        // comma segments are skipped, exactly like Xray's split.
        let colon_pins = "ab:".repeat(31) + "ab";
        let two_pins = format!("{}, {}", "ab".repeat(32), "cd".repeat(32));
        let upper_pin = "AB".repeat(32);
        let empty_segment_pins = format!("{},,{}", "ab".repeat(32), "cd".repeat(32));
        for pins in [
            "",
            "01ab".repeat(16).as_str(),
            colon_pins.as_str(),
            two_pins.as_str(),
            upper_pin.as_str(),
            empty_segment_pins.as_str(),
        ] {
            let tls = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    fingerprint: "chrome".into(),
                    pinned_peer_cert_sha256: pins.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            assert!(
                !validate_stream(&tls)
                    .iter()
                    .any(|issue| issue.code == ValidationCode::PinnedPeerCertSha256Invalid),
                "pcs {pins:?} must stay valid"
            );
        }
        // Non-hex, wrong-length, and whitespace-only entries fire with the
        // wire path and Error severity.
        let short_pin = "ab".repeat(31);
        for pins in ["zz".repeat(32).as_str(), short_pin.as_str(), "gg"] {
            let tls = StreamModel {
                security: Security::Tls,
                tls_settings: Some(crate::model::stream::TlsModel {
                    fingerprint: "chrome".into(),
                    pinned_peer_cert_sha256: pins.into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let issues = validate_stream(&tls);
            let finding = finding_with_code(&issues, ValidationCode::PinnedPeerCertSha256Invalid)
                .expect("pcs {pins:?} must fire PinnedPeerCertSha256Invalid");
            assert_eq!(
                finding.path.as_deref(),
                Some("stream.tlsSettings.pinnedPeerCertSha256")
            );
            assert_eq!(finding.severity, Severity::Error);
        }
    }

    #[test]
    fn version_strings_outside_the_range_warn_with_paths_and_never_gate() {
        let version_stream = |min: &str, max: &str| StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                fingerprint: "chrome".into(),
                min_version: min.into(),
                max_version: max.into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        // In-range values and empty defaults never warn.
        for (min, max) in [("", ""), ("1.0", "1.3"), ("1.2", "1.2")] {
            assert!(
                !validate_stream(&version_stream(min, max))
                    .iter()
                    .any(|issue| issue.code == ValidationCode::TlsVersionRangeInvalid),
                "versions {min:?}/{max:?} must not warn"
            );
        }
        // One warning per offending field, Warning severity, on the field's
        // own wire path.
        for version in ["1.4", "2.0", "0.9", "tls1.2", "1.2.3"] {
            for (field, path) in [
                (version, "stream.tlsSettings.minVersion"),
                (version, "stream.tlsSettings.maxVersion"),
            ] {
                let stream = version_stream(
                    if path.ends_with("minVersion") {
                        field
                    } else {
                        "1.2"
                    },
                    if path.ends_with("maxVersion") {
                        field
                    } else {
                        "1.2"
                    },
                );
                let issues = validate_stream(&stream);
                let finding = finding_with_code(&issues, ValidationCode::TlsVersionRangeInvalid)
                    .expect("version {field:?} at {path} must warn");
                assert_eq!(finding.path.as_deref(), Some(path));
                assert_eq!(finding.severity, Severity::Warning);
            }
        }
        // Both fields out of range: two warnings, one per field.
        let issues = validate_stream(&version_stream("1.4", "2.1"));
        let version_issues: Vec<&ValidationIssue> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::TlsVersionRangeInvalid)
            .collect();
        assert_eq!(version_issues.len(), 2, "{issues:#?}");
        assert_eq!(
            version_issues[0].path.as_deref(),
            Some("stream.tlsSettings.minVersion")
        );
        assert_eq!(
            version_issues[1].path.as_deref(),
            Some("stream.tlsSettings.maxVersion")
        );
    }

    // ---------- repro-gated rules batch ----------
    //
    // Every rule below shipped only after a live xray 26.7.28 reproduction
    // (2026-09-06): the TLS in-range min > max inversion and
    // xhttpSettings.extra shadowing. The dropped candidates (ALPN h2-first /
    // uTLS override, vision + non-RAW transports, vision + pinned TLS ≤ 1.2)
    // ship no code.

    #[test]
    fn tls_min_exceeds_max_warns_never_gates() {
        let version_stream = |min: &str, max: &str| StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                fingerprint: "chrome".into(),
                min_version: min.into(),
                max_version: max.into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        // Inverted in-range pairs warn exactly once, on the block path,
        // Warning severity (config loads and the version pins silently
        // never apply — repro 2026-09-06).
        for (min, max) in [("1.3", "1.2"), ("1.2", "1.1"), ("1.3", "1.0")] {
            let issues = validate_stream(&version_stream(min, max));
            let findings: Vec<&ValidationIssue> = issues
                .iter()
                .filter(|issue| issue.code == ValidationCode::TlsMinExceedsMax)
                .collect();
            assert_eq!(findings.len(), 1, "min {min:?} > max {max:?}: {issues:#?}");
            assert_eq!(
                findings[0].path.as_deref(),
                Some("stream.tlsSettings"),
                "min {min:?} > max {max:?}"
            );
            assert_eq!(findings[0].severity, Severity::Warning);
        }
        // Equal and ordered ranges, empty defaults, and out-of-vocabulary
        // strings never fire this rule — the out-of-vocabulary pair stays
        // TlsVersionRangeInvalid's business.
        for (min, max) in [
            ("", ""),
            ("1.0", "1.3"),
            ("1.2", "1.2"),
            ("1.0", "1.0"),
            ("1.4", "2.1"),
        ] {
            assert!(
                !validate_stream(&version_stream(min, max))
                    .iter()
                    .any(|issue| issue.code == ValidationCode::TlsMinExceedsMax),
                "versions {min:?}/{max:?} must not fire TlsMinExceedsMax"
            );
        }
    }

    #[test]
    fn xhttp_extra_key_shadowing_warns_with_the_key() {
        let with_extra = XhttpSettings {
            x_padding_method: "tokenish".into(),
            ..Default::default()
        };
        let mut with_extra = with_extra;
        with_extra
            .extra
            .insert("xPaddingMethod".into(), json!("bogus"));
        let issues = validate_stream(&xhttp_stream(with_extra));
        let finding = issues
            .iter()
            .find(|issue| {
                matches!(
                    &issue.code,
                    ValidationCode::XhttpExtraShadowsSettings(key)
                        if key == "xPaddingMethod"
                )
            })
            .expect("xPaddingMethod in extra must warn");
        assert_eq!(
            finding.path.as_deref(),
            Some("stream.xhttpSettings.xPaddingMethod")
        );
        assert_eq!(finding.severity, Severity::Warning);
        // The rendered message carries the offending key (fill arm).
        let rendered = crate::i18n::validation_issue_message(
            &warning(
                ValidationCode::XhttpExtraShadowsSettings("xPaddingMethod".into()),
                Some("stream.xhttpSettings.xPaddingMethod".into()),
            ),
            crate::model::settings::Language::En,
        );
        assert!(rendered.contains("xPaddingMethod"), "{rendered}");
        // Case-insensitive extra keys are caught too (serde flatten is
        // exact-case, but Go's JSON unmarshal is not).
        let mut case_extra = XhttpSettings::default();
        case_extra
            .extra
            .insert("XPADDINGMETHOD".into(), json!("bogus"));
        let issues = validate_stream(&xhttp_stream(case_extra));
        assert!(issues.iter().any(|issue| {
            matches!(
                &issue.code,
                ValidationCode::XhttpExtraShadowsSettings(key)
                    if key == "xPaddingMethod"
            )
        }));
        // An unmodeled extra key stays silent, and so does canonical state.
        let mut other_extra = XhttpSettings::default();
        other_extra.extra.insert("xPaddingCaps".into(), json!(42));
        assert!(validate_stream(&xhttp_stream(other_extra)).is_empty());
        assert!(validate_stream(&xhttp_stream(XhttpSettings::default())).is_empty());
    }

    #[test]
    fn canonical_uuid_predicate_is_parse_str_and_nothing_more() {
        for accepted in [
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            // Hex is case-insensitive.
            "B831381D-6324-4D53-AD4F-8CDA48B30811",
            // `Uuid::parse_str` also accepts its unhyphenated 32-hex
            // "simple" form, and all four callers have always shared that
            // verdict.
            "b10a8db164e0754105b7a99be72e3fe5",
        ] {
            assert!(is_canonical_uuid(accepted), "{accepted:?} must pass");
        }
        for rejected in [
            // 1-30-char strings: Xray sha1-maps these to another account.
            "some-account-name",
            // Canonical shape cut short (the import grammar's own case).
            "b831381d-6324-4d53-ad4f-8cda48b3081",
            "",
            // 32 characters, one of them not hex.
            "b10a8db164e0754105b7a99be72e3feG",
            // Canonical shape, non-hex digits.
            "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz",
        ] {
            assert!(!is_canonical_uuid(rejected), "{rejected:?} must be refused");
        }
    }
}
