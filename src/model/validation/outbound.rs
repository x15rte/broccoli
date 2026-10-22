//! Validation rules of the outbound scope.
//!
//! Split out of [`crate::model::validation`]; that module holds the taxonomy
//! and the vocabulary more than one scope reads.

use super::stream::{
    finalmask_udp_hop_interval_mode, freedom_domain_strategy_supported,
    hop_transport_migrates_connections, is_canonical_uuid, shadowsocks_2022_key_usable,
    shadowsocks_method_supported, sockopt_address_port_strategy_supported,
    target_strategy_supported, validate_stream, vless_flow_supported, vmess_security_supported,
};
use super::{
    ValidationCode, ValidationIssue, Verdict, excerpt, extra_has_key, extra_key_set,
    is_vision_flow, issue, warning,
};
use crate::model::inbound::Sniffing;
use crate::model::outbound::{
    Fragment, MuxModel, Noise, OutboundModel, Protocol, ProtocolSettings,
    blackhole_response_is_custom, blackhole_response_type_supported,
    endpoint_requires_transport_security, is_valid_wireguard_key,
    masque_remote_dns_entry_supported, vless_encryption_supported,
    wireguard_remote_dns_entry_supported,
};
use crate::model::stream::{
    Network, Security, StreamModel, XDRIVE_DEFAULT_MAX_POLL_INTERVAL_MS,
    XDRIVE_DEFAULT_POLL_INTERVAL_MS, XDRIVE_MAX_CONCURRENCY, XDRIVE_MAX_SEGMENT_BYTES,
    XDRIVE_SERVICE_DRIVE, XDRIVE_SERVICE_DRIVE_RETIRED, XDRIVE_SERVICE_LOCAL,
    XDRIVE_SERVICE_TEMPLATE, XDRIVE_TEMPLATE_MAX_CONCURRENCY, XdriveOperation, XdriveTemplate,
    xdrive_names_regex_supported, xdrive_service_supported, xdrive_template_auth_type_supported,
};
use crate::model::{fold_eq, go_std_base64_decodes, parse_range_go, vocabulary_holds};
use base64::Engine as _;
use serde_json::Value;
use std::borrow::Cow;

/// Mux/vision predicate (shared with the editor's targeted-inline hints, so
/// the model and the UI can never disagree): true when a VLESS profile
/// combines a vision flow with TCP-carrying mux:
/// Xray's XRV servers reject TCP frames over mux (breaking the whole mux
/// connection on the first one), so such a profile cannot work. `concurrency
/// = -1` is the TCP-direct escape hatch — XUDP stays available, so it never
/// warns; the XUDP knobs (`xudpConcurrency`/`xudpProxyUDP443`) do NOT
/// suppress the warning, because TCP rides smux whenever mux is enabled with
/// a non-negative concurrency.
pub fn mux_conflicts_with_vision_flow(
    flow: &str,
    mux_enabled: bool,
    mux_concurrency: Option<i16>,
) -> bool {
    is_vision_flow(flow) && mux_enabled && mux_concurrency != Some(-1)
}

/// The `xudpProxyUDP443` vocabulary: the three modes Xray's mux Build
/// accepts verbatim (infra/conf/xray.go MuxConfig.Build — an exact,
/// case-sensitive switch; empty is separately legal and defaults to
/// `reject` on the wire). Shared with the editor combo, so the offered
/// choices and this refusal predicate can never disagree.
pub const XUDP_PROXY_UDP443_MODES: &[&str] = &["reject", "allow", "skip"];

/// True when a `xudpProxyUDP443` is legal on the wire —
/// empty (Xray defaults it to `reject`) or one of {reject, allow, skip}.
/// Xray's conf build refuses every other value (infra/conf/xray.go:
/// 110-117), including case variants — the switch never lowercases.
fn xudp_proxy_udp443_supported(value: &str) -> bool {
    value.is_empty() || XUDP_PROXY_UDP443_MODES.contains(&value)
}

/// Concurrency reinterpretation: true when mux is
/// enabled with a `concurrency` value Xray silently changes the meaning
/// of — `0` runs as 8, values above 128 clamp to 128, and any negative
/// other than the documented `-1` TCP-direct escape disables mux entirely
/// (proxy outbound handler; docs outbound.md MuxObject bounds [1, 128]).
/// Disabled blocks never fire: Xray reads `concurrency` only inside the
/// `Enabled` branch, so an out-of-band value there is a dead knob, not a
/// reinterpretation. `-1` and 1..=128 never fire.
fn mux_concurrency_reinterpreted(mux_enabled: bool, concurrency: Option<i16>) -> bool {
    mux_enabled && concurrency.is_some_and(|c| c == 0 || !(-1..=128).contains(&c))
}

/// Dead XUDP knobs: true when an XUDP knob is set
/// while `mux.enabled` is off — Xray reads `xudpConcurrency` /
/// `xudpProxyUDP443` only inside the `Enabled` block (proxy outbound
/// handler), so the whole XUDP side is silently ignored.
fn mux_xudp_knobs_inert(m: &MuxModel) -> bool {
    !m.enabled && (m.xudp_concurrency.is_some() || m.xudp_proxy_udp443.is_some())
}

// ---------- outbound envelope / DNS-rule vocabularies ----------
//
// These three rules used to live only in the servers editor's error list.
// They decide whether the configuration is valid, so the model pass owns
// them now: [`validate_outbound`] reports the codes, and the editor's
// inline hints and combos call these same predicates instead of carrying
// private copies.

/// True when a freedom `finalRules[].action` is one Xray's freedom build
/// accepts — `allow` or `block`, under [`vocabulary_holds`] (the core
/// lowercases the action before its switch, infra/conf/freedom.go:255; the
/// editor combo offers exactly these spellings).
pub fn freedom_final_rule_supported(action: &str) -> bool {
    vocabulary_holds(&["allow", "block"], action)
}

/// The DNS-out `rules[].action` vocabulary — the four actions Xray's DNS
/// config build accepts. The editor combo additionally offers the empty
/// "(default)" display entry; an empty action is not an action.
pub const DNS_OUT_ACTIONS: &[&str] = &["direct", "drop", "return", "hijack"];

/// True when a DNS-out `rules[].action` names one of [`DNS_OUT_ACTIONS`],
/// under [`vocabulary_holds`] — the core lowercases the action before its
/// switch (infra/conf/dns_proxy.go:23).
pub fn dns_out_action_supported(action: &str) -> bool {
    vocabulary_holds(DNS_OUT_ACTIONS, action)
}

/// True when a `sendThrough` value is one Xray's dialer accepts —
/// `origin`/`srcip` or an IP address / CIDR literal.
pub fn send_through_supported(value: &str) -> bool {
    matches!(value, "origin" | "srcip")
        || value.parse::<std::net::IpAddr>().is_ok()
        || value.parse::<cidr_shim::Cidr>().is_ok()
}

/// Minimal CIDR parse shim so the sendThrough rule needs no extra dep.
mod cidr_shim {
    pub struct Cidr;
    impl std::str::FromStr for Cidr {
        type Err = ();
        fn from_str(s: &str) -> Result<Self, ()> {
            let (ip, len) = s.split_once('/').ok_or(())?;
            ip.parse::<std::net::IpAddr>().map_err(|_| ())?;
            let n: u8 = len.parse().map_err(|_| ())?;
            let max = if ip.contains(':') { 128 } else { 32 };
            if n > max {
                return Err(());
            }
            Ok(Cidr)
        }
    }
}

/// True when a sniffing `destOverride` item names one
/// of the protocols Xray's SniffingConfig build accepts, case-insensitively
/// (infra/conf/xray.go: http, tls with the https/ssl spellings folded in,
/// quic, and fakedns with the `fakedns+others` spelling folded in). The
/// "fakedns" item the generator appends itself at wire time is part of this
/// vocabulary, so the rule can never false-positive on it.
pub fn sniffing_dest_override_supported(protocol: &str) -> bool {
    vocabulary_holds(
        &[
            "http",
            "tls",
            "https",
            "ssl",
            "quic",
            "fakedns",
            "fakedns+others",
        ],
        protocol,
    )
}

/// Validate one inbound sniffing block. `prefix`
/// is the state-file path of the sniffing block (e.g.
/// `"localInbounds[0].sniffing"`); each finding names the offending field
/// as `{prefix}.destOverride`. Error tier: Xray refuses the whole config at
/// load on an unknown protocol, and this verdict gates generation exactly
/// like that load refusal. Emits one issue per offending item — never on
/// `fakedns`/`fakedns+others`, which Xray accepts and the generator
/// appends at wire time.
pub fn validate_sniffing(sniffing: &Sniffing, prefix: &str) -> Verdict {
    let mut issues = Vec::new();
    for item in &sniffing.dest_override {
        if !sniffing_dest_override_supported(item) {
            issues.push(issue(
                ValidationCode::SniffingDestOverrideInvalid,
                Some(format!("{prefix}.destOverride")),
            ));
        }
    }
    Verdict::from_issues(issues)
}

/// True when a freedom `settings.fragment` block cannot load.
///
/// `Fragment.Build` (`infra/conf/freedom.go`) folds `packets` with
/// `strings.ToLower` and then reads one of three shapes: `tlshello` (TLS
/// Hello fragmentation), empty (every packet), or a `ParseRangeString` value
/// whose start is not 0 — that parser never trims and is 64-bit, so
/// `"9999999999"` loads while a padded `" 1-3"` fails the build. `length` and
/// `interval` must both be present, and a `length` whose ordered start is 0 is
/// refused (`Int32Range.UnmarshalJSON` swaps the pair first, so `"3-0"` reads
/// as a 0 start on the wire). Bounds that only look backwards still load:
/// `crypto.RandBetween` swaps an inverted pair (`common/crypto/crypto.go:12`),
/// so an inverted or negative range is no finding. Every row of that table is
/// live on the pinned v26.9.30 binary (`xray run -test`: exit 0 accepted,
/// exit 23 refused).
fn freedom_fragment_unrunnable(fragment: &Fragment) -> bool {
    let packets_unrunnable = !fragment.packets.is_empty()
        && !fold_eq(&fragment.packets, "tlshello")
        && parse_range_go(&fragment.packets).is_none_or(|(start, _)| start == 0);
    packets_unrunnable
        || fragment
            .length
            .is_none_or(|range| range.from.min(range.to) == 0)
        || fragment.interval.is_none()
}

/// True when a freedom `settings.noises` entry cannot load.
///
/// `ParseNoise` (`infra/conf/freedom.go`) reads the entry in three parts. The
/// `type` is compared exactly — no fold, no trim — over `rand`/`str`/`hex`/
/// `base64`. The `packet` is trimmed first and then read per type: `rand`
/// parses it with the same 64-bit, never-trimmed `ParseRangeString` the
/// fragment's `packets` uses (its start must not be 0); `str` takes it as
/// written; `hex` must decode as hex, an empty payload being zero bytes; and
/// `base64` is normalized (`+`→`-`, `/`→`_`, `=` dropped) and decoded as raw
/// URL base64. `applyTo` folds with `strings.ToLower` over the empty default
/// plus `ip`, `all`, `ipv4`, `ipv6`. `delay` is read when present and
/// constrains nothing. Every row of that table is live on the pinned v26.9.30
/// binary (`xray run -test`: exit 0 accepted, exit 23 refused).
fn freedom_noise_unrunnable(noise: &Noise) -> bool {
    let packet = noise.packet.trim();
    let packet_unrunnable = match noise.r#type.as_str() {
        "rand" => parse_range_go(packet).is_none_or(|(start, _)| start == 0),
        "str" => false,
        "hex" => !(packet.len().is_multiple_of(2) && packet.bytes().all(|b| b.is_ascii_hexdigit())),
        "base64" => {
            use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

            // Go's non-strict `base64.RawURLEncoding`: non-zero trailing bits
            // decode to the same bytes, and `\r`/`\n` are skipped anywhere, so
            // the bundled engine's strict trailing-bit check is relaxed and
            // the newlines are dropped before the decode.
            const GO_RAW_URL_SAFE: GeneralPurpose = GeneralPurpose::new(
                &base64::alphabet::URL_SAFE,
                GeneralPurposeConfig::new()
                    .with_decode_allow_trailing_bits(true)
                    .with_decode_padding_mode(DecodePaddingMode::RequireNone),
            );

            let normalized = packet.replace('+', "-").replace('/', "_").replace('=', "");
            let stripped = if normalized.contains(['\r', '\n']) {
                Cow::Owned(
                    normalized
                        .chars()
                        .filter(|c| !matches!(c, '\r' | '\n'))
                        .collect::<String>(),
                )
            } else {
                Cow::Borrowed(normalized.as_str())
            };
            GO_RAW_URL_SAFE.decode(stripped.as_bytes()).is_err()
        }
        _ => true,
    };
    let apply_to_unrunnable = !noise.apply_to.is_empty()
        && !vocabulary_holds(&["ip", "all", "ipv4", "ipv6"], &noise.apply_to);
    packet_unrunnable || apply_to_unrunnable
}

/// True when a `masqueSettings.path` is one the pinned core builds:
/// `infra/conf/transport_method.go:801-813` substitutes the default for an
/// empty path, rewrites `{target}` and `{ipproto}` to `*`, and then requires
/// a leading `/` and no leftover braces. The core additionally rewrites the
/// four combined `{?…}`/`{&…}` query forms; the app accepts only the two
/// documented placeholders, so a path built on a combined form is refused
/// here even though the core would run it.
fn masque_path_supported(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    let replaced = path.replace("{target}", "*").replace("{ipproto}", "*");
    replaced.starts_with('/') && !replaced.contains('{') && !replaced.contains('}')
}

/// True when a `masqueSettings.host` is the bare `host[:port]` authority the
/// core's `url.Parse("https://" + host)` accepts with `u.Host == host`
/// (infra/conf/transport_method.go:813-817): no scheme, path, query, fragment
/// or userinfo separator, an optional all-digit port, and — when bracketed —
/// an IPv6 literal. Empty stays valid (the core leaves the request authority
/// to the dial address).
fn masque_host_supported(host: &str) -> bool {
    if host.is_empty() {
        return true;
    }
    // The URL parser always reports a scheme/mark separator outside the
    // authority as a different host, so any of these makes `u.Host` differ
    // from the input.
    if host
        .bytes()
        .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'/' | b'?' | b'#' | b'@' | b'\\'))
    {
        return false;
    }
    let name = if let Some(rest) = host.strip_prefix('[') {
        let Some((literal, tail)) = rest.split_once(']') else {
            return false;
        };
        if literal.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        return match tail.strip_prefix(':') {
            Some(port) => !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()),
            None => tail.is_empty(),
        };
    } else {
        match host.split_once(':') {
            Some((name, port)) => {
                if !port.bytes().all(|byte| byte.is_ascii_digit()) {
                    return false;
                }
                name
            }
            None => host,
        }
    };
    !name.is_empty()
}

/// True when one `masqueSettings.headers` name is a valid HTTP field name
/// (the core's `httpguts.ValidHeaderFieldName`, a non-empty RFC 7230 token).
fn masque_header_name_supported(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// True when one `masqueSettings.headers` value is a valid HTTP field value
/// (the core's `httpguts.ValidHeaderFieldValue`): no control byte other than
/// the two line whitespace characters, and no DEL.
fn masque_header_value_supported(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| (byte >= b' ' || byte == b'\t') && byte != 0x7f)
}

/// The MASQUE outbound/transport pair rules and the transport's own option
/// rules. The pair rules need the outbound protocol and the stream at once,
/// so they live here; the transport's own rules (`path`, `host`, `headers`,
/// credentials, the ALPN pair) ride `validate_stream` below.
fn validate_masque(o: &OutboundModel, issues: &mut Vec<ValidationIssue>) {
    if o.protocol == Protocol::Masque && o.stream.network != Network::Masque {
        issues.push(issue(
            ValidationCode::MasqueOutboundRequiresMasqueTransport,
            Some("stream.network".into()),
        ));
    }
    if o.stream.network == Network::Masque && o.protocol != Protocol::Masque {
        issues.push(issue(
            ValidationCode::MasqueTransportRequiresMasqueOutbound,
            Some("stream.network".into()),
        ));
    }
    if o.protocol == Protocol::Masque && o.mux.enabled {
        issues.push(issue(
            ValidationCode::MasqueOutboundMuxUnsupported,
            Some("mux.enabled".into()),
        ));
    }
    if let ProtocolSettings::Masque(settings) = &o.settings {
        if settings.address.is_empty() {
            issues.push(issue(
                ValidationCode::MasqueSettingsIncomplete,
                Some("settings.address".into()),
            ));
        }
        if settings.port == 0 {
            issues.push(issue(
                ValidationCode::MasqueSettingsIncomplete,
                Some("settings.port".into()),
            ));
        }
        if settings
            .remote_dns
            .iter()
            .any(|entry| masque_remote_dns_verdict(entry).is_some())
        {
            issues.push(issue(
                ValidationCode::MasqueRemoteDnsInvalid,
                Some("settings.remoteDNS".into()),
            ));
        }
    }
}

/// The verdict of one WireGuard in-network DNS entry: the core parses every
/// entry with `netip.MustParseAddr` while it builds the outbound, so a single
/// bad entry is the refusal the list rule reports — which is what the editor's
/// row renders, entry by entry.
pub fn wireguard_remote_dns_verdict(entry: &str) -> Option<ValidationCode> {
    (!wireguard_remote_dns_entry_supported(entry))
        .then_some(ValidationCode::WireguardRemoteDnsInvalid)
}

/// The verdict of one MASQUE in-tunnel DNS entry: the core parses every entry
/// with `netip.ParseAddr` while it builds the outbound and refuses the config
/// (infra/conf/masque.go:27-30), so one bad entry is the refusal the list rule
/// reports — which is what the editor's row renders, entry by entry.
pub fn masque_remote_dns_verdict(entry: &str) -> Option<ValidationCode> {
    (!masque_remote_dns_entry_supported(entry)).then_some(ValidationCode::MasqueRemoteDnsInvalid)
}

/// The verdict of the WireGuard `settings.secretKey` field: `WireGuardConfig.Build`
/// runs it through `ParseWireGuardKey` (infra/conf/wireguard.go), which refuses
/// the empty string and anything that is neither 64 hexadecimal digits nor the
/// raw base64 of the same 32 bytes. The pass reports this code and the editor's
/// field renders its message, so the two readers cannot disagree.
pub fn wireguard_secret_key_verdict(value: &str) -> Option<ValidationCode> {
    (!is_valid_wireguard_key(value)).then_some(ValidationCode::WireguardSecretKeyInvalid)
}

/// The verdict of one WireGuard peer's optional `preSharedKey`: empty is the
/// core's zero shape, and anything else must be a key it builds (the peer's
/// `Build` runs it through `ParseWireGuardKey`, infra/conf/wireguard.go). The
/// editor's field renders this code's message, and the pass reports it for the
/// peer list.
pub fn wireguard_preshared_key_verdict(value: &str) -> Option<ValidationCode> {
    (!value.is_empty() && !is_valid_wireguard_key(value))
        .then_some(ValidationCode::WireguardPresharedKeyInvalid)
}

/// The verdict of one WireGuard peer's `publicKey`: an empty key and one the
/// core cannot parse are the same refusal at config load, so one code covers
/// both (see [`ValidationCode::WireguardPeerPublicKeyRequired`]). The editor's
/// field renders this code's message, and the pass reports it for the peer list.
pub fn wireguard_peer_public_key_verdict(value: &str) -> Option<ValidationCode> {
    (!is_valid_wireguard_key(value)).then_some(ValidationCode::WireguardPeerPublicKeyRequired)
}

/// The `masque` transport's own option rules, on the stream where its
/// settings live: TLS, `path`, `host`, `headers`, credentials and the ALPN
/// pair. Called from `validate_stream`'s visit.
pub(super) fn validate_masque_stream(stream: &StreamModel, issues: &mut Vec<ValidationIssue>) {
    if stream.network != Network::Masque {
        return;
    }
    if stream.security != Security::Tls {
        issues.push(issue(
            ValidationCode::MasqueTransportRequiresTls,
            Some("stream.security".into()),
        ));
    }
    if let Some(masque) = stream.masque_settings.as_ref() {
        if !masque_path_supported(&masque.path) {
            issues.push(issue(
                ValidationCode::MasquePathInvalid,
                Some("stream.masqueSettings.path".into()),
            ));
        }
        if !masque_host_supported(&masque.host) {
            issues.push(issue(
                ValidationCode::MasqueHostInvalid,
                Some("stream.masqueSettings.host".into()),
            ));
        }
        let credentials = !masque.user.is_empty() || !masque.pass.is_empty();
        if credentials && masque.user.contains(':') {
            issues.push(issue(
                ValidationCode::MasqueUserColon,
                Some("stream.masqueSettings.user".into()),
            ));
        }
        for (name, value) in &masque.headers {
            // A non-string value has its own rule (`HeaderValuesNotStrings`);
            // this pass only judges the names and values that reach the
            // core's string-typed map. The core checks the name/value shape
            // before the reserved-name switch, so that order is kept.
            let Some(value) = value.as_str() else {
                continue;
            };
            if !masque_header_name_supported(name) || !masque_header_value_supported(value) {
                issues.push(issue(
                    ValidationCode::MasqueHeaderInvalid(excerpt(name)),
                    Some("stream.masqueSettings.headers".into()),
                ));
                continue;
            }
            let lower = name.to_ascii_lowercase();
            if matches!(lower.as_str(), "host" | "capsule-protocol") {
                issues.push(issue(
                    ValidationCode::MasqueReservedHeader(excerpt(name)),
                    Some("stream.masqueSettings.headers".into()),
                ));
            } else if lower == "authorization" && credentials {
                issues.push(issue(
                    ValidationCode::MasqueAuthorizationConflict,
                    Some("stream.masqueSettings.headers".into()),
                ));
            }
        }
    }
    // The transport dials HTTP/2 only when the TLS ALPN list carries `h2` and
    // no `h3` (transport/internet/masque/dialer.go:132-134); with both the
    // list picks HTTP/3, which the core accepts silently.
    if stream.security == Security::Tls
        && let Some(tls) = stream.tls_settings.as_ref()
        && tls.alpn.iter().any(|value| value == "h2")
        && tls.alpn.iter().any(|value| value == "h3")
    {
        issues.push(warning(
            ValidationCode::MasqueAlpnPrefersHttp3,
            Some("stream.tlsSettings.alpn".into()),
        ));
    }
}

/// The `xdrive` transport's own rules, on the stream where its settings live:
/// the service discriminator and its per-service requirements, the template's
/// four operations and its authorization, and the scalars the runtime
/// rewrites. Called from `validate_stream`'s visit.
///
/// Only the service and the Drive-secret count are refused while the core
/// loads the document; the folder, the template operations and the
/// authorization are refused while the transport is built, which the
/// config-file check never reaches. The model reports them all here because
/// the app must not hand the runtime a document it knows will fail at start.
pub(super) fn validate_xdrive_stream(stream: &StreamModel, issues: &mut Vec<ValidationIssue>) {
    if stream.network != Network::Xdrive {
        return;
    }
    // An absent block is `TransportSettingsMissing`'s finding; nothing here
    // can judge a block that is not there.
    let Some(xdrive) = stream.xdrive_settings.as_ref() else {
        return;
    };
    let retired_drive_service =
        xdrive.retired_drive_service || xdrive.service == XDRIVE_SERVICE_DRIVE_RETIRED;
    if xdrive.service.is_empty() {
        issues.push(issue(
            ValidationCode::XdriveServiceMissing,
            Some("stream.xdriveSettings.service".into()),
        ));
    } else if retired_drive_service {
        // A stored profile reaches this point already migrated; a block built
        // in memory still names the old spelling. Both warn and are emitted
        // (or saved) in the current spelling.
        issues.push(warning(
            ValidationCode::XdriveDriveServiceRenamed,
            Some("stream.xdriveSettings.service".into()),
        ));
    } else if !xdrive_service_supported(&xdrive.service) {
        issues.push(issue(
            ValidationCode::XdriveServiceUnsupported(excerpt(&xdrive.service)),
            Some("stream.xdriveSettings.service".into()),
        ));
    }
    match xdrive.service.as_str() {
        XDRIVE_SERVICE_DRIVE | XDRIVE_SERVICE_DRIVE_RETIRED => {
            if xdrive.secrets.len() != 3 || xdrive.secrets.iter().any(String::is_empty) {
                issues.push(issue(
                    ValidationCode::XdriveDriveSecretsInvalid,
                    Some("stream.xdriveSettings.secrets".into()),
                ));
            }
            if xdrive.remote_folder.is_empty() {
                issues.push(issue(
                    ValidationCode::XdriveRemoteFolderRequired,
                    Some("stream.xdriveSettings.remoteFolder".into()),
                ));
            }
        }
        XDRIVE_SERVICE_LOCAL => {
            if xdrive.remote_folder.is_empty() {
                issues.push(issue(
                    ValidationCode::XdriveRemoteFolderRequired,
                    Some("stream.xdriveSettings.remoteFolder".into()),
                ));
            }
        }
        XDRIVE_SERVICE_TEMPLATE => match xdrive.template.as_ref() {
            None => issues.push(issue(
                ValidationCode::XdriveTemplateMissing,
                Some("stream.xdriveSettings.template".into()),
            )),
            Some(template) => validate_xdrive_template(template, issues),
        },
        _ => {}
    }
    if xdrive.segment_bytes > XDRIVE_MAX_SEGMENT_BYTES {
        issues.push(warning(
            ValidationCode::XdriveScalarClamped,
            Some("stream.xdriveSettings.segmentBytes".into()),
        ));
    }
    if xdrive.concurrency > XDRIVE_MAX_CONCURRENCY {
        issues.push(warning(
            ValidationCode::XdriveScalarClamped,
            Some("stream.xdriveSettings.concurrency".into()),
        ));
    }
    // Zero keeps the core's default, so the comparison uses the effective
    // values the runtime compares (params.go:65-67).
    let effective = |value: u32, default: u32| if value == 0 { default } else { value };
    if effective(
        xdrive.max_poll_interval_ms,
        XDRIVE_DEFAULT_MAX_POLL_INTERVAL_MS,
    ) < effective(xdrive.poll_interval_ms, XDRIVE_DEFAULT_POLL_INTERVAL_MS)
    {
        issues.push(warning(
            ValidationCode::XdriveScalarClamped,
            Some("stream.xdriveSettings.maxPollIntervalMs".into()),
        ));
    }
}

/// The template backend's rules: every operation needs a URL, the list
/// operation's pattern needs a capture group, the authorization type must be
/// one the runtime knows (with a token URL for the oauth2 flow), and every
/// header or form map must hold strings. Called from
/// [`validate_xdrive_stream`]; the paths below are absolute wire paths.
fn validate_xdrive_template(template: &XdriveTemplate, issues: &mut Vec<ValidationIssue>) {
    for op in XdriveOperation::ALL {
        let name = op.as_str();
        let operation = template.operation(op);
        if operation.url.is_empty() {
            issues.push(issue(
                ValidationCode::XdriveTemplateOperationUrlRequired(name.into()),
                Some(format!("stream.xdriveSettings.template.{name}.url")),
            ));
        }
        if !operation.headers.values().all(Value::is_string) {
            issues.push(issue(
                ValidationCode::XdriveTemplateHeaderValuesNotStrings,
                Some(format!("stream.xdriveSettings.template.{name}.headers")),
            ));
        }
    }
    if !xdrive_names_regex_supported(&template.list.names_regex) {
        issues.push(issue(
            ValidationCode::XdriveTemplateNamesRegexInvalid,
            Some("stream.xdriveSettings.template.list.namesRegex".into()),
        ));
    }
    if !xdrive_template_auth_type_supported(&template.auth.r#type) {
        issues.push(issue(
            ValidationCode::XdriveTemplateAuthTypeUnsupported(excerpt(&template.auth.r#type)),
            Some("stream.xdriveSettings.template.auth.type".into()),
        ));
    }
    if template.auth.r#type == "oauth2" && template.auth.token_url.is_empty() {
        issues.push(issue(
            ValidationCode::XdriveTemplateTokenUrlRequired,
            Some("stream.xdriveSettings.template.auth.tokenUrl".into()),
        ));
    }
    for (map, suffix) in [
        (&template.auth.header, "template.auth.header"),
        (&template.auth.form, "template.auth.form"),
    ] {
        if !map.values().all(Value::is_string) {
            issues.push(issue(
                ValidationCode::XdriveTemplateHeaderValuesNotStrings,
                Some(format!("stream.xdriveSettings.{suffix}")),
            ));
        }
    }
    if template.concurrency > XDRIVE_TEMPLATE_MAX_CONCURRENCY {
        issues.push(warning(
            ValidationCode::XdriveScalarClamped,
            Some("stream.xdriveSettings.template.concurrency".into()),
        ));
    }
}

/// The core's outbound gate for the `xdrive` transport
/// (`validateXDrive`, infra/conf/xray.go:272-316, called from the outbound
/// build at :398): the account must be VLESS without `flow` or `testpre`,
/// with an `encryption` value, and — unless it is a reverse-proxy account,
/// which opens its own mux — Mux.Cool enabled with non-negative knobs and
/// `xudpProxyUDP443` other than `skip`. Each violation is its own finding so
/// the editor can name the field to fix.
pub(super) fn validate_xdrive_outbound(o: &OutboundModel, issues: &mut Vec<ValidationIssue>) {
    if o.stream.network != Network::Xdrive {
        return;
    }
    let ProtocolSettings::Vless(settings) = &o.settings else {
        issues.push(issue(
            ValidationCode::XdriveRequiresVless,
            Some("protocol".into()),
        ));
        return;
    };
    if !settings.flow.is_empty() {
        issues.push(issue(
            ValidationCode::XdriveVlessFlowUnsupported,
            Some("settings.flow".into()),
        ));
    }
    if matches!(settings.encryption.as_str(), "" | "none") {
        issues.push(issue(
            ValidationCode::XdriveVlessEncryptionRequired,
            Some("settings.encryption".into()),
        ));
    }
    // `reverse` is the core's own exemption: the reverse connection opens a
    // mux of its own, so the mux knobs are not the transport's.
    if settings.reverse.is_none() {
        if !o.mux.enabled {
            issues.push(issue(
                ValidationCode::XdriveMuxRequired,
                Some("mux.enabled".into()),
            ));
        }
        if o.mux.concurrency.is_some_and(|value| value < 0) {
            issues.push(issue(
                ValidationCode::XdriveMuxConcurrencyNegative,
                Some("mux.concurrency".into()),
            ));
        }
        if o.mux.xudp_concurrency.is_some_and(|value| value < 0) {
            issues.push(issue(
                ValidationCode::XdriveMuxConcurrencyNegative,
                Some("mux.xudpConcurrency".into()),
            ));
        }
        if o.mux.xudp_proxy_udp443.as_deref() == Some("skip") {
            issues.push(issue(
                ValidationCode::XdriveMuxXudpProxyUdp443Skip,
                Some("mux.xudpProxyUDP443".into()),
            ));
        }
    }
    // `testpre` has no editor and no model field: only a hand-edited or
    // imported `settings` object can carry it. Go binds it as a `uint32`, so
    // `null` is the zero a missing key leaves and `0` is the allowed value;
    // any other shape is either non-zero or a load error the core refuses.
    let testpre_set = settings.extra.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("testpre") && !value.is_null() && value.as_u64() != Some(0)
    });
    if testpre_set {
        issues.push(issue(
            ValidationCode::XdriveVlessTestpreUnsupported,
            Some("settings.testpre".into()),
        ));
    }
}

/// Validate one outbound: protocol-level rules, transport security, and the
/// whole stream (recursively over XHTTP downloads) — one pass, no
/// short-circuit; every violation is reported.
pub fn validate_outbound(o: &OutboundModel) -> Verdict {
    let mut issues = Vec::new();

    // The retired `proxySettings` key left this mark behind: the pinned core
    // refuses to build the outbound while the stored profile carries it
    // (infra/conf/xray.go:262), so the profile gates until the user resolves
    // it — the key is kept verbatim for the settings file and is never
    // migrated. Carries no path: the key is not a field of the model, and
    // the servers-level pass scopes the finding with the profile's location.
    if o.retired_proxy_settings.is_some() {
        issues.push(issue(ValidationCode::OutboundProxySettingsRemoved, None));
    }
    if let ProtocolSettings::Shadowsocks(settings) = &o.settings
        && settings.level.is_some_and(|level| level > u8::MAX.into())
    {
        issues.push(issue(
            ValidationCode::ShadowsocksLevelRange,
            Some("settings.level".into()),
        ));
    }
    if let ProtocolSettings::Blackhole(settings) = &o.settings
        && let Some(response) = settings.response.as_ref()
    {
        if !blackhole_response_type_supported(&response.r#type) {
            issues.push(issue(
                ValidationCode::BlackholeResponseInvalid,
                Some("settings.response.type".into()),
            ));
        }
        if blackhole_response_is_custom(&response.r#type)
            && !go_std_base64_decodes(&response.custom_response_data)
        {
            issues.push(issue(
                ValidationCode::BlackholeCustomResponseDataInvalid,
                Some("settings.response.customResponseData".into()),
            ));
        }
    }
    if let ProtocolSettings::Hysteria(settings) = &o.settings
        && settings.version != 2
    {
        issues.push(issue(
            ValidationCode::HysteriaTransportVersion,
            Some("settings.version".into()),
        ));
    }
    // WireGuard settings the core cannot build — the in-network resolver
    // list and the key/peer material. The resolver list: the pinned core
    // parses each entry with `netip.MustParseAddr` while it creates the
    // outbound client, so a non-address entry panics the whole process
    // during config load (proxy/wireguard/client.go:102-108; verified against
    // the pinned binary, which exits with that panic under `run -test`). The
    // material: `WireGuardConfig.Build` refuses a non-buildable `secretKey`
    // (infra/conf/wireguard.go:76) and a `reserved` that is set but not three
    // bytes (infra/conf/wireguard.go:123), and each peer's non-empty
    // `publicKey`/`preSharedKey` is parsed in the peer's own `Build`
    // (infra/conf/wireguard.go:33,40); `NewClient` refuses an empty peer
    // list, a peer without a public key and a peer without an endpoint while
    // it constructs the handler (proxy/wireguard/client.go:86-93) — all at
    // config load, all reached by `run -test`. Error tier: the profile gates
    // until the field is fixed.
    //
    // The retired `domainStrategy` key is different: the core ignores it
    // (the field and its switch are gone), the value never reaches the
    // generated document, and the profile applies normally — advisory tier.
    //
    // The predicates are the editor's old draft requirements, moved here so
    // one verdict covers the editor, generation, and the importer.
    if let ProtocolSettings::Wireguard(settings) = &o.settings {
        if settings
            .remote_dns
            .iter()
            .any(|entry| wireguard_remote_dns_verdict(entry).is_some())
        {
            issues.push(issue(
                ValidationCode::WireguardRemoteDnsInvalid,
                Some("settings.remoteDNS".into()),
            ));
        }
        if !settings.domain_strategy.is_empty() {
            issues.push(warning(
                ValidationCode::WireguardDomainStrategyRetired,
                Some("settings.domainStrategy".into()),
            ));
        }
        if wireguard_secret_key_verdict(&settings.secret_key).is_some() {
            issues.push(issue(
                ValidationCode::WireguardSecretKeyInvalid,
                Some("settings.secretKey".into()),
            ));
        }
        if settings
            .reserved
            .as_ref()
            .is_some_and(|reserved| !reserved.is_empty() && reserved.len() != 3)
        {
            issues.push(issue(
                ValidationCode::WireguardReservedKeyBytes,
                Some("settings.reserved".into()),
            ));
        }
        if settings.peers.is_empty() {
            issues.push(issue(
                ValidationCode::WireguardPeersRequired,
                Some("settings.peers".into()),
            ));
        }
        if settings
            .peers
            .iter()
            .any(|peer| wireguard_peer_public_key_verdict(&peer.public_key).is_some())
        {
            issues.push(issue(
                ValidationCode::WireguardPeerPublicKeyRequired,
                Some("settings.peers[].publicKey".into()),
            ));
        }
        if settings
            .peers
            .iter()
            .any(|peer| peer.endpoint.trim().is_empty())
        {
            issues.push(issue(
                ValidationCode::WireguardPeerEndpointRequired,
                Some("settings.peers[].endpoint".into()),
            ));
        }
        if settings
            .peers
            .iter()
            .any(|peer| wireguard_preshared_key_verdict(&peer.pre_shared_key).is_some())
        {
            issues.push(issue(
                ValidationCode::WireguardPresharedKeyInvalid,
                Some("settings.peers[].preSharedKey".into()),
            ));
        }
    }

    // Protocol-`settings` vocabulary / required values: the out-of-vocab
    // VLESS flow/encryption, unsupported SS method, missing Trojan/SS
    // essentials, and VLESS/VMess port-0 / non-UUID id rows the editor combos
    // and the share-link grammar already refuse. These gate save/apply exactly
    // like an import refusal, whatever the source of the profile (state file,
    // deserialization, draft). The SS-2022 key rule joins them for every key
    // the core refuses at load; only a key longer than the method's size, which
    // the core hashes down and runs, warns.
    // Paths are the wire paths of the offending fields.
    match &o.settings {
        ProtocolSettings::Vless(settings) => {
            if !vless_flow_supported(&settings.flow) {
                issues.push(issue(
                    ValidationCode::VlessFlowUnsupported,
                    Some("settings.flow".into()),
                ));
            }
            if !vless_encryption_supported(&settings.encryption) {
                issues.push(issue(
                    ValidationCode::VlessEncryptionUnsupported,
                    Some("settings.encryption".into()),
                ));
            }
            if settings.port == 0 {
                issues.push(issue(
                    ValidationCode::SettingsPortZero,
                    Some("settings.port".into()),
                ));
            }
            if !settings.id.is_empty() && !is_canonical_uuid(&settings.id) {
                issues.push(issue(
                    ValidationCode::SettingsIdNotUuid,
                    Some("settings.id".into()),
                ));
            }
        }
        ProtocolSettings::Vmess(settings) => {
            if settings.port == 0 {
                issues.push(issue(
                    ValidationCode::SettingsPortZero,
                    Some("settings.port".into()),
                ));
            }
            if !settings.id.is_empty() && !is_canonical_uuid(&settings.id) {
                issues.push(issue(
                    ValidationCode::SettingsIdNotUuid,
                    Some("settings.id".into()),
                ));
            }
            // The core does not refuse the value: it lowercases the spelling
            // and takes `auto` for anything else, which the generated document
            // carries too. Advisory, never a gate.
            if !vmess_security_supported(&settings.security) {
                issues.push(warning(
                    ValidationCode::VmessSecurityUnsupported,
                    Some("settings.security".into()),
                ));
            }
        }
        ProtocolSettings::Trojan(settings) => {
            if settings.address.is_empty() {
                issues.push(issue(
                    ValidationCode::TrojanSettingsIncomplete,
                    Some("settings.address".into()),
                ));
            }
            if settings.password.is_empty() {
                issues.push(issue(
                    ValidationCode::TrojanSettingsIncomplete,
                    Some("settings.password".into()),
                ));
            }
            if settings.port == 0 {
                issues.push(issue(
                    ValidationCode::TrojanSettingsIncomplete,
                    Some("settings.port".into()),
                ));
            }
        }
        ProtocolSettings::Shadowsocks(settings) => {
            if settings.address.is_empty() {
                issues.push(issue(
                    ValidationCode::ShadowsocksSettingsIncomplete,
                    Some("settings.address".into()),
                ));
            }
            if settings.password.is_empty() {
                issues.push(issue(
                    ValidationCode::ShadowsocksSettingsIncomplete,
                    Some("settings.password".into()),
                ));
            }
            if settings.port == 0 {
                issues.push(issue(
                    ValidationCode::ShadowsocksSettingsIncomplete,
                    Some("settings.port".into()),
                ));
            }
            if !shadowsocks_method_supported(&settings.method) {
                issues.push(issue(
                    ValidationCode::ShadowsocksMethodUnsupported,
                    Some("settings.method".into()),
                ));
            }
            if !shadowsocks_2022_key_usable(&settings.method, &settings.password) {
                issues.push(issue(
                    ValidationCode::Shadowsocks2022KeyInvalid,
                    Some("settings.password".into()),
                ));
            }
        }
        _ => {}
    }

    // Extra-passthrough scans — per-settings extras: serde binds only the
    // exact-case modeled fields, so a removed/inert key lands in the
    // flattened `extra` map and is still flattened verbatim into the
    // generated `settings` object. Removed-feature keys are Error (Xray
    // refuses the outbound at load); accepted-then-ignored keys are Warning
    // (Severity::Warning).
    // Value tests mirror Go's unmarshal: JSON `null` is the zero value that
    // leaves the field nil/empty and stays silent.
    match &o.settings {
        ProtocolSettings::Trojan(settings) => {
            // Trojan `flow` — conf/trojan.go refuses a non-empty flow
            // (PrintRemovedFeatureError); the empty string is the zero
            // value and stays silent. Xray's own deprecation note moves
            // Trojan users to VLESS with a vision flow.
            if settings.extra.iter().any(|(key, value)| {
                key.eq_ignore_ascii_case("flow")
                    && !value.is_null()
                    && !matches!(value, Value::String(flow) if flow.is_empty())
            }) {
                issues.push(issue(
                    ValidationCode::TrojanFlowRemoved,
                    Some("settings.flow".into()),
                ));
            }
        }
        ProtocolSettings::Vmess(settings) => {
            // VMess `alterId`/`aid` — the legacy alterId field is gone
            // from conf/vmess.go (VMess is AEAD-only), so Xray silently
            // ignores any carried value.
            for wire_key in ["alterId", "aid"] {
                if extra_has_key(&settings.extra, wire_key) {
                    issues.push(warning(
                        ValidationCode::VmessAlterIdIgnored,
                        Some(format!("settings.{wire_key}")),
                    ));
                }
            }
        }
        ProtocolSettings::Vless(settings) => {
            // VLESS `seed` — parsed-but-inert upstream: the conf struct
            // keeps the field but Build never assigns it (the assignment is
            // commented out, conf/vless.go), so Xray silently drops the
            // carried value.
            if extra_has_key(&settings.extra, "seed") {
                issues.push(warning(
                    ValidationCode::VlessSeedIgnored,
                    Some("settings.seed".into()),
                ));
            }
        }
        ProtocolSettings::Freedom(settings) => {
            // Freedom singular `noise` — conf/freedom.go refuses a
            // non-nil NoiseConfig with PrintRemovedFeatureError naming the
            // `noises` array as the migration. The modeled `noises` field
            // is never affected.
            if extra_key_set(&settings.extra, "noise") {
                issues.push(issue(
                    ValidationCode::FreedomNoiseRemoved,
                    Some("settings.noise".into()),
                ));
            }
            // Freedom `domainStrategy` is unmodeled (only
            // `targetStrategy` is), so any carried value lives in `extra` —
            // yet Xray reads it whenever targetStrategy is empty. Only
            // out-of-vocabulary values fail: conf/freedom.go lowercases and
            // switches over the ten strategies, refusing everything else at
            // load; non-string values fail Go's `string` unmarshal the same
            // way. In-vocabulary values work on the wire and stay silent.
            if settings.extra.iter().any(|(key, value)| {
                key.eq_ignore_ascii_case("domainStrategy")
                    && !value.is_null()
                    && !matches!(
                        value,
                        Value::String(strategy)
                            if strategy.is_empty() || freedom_domain_strategy_supported(strategy)
                    )
            }) {
                issues.push(issue(
                    ValidationCode::FreedomDomainStrategyUnsupported,
                    Some("settings.domainStrategy".into()),
                ));
            }
            // Freedom is built from the whole document, and
            // `infra/conf/xray.go` refuses the outbound whenever the effective
            // `sockopt.addressPortStrategy` is not `AddressPortStrategy_None`:
            // freedom's dialer reads no such field. The empty spelling and
            // `none` are that variant, so only the six SRV/TXT strategies
            // gate; an out-of-vocabulary value is the sockopt rule's own
            // finding.
            if let Some(sockopt) = o.stream.sockopt.as_ref()
                && sockopt_address_port_strategy_supported(&sockopt.address_port_strategy)
                && !sockopt.address_port_strategy.is_empty()
                && !fold_eq(&sockopt.address_port_strategy, "none")
            {
                issues.push(issue(
                    ValidationCode::FreedomAddressPortStrategyUnsupported,
                    Some("stream.sockopt.addressPortStrategy".into()),
                ));
            }
            // A `sockopt.dialerProxy` makes freedom a non-final outbound, and
            // its handler then drops the whole final-rule set and logs that
            // the setting is ignored (proxy/freedom/freedom.go:193-197). The
            // document still loads and runs, just without the rules, so this
            // warns; the dialerProxy value itself stays legal.
            if !settings.final_rules.is_empty()
                && o.stream
                    .sockopt
                    .as_ref()
                    .is_some_and(|sockopt| !sockopt.dialer_proxy.is_empty())
            {
                issues.push(warning(
                    ValidationCode::FreedomFinalRulesIgnored,
                    Some("settings.finalRules".into()),
                ));
            }
        }
        _ => {}
    }

    // Transport security: Xray rejects Vision flow without TLS/REALITY, and
    // rejects plaintext VLESS/Trojan connections to public endpoints. Vision
    // wins over the plaintext-public rule when both apply (matches the old
    // single-error precedence).
    if o.stream.security == Security::None {
        match &o.settings {
            ProtocolSettings::Vless(settings) if is_vision_flow(&settings.flow) => {
                issues.push(issue(
                    ValidationCode::VisionRequiresTlsOrReality,
                    Some("settings.flow".into()),
                ));
            }
            ProtocolSettings::Vless(settings)
                if matches!(settings.encryption.as_str(), "" | "none")
                    && endpoint_requires_transport_security(&settings.address) =>
            {
                issues.push(issue(
                    ValidationCode::PublicVlessRequiresTlsOrEncryption,
                    None,
                ));
            }
            ProtocolSettings::Trojan(settings)
                if endpoint_requires_transport_security(&settings.address) =>
            {
                issues.push(issue(
                    ValidationCode::PublicTrojanRequiresTlsOrReality,
                    None,
                ));
            }
            _ => {}
        }
    }

    // Advisory: vision flow over enabled TCP mux. The
    // profile is xray-legal but deterministically broken — the server tears
    // the whole mux connection down on the first TCP frame — so this warns
    // (Severity::Warning) and never gates; the message names the fix.
    if let ProtocolSettings::Vless(settings) = &o.settings
        && mux_conflicts_with_vision_flow(&settings.flow, o.mux.enabled, o.mux.concurrency)
    {
        issues.push(warning(
            ValidationCode::MuxWithVisionFlow,
            Some("mux".into()),
        ));
    }

    // Mux-block semantics: the
    // local-only mux block has no share-link seam, so the model pass is its
    // single validation surface besides the editor combo/slider keystroke
    // constraints (which cannot see deserialized values). These rules are
    // purely additive on the same block — nothing below suppresses or dedups
    // the MuxWithVisionFlow warning above when both apply.
    if o.mux
        .xudp_proxy_udp443
        .as_deref()
        .is_some_and(|value| !xudp_proxy_udp443_supported(value))
    {
        issues.push(issue(
            ValidationCode::MuxXudpProxyUdp443Unsupported,
            Some("mux.xudpProxyUDP443".into()),
        ));
    }
    if mux_concurrency_reinterpreted(o.mux.enabled, o.mux.concurrency) {
        issues.push(warning(
            ValidationCode::MuxConcurrencyReinterpreted,
            Some("mux.concurrency".into()),
        ));
    }
    if mux_xudp_knobs_inert(&o.mux) {
        issues.push(warning(
            ValidationCode::MuxXudpKnobsInert,
            Some("mux.enabled".into()),
        ));
    }

    // Outbound `targetStrategy` vocabulary:
    // Xray lowercases the value and refuses every non-empty strategy
    // outside its set at conf load (infra/conf/xray.go
    // OutboundDetectorConfig.Build), so this is Error-tier and gates
    // save/apply/import like any other model refusal. Empty stays legal —
    // the wire default is `asis`.
    if o.target_strategy
        .as_deref()
        .is_some_and(|strategy| !strategy.is_empty() && !target_strategy_supported(strategy))
    {
        issues.push(issue(
            ValidationCode::OutboundTargetStrategyInvalid,
            Some("targetStrategy".into()),
        ));
    }

    // Inbound-style sniffing that rides outbound settings: Xray
    // builds a loopback outbound's sniffing block through the very same
    // SniffingConfig.Build (infra/conf/loopback.go) and refuses unknown
    // destOverride protocols at load, so the same code + predicate gate
    // here with the settings-level wire path.
    if let ProtocolSettings::Loopback(settings) = &o.settings
        && let Some(sniffing) = settings.sniffing.as_ref()
    {
        issues.extend(validate_sniffing(sniffing, "settings.sniffing"));
    }

    // Freedom's fragment and noises blocks are load-fatal — `Fragment.Build`
    // and `ParseNoise` (infra/conf/freedom.go) refuse a value they cannot read,
    // a fragment `length` or `interval` that is absent, and a fragment
    // `length` whose ordered start is 0 — so every profile that carries one
    // gates here, keyed by the offending block's wire path. The editor used to
    // carry these rules alone, which left raw-JSON and imported profiles
    // ungated.
    if let ProtocolSettings::Freedom(settings) = &o.settings {
        if settings
            .fragment
            .as_ref()
            .is_some_and(freedom_fragment_unrunnable)
        {
            issues.push(issue(
                ValidationCode::FreedomFragmentInvalid,
                Some("settings.fragment".into()),
            ));
        }
        for (index, noise) in settings.noises.iter().enumerate() {
            if freedom_noise_unrunnable(noise) {
                issues.push(issue(
                    ValidationCode::FreedomNoiseInvalid,
                    Some(format!("settings.noises[{index}]")),
                ));
            }
        }
    }

    // Editor rules that decide configuration validity — moved into the
    // per-model pass so the editor, generation and the importer all consume
    // one verdict. Each rule keeps the editor's old error shape: one finding
    // per rule, whole-model (the message names no field), so the rendered
    // text is byte-identical wherever the editor lists it.
    if o.send_through
        .as_deref()
        .is_some_and(|value| !send_through_supported(value))
    {
        issues.push(issue(ValidationCode::SendThroughInvalid, None));
    }
    if let ProtocolSettings::Freedom(settings) = &o.settings
        && settings
            .final_rules
            .iter()
            .any(|rule| !freedom_final_rule_supported(&rule.action))
    {
        issues.push(issue(ValidationCode::FreedomFinalRuleInvalid, None));
    }
    if let ProtocolSettings::Dns(settings) = &o.settings
        && settings
            .rules
            .iter()
            .any(|rule| !dns_out_action_supported(&rule.action))
    {
        issues.push(issue(ValidationCode::DnsRuleActionInvalid, None));
    }

    // Advisory: a `udphop` interval mode moves the outbound's socket, and
    // only a transport that can move a live connection runs it: hysteria2
    // (quic-go in `transport/internet/hysteria/dialer.go`), the splithttp
    // HTTP/3 mode — TLS ALPN exactly `["h3"]`, which is the branch that
    // applies the mask manager (`transport/internet/splithttp/dialer.go:216`)
    // — and the WireGuard outbound, which applies the mask to its own packet
    // conn and follows endpoint changes (`proxy/wireguard/client.go:309-310`).
    // Every other transport either never wraps the mask list or cannot carry
    // the connection across a hop, so the hop cannot run. The core starts
    // either way, so this is a configuration warning, never a gate.
    if finalmask_udp_hop_interval_mode(&o.stream) && !hop_transport_migrates_connections(o) {
        issues.push(warning(
            ValidationCode::FinalmaskUdpHopIntervalTransportConflict,
            None,
        ));
    }

    validate_masque(o, &mut issues);
    validate_xdrive_outbound(o, &mut issues);
    issues.extend(validate_stream(&o.stream));
    Verdict::from_issues(issues)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::stream::{
        FinalmaskModel, HttpupgradeSettings, HysteriaTransport, MasqueTransport, SockoptModel,
        WsSettings, XdriveTemplateOp, XdriveTransport, XhttpSettings,
    };
    use crate::model::validation::Severity;
    use crate::model::validation::tests::{codes, finding};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::json;
    /// The VMess security rule is advisory, because the core does not refuse
    /// the value: `VMessAccount.Build` lowercases the spelling and maps
    /// anything outside its three ciphers onto `auto` (infra/conf/vmess.go:27-36),
    /// which `xray run -test` confirms on the pinned binary — `AES-128-GCM`
    /// and `bogus` both exit 0, and the generated document carries `auto` for
    /// either.
    #[test]
    fn vmess_security_outside_the_vocabulary_warns_without_gating() {
        fn verdict(security: &str) -> Verdict {
            let mut outbound = OutboundModel::new(Protocol::Vmess);
            let ProtocolSettings::Vmess(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.address = "vmess.example.com".into();
            settings.port = 443;
            settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
            settings.security = security.into();
            validate_outbound(&outbound)
        }

        for accepted in ["", "auto", "AUTO", "AES-128-GCM", "chacha20-poly1305"] {
            let verdict = verdict(accepted);
            assert!(
                verdict.iter().next().is_none(),
                "{accepted:?} is a value the core reads: {verdict:?}"
            );
        }
        for rewritten in ["bogus", "auto ", "aes128-gcm"] {
            let verdict = verdict(rewritten);
            assert!(!verdict.has_blocking(), "{rewritten:?} must not gate");
            let issue = verdict
                .advisory()
                .next()
                .unwrap_or_else(|| panic!("{rewritten:?} must warn: {verdict:?}"));
            assert_eq!(issue.code, ValidationCode::VmessSecurityUnsupported);
            assert_eq!(issue.severity, Severity::Warning);
            assert_eq!(issue.path.as_deref(), Some("settings.security"));
        }
    }

    #[test]
    fn single_pass_reports_protocol_stream_and_transport_security_issues() {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "example.com".into();
        settings.flow = "xtls-rprx-vision".into();
        settings.encryption = "none".into();
        // Ws without settings + Reality on Ws + sockopt violation: stream,
        // transport-security, and sockopt classes surface in one call.
        // VisionRequiresTlsOrReality deliberately does NOT fire here: REALITY
        // satisfies the Vision security requirement (the gate is
        // security == None), so this fixture only exercises the reality/ws
        // conflict, missing-settings, and sockopt rules.
        outbound.stream.network = crate::model::stream::Network::Ws;
        outbound.stream.security = Security::Reality;
        outbound.stream.reality_settings = Some(Default::default());
        outbound.stream.sockopt = Some(SockoptModel {
            domain_strategy: "future-strategy".into(),
            ..Default::default()
        });

        let issues = validate_outbound(&outbound);
        let found = codes(&issues);
        for code in [
            ValidationCode::RealityRequiresTransport,
            ValidationCode::TransportSettingsMissing(crate::model::stream::Network::Ws),
            ValidationCode::SockoptDomainStrategyInvalid,
        ] {
            assert!(found.contains(&code), "missing {code:?} in {found:#?}");
        }
    }

    /// Xray types `wsSettings.headers`, `httpupgradeSettings.headers` and the
    /// XHTTP settings' `headers` as `map[string]string`. A non-string value
    /// cannot be built into the document (and cannot be migrated out of the
    /// legacy `Host` form), and only a hand-edited state file can carry one —
    /// the share-link grammar refuses it on import — so the model must gate it
    /// with a field-scoped finding instead of spending a core start on the
    /// failure.
    #[test]
    fn non_string_transport_header_values_gate_the_profile() {
        for (network, path) in [
            (Network::Xhttp, "stream.xhttpSettings.headers"),
            (Network::Ws, "stream.wsSettings.headers"),
            (Network::Httpupgrade, "stream.httpupgradeSettings.headers"),
        ] {
            let headers = |value: Value| {
                let mut headers = serde_json::Map::new();
                headers.insert("Host".to_string(), value);
                headers
            };

            let mut outbound = vless_canonical();
            outbound.stream.network = network;
            match network {
                Network::Xhttp => {
                    outbound.stream.xhttp_settings = Some(XhttpSettings {
                        headers: headers(json!(123)),
                        ..Default::default()
                    })
                }
                Network::Ws => {
                    outbound.stream.ws_settings = Some(WsSettings {
                        headers: headers(json!(123)),
                        ..Default::default()
                    })
                }
                Network::Httpupgrade => {
                    outbound.stream.httpupgrade_settings = Some(HttpupgradeSettings {
                        headers: headers(json!(123)),
                        ..Default::default()
                    })
                }
                _ => unreachable!(),
            }
            let issues = validate_outbound(&outbound);
            let finding = issues
                .iter()
                .find(|issue| issue.code == ValidationCode::HeaderValuesNotStrings(network))
                .unwrap_or_else(|| {
                    panic!("{network:?} must gate a non-string header value: {issues:#?}")
                });
            assert_eq!(finding.path.as_deref(), Some(path));
            assert_eq!(finding.severity, Severity::Error);

            // A string-valued map — including the legacy `Host` form the wire
            // pass canonicalizes — still validates.
            let mut outbound = vless_canonical();
            outbound.stream.network = network;
            let string_headers = headers(json!("example.com"));
            match network {
                Network::Xhttp => {
                    outbound.stream.xhttp_settings = Some(XhttpSettings {
                        headers: string_headers,
                        ..Default::default()
                    })
                }
                Network::Ws => {
                    outbound.stream.ws_settings = Some(WsSettings {
                        headers: string_headers,
                        ..Default::default()
                    })
                }
                Network::Httpupgrade => {
                    outbound.stream.httpupgrade_settings = Some(HttpupgradeSettings {
                        headers: string_headers,
                        ..Default::default()
                    })
                }
                _ => unreachable!(),
            }
            let issues = validate_outbound(&outbound);
            assert!(
                !issues
                    .iter()
                    .any(|issue| matches!(issue.code, ValidationCode::HeaderValuesNotStrings(_))),
                "{network:?} must accept string header values: {issues:#?}"
            );
        }
    }

    #[test]
    fn hysteria_version_rule_covers_outbound_and_transport_with_distinct_paths() {
        let mut outbound = OutboundModel::new(Protocol::Hysteria);
        let ProtocolSettings::Hysteria(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.version = 1;
        outbound.stream.network = crate::model::stream::Network::Hysteria;
        outbound.stream.hysteria_settings = Some(HysteriaTransport {
            version: 1,
            ..Default::default()
        });
        outbound.stream.security = Security::Tls;
        outbound.stream.tls_settings = Some(Default::default());

        let issues = validate_outbound(&outbound);
        let version_issues: Vec<&ValidationIssue> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::HysteriaTransportVersion)
            .collect();
        assert_eq!(version_issues.len(), 2, "{issues:#?}");
        assert_eq!(version_issues[0].path.as_deref(), Some("settings.version"));
        assert_eq!(
            version_issues[1].path.as_deref(),
            Some("stream.hysteriaSettings.version")
        );
    }

    /// A runnable MASQUE outbound: address and port set, and the masque
    /// transport with TLS that `OutboundModel::new` materializes.
    fn runnable_masque() -> OutboundModel {
        let mut outbound = OutboundModel::new(Protocol::Masque);
        let ProtocolSettings::Masque(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "masque.example.com".into();
        settings.port = 443;
        outbound
    }

    /// The pinned core refuses the masque transport on another protocol at
    /// config load and refuses a masque outbound without its transport, with
    /// mux, or without TLS at instance creation; the model gates each.
    #[test]
    fn masque_outbound_and_transport_pair_rules_gate_both_directions() {
        assert!(
            !validate_outbound(&runnable_masque()).has_blocking(),
            "a masque outbound over its own transport must pass"
        );

        // A masque outbound on another transport (the core answers `not
        // masque transport` at instance creation).
        let mut orphan = runnable_masque();
        orphan.stream.network = Network::Raw;
        let found = codes(&validate_outbound(&orphan));
        assert!(
            found.contains(&ValidationCode::MasqueOutboundRequiresMasqueTransport),
            "{found:#?}"
        );

        // The masque transport on another protocol (a config-load refusal).
        let mut foreign = runnable_masque();
        foreign.protocol = Protocol::Vless;
        foreign.settings = ProtocolSettings::default_for(Protocol::Vless);
        let found = codes(&validate_outbound(&foreign));
        assert!(
            found.contains(&ValidationCode::MasqueTransportRequiresMasqueOutbound),
            "{found:#?}"
        );

        // Mux on the masque outbound (a config-load refusal).
        let mut muxed = runnable_masque();
        muxed.mux.enabled = true;
        let found = codes(&validate_outbound(&muxed));
        assert!(found.contains(&ValidationCode::MasqueOutboundMuxUnsupported));

        // No TLS on the masque transport (an instance-creation refusal).
        let mut plain = runnable_masque();
        plain.stream.security = Security::None;
        let found = codes(&validate_outbound(&plain));
        assert!(
            found.contains(&ValidationCode::MasqueTransportRequiresTls),
            "{found:#?}"
        );

        // Missing address and port (config-load refusals).
        let mut incomplete = runnable_masque();
        let ProtocolSettings::Masque(settings) = &mut incomplete.settings else {
            unreachable!()
        };
        settings.address = String::new();
        settings.port = 0;
        let issues = validate_outbound(&incomplete);
        let paths: Vec<&str> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::MasqueSettingsIncomplete)
            .filter_map(|issue| issue.path.as_deref())
            .collect();
        assert_eq!(paths, ["settings.address", "settings.port"]);

        // A remote DNS entry that is not an address literal.
        let mut dns = runnable_masque();
        let ProtocolSettings::Masque(settings) = &mut dns.settings else {
            unreachable!()
        };
        settings.remote_dns = vec!["not-an-ip".into()];
        let found = codes(&validate_outbound(&dns));
        assert!(found.contains(&ValidationCode::MasqueRemoteDnsInvalid));

        // An empty remote DNS list stays legal: the core substitutes its own.
        let ProtocolSettings::Masque(settings) = &mut dns.settings else {
            unreachable!()
        };
        settings.remote_dns.clear();
        let found = codes(&validate_outbound(&dns));
        assert!(!found.contains(&ValidationCode::MasqueRemoteDnsInvalid));
    }

    /// The masque transport's own option rules: path placeholders, host
    /// shape, header names and values, the reserved names, the credential
    /// clash, and the HTTP/2-versus-HTTP/3 ALPN pair.
    #[test]
    fn masque_transport_option_rules_gate_path_host_headers_and_credentials() {
        let with_transport = |mutate: &dyn Fn(&mut MasqueTransport)| -> Verdict {
            let mut outbound = runnable_masque();
            let masque = outbound
                .stream
                .masque_settings
                .as_mut()
                .expect("a masque outbound materializes its transport");
            mutate(masque);
            validate_outbound(&outbound)
        };

        // Empty path (the core's own default) and the two documented
        // placeholders are accepted.
        for accepted in [
            "",
            "/.well-known/masque/ip/*/*/",
            "/.well-known/masque/ip/{target}/{ipproto}/",
        ] {
            let verdict = with_transport(&|masque| masque.path = accepted.into());
            assert!(
                !codes(&verdict).contains(&ValidationCode::MasquePathInvalid),
                "{accepted:?} must be accepted"
            );
        }
        // A missing leading slash, an undocumented placeholder, or a combined
        // query form is refused.
        for refused in ["x/y", "/x/{foo}/", "/x/{?target,ipproto}"] {
            let verdict = with_transport(&|masque| masque.path = refused.into());
            assert!(
                codes(&verdict).contains(&ValidationCode::MasquePathInvalid),
                "{refused:?} must be refused"
            );
        }

        // A bare host with an optional port is accepted.
        for accepted in ["", "example.com", "example.com:8443", "[::1]:443"] {
            let verdict = with_transport(&|masque| masque.host = accepted.into());
            assert!(
                !codes(&verdict).contains(&ValidationCode::MasqueHostInvalid),
                "{accepted:?} must be accepted"
            );
        }
        // A scheme, userinfo, path or space is refused.
        for refused in [
            "http://evil/x",
            "user@example.com",
            "example.com/path",
            "exa mple",
        ] {
            let verdict = with_transport(&|masque| masque.host = refused.into());
            assert!(
                codes(&verdict).contains(&ValidationCode::MasqueHostInvalid),
                "{refused:?} must be refused"
            );
        }

        // The two reserved names, whatever their case.
        for reserved in ["Host", "host", "Capsule-Protocol"] {
            let verdict = with_transport(&|masque| {
                masque.headers.insert(reserved.into(), json!("x"));
            });
            let found = codes(&verdict);
            assert!(
                found.contains(&ValidationCode::MasqueReservedHeader(reserved.into())),
                "{reserved:?}: {found:#?}"
            );
        }

        // An invalid field name and an invalid field value, each carried by
        // the offending name.
        let verdict = with_transport(&|masque| {
            masque.headers.insert("Bad Name".into(), json!("x"));
        });
        assert!(codes(&verdict).contains(&ValidationCode::MasqueHeaderInvalid("Bad Name".into())));
        let verdict = with_transport(&|masque| {
            masque.headers.insert("X-Test".into(), json!("bad\nvalue"));
        });
        assert!(codes(&verdict).contains(&ValidationCode::MasqueHeaderInvalid("X-Test".into())));

        // An explicit authorization header beside credentials.
        let verdict = with_transport(&|masque| {
            masque.user = "user".into();
            masque.pass = "pass".into();
            masque
                .headers
                .insert("Authorization".into(), json!("Basic x"));
        });
        assert!(codes(&verdict).contains(&ValidationCode::MasqueAuthorizationConflict));

        // A colon in the user cannot be represented by the folded header.
        let verdict = with_transport(&|masque| {
            masque.user = "a:b".into();
            masque.pass = "pass".into();
        });
        assert!(codes(&verdict).contains(&ValidationCode::MasqueUserColon));

        // Both protocol identifiers make the transport pick HTTP/3 without
        // the user asking for it; the core runs the config, so this warns.
        let mut outbound = runnable_masque();
        outbound
            .stream
            .tls_settings
            .as_mut()
            .expect("a masque outbound carries TLS")
            .alpn = vec!["h2".into(), "h3".into()];
        let verdict = validate_outbound(&outbound);
        assert!(!verdict.has_blocking(), "the ALPN pair must not gate");
        assert!(
            verdict
                .advisory()
                .any(|issue| issue.code == ValidationCode::MasqueAlpnPrefersHttp3),
            "{verdict:#?}"
        );

        // A single HTTP/2 identifier is the explicit choice and stays silent.
        let mut outbound = runnable_masque();
        outbound.stream.tls_settings.as_mut().unwrap().alpn = vec!["h2".into()];
        assert!(validate_outbound(&outbound).advisory().next().is_none());
    }

    /// The `masqueSettings` block is required like every other block-carrying
    /// transport, and a non-string header value is the shared
    /// `HeaderValuesNotStrings` finding.
    #[test]
    fn masque_transport_settings_missing_and_non_string_headers_are_reported() {
        let mut outbound = runnable_masque();
        outbound.stream.masque_settings = None;
        let found = codes(&validate_outbound(&outbound));
        assert!(
            found.contains(&ValidationCode::TransportSettingsMissing(Network::Masque)),
            "{found:#?}"
        );

        let mut outbound = runnable_masque();
        outbound
            .stream
            .masque_settings
            .as_mut()
            .unwrap()
            .headers
            .insert("X-Num".into(), json!(1));
        let found = codes(&validate_outbound(&outbound));
        assert!(
            found.contains(&ValidationCode::HeaderValuesNotStrings(Network::Masque)),
            "{found:#?}"
        );
    }

    /// An xdrive outbound on the given settings, in the one protocol and
    /// account shape the core's gate accepts, so the transport findings
    /// stand alone.
    fn xdrive_outbound(settings: XdriveTransport) -> OutboundModel {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(account) = &mut outbound.settings else {
            unreachable!("a VLESS outbound carries VLESS settings");
        };
        account.address = "xdrive.example.com".into();
        account.port = 443;
        account.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
        account.encryption =
            "mlkem768x25519plus.native.1rtt.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA".into();
        outbound.mux.enabled = true;
        outbound.stream.network = Network::Xdrive;
        outbound.stream.xdrive_settings = Some(Box::new(settings));
        outbound
    }

    /// A complete local-backend block so each gate rule is the only finding
    /// under test.
    fn local_xdrive_settings() -> XdriveTransport {
        XdriveTransport {
            service: super::XDRIVE_SERVICE_LOCAL.into(),
            remote_folder: "C:/store".into(),
            ..Default::default()
        }
    }

    /// A complete template the runtime builds without complaint.
    fn runnable_template() -> XdriveTemplate {
        let operation = |name: &str| XdriveTemplateOp {
            url: format!("https://api.example.com/{name}"),
            ..Default::default()
        };
        XdriveTemplate {
            put: operation("put"),
            get: operation("get"),
            delete: operation("delete"),
            list: XdriveTemplateOp {
                url: "https://api.example.com/list".into(),
                names_regex: "\"name\":\"([^\"]+)\"".into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// The service discriminator and each backend's own requirement: an
    /// unchosen or unsupported service is refused by name, Drive needs
    /// exactly three non-empty secrets and a folder, local needs a folder,
    /// and template needs its object.
    #[test]
    fn xdrive_service_rules_gate_each_backend() {
        // No choice made.
        let found = codes(&validate_outbound(&xdrive_outbound(XdriveTransport {
            remote_folder: "folder".into(),
            ..Default::default()
        })));
        assert!(
            found.contains(&ValidationCode::XdriveServiceMissing),
            "{found:#?}"
        );

        // A service the core's conf build refuses, named.
        let found = codes(&validate_outbound(&xdrive_outbound(XdriveTransport {
            service: "S3".into(),
            remote_folder: "folder".into(),
            ..Default::default()
        })));
        assert!(
            found.contains(&ValidationCode::XdriveServiceUnsupported("S3".into())),
            "{found:#?}"
        );

        // local: a named path is enough.
        let local = xdrive_outbound(XdriveTransport {
            service: super::XDRIVE_SERVICE_LOCAL.into(),
            remote_folder: "C:/store".into(),
            ..Default::default()
        });
        assert!(!validate_outbound(&local).has_blocking());

        // local: an empty folder is a start-time refusal the model reports.
        let empty_local = xdrive_outbound(XdriveTransport {
            service: super::XDRIVE_SERVICE_LOCAL.into(),
            ..Default::default()
        });
        let found = codes(&validate_outbound(&empty_local));
        assert!(
            found.contains(&ValidationCode::XdriveRemoteFolderRequired),
            "{found:#?}"
        );

        // Google Drive: three non-empty secrets in order plus a folder id.
        let drive = xdrive_outbound(XdriveTransport {
            service: super::XDRIVE_SERVICE_DRIVE.into(),
            remote_folder: "folder-id".into(),
            secrets: vec!["id".into(), "secret".into(), "refresh".into()],
            ..Default::default()
        });
        assert!(!validate_outbound(&drive).has_blocking());

        for secrets in [
            vec!["id".into(), "secret".into()],
            vec!["id".into(), "secret".into(), String::new()],
        ] {
            let broken_drive = xdrive_outbound(XdriveTransport {
                service: super::XDRIVE_SERVICE_DRIVE.into(),
                remote_folder: "folder-id".into(),
                secrets,
                ..Default::default()
            });
            let found = codes(&validate_outbound(&broken_drive));
            assert!(
                found.contains(&ValidationCode::XdriveDriveSecretsInvalid),
                "{found:#?}"
            );
        }

        // template: the object is required, and a complete one passes.
        let missing = xdrive_outbound(XdriveTransport {
            service: super::XDRIVE_SERVICE_TEMPLATE.into(),
            remote_folder: "token".into(),
            ..Default::default()
        });
        let found = codes(&validate_outbound(&missing));
        assert!(
            found.contains(&ValidationCode::XdriveTemplateMissing),
            "{found:#?}"
        );

        let complete = xdrive_outbound(XdriveTransport {
            service: super::XDRIVE_SERVICE_TEMPLATE.into(),
            remote_folder: "token".into(),
            template: Some(runnable_template()),
            ..Default::default()
        });
        assert!(!validate_outbound(&complete).has_blocking());
    }

    /// The template's own rules: every operation needs a URL, the list
    /// operation's pattern needs a capture group, the authorization type must
    /// be one the runtime knows (with a token URL for oauth2), and header and
    /// form maps hold strings only.
    #[test]
    fn xdrive_template_rules_gate_operations_auth_and_patterns() {
        let with_template = |mutate: &dyn Fn(&mut XdriveTemplate)| -> Verdict {
            let mut template = runnable_template();
            mutate(&mut template);
            validate_outbound(&xdrive_outbound(XdriveTransport {
                service: super::XDRIVE_SERVICE_TEMPLATE.into(),
                remote_folder: "token".into(),
                template: Some(template),
                ..Default::default()
            }))
        };

        let verdict = with_template(&|template| template.put.url.clear());
        let issue = verdict
            .blocking()
            .find(|issue| {
                issue.code == ValidationCode::XdriveTemplateOperationUrlRequired("put".into())
            })
            .expect("the missing put URL is refused");
        assert_eq!(
            issue.path.as_deref(),
            Some("stream.xdriveSettings.template.put.url")
        );

        let verdict = with_template(&|template| template.list.names_regex = ".*".into());
        let issue = verdict
            .blocking()
            .find(|issue| issue.code == ValidationCode::XdriveTemplateNamesRegexInvalid)
            .expect("a pattern with no capture group is refused");
        assert_eq!(
            issue.path.as_deref(),
            Some("stream.xdriveSettings.template.list.namesRegex")
        );

        let verdict = with_template(&|template| template.auth.r#type = "bearer".into());
        assert!(
            codes(&verdict).contains(&ValidationCode::XdriveTemplateAuthTypeUnsupported(
                "bearer".into()
            )),
            "{verdict:#?}"
        );

        let verdict = with_template(&|template| template.auth.r#type = "oauth2".into());
        let issue = verdict
            .blocking()
            .find(|issue| issue.code == ValidationCode::XdriveTemplateTokenUrlRequired)
            .expect("an oauth2 flow without a token URL is refused");
        assert_eq!(
            issue.path.as_deref(),
            Some("stream.xdriveSettings.template.auth.tokenUrl")
        );

        let verdict = with_template(&|template| {
            template.get.headers.insert("X-Num".into(), json!(1));
        });
        let issue = verdict
            .blocking()
            .find(|issue| issue.code == ValidationCode::XdriveTemplateHeaderValuesNotStrings)
            .expect("a non-string header value is refused");
        assert_eq!(
            issue.path.as_deref(),
            Some("stream.xdriveSettings.template.get.headers")
        );
    }

    /// The scalars the runtime rewrites are advisory: the value is legal and
    /// the core caps or raises it while the transport is built.
    #[test]
    fn xdrive_scalars_warn_where_the_core_rewrites_them() {
        let advisory_paths = |settings: XdriveTransport| -> Vec<Option<String>> {
            validate_outbound(&xdrive_outbound(settings))
                .advisory()
                .map(|issue| issue.path.clone())
                .collect()
        };

        let local = |settings: XdriveTransport| XdriveTransport {
            service: super::XDRIVE_SERVICE_LOCAL.into(),
            remote_folder: "C:/store".into(),
            ..settings
        };

        let paths = advisory_paths(local(XdriveTransport {
            concurrency: super::XDRIVE_MAX_CONCURRENCY + 1,
            segment_bytes: super::XDRIVE_MAX_SEGMENT_BYTES + 1,
            ..Default::default()
        }));
        assert!(
            paths.contains(&Some("stream.xdriveSettings.concurrency".into())),
            "{paths:#?}"
        );
        assert!(
            paths.contains(&Some("stream.xdriveSettings.segmentBytes".into())),
            "{paths:#?}"
        );

        // A max poll interval below the min poll interval, compared on the
        // effective values the runtime uses.
        let paths = advisory_paths(local(XdriveTransport {
            max_poll_interval_ms: 10,
            ..Default::default()
        }));
        assert!(
            paths.contains(&Some("stream.xdriveSettings.maxPollIntervalMs".into())),
            "{paths:#?}"
        );

        // In range: no advisory.
        let paths = advisory_paths(local(XdriveTransport {
            concurrency: super::XDRIVE_MAX_CONCURRENCY,
            segment_bytes: super::XDRIVE_MAX_SEGMENT_BYTES,
            poll_interval_ms: 50,
            max_poll_interval_ms: 500,
            ..Default::default()
        }));
        assert!(paths.is_empty(), "{paths:#?}");
    }

    /// A stored freedom outbound carrying xdrive is refused by the core's
    /// gate, and the load leaves the stored protocol and transport exactly as
    /// written: the user decides how to change the protocol.
    #[test]
    fn xdrive_transport_requires_vless_and_never_rewrites_a_stored_profile() {
        let stored = json!({
            "protocol": "freedom",
            "settings": {},
            "streamSettings": {
                "network": "xdrive",
                "xdriveSettings": {
                    "service": "local",
                    "remoteFolder": "C:/store"
                }
            }
        });
        let outbound: OutboundModel = serde_json::from_value(stored.clone())
            .expect("a stored freedom+xdrive profile still loads");
        let verdict = validate_outbound(&outbound);
        let issue = finding(&verdict, &ValidationCode::XdriveRequiresVless)
            .expect("the core's non-VLESS refusal must gate the profile");
        assert_eq!(issue.severity, Severity::Error);
        assert_eq!(issue.path.as_deref(), Some("protocol"));
        assert_eq!(
            serde_json::to_value(&outbound).expect("the profile serializes"),
            stored,
            "the stored protocol and transport must not be rewritten"
        );
    }

    /// A VLESS flow is refused against the field that carries it.
    #[test]
    fn xdrive_vless_flow_is_refused() {
        let mut outbound = xdrive_outbound(local_xdrive_settings());
        let ProtocolSettings::Vless(account) = &mut outbound.settings else {
            unreachable!();
        };
        account.flow = "xtls-rprx-vision".into();
        let verdict = validate_outbound(&outbound);
        let issue = finding(&verdict, &ValidationCode::XdriveVlessFlowUnsupported)
            .expect("a VLESS flow is refused");
        assert_eq!(issue.path.as_deref(), Some("settings.flow"));
    }

    /// Both spellings the core refuses — empty and `none` — are refused, and
    /// the finding points at the field the Generate action fills.
    #[test]
    fn xdrive_vless_encryption_is_required() {
        for encryption in ["", "none"] {
            let mut outbound = xdrive_outbound(local_xdrive_settings());
            let ProtocolSettings::Vless(account) = &mut outbound.settings else {
                unreachable!();
            };
            account.encryption = encryption.into();
            let verdict = validate_outbound(&outbound);
            let issue = finding(&verdict, &ValidationCode::XdriveVlessEncryptionRequired)
                .unwrap_or_else(|| panic!("encryption {encryption:?} must be refused"));
            assert_eq!(issue.path.as_deref(), Some("settings.encryption"));
        }
    }

    /// A non-zero `testpre` is refused; zero and an absent key are the core's
    /// own default.
    #[test]
    fn xdrive_vless_testpre_is_refused() {
        let mut outbound = xdrive_outbound(local_xdrive_settings());
        let ProtocolSettings::Vless(account) = &mut outbound.settings else {
            unreachable!();
        };
        account.extra.insert("testpre".into(), json!(1));
        let verdict = validate_outbound(&outbound);
        let issue = finding(&verdict, &ValidationCode::XdriveVlessTestpreUnsupported)
            .expect("a non-zero testpre is refused");
        assert_eq!(issue.path.as_deref(), Some("settings.testpre"));

        let ProtocolSettings::Vless(account) = &mut outbound.settings else {
            unreachable!();
        };
        account.extra.insert("testpre".into(), json!(0));
        let verdict = validate_outbound(&outbound);
        assert!(finding(&verdict, &ValidationCode::XdriveVlessTestpreUnsupported).is_none());
    }

    /// Mux.Cool is required for the transport unless the account is a
    /// reverse-proxy account, which opens its own mux.
    #[test]
    fn xdrive_mux_is_required() {
        let mut outbound = xdrive_outbound(local_xdrive_settings());
        outbound.mux.enabled = false;
        let verdict = validate_outbound(&outbound);
        let issue =
            finding(&verdict, &ValidationCode::XdriveMuxRequired).expect("disabled mux is refused");
        assert_eq!(issue.path.as_deref(), Some("mux.enabled"));

        let ProtocolSettings::Vless(account) = &mut outbound.settings else {
            unreachable!();
        };
        account.reverse = Some(crate::model::outbound::VlessReverse {
            tag: "reverse".into(),
            ..Default::default()
        });
        let verdict = validate_outbound(&outbound);
        assert!(
            finding(&verdict, &ValidationCode::XdriveMuxRequired).is_none(),
            "a reverse account opens its own mux"
        );
    }

    /// Both negative knobs are refused, each against the field that carries
    /// the value.
    #[test]
    fn xdrive_negative_mux_knobs_are_refused() {
        let mut outbound = xdrive_outbound(local_xdrive_settings());
        outbound.mux.concurrency = Some(-1);
        outbound.mux.xudp_concurrency = Some(-1);
        let issues = validate_outbound(&outbound);
        assert_eq!(
            issues
                .iter()
                .filter(|issue| issue.code == ValidationCode::XdriveMuxConcurrencyNegative)
                .count(),
            2,
            "{issues:#?}"
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.path.as_deref() == Some("mux.concurrency"))
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.path.as_deref() == Some("mux.xudpConcurrency"))
        );
    }

    /// The `skip` XUDP mode is refused for the transport.
    #[test]
    fn xdrive_skip_udp443_mode_is_refused() {
        let mut outbound = xdrive_outbound(local_xdrive_settings());
        outbound.mux.xudp_proxy_udp443 = Some("skip".into());
        let verdict = validate_outbound(&outbound);
        let issue = finding(&verdict, &ValidationCode::XdriveMuxXudpProxyUdp443Skip)
            .expect("the skip mode is refused");
        assert_eq!(issue.path.as_deref(), Some("mux.xudpProxyUDP443"));
    }

    /// An interval hop mode moves the outbound's socket, so only a transport
    /// whose connection migrates survives it: the QUIC-based hysteria2 and
    /// xhttp transports, or the WireGuard outbound. Everything else is a
    /// configuration warning (never a gate) and `perConnRemote` is always
    /// fine.
    #[test]
    fn udphop_interval_modes_warn_only_on_transports_that_cannot_migrate() {
        let interval_mask = |mode: &str| FinalmaskModel {
            udp: vec![
                serde_json::from_value(json!({
                    "type": "udphop",
                    "settings": {"mode": mode, "interval": "5-10"}
                }))
                .expect("the udphop envelope loads"),
            ],
            ..Default::default()
        };

        let advisory = |outbound: &OutboundModel| -> usize {
            validate_outbound(outbound)
                .iter()
                .filter(|issue| {
                    issue.code == ValidationCode::FinalmaskUdpHopIntervalTransportConflict
                })
                .count()
        };

        // Every interval spelling on a transport that cannot run a hop. The
        // mode parse mirrors the load build: case-insensitive, no trimming.
        for mode in [
            "intervalLocal",
            "intervalRemote",
            "intervalLocal,intervalRemote",
            "INTERVALREMOTE,INTERVALLOCAL",
        ] {
            let mut outbound = OutboundModel::new(Protocol::Vless);
            outbound.stream.finalmask = Some(interval_mask(mode));
            let issues = validate_outbound(&outbound);
            let found: Vec<_> = issues
                .iter()
                .filter(|issue| {
                    issue.code == ValidationCode::FinalmaskUdpHopIntervalTransportConflict
                })
                .collect();
            assert_eq!(found.len(), 1, "mode {mode:?}: {issues:#?}");
            assert_eq!(found[0].severity, Severity::Warning);
            assert_eq!(found[0].path, None);
        }

        // A whitespace-carrying component is the mode load error's business
        // alone: the advisory must not add a second message for one value.
        let mut spaced = OutboundModel::new(Protocol::Vless);
        spaced.stream.finalmask = Some(interval_mask("intervalLocal, intervalRemote"));
        let issues = validate_outbound(&spaced);
        assert!(
            issues
                .iter()
                .any(|issue| issue.code == ValidationCode::FinalmaskUdpHopModeInvalid),
            "{issues:#?}"
        );
        assert_eq!(advisory(&spaced), 0, "{issues:#?}");

        // Transports that never wrap the mask list, or cannot move a live
        // connection, warn the same way.
        for network in [
            Network::Ws,
            Network::Kcp,
            Network::Grpc,
            Network::Httpupgrade,
        ] {
            let mut outbound = OutboundModel::new(Protocol::Vless);
            outbound.stream.network = network;
            outbound.stream.finalmask = Some(interval_mask("intervalLocal"));
            assert_eq!(advisory(&outbound), 1, "network {network:?}");
        }

        // The transports that can run a hop never warn: hysteria2 and
        // WireGuard unconditionally, xhttp only in its HTTP/3 shape (TLS
        // with ALPN exactly ["h3"]).
        let mut hysteria = OutboundModel::new(Protocol::Vless);
        hysteria.stream.network = Network::Hysteria;
        hysteria.stream.finalmask = Some(interval_mask("intervalLocal"));
        assert_eq!(advisory(&hysteria), 0);

        let mut wireguard = OutboundModel::new(Protocol::Wireguard);
        wireguard.stream.finalmask = Some(interval_mask("intervalLocal,intervalRemote"));
        assert_eq!(advisory(&wireguard), 0);

        let xhttp_with_tls = |alpn: Vec<String>| {
            let mut outbound = OutboundModel::new(Protocol::Vless);
            outbound.stream.network = Network::Xhttp;
            outbound.stream.security = Security::Tls;
            outbound.stream.tls_settings = Some(crate::model::stream::TlsModel {
                alpn,
                ..Default::default()
            });
            outbound.stream.finalmask = Some(interval_mask("intervalLocal"));
            outbound
        };
        assert_eq!(advisory(&xhttp_with_tls(vec!["h3".into()])), 0);

        // Every non-HTTP/3 xhttp shape warns: no TLS (HTTP/1.1), an empty or
        // longer ALPN list and a non-h3 ALPN (HTTP/2), and REALITY, which
        // forces HTTP/2 before the ALPN is read.
        for alpn in [vec![], vec!["h2".into()], vec!["h3".into(), "h2".into()]] {
            assert_eq!(advisory(&xhttp_with_tls(alpn.clone())), 1, "alpn {alpn:?}");
        }
        let mut no_tls = OutboundModel::new(Protocol::Vless);
        no_tls.stream.network = Network::Xhttp;
        no_tls.stream.finalmask = Some(interval_mask("intervalLocal"));
        assert_eq!(advisory(&no_tls), 1);
        let mut reality = OutboundModel::new(Protocol::Vless);
        reality.stream.network = Network::Xhttp;
        reality.stream.security = Security::Reality;
        reality.stream.finalmask = Some(interval_mask("intervalLocal"));
        assert_eq!(advisory(&reality), 1);

        // `perConnRemote`, a mask-free stream, and an unparsable mode never
        // raise the advisory.
        let mut outbound = OutboundModel::new(Protocol::Vless);
        outbound.stream.finalmask = Some(interval_mask("perConnRemote"));
        assert_eq!(advisory(&outbound), 0);
        let mut outbound = OutboundModel::new(Protocol::Vless);
        outbound.stream.finalmask = Some(interval_mask("banana"));
        assert_eq!(advisory(&outbound), 0);
        assert_eq!(advisory(&OutboundModel::new(Protocol::Vless)), 0);

        // A non-hop mask with an unrelated mode-shaped extra stays quiet.
        let mut outbound = OutboundModel::new(Protocol::Vless);
        outbound.stream.finalmask = Some(FinalmaskModel {
            udp: vec![
                serde_json::from_value(json!({
                    "type": "salamander", "settings": {"password": "pw", "mode": "intervalLocal"}
                }))
                .expect("the salamander envelope loads"),
            ],
            ..Default::default()
        });
        assert_eq!(advisory(&outbound), 0);
    }

    #[test]
    fn sniffing_dest_override_refuses_unknown_protocols_case_insensitively() {
        for item in [
            "http",
            "tls",
            "https",
            "ssl",
            "quic",
            "fakedns",
            "fakedns+others",
            "HTTP",
            "TLS",
            "FAKEDNS+OTHERS",
        ] {
            let sniffing = Sniffing {
                dest_override: vec![item.into()],
                ..Default::default()
            };
            assert!(
                validate_sniffing(&sniffing, "localInbounds[0].sniffing").is_empty(),
                "{item:?} must be accepted"
            );
        }
        for item in ["tcp", "h2", "fakedns2", "http2", "  tls"] {
            let sniffing = Sniffing {
                dest_override: vec![item.into()],
                ..Default::default()
            };
            let issues = validate_sniffing(&sniffing, "localInbounds[0].sniffing");
            let finding = issues
                .iter()
                .find(|issue| issue.code == ValidationCode::SniffingDestOverrideInvalid)
                .expect("junk item refused");
            assert_eq!(finding.severity, Severity::Error);
            assert_eq!(
                finding.path.as_deref(),
                Some("localInbounds[0].sniffing.destOverride")
            );
        }
        // One issue per offending item; the default state and the fakedns
        // wire form the generator appends itself stay clean.
        let junk = Sniffing {
            dest_override: vec!["http".into(), "tcp".into(), "quic".into(), "nope".into()],
            ..Default::default()
        };
        let issues = validate_sniffing(&junk, "dokodemo[3].sniffing");
        assert_eq!(issues.len(), 2, "{issues:#?}");
        assert!(validate_sniffing(&Sniffing::default(), "localInbounds[0].sniffing").is_empty());
    }

    #[test]
    fn outbound_target_strategy_outside_vocab_is_refused() {
        // Canonical: None, empty, and every strategy in any case pass.
        let canonical_values: Vec<Option<&str>> = [
            None,
            Some(""),
            Some("asis"),
            Some("AsIs"),
            Some("useip"),
            Some("UseIP"),
            Some("useipv4"),
            Some("useipv6"),
            Some("useipv4v6"),
            Some("useipv6v4"),
            Some("forceip"),
            Some("forceipv4"),
            Some("forceipv6"),
            Some("forceipv4v6"),
            Some("forceipv6v4"),
            Some("FORCEIPV4V6"),
        ]
        .into_iter()
        .collect();
        for value in canonical_values {
            let mut outbound = OutboundModel::new(Protocol::Vless);
            outbound.target_strategy = value.map(str::to_string);
            let issues = validate_outbound(&outbound);
            assert!(
                issues
                    .iter()
                    .all(|issue| issue.code != ValidationCode::OutboundTargetStrategyInvalid),
                "{value:?}: {issues:#?}"
            );
        }
        for junk in ["origin", "random", "forceipv7"] {
            let mut outbound = OutboundModel::new(Protocol::Vless);
            outbound.target_strategy = Some(junk.into());
            let issues = validate_outbound(&outbound);
            let finding = issues
                .iter()
                .find(|issue| issue.code == ValidationCode::OutboundTargetStrategyInvalid)
                .expect("junk strategy refused");
            assert_eq!(finding.severity, Severity::Error);
            assert_eq!(finding.path.as_deref(), Some("targetStrategy"));
        }
    }

    #[test]
    fn loopback_outbound_sniffing_gates_through_validate_outbound() {
        // Xray's loopback outbound builds its sniffing block through the
        // same SniffingConfig.Build as inbound envelopes
        // (infra/conf/loopback.go), so an out-of-vocab item is a load
        // refusal here too, with the settings-level path.
        let mut outbound = OutboundModel::new(Protocol::Loopback);
        if let ProtocolSettings::Loopback(settings) = &mut outbound.settings {
            settings.sniffing = Some(Sniffing {
                dest_override: vec!["tcp".into()],
                ..Default::default()
            });
        }
        let issues = validate_outbound(&outbound);
        let finding = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::SniffingDestOverrideInvalid)
            .expect("junk destOverride refused on loopback");
        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(
            finding.path.as_deref(),
            Some("settings.sniffing.destOverride")
        );

        // Canonical loopback sniffing stays silent.
        if let ProtocolSettings::Loopback(settings) = &mut outbound.settings {
            settings.sniffing = Some(Sniffing {
                dest_override: vec!["http".into(), "quic".into()],
                ..Default::default()
            });
        }
        assert!(
            validate_outbound(&outbound)
                .iter()
                .all(|issue| issue.code != ValidationCode::SniffingDestOverrideInvalid)
        );
    }

    #[test]
    fn vision_precedence_over_public_plaintext() {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "plain.example.com".into();
        settings.port = 443;
        settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
        settings.flow = "xtls-rprx-vision".into();
        settings.encryption = "none".into();
        let issues = validate_outbound(&outbound);
        assert_eq!(
            codes(&issues),
            vec![ValidationCode::VisionRequiresTlsOrReality]
        );
    }

    #[test]
    fn public_plaintext_vless_and_trojan_report_their_own_codes() {
        let mut vless = OutboundModel::new(Protocol::Vless);
        {
            let ProtocolSettings::Vless(settings) = &mut vless.settings else {
                unreachable!()
            };
            settings.address = "example.com".into();
            settings.port = 443;
            settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
            settings.encryption = "none".into();
        }
        assert!(
            codes(&validate_outbound(&vless))
                .contains(&ValidationCode::PublicVlessRequiresTlsOrEncryption)
        );

        {
            let ProtocolSettings::Vless(settings) = &mut vless.settings else {
                unreachable!()
            };
            settings.encryption = "mlkem768x25519plus.native.0rtt.key".into();
        }
        assert!(
            codes(&validate_outbound(&vless)).contains(&ValidationCode::VlessEncryptionUnsupported),
            "an all-short-key value must be refused"
        );
        {
            let ProtocolSettings::Vless(settings) = &mut vless.settings else {
                unreachable!()
            };
            settings.encryption =
                "mlkem768x25519plus.native.0rtt.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA".into();
        }
        assert!(validate_outbound(&vless).is_empty());
        let _ = vless.stream.select_security(Security::Tls);
        assert!(validate_outbound(&vless).is_empty());

        let mut trojan = OutboundModel::new(Protocol::Trojan);
        {
            let ProtocolSettings::Trojan(settings) = &mut trojan.settings else {
                unreachable!()
            };
            settings.address = "8.8.8.8".into();
            settings.port = 443;
            settings.password = "secret".into();
        }
        assert!(
            codes(&validate_outbound(&trojan))
                .contains(&ValidationCode::PublicTrojanRequiresTlsOrReality)
        );
        {
            let ProtocolSettings::Trojan(settings) = &mut trojan.settings else {
                unreachable!()
            };
            settings.address = "router.local".into();
        }
        assert!(validate_outbound(&trojan).is_empty());
    }

    #[test]
    fn shadowsocks_level_and_blackhole_response_are_protocol_rules() {
        let mut ss = OutboundModel::new(Protocol::Shadowsocks);
        {
            let ProtocolSettings::Shadowsocks(settings) = &mut ss.settings else {
                unreachable!()
            };
            settings.address = "example.com".into();
            settings.port = 8388;
            settings.method = "aes-128-gcm".into();
            settings.password = "secret".into();
            settings.level = Some(256);
        }
        assert!(codes(&validate_outbound(&ss)).contains(&ValidationCode::ShadowsocksLevelRange));
        {
            let ProtocolSettings::Shadowsocks(settings) = &mut ss.settings else {
                unreachable!()
            };
            settings.level = Some(255);
        }
        assert!(validate_outbound(&ss).is_empty());

        let mut bh = OutboundModel::new(Protocol::Blackhole);
        {
            let ProtocolSettings::Blackhole(settings) = &mut bh.settings else {
                unreachable!()
            };
            settings.response = Some(crate::model::outbound::BlackholeResponse {
                r#type: "future".into(),
                ..Default::default()
            });
        }
        assert!(codes(&validate_outbound(&bh)).contains(&ValidationCode::BlackholeResponseInvalid));
    }

    #[test]
    fn blackhole_custom_response_base64_gates_only_for_the_custom_type() {
        fn set(bh: &mut OutboundModel, r#type: &str, data: &str) {
            let ProtocolSettings::Blackhole(settings) = &mut bh.settings else {
                unreachable!()
            };
            settings.response = Some(crate::model::outbound::BlackholeResponse {
                r#type: r#type.into(),
                custom_response_data: data.into(),
                ..Default::default()
            });
        }

        let mut bh = OutboundModel::new(Protocol::Blackhole);

        set(&mut bh, "custom", "aGk=");
        assert!(validate_outbound(&bh).is_empty());

        // An absent payload is a valid empty response body, not a decode error.
        set(&mut bh, "custom", "");
        assert!(validate_outbound(&bh).is_empty());

        set(&mut bh, "custom", "not base64!");
        let issues = validate_outbound(&bh);
        assert!(codes(&issues).contains(&ValidationCode::BlackholeCustomResponseDataInvalid));
        let finding = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::BlackholeCustomResponseDataInvalid)
            .expect("custom payload finding");
        assert_eq!(
            finding.path.as_deref(),
            Some("settings.response.customResponseData")
        );
        assert_eq!(
            crate::i18n::validation_issue_message(finding, crate::model::settings::Language::En),
            "settings.response.customResponseData: Blackhole custom response data must be \
             standard base64 with the = padding."
        );

        // Xray only decodes the payload for the custom type (blackhole.go
        // conf build), so a stray value under none/http must not gate.
        set(&mut bh, "none", "not base64!");
        assert!(validate_outbound(&bh).is_empty());
        set(&mut bh, "http", "not base64!");
        assert!(validate_outbound(&bh).is_empty());

        // The custom match is the same lowercased one (infra/conf/blackhole.go:24,31),
        // so a case-variant custom spelling still decodes the payload.
        set(&mut bh, "Custom", "not base64!");
        let issues = validate_outbound(&bh);
        assert!(codes(&issues).contains(&ValidationCode::BlackholeCustomResponseDataInvalid));
        let finding = issues
            .iter()
            .find(|issue| issue.code == ValidationCode::BlackholeCustomResponseDataInvalid)
            .expect("custom payload finding");
        assert_eq!(
            finding.path.as_deref(),
            Some("settings.response.customResponseData")
        );
        set(&mut bh, "Custom", "aGk=");
        assert!(validate_outbound(&bh).is_empty());
        set(&mut bh, "HTTP", "not base64!");
        assert!(validate_outbound(&bh).is_empty());

        set(&mut bh, "future", "");
        assert!(codes(&validate_outbound(&bh)).contains(&ValidationCode::BlackholeResponseInvalid));
    }

    #[test]
    fn blackhole_response_type_accepts_the_vocabulary_in_any_case() {
        fn set(bh: &mut OutboundModel, r#type: &str) {
            let ProtocolSettings::Blackhole(settings) = &mut bh.settings else {
                unreachable!()
            };
            settings.response = Some(crate::model::outbound::BlackholeResponse {
                r#type: r#type.into(),
                ..Default::default()
            });
        }

        let mut bh = OutboundModel::new(Protocol::Blackhole);
        // Xray lowercases the stored value before matching its vocabulary
        // (infra/conf/blackhole.go:24-26): every spelling below loads
        // upstream (the empty spelling alongside `none` selects no
        // response), so none of them may gate here.
        for spelling in [
            "", "none", "None", "NONE", "http", "Http", "HTTP", "custom", "Custom", "CUSTOM",
        ] {
            set(&mut bh, spelling);
            assert!(
                validate_outbound(&bh).is_empty(),
                "{spelling:?} is accepted by the core and must not gate"
            );
        }

        // The vocabulary is closed: anything else fails the build upstream.
        for spelling in ["future", "customs", "none ", "custom-response"] {
            set(&mut bh, spelling);
            assert!(
                codes(&validate_outbound(&bh)).contains(&ValidationCode::BlackholeResponseInvalid),
                "{spelling:?} is refused by the core and must gate"
            );
        }
    }

    #[test]
    fn reality_settings_missing_is_reported() {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        outbound.stream.security = Security::Reality;
        outbound.stream.network = crate::model::stream::Network::Raw;
        let issues = validate_outbound(&outbound);
        assert!(codes(&issues).contains(&ValidationCode::RealitySettingsMissing));
    }

    // ---------- extra-passthrough scans ----------
    //
    // The pins below sit beside the masterKeyLog/allowInsecure case-variant
    // pins: one test per case asserts the code fires case-insensitively on a
    // profile carrying the extra key, with the wire path and severity of the
    // case, and that canonical profiles validate clean. Removed-feature keys
    // are Error (Xray refuses at conf load); inert keys are Warning
    // (advisory, never gating).

    fn trojan_canonical() -> OutboundModel {
        let mut outbound = OutboundModel::new(Protocol::Trojan);
        let ProtocolSettings::Trojan(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "10.0.0.1".into();
        settings.port = 443;
        settings.password = "secret".into();
        outbound
    }

    fn freedom_canonical() -> OutboundModel {
        OutboundModel::new(Protocol::Freedom)
    }

    #[test]
    fn trojan_flow_extra_is_refused_like_the_removed_feature() {
        // Xray's TrojanClientConfig.Build refuses a non-empty
        // `flow` with PrintRemovedFeatureError (conf/trojan.go) — any case
        // variant binds the same field, so the extra scan must refuse it
        // exactly like the masterKeyLog scans.
        for key in ["flow", "FLOW", "Flow"] {
            let mut outbound = trojan_canonical();
            let ProtocolSettings::Trojan(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings
                .extra
                .insert(key.to_string(), json!("xtls-rprx-vision"));
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::TrojanFlowRemoved,
                    Some("settings.flow".into()),
                )],
                "extra key {key:?} must refuse like the removed feature"
            );
        }
        // The zero shapes stay silent: JSON null and the empty string both
        // leave Xray's `Flow string` at its zero value.
        for value in [Value::Null, json!("")] {
            let mut outbound = trojan_canonical();
            let ProtocolSettings::Trojan(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.extra.insert("flow".into(), value);
            assert!(
                validate_outbound(&outbound).is_empty(),
                "flow zero shapes must stay valid"
            );
        }
        // Canonical Trojan profiles (no extras) stay clean.
        assert!(validate_outbound(&trojan_canonical()).is_empty());
    }

    #[test]
    fn vmess_alter_id_and_aid_extras_warn_as_inert() {
        // conf/vmess.go has no alterId/aid field (VMess is
        // AEAD-only), so Xray silently ignores any carried value — the
        // import grammar refuses both spellings; the model scan is the
        // state-path counterpart and stays advisory.
        for (key, path) in [("alterId", "settings.alterId"), ("AID", "settings.aid")] {
            let mut outbound = vmess_canonical();
            let ProtocolSettings::Vmess(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.extra.insert(key.to_string(), json!(1));
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![warning(
                    ValidationCode::VmessAlterIdIgnored,
                    Some(path.into()),
                )],
                "extra key {key:?} must warn exactly once"
            );
        }
        // Both spellings at once: one advisory per carried key.
        let mut outbound = vmess_canonical();
        {
            let ProtocolSettings::Vmess(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.extra.insert("alterId".into(), json!(1));
            settings.extra.insert("aid".into(), json!(0));
        }
        let issues = validate_outbound(&outbound);
        let alter_id_issues: Vec<&ValidationIssue> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::VmessAlterIdIgnored)
            .collect();
        assert_eq!(alter_id_issues.len(), 2, "{issues:#?}");
        assert_eq!(alter_id_issues[0].path.as_deref(), Some("settings.alterId"));
        assert_eq!(alter_id_issues[1].path.as_deref(), Some("settings.aid"));
        assert!(
            alter_id_issues
                .iter()
                .all(|issue| issue.severity == Severity::Warning)
        );
    }

    #[test]
    fn vless_seed_extra_warns_as_inert() {
        // The VLESS conf struct still parses `seed` but Build never
        // assigns it — the assignment is commented out upstream
        // (conf/vless.go) — so Xray silently drops any carried value and the
        // model warns.
        for key in ["seed", "SEED"] {
            let mut outbound = vless_canonical();
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            // Private literal: keeps the public-plaintext TLS rule off this
            // fixture so the exact vector below isolates VlessSeedIgnored.
            settings.address = "10.0.0.1".into();
            settings.extra.insert(key.to_string(), json!("legacy-obfs"));
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![warning(
                    ValidationCode::VlessSeedIgnored,
                    Some("settings.seed".into()),
                )],
                "extra key {key:?} must warn exactly once"
            );
        }
        // Canonical VLESS settings (no extras) never fire the scan (the
        // shared fixture carries a public literal, so the plaintext-TLS rule
        // may fire — only VlessSeedIgnored must stay absent).
        let canonical_issues = validate_outbound(&vless_canonical());
        assert!(
            !codes(&canonical_issues).contains(&ValidationCode::VlessSeedIgnored),
            "{canonical_issues:#?}"
        );
    }

    #[test]
    fn freedom_singular_noise_extra_is_refused_and_the_noises_field_stays_legal() {
        // conf/freedom.go refuses a non-null singular `noise`
        // object with PrintRemovedFeatureError naming `noises` as the
        // migration. Null is the Go zero shape and stays silent, and the
        // modeled plural `noises` field is the legal spelling — it never
        // trips the extra scan.
        for key in ["noise", "NOISE"] {
            let mut outbound = freedom_canonical();
            let ProtocolSettings::Freedom(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings
                .extra
                .insert(key.to_string(), json!({"type": "rand", "packet": "1-3"}));
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::FreedomNoiseRemoved,
                    Some("settings.noise".into()),
                )],
                "extra key {key:?} must refuse like the removed feature"
            );
        }
        let mut silent = freedom_canonical();
        {
            let ProtocolSettings::Freedom(settings) = &mut silent.settings else {
                unreachable!()
            };
            settings.extra.insert("noise".into(), Value::Null);
        }
        assert!(validate_outbound(&silent).is_empty());

        let mut plural = freedom_canonical();
        {
            let ProtocolSettings::Freedom(settings) = &mut plural.settings else {
                unreachable!()
            };
            settings.noises = vec![crate::model::outbound::Noise {
                r#type: "rand".into(),
                packet: "1-3".into(),
                ..Default::default()
            }];
        }
        let issues = validate_outbound(&plural);
        assert!(
            !codes(&issues).contains(&ValidationCode::FreedomNoiseRemoved),
            "the modeled noises field must never trip the singular scan: {issues:#?}"
        );
    }

    #[test]
    fn freedom_domain_strategy_extra_outside_the_vocabulary_is_refused() {
        // Xray's freedom Build lowercases `domainStrategy` and
        // switches over the ten strategies (conf/freedom.go) — values in the
        // vocabulary work on the wire in any case and stay silent; every
        // other non-null value refuses the outbound at load (non-string
        // JSON shapes included — Go's `string` unmarshal fails them).
        for strategy in ["asis", "useipv4", "ForceIPV6", "useipv4v6", "forceipv6v4"] {
            let mut outbound = freedom_canonical();
            let ProtocolSettings::Freedom(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings
                .extra
                .insert("domainStrategy".into(), json!(strategy));
            let issues = validate_outbound(&outbound);
            assert!(
                issues.is_empty(),
                "domainStrategy {strategy:?} must stay silent: {issues:#?}"
            );
        }
        // Empty and null are the zero shapes (the wire default `asis`).
        for value in [json!(""), Value::Null] {
            let mut outbound = freedom_canonical();
            let ProtocolSettings::Freedom(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.extra.insert("domainStrategy".into(), value);
            assert!(validate_outbound(&outbound).is_empty());
        }
        for (key, value) in [
            ("domainStrategy", json!("tlshello")),
            ("DomainStrategy", json!("bogus")),
            ("domainstrategy", json!(42)),
        ] {
            let mut outbound = freedom_canonical();
            let ProtocolSettings::Freedom(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.extra.insert(key.to_string(), value);
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::FreedomDomainStrategyUnsupported,
                    Some("settings.domainStrategy".into()),
                )],
                "key {key:?} with an out-of-vocabulary value must refuse"
            );
        }
    }

    #[test]
    fn freedom_refuses_every_effective_address_port_strategy_but_none() {
        // The freedom handler is built from the whole document, and
        // infra/conf/xray.go refuses the outbound whenever the effective
        // `sockopt.addressPortStrategy` is not `AddressPortStrategy_None`:
        // freedom's own dialer reads no such field. The empty spelling and
        // `none` are that variant, so those stay silent, and the gate covers
        // the SRV/TXT orders in any case.
        for strategy in ["srvportonly", "SRVPortOnly", "txtportandaddress"] {
            let mut outbound = freedom_canonical();
            outbound.stream.sockopt = Some(SockoptModel {
                address_port_strategy: strategy.into(),
                ..Default::default()
            });
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![issue(
                    ValidationCode::FreedomAddressPortStrategyUnsupported,
                    Some("stream.sockopt.addressPortStrategy".into()),
                )],
                "strategy {strategy:?} must gate the freedom outbound"
            );
        }
        for strategy in ["", "none", "NONE"] {
            let mut outbound = freedom_canonical();
            outbound.stream.sockopt = Some(SockoptModel {
                address_port_strategy: strategy.into(),
                ..Default::default()
            });
            assert!(
                validate_outbound(&outbound).is_empty(),
                "strategy {strategy:?} maps to AddressPortStrategy_None upstream"
            );
        }
        // A dialer that reads the field keeps it: the finding is freedom's.
        let mut vless = vless_canonical();
        vless.stream.sockopt = Some(SockoptModel {
            address_port_strategy: "srvportonly".into(),
            ..Default::default()
        });
        assert!(
            !codes(&validate_outbound(&vless))
                .contains(&ValidationCode::FreedomAddressPortStrategyUnsupported),
            "the SRV strategy is a VLESS dialer's own setting"
        );
        // An out-of-vocabulary value stays the sockopt rule's finding alone:
        // one field must not report two causes.
        let mut outbound = freedom_canonical();
        outbound.stream.sockopt = Some(SockoptModel {
            address_port_strategy: "bogus".into(),
            ..Default::default()
        });
        assert_eq!(
            codes(&validate_outbound(&outbound)),
            vec![ValidationCode::SockoptAddressPortStrategyInvalid],
            "the freedom gate must defer to the vocabulary rule"
        );
    }

    #[test]
    fn freedom_final_rules_warn_inert_beside_a_dialer_proxy() {
        // A `sockopt.dialerProxy` makes freedom a non-final outbound, and its
        // handler then returns before building any final rule, logging that
        // the whole setting is ignored (proxy/freedom/freedom.go:193-197).
        // The document loads and runs without the rules, so the model warns.
        let with_rules = |rules: bool, dialer_proxy: &str| {
            let mut outbound = freedom_canonical();
            let ProtocolSettings::Freedom(settings) = &mut outbound.settings else {
                unreachable!()
            };
            if rules {
                settings
                    .final_rules
                    .push(crate::model::outbound::FreedomFinalRule {
                        action: "block".into(),
                        ..Default::default()
                    });
            }
            if !dialer_proxy.is_empty() {
                outbound.stream.sockopt = Some(SockoptModel {
                    dialer_proxy: dialer_proxy.into(),
                    ..Default::default()
                });
            }
            outbound
        };
        // Freedom stays final without a dialerProxy: the rules are live.
        assert!(validate_outbound(&with_rules(true, "")).is_empty());
        // Nothing to ignore without rules, whatever the dialerProxy says.
        assert!(validate_outbound(&with_rules(false, "srv-bbbbbbbb")).is_empty());
        assert_eq!(
            validate_outbound(&with_rules(true, "srv-bbbbbbbb")),
            vec![warning(
                ValidationCode::FreedomFinalRulesIgnored,
                Some("settings.finalRules".into()),
            )]
        );
        // Upstream reads the proxy tag's length, so a whitespace value still
        // counts as set and the rules are still inert.
        assert_eq!(
            validate_outbound(&with_rules(true, " ")),
            vec![warning(
                ValidationCode::FreedomFinalRulesIgnored,
                Some("settings.finalRules".into()),
            )]
        );
    }

    #[test]
    fn hysteria_legacy_quic_knob_extras_warn_moved_to_finalmask() {
        // The pinned core's HysteriaConfig declares none of
        // congestion/up/down/udphop (infra/conf/transport_method.go), so Go's
        // JSON unmarshal ignores them and nothing is logged — the config
        // loads and runs without the knobs, so the model warns (advisory,
        // never gating).
        for (key, path) in [
            ("congestion", "stream.hysteriaSettings.congestion"),
            ("CONGESTION", "stream.hysteriaSettings.congestion"),
            ("up", "stream.hysteriaSettings.up"),
            ("down", "stream.hysteriaSettings.down"),
            ("udphop", "stream.hysteriaSettings.udphop"),
        ] {
            let mut outbound = OutboundModel::new(Protocol::Hysteria);
            outbound
                .stream
                .hysteria_settings
                .as_mut()
                .unwrap()
                .extra
                .insert(key.to_string(), json!("50 mbps"));
            let issues = validate_outbound(&outbound);
            assert_eq!(
                issues,
                vec![warning(
                    ValidationCode::HysteriaQuicKnobsMoved,
                    Some(path.into()),
                )],
                "legacy knob {key:?} must warn exactly once"
            );
        }
        // JSON null is the Go zero shape and stays silent; a canonical
        // hysteria profile stays clean.
        let mut null_knob = OutboundModel::new(Protocol::Hysteria);
        null_knob
            .stream
            .hysteria_settings
            .as_mut()
            .unwrap()
            .extra
            .insert("congestion".into(), Value::Null);
        assert!(validate_outbound(&null_knob).is_empty());
        assert!(validate_outbound(&OutboundModel::new(Protocol::Hysteria)).is_empty());
    }

    #[test]
    fn extra_keys_fire_after_deserialization_the_state_path() {
        // The state path end to end: unknown keys in the settings /
        // streamSettings JSON land in the flattened `extra` maps through
        // serde (the share-link grammar refuses these keys on import, so
        // the model scan is the counterpart for deserialized profiles) and
        // must fire with the same codes as the hand-built fixtures above.
        let profile: OutboundModel = serde_json::from_value(json!({
            "protocol": "trojan",
            "settings": {
                "address": "1.2.3.4",
                "port": 443,
                "password": "secret",
                "flow": "xtls-rprx-vision"
            },
            "streamSettings": {
                "network": "kcp",
                "kcpSettings": {"mtu": 1200, "seed": "legacy"}
            }
        }))
        .unwrap();
        let issues = validate_outbound(&profile);
        let found = codes(&issues);
        assert!(
            found.contains(&ValidationCode::TrojanFlowRemoved),
            "{issues:#?}"
        );
        assert!(
            found.contains(&ValidationCode::KcpSeedHeaderRemoved),
            "{issues:#?}"
        );
    }

    // ---------- configuration-warning tier ----------

    /// A TLS-protected VLESS outbound that trips no other rule, so the
    /// mux/vision matrix below isolates MuxWithVisionFlow. (Carries the
    /// canonical essentials — port, UUID id — so those rules stay
    /// silent too.)
    fn vless_over_tls() -> OutboundModel {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "example.com".into();
        settings.port = 443;
        settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
        settings.encryption = "none".into();
        let _ = outbound.stream.select_security(Security::Tls);
        outbound
    }

    fn mux_finding(issues: &[ValidationIssue]) -> Option<&ValidationIssue> {
        issues
            .iter()
            .find(|issue| issue.code == ValidationCode::MuxWithVisionFlow)
    }

    #[test]
    fn vision_flow_with_enabled_tcp_mux_warns_and_carries_warning_severity() {
        let mut outbound = vless_over_tls();
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision".into();
        outbound.mux.enabled = true;
        // concurrency unset (None → Xray's default 8) and an explicit
        // positive value both carry TCP over smux — both must warn.
        let issues = validate_outbound(&outbound);
        let finding = mux_finding(&issues).expect("vision + enabled mux must warn");
        assert_eq!(finding.path.as_deref(), Some("mux"));
        assert_eq!(finding.severity, Severity::Warning);

        outbound.mux.concurrency = Some(8);
        let issues = validate_outbound(&outbound);
        assert!(mux_finding(&issues).is_some(), "{issues:#?}");

        // concurrency -1 is the TCP-direct escape hatch (XUDP stays
        // available): the combination must not warn.
        outbound.mux.concurrency = Some(-1);
        assert!(
            mux_finding(&validate_outbound(&outbound)).is_none(),
            "concurrency -1 keeps TCP direct; no warning may fire"
        );
    }

    #[test]
    fn xudp_knobs_alone_never_trigger_the_vision_warning_and_do_not_suppress_it() {
        // XUDP-only multiplexing — the knobs without enabled TCP mux — is
        // the sanctioned vision-flow path: the MuxWithVisionFlow warning
        // never fires here. (The separate MuxXudpKnobsInert
        // dead-knob warning legitimately does — a different predicate,
        // pinned in its own tests below.)
        let mut outbound = vless_over_tls();
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision-udp443".into();
        outbound.mux.xudp_concurrency = Some(8);
        outbound.mux.xudp_proxy_udp443 = Some("allow".into());
        assert!(
            mux_finding(&validate_outbound(&outbound)).is_none(),
            "XUDP knobs without enabled mux must not trigger the vision warning"
        );

        // XUDP knobs do NOT suppress the rule once TCP mux is enabled:
        // Xray builds XUDP inside the mux.Enabled block and TCP always
        // rides smux while enabled ∧ concurrency ≥ 0.
        outbound.mux.enabled = true;
        outbound.mux.concurrency = Some(8);
        assert!(
            mux_finding(&validate_outbound(&outbound)).is_some(),
            "XUDP knobs must not suppress the vision+mux warning"
        );
    }

    #[test]
    fn vision_or_mux_alone_and_non_vless_protocols_never_warn() {
        // Vision flow without mux.
        let mut outbound = vless_over_tls();
        {
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.flow = "xtls-rprx-vision".into();
        }
        assert!(mux_finding(&validate_outbound(&outbound)).is_none());

        // Enabled mux without a vision flow (empty and non-vision flows).
        outbound.mux.enabled = true;
        outbound.mux.concurrency = Some(8);
        for flow in ["", "xtls-rprx-xray"] {
            {
                let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                    unreachable!()
                };
                settings.flow = flow.into();
            }
            let issues = validate_outbound(&outbound);
            assert!(
                mux_finding(&issues).is_none(),
                "flow {flow:?} with enabled mux must not warn: {issues:#?}"
            );
        }

        // A non-VLESS protocol carrying enabled mux never warns.
        let mut trojan = OutboundModel::new(Protocol::Trojan);
        {
            let ProtocolSettings::Trojan(settings) = &mut trojan.settings else {
                unreachable!()
            };
            settings.address = "router.local".into();
        }
        trojan.mux.enabled = true;
        trojan.mux.concurrency = Some(8);
        assert!(mux_finding(&validate_outbound(&trojan)).is_none());
    }

    /// The severity tier: the two new codes are Warning; every pre-existing
    /// rule stays Error (they keep gating save/import/apply).
    #[test]
    fn warning_codes_are_advisory_and_existing_codes_stay_blocking() {
        let mut outbound = vless_over_tls();
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision".into();
        outbound.mux.enabled = true;
        outbound.stream.tls_settings = Some(crate::model::stream::TlsModel {
            server_name: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d".into(),
            ..Default::default()
        });
        let issues = validate_outbound(&outbound);
        for issue in &issues {
            assert_eq!(
                issue.severity,
                Severity::Warning,
                "{issue:?} must be advisory"
            );
        }
        // A blocking fixture (masterKeyLog is refused) must still carry
        // Severity::Error end to end.
        let tls_stream = StreamModel {
            security: Security::Tls,
            tls_settings: Some(crate::model::stream::TlsModel {
                master_key_log: "C:\\xray-keys.log".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let issues = validate_stream(&tls_stream);
        assert_eq!(issues[0].severity, Severity::Error);
    }

    // ---------- mux-block semantics ----------

    /// The mux fixtures reuse `vless_over_tls` (canonical VLESS/TLS
    /// with no vision flow), so every code set asserted below is exact: no
    /// other rule can fire on these profiles.
    #[test]
    fn xudp_proxy_udp443_outside_the_whitelist_errors_and_canonical_values_stay_silent() {
        // Xray's mux Build switch is an exact, case-sensitive match
        // (infra/conf/xray.go MuxConfig.Build): every non-empty value
        // outside {reject, allow, skip} — case variants included — refuses
        // the config at load, so the model refuses it too (Error tier).
        for value in ["Reject", "ALLOW", "reject-udp", "skip ", "auto", "0"] {
            let mut outbound = vless_over_tls();
            // Enabled block: the 1.24 dead-knob rule stays off, isolating
            // the whitelist Error under test.
            outbound.mux.enabled = true;
            outbound.mux.xudp_proxy_udp443 = Some(value.into());
            let issues = validate_outbound(&outbound);
            assert_eq!(
                codes(&issues),
                vec![ValidationCode::MuxXudpProxyUdp443Unsupported],
                "xudpProxyUDP443 {value:?} must error exactly once: {issues:#?}"
            );
            let finding = finding(&issues, &ValidationCode::MuxXudpProxyUdp443Unsupported).unwrap();
            assert_eq!(finding.severity, Severity::Error);
            assert_eq!(finding.path.as_deref(), Some("mux.xudpProxyUDP443"));
        }

        // Still refused on a disabled block: the vocabulary switch runs in
        // Build, before the handler ever looks at `enabled`. (The 1.24
        // dead-knob warning fires alongside — asserted in the coexistence
        // test below.)
        let mut disabled = vless_over_tls();
        disabled.mux.xudp_proxy_udp443 = Some("auto".into());
        let issues = validate_outbound(&disabled);
        assert!(
            codes(&issues).contains(&ValidationCode::MuxXudpProxyUdp443Unsupported),
            "{issues:#?}"
        );

        // Canonical over a live block: unset, empty (Xray defaults it to
        // `reject` on the wire), and each whitelisted mode never fire.
        for value in [None, Some(""), Some("reject"), Some("allow"), Some("skip")] {
            let mut outbound = vless_over_tls();
            outbound.mux.enabled = true;
            outbound.mux.xudp_proxy_udp443 = value.map(str::to_string);
            let issues = validate_outbound(&outbound);
            assert!(
                issues.is_empty(),
                "xudpProxyUDP443 {value:?} must stay silent: {issues:#?}"
            );
        }
    }

    #[test]
    fn concurrency_outside_documented_bounds_warns_only_while_mux_is_enabled() {
        // Reinterpreted values over an enabled block: 0 → 8, > 128 →
        // clamp 128, negatives other than -1 → mux off (TCP direct).
        for value in [Some(0), Some(-2), Some(-100), Some(129), Some(1024)] {
            let mut outbound = vless_over_tls();
            outbound.mux.enabled = true;
            outbound.mux.concurrency = value;
            let issues = validate_outbound(&outbound);
            assert_eq!(
                codes(&issues),
                vec![ValidationCode::MuxConcurrencyReinterpreted],
                "concurrency {value:?} over enabled mux must warn exactly once: {issues:#?}"
            );
            let finding = finding(&issues, &ValidationCode::MuxConcurrencyReinterpreted).unwrap();
            assert_eq!(finding.severity, Severity::Warning);
            assert_eq!(finding.path.as_deref(), Some("mux.concurrency"));
        }

        // Documented values never warn: unset (the wire default 8), the
        // -1 TCP-direct escape, and 1..=128.
        for value in [None, Some(-1), Some(1), Some(8), Some(128)] {
            let mut outbound = vless_over_tls();
            outbound.mux.enabled = true;
            outbound.mux.concurrency = value;
            let issues = validate_outbound(&outbound);
            assert!(
                issues.is_empty(),
                "concurrency {value:?} over enabled mux must stay silent: {issues:#?}"
            );
        }

        // Disabled block: Xray never reads `concurrency` (the whole mux
        // block is inert), so nothing is reinterpreted and nothing warns —
        // an out-of-band value there is dead, not changed in meaning.
        for value in [Some(0), Some(-2), Some(300)] {
            let mut outbound = vless_over_tls();
            outbound.mux.enabled = false;
            outbound.mux.concurrency = value;
            let issues = validate_outbound(&outbound);
            assert!(
                issues.is_empty(),
                "concurrency {value:?} on a disabled mux block must stay silent: {issues:#?}"
            );
        }
    }

    #[test]
    fn xudp_knobs_without_enabled_warn_and_are_silent_with_enabled() {
        // Each knob alone and both together surface the dead-knob warning
        // on the mux.enabled gate.
        for (xudp_concurrency, xudp_proxy_udp443) in [
            (Some(8), None),
            (None, Some("allow")),
            (Some(8), Some("skip")),
        ] {
            let mut outbound = vless_over_tls();
            outbound.mux.xudp_concurrency = xudp_concurrency;
            outbound.mux.xudp_proxy_udp443 = xudp_proxy_udp443.map(str::to_string);
            let issues = validate_outbound(&outbound);
            assert_eq!(
                codes(&issues),
                vec![ValidationCode::MuxXudpKnobsInert],
                "{xudp_concurrency:?}/{xudp_proxy_udp443:?} without enabled must warn \
                 exactly once: {issues:#?}"
            );
            let finding = finding(&issues, &ValidationCode::MuxXudpKnobsInert).unwrap();
            assert_eq!(finding.severity, Severity::Warning);
            assert_eq!(finding.path.as_deref(), Some("mux.enabled"));
        }

        // Canonical: the knobs with mux enabled — including the XUDP-only
        // wire shape (concurrency -1) — stay silent, and a bare enabled
        // block with no knobs stays silent.
        for (enabled, concurrency) in [(true, None), (true, Some(-1)), (true, Some(8))] {
            let mut outbound = vless_over_tls();
            outbound.mux.enabled = enabled;
            outbound.mux.concurrency = concurrency;
            outbound.mux.xudp_concurrency = Some(8);
            outbound.mux.xudp_proxy_udp443 = Some("allow".into());
            let issues = validate_outbound(&outbound);
            assert!(
                issues.is_empty(),
                "XUDP knobs over enabled mux (concurrency {concurrency:?}) must stay silent: \
                 {issues:#?}"
            );
        }
        let issues = validate_outbound(&vless_over_tls());
        assert!(issues.is_empty());
    }

    #[test]
    fn mux_warnings_coexist_with_the_vision_warning_and_never_suppress() {
        // The concurrency warning and the vision warning apply to the same
        // enabled block (concurrency -2 is a reinterpreted negative AND
        // carries TCP over smux under a vision flow): both render.
        let mut outbound = vless_over_tls();
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision".into();
        outbound.mux.enabled = true;
        outbound.mux.concurrency = Some(-2);
        let issues = validate_outbound(&outbound);
        let found = codes(&issues);
        assert!(
            found.contains(&ValidationCode::MuxWithVisionFlow),
            "{issues:#?}"
        );
        assert!(
            found.contains(&ValidationCode::MuxConcurrencyReinterpreted),
            "{issues:#?}"
        );

        // The dead-knob and out-of-vocabulary rules on the same disabled block:
        // the dead-knob warning and the load-refusal Error both render (Xray
        // would refuse the value at conf load AND ignore the block at run time).
        let mut dead = vless_over_tls();
        dead.mux.xudp_proxy_udp443 = Some("auto".into());
        let issues = validate_outbound(&dead);
        assert!(
            codes(&issues).contains(&ValidationCode::MuxXudpKnobsInert),
            "{issues:#?}"
        );
        assert!(
            codes(&issues).contains(&ValidationCode::MuxXudpProxyUdp443Unsupported),
            "{issues:#?}"
        );

        // The sanctioned XUDP-only vision profile — enabled, concurrency
        // -1, XUDP knobs, vision-udp443 flow — trips none of the mux rules
        // (escape semantics intact end to end).
        let mut xudp_only = vless_over_tls();
        let ProtocolSettings::Vless(settings) = &mut xudp_only.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision-udp443".into();
        xudp_only.mux.enabled = true;
        xudp_only.mux.concurrency = Some(-1);
        xudp_only.mux.xudp_concurrency = Some(8);
        xudp_only.mux.xudp_proxy_udp443 = Some("allow".into());
        let issues = validate_outbound(&xudp_only);
        assert!(
            issues.is_empty(),
            "the XUDP-only vision profile must stay clean: {issues:#?}"
        );
    }

    // ---------- protocol-settings vocabulary / required values ----------
    //
    // Tests beside the existing pins: each new code fires on a crafted
    // profile with its wire path and is absent on the canonical value. All
    // fixtures use a private-literal address and canonical essentials so no
    // transport-security or draft-noise rules obscure the assertions.
    // (The settings `protocol` mismatch guard in the model constructors is
    // bypassed the same way the existing pins do it.)

    const CANONICAL_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn vless_canonical() -> OutboundModel {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "1.2.3.4".into();
        settings.port = 443;
        settings.id = CANONICAL_UUID.into();
        settings.encryption = "none".into();
        outbound
    }

    fn vmess_canonical() -> OutboundModel {
        let mut outbound = OutboundModel::new(Protocol::Vmess);
        let ProtocolSettings::Vmess(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "1.2.3.4".into();
        settings.port = 443;
        settings.id = CANONICAL_UUID.into();
        outbound
    }

    fn shadowsocks_canonical() -> OutboundModel {
        let mut outbound = OutboundModel::new(Protocol::Shadowsocks);
        let ProtocolSettings::Shadowsocks(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.address = "1.2.3.4".into();
        settings.port = 8388;
        settings.method = "aes-128-gcm".into();
        settings.password = "secret".into();
        outbound
    }

    const MUST_NOT_FIRE_CODES: &[ValidationCode] = &[
        ValidationCode::VlessFlowUnsupported,
        ValidationCode::VlessEncryptionUnsupported,
        ValidationCode::ShadowsocksMethodUnsupported,
        ValidationCode::Shadowsocks2022KeyInvalid,
        ValidationCode::TrojanSettingsIncomplete,
        ValidationCode::ShadowsocksSettingsIncomplete,
        ValidationCode::SettingsPortZero,
        ValidationCode::SettingsIdNotUuid,
    ];

    #[test]
    fn canonical_protocol_settings_never_fire() {
        for outbound in [
            vless_canonical(),
            vmess_canonical(),
            OutboundModel::new(Protocol::Trojan),
            shadowsocks_canonical(),
        ] {
            let mut outbound = outbound;
            if let ProtocolSettings::Trojan(settings) = &mut outbound.settings {
                settings.address = "1.2.3.4".into();
                settings.port = 443;
                settings.password = "secret".into();
            }
            let issues = validate_outbound(&outbound);
            for code in MUST_NOT_FIRE_CODES {
                assert!(
                    !issues.iter().any(|issue| &issue.code == code),
                    "{code:?} fired on a canonical profile: {issues:#?}"
                );
            }
        }
    }

    #[test]
    fn vless_out_of_vocab_values_fire_errors_with_wire_paths() {
        let mut outbound = vless_canonical();
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-xtls".into();
        settings.encryption = "aes-128-gcm".into();
        settings.port = 0;
        settings.id = "short-not-a-uuid".into();
        let issues = validate_outbound(&outbound);
        for (code, path) in [
            (ValidationCode::VlessFlowUnsupported, "settings.flow"),
            (
                ValidationCode::VlessEncryptionUnsupported,
                "settings.encryption",
            ),
            (ValidationCode::SettingsPortZero, "settings.port"),
            (ValidationCode::SettingsIdNotUuid, "settings.id"),
        ] {
            let issue = finding(&issues, &code).unwrap_or_else(|| {
                panic!("{code:?} must fire on the crafted VLESS profile: {issues:#?}")
            });
            assert_eq!(issue.path.as_deref(), Some(path));
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
        }
    }

    #[test]
    fn vless_encryption_rejects_every_padding_and_key_mismatch_class() {
        // The core reads a part shorter than 20 characters as a padding
        // token (infra/conf/vless.go:352-356). With no key part at all its
        // padding slice runs past the end of the value and panics (:370);
        // a short token after a key part cuts the padding out of that key,
        // so handler creation fails with `failed to use encryption`
        // (proxy/vless/outbound/outbound.go:95). A padding prefix must
        // satisfy the grammar the core's client parses
        // (proxy/vless/encryption/common.go:223-257), and a 1184-byte key
        // must hold ML-KEM-768 coefficients below q = 3329. The model
        // refuses every such shape. Junk in a key stays refused even where
        // the core's decoder skips it (a newline) — the recorded deliberate
        // strictness.
        const X25519: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
        let mlkem = URL_SAFE_NO_PAD.encode([7_u8; 1184]);
        // ML-KEM-768 bodies around the core's coefficient boundary: each of
        // the 384 three-byte chunks of the first 1152 bytes holds two 12-bit
        // little-endian coefficients, both must stay below q = 3329, and the
        // trailing 32-byte rho is unchecked.
        let mlkem_key = |mutate: fn(&mut [u8; 1184])| {
            let mut body = [0_u8; 1184];
            mutate(&mut body);
            URL_SAFE_NO_PAD.encode(body)
        };
        let first_coeff_3328 = mlkem_key(|body| body[1] = 0x0d);
        let first_coeff_3329 = mlkem_key(|body| {
            body[0] = 0x01;
            body[1] = 0x0d;
        });
        let second_coeff_3328 = mlkem_key(|body| body[2] = 0xd0);
        let second_coeff_4080 = mlkem_key(|body| body[2] = 0xff);
        let last_coeff_4080 = mlkem_key(|body| body[1151] = 0xff);
        let rho_max = mlkem_key(|body| {
            body[1] = 0x0d;
            body[1152..].fill(0xff);
        });
        let body_max = mlkem_key(|body| body.fill(0xff));
        // Go's decoder tolerates non-zero trailing bits: the spare bit in
        // the 43rd character decodes to the same 32 bytes.
        let trailing_bits = format!("{}B", &X25519[..42]);
        let cases = [
            // `none`, a real X25519 key, a real ML-KEM key, and keys behind
            // valid padding prefixes stay accepted; only the even-index
            // items in a padding prefix count toward the 65553 total.
            ("none".to_string(), true),
            (format!("mlkem768x25519plus.native.1rtt.{X25519}"), true),
            (format!("mlkem768x25519plus.xorpub.0rtt.{mlkem}"), true),
            (
                format!("mlkem768x25519plus.random.1rtt.100-35-35.{X25519}"),
                true,
            ),
            (
                format!(
                    "mlkem768x25519plus.random.1rtt.100-111-1111.50-0-3333.200-100-2000.{X25519}"
                ),
                true,
            ),
            // A lone empty token joins to the empty padding string the core
            // returns on before parsing (common.go:224-226), so it loads.
            (format!("mlkem768x25519plus.native.1rtt..{X25519}"), true),
            // A fourth `-` field is ignored, exactly as the core reads the
            // first three and drops the rest.
            (
                format!("mlkem768x25519plus.native.1rtt.100-35-35-999.{X25519}"),
                true,
            ),
            // ML-KEM coefficient boundaries: 3328 in either coefficient of
            // the first chunk loads, a 0xFF-filled rho loads, and non-zero
            // trailing bits decode to the same X25519 key.
            (
                format!("mlkem768x25519plus.xorpub.0rtt.{first_coeff_3328}"),
                true,
            ),
            (
                format!("mlkem768x25519plus.xorpub.0rtt.{second_coeff_3328}"),
                true,
            ),
            (format!("mlkem768x25519plus.xorpub.0rtt.{rho_max}"), true),
            (
                format!("mlkem768x25519plus.native.1rtt.{trailing_bits}"),
                true,
            ),
            // A coefficient of 3329 or larger anywhere in the first 1152
            // bytes fails handler creation with `invalid polynomial
            // encoding`, as does a 0xFF-filled body.
            (
                format!("mlkem768x25519plus.xorpub.0rtt.{first_coeff_3329}"),
                false,
            ),
            (
                format!("mlkem768x25519plus.xorpub.0rtt.{second_coeff_4080}"),
                false,
            ),
            (
                format!("mlkem768x25519plus.xorpub.0rtt.{last_coeff_4080}"),
                false,
            ),
            (format!("mlkem768x25519plus.xorpub.0rtt.{body_max}"), false),
            // Every part short: the core panics at config load.
            ("mlkem768x25519plus.native.1rtt.key".to_string(), false),
            ("mlkem768x25519plus.native.1rtt.KEY".to_string(), false),
            ("mlkem768x25519plus.native.1rtt.".to_string(), false),
            ("mlkem768x25519plus.native.1rtt.ab".to_string(), false),
            ("mlkem768x25519plus.native.1rtt.a.b".to_string(), false),
            (
                "mlkem768x25519plus.native.1rtt.key.extra".to_string(),
                false,
            ),
            // A short token after a key part: handler creation fails.
            (format!("mlkem768x25519plus.native.1rtt.{X25519}.ab"), false),
            // A short token before the key part is padding, and this one
            // fails the padding grammar (fewer than three `-` fields).
            (format!("mlkem768x25519plus.native.1rtt.ab.{X25519}"), false),
            // Two empty tokens join to a dot, not to an empty string, and
            // the core refuses that padding item.
            (format!("mlkem768x25519plus.native.1rtt...{X25519}"), false),
            // Padding prefixes the core's grammar refuses: the first item
            // is under 100, an item has two fields, and the even-index
            // total exceeds 65553.
            (
                format!("mlkem768x25519plus.native.1rtt.99-35-35.{X25519}"),
                false,
            ),
            (
                format!("mlkem768x25519plus.native.1rtt.100-35.{X25519}"),
                false,
            ),
            (
                format!(
                    "mlkem768x25519plus.native.1rtt.100-35-65535.100-35-35.100-35-65535.{X25519}"
                ),
                false,
            ),
            // A key-shaped part that decodes to neither 32 nor 1184 bytes,
            // a real key with trailing junk, an extra character, `=` padding
            // (not part of the raw grammar), and a key with a newline the
            // core's decoder skips — the app refuses every byte outside the
            // alphabet, the recorded strictness.
            (
                "mlkem768x25519plus.native.1rtt.AAAAAAAAAAAAAAAAAAAA".to_string(),
                false,
            ),
            (format!("mlkem768x25519plus.native.1rtt.{X25519}!"), false),
            (format!("mlkem768x25519plus.native.1rtt.{X25519}A"), false),
            (format!("mlkem768x25519plus.native.1rtt.{X25519}="), false),
            (format!("mlkem768x25519plus.native.1rtt.{X25519}\n"), false),
        ];
        let mut outbound = vless_canonical();
        for (value, accepted) in cases {
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.encryption = value.clone();
            let issues = validate_outbound(&outbound);
            let reported = finding(&issues, &ValidationCode::VlessEncryptionUnsupported).is_some();
            assert_eq!(!reported, accepted, "{value:?}: {issues:#?}");
        }
    }

    #[test]
    fn vless_empty_states_are_accepted_by_the_model() {
        // `""` encryption/flow/id are the state seam's defaults (a fresh
        // profile before the editor's enforce_invariants normalization);
        // the model accepts them — the required-value rules live in the
        // editor's draft sweep. Fields are cleared *after*
        // `OutboundModel::new` (whose enforce_invariants would already have
        // normalized encryption to "none"); address/port are pinned so no
        // other rule distracts.
        let mut outbound = OutboundModel::new(Protocol::Vless);
        {
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.address = "1.2.3.4".into();
            settings.port = 443;
            settings.id.clear();
            settings.flow.clear();
            settings.encryption.clear();
        }
        let issues = validate_outbound(&outbound);
        for code in MUST_NOT_FIRE_CODES {
            assert!(
                !issues.iter().any(|issue| &issue.code == code),
                "{code:?} must not fire on empty default settings: {issues:#?}"
            );
        }
    }

    #[test]
    fn vmess_port_zero_and_short_id_fire_with_wire_paths() {
        let mut outbound = vmess_canonical();
        let ProtocolSettings::Vmess(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.port = 0;
        settings.id = "b831381d".into(); // 8 chars: sha1-mapped by Xray, refused here
        let issues = validate_outbound(&outbound);
        for code in [
            ValidationCode::SettingsPortZero,
            ValidationCode::SettingsIdNotUuid,
        ] {
            let issue = finding(&issues, &code)
                .unwrap_or_else(|| panic!("{code:?} must fire: {issues:#?}"));
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
        }
        assert_eq!(
            finding(&issues, &ValidationCode::SettingsPortZero)
                .unwrap()
                .path
                .as_deref(),
            Some("settings.port")
        );
        assert_eq!(
            finding(&issues, &ValidationCode::SettingsIdNotUuid)
                .unwrap()
                .path
                .as_deref(),
            Some("settings.id")
        );
    }

    #[test]
    fn trojan_required_values_fire_one_issue_per_missing_field() {
        let outbound = OutboundModel::new(Protocol::Trojan);
        let issues = validate_outbound(&outbound);
        let trojan_issues: Vec<&ValidationIssue> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::TrojanSettingsIncomplete)
            .collect();
        assert_eq!(trojan_issues.len(), 3, "{issues:#?}");
        let mut paths: Vec<&str> = trojan_issues
            .iter()
            .map(|issue| issue.path.as_deref().unwrap())
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            ["settings.address", "settings.password", "settings.port"]
        );
        for issue in trojan_issues {
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
        }
    }

    #[test]
    fn shadowsocks_required_values_and_method_vocabulary() {
        // Defaults: empty address/password/port and an empty method — the
        // essentials fire per field and the empty method is out of the
        // vocabulary (Xray's unknown-cipher error), all Errors.
        let outbound = OutboundModel::new(Protocol::Shadowsocks);
        let issues = validate_outbound(&outbound);
        let mut paths: Vec<&str> = issues
            .iter()
            .filter(|issue| issue.code == ValidationCode::ShadowsocksSettingsIncomplete)
            .map(|issue| issue.path.as_deref().unwrap())
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            ["settings.address", "settings.password", "settings.port"]
        );
        let method_issue = finding(&issues, &ValidationCode::ShadowsocksMethodUnsupported)
            .unwrap_or_else(|| panic!("empty method is unsupported: {issues:#?}"));
        assert_eq!(method_issue.path.as_deref(), Some("settings.method"));
        assert_eq!(method_issue.severity, Severity::Error);
        for issue in issues.iter().filter(|issue| {
            issue.code == ValidationCode::ShadowsocksSettingsIncomplete
                || issue.code == ValidationCode::ShadowsocksMethodUnsupported
        }) {
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
        }

        // The accepted vocabulary mirrors the import whitelist: AEAD methods
        // (case-insensitive, legacy alias spellings included), exact 2022
        // names — and nothing else. Legacy stream ciphers hit the same
        // unknown-cipher load error and are refused.
        let key_32b = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="; // base64 of 32 bytes
        for (method, password) in [
            ("AES-128-GCM", "opaque"),
            ("aead_aes_256_gcm", "opaque"),
            ("chacha20-ietf-poly1305", "opaque"),
            ("xchacha20-poly1305", "opaque"),
            ("aead_xchacha20_poly1305", "opaque"),
            ("2022-blake3-aes-128-gcm", "MDEyMzQ1Njc4OWFiY2RlZg=="),
            ("2022-blake3-aes-256-gcm", key_32b),
            ("2022-blake3-chacha20-poly1305", key_32b),
        ] {
            let mut outbound = shadowsocks_canonical();
            let ProtocolSettings::Shadowsocks(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.method = method.into();
            settings.password = password.into();
            let issues = validate_outbound(&outbound);
            for code in [
                ValidationCode::ShadowsocksMethodUnsupported,
                ValidationCode::Shadowsocks2022KeyInvalid,
            ] {
                assert!(
                    !issues.iter().any(|issue| issue.code == code),
                    "{code:?} fired for accepted method {method:?}: {issues:#?}"
                );
            }
        }

        for method in ["aes-256-cfb", "rc4-md5", "2022-blake3-unsupported"] {
            let mut outbound = shadowsocks_canonical();
            let ProtocolSettings::Shadowsocks(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.method = method.into();
            let issues = validate_outbound(&outbound);
            let issue = finding(&issues, &ValidationCode::ShadowsocksMethodUnsupported)
                .unwrap_or_else(|| panic!("{method:?} must be refused: {issues:#?}"));
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
            assert_eq!(issue.path.as_deref(), Some("settings.method"));
        }
    }

    #[test]
    fn shadowsocks2022_key_rule_gates_the_keys_the_rewritten_core_refuses() {
        // Every key text is built from its bytes: the rule reads the decoded
        // byte count, and a password-shaped literal in the source is what
        // these fixtures must not be.
        let key_16 = base64_run(1, 16);
        let key_16_b = base64_run(2, 16);
        let key_32 = base64_run(b'0', 32);

        // The method name folds case-insensitively (`GetCipherMethod`
        // lowercases before its map lookup), so the mixed-case spelling is
        // the same method the core builds.
        assertions_on_key_rule("2022-BLAKE3-AES-128-GCM", &key_16, false);
        assertions_on_key_rule("2022-blake3-AES-128-GCM", &key_16, false);

        // The core parses each colon-separated part through `ParseKey`: it
        // decodes standard base64, falls back to the raw bytes when the decode
        // fails, and requires exactly the method's key size. Every row below
        // was re-probed on the pinned v26.9.30 binary (`xray run -test`).
        //
        // Accepted: a right-length key in base64 or raw form, and the
        // colon-joined multi-psk form under the AES methods.
        for (method, password) in [
            ("2022-blake3-aes-128-gcm", key_16.as_str()),
            // Raw 16 bytes: base64 decoding fails, so the raw bytes are read.
            ("2022-blake3-aes-128-gcm", &"!".repeat(16)),
            ("2022-blake3-aes-256-gcm", key_32.as_str()),
            ("2022-blake3-aes-256-gcm", &"!".repeat(32)),
            ("2022-blake3-chacha20-poly1305", key_32.as_str()),
            ("2022-blake3-aes-128-gcm", &format!("{key_16}:{key_16_b}")),
            ("2022-blake3-aes-256-gcm", &format!("{key_32}:{key_32}")),
        ] {
            assertions_on_key_rule(method, password, false);
        }

        // Refused: a base64 body longer or shorter than the method's size, a
        // base64 body that happens to be the right *string* length but decodes
        // to the wrong byte count, a right-length key for the wrong method,
        // and the ChaCha20 multi-psk form. (A 24-byte key for AES-128 exited 0
        // under the old core; it now exits 23 with `invalid key`.)
        let longer = base64_run(1, 24);
        let key_15 = base64_run(1, 15);
        for (method, password) in [
            ("2022-blake3-aes-128-gcm", longer.as_str()),
            ("2022-blake3-aes-128-gcm", key_15.as_str()),
            // 16 base64 characters decode to 12 bytes.
            ("2022-blake3-aes-128-gcm", &base64_run(1, 12)),
            // Right string length, wrong decoded length.
            ("2022-blake3-aes-128-gcm", key_16.trim_end_matches('=')),
            ("2022-blake3-aes-256-gcm", key_16.as_str()),
            ("2022-blake3-chacha20-poly1305", key_16.as_str()),
            (
                "2022-blake3-chacha20-poly1305",
                &format!("{key_32}:{key_32}"),
            ),
            // Every part must clear the size, not just the first.
            ("2022-blake3-aes-128-gcm", &format!("{key_16}:{key_15}")),
        ] {
            assertions_on_key_rule(method, password, true);
        }

        // An empty password on a 2022 method belongs to the required-value
        // Error rule only — the key rule must not double-report.
        let mut outbound = shadowsocks_canonical();
        let ProtocolSettings::Shadowsocks(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.method = "2022-blake3-aes-128-gcm".into();
        settings.password = String::new();
        let issues = validate_outbound(&outbound);
        assert!(
            issues.iter().any(|issue| {
                issue.code == ValidationCode::ShadowsocksSettingsIncomplete
                    && issue.path.as_deref() == Some("settings.password")
            }),
            "empty 2022 password must stay an Error: {issues:#?}"
        );
        assert!(
            finding(&issues, &ValidationCode::Shadowsocks2022KeyInvalid).is_none(),
            "an empty 2022 password belongs to the required-value rule alone: {issues:#?}"
        );

        // Non-2022 methods treat the password as opaque.
        assertions_on_key_rule("aes-256-gcm", &"garbage".repeat(2), false);
    }

    /// Standard base64 of `count` copies of `byte`: the Shadowsocks-2022 key
    /// rules read the decoded byte count, so every key text a row needs is
    /// built here rather than spelled out.
    fn base64_run(byte: u8, count: usize) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(vec![byte; count])
    }

    /// The one `Shadowsocks2022KeyInvalid` finding `password` draws under
    /// `method`: `refused` says whether the core refuses the key, and the
    /// finding must then be a gating Error at `settings.password`; otherwise it
    /// must stay silent.
    fn assertions_on_key_rule(method: &str, password: &str, refused: bool) {
        let mut outbound = shadowsocks_canonical();
        let ProtocolSettings::Shadowsocks(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.method = method.into();
        settings.password = password.into();
        let issues = validate_outbound(&outbound);
        let finding = finding(&issues, &ValidationCode::Shadowsocks2022KeyInvalid);
        if refused {
            let issue = finding
                .unwrap_or_else(|| panic!("{method}: a refused key must report: {issues:#?}"));
            assert_eq!(
                issue.severity,
                Severity::Error,
                "{method}: a refusal is an error"
            );
            assert_eq!(issue.path.as_deref(), Some("settings.password"));
            assert!(
                issues.iter().any(|issue| issue.severity == Severity::Error),
                "{method}: a refusal gates"
            );
        } else {
            assert!(
                finding.is_none(),
                "{method}: the key rule must stay silent: {issues:#?}"
            );
        }
    }

    #[test]
    fn uuid_rule_fires_only_for_nonempty_noncanonical_ids() {
        for id in [
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            "B831381D-6324-4D53-AD4F-8CDA48B30811",
        ] {
            let mut outbound = vless_canonical();
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.id = id.into();
            let issues = validate_outbound(&outbound);
            assert!(
                !issues
                    .iter()
                    .any(|issue| issue.code == ValidationCode::SettingsIdNotUuid),
                "canonical id {id:?} must pass: {issues:#?}"
            );
        }
        // The divergence: Xray sha1-maps 1-30-char strings to a deterministic
        // v5 UUID (different account) and accepts 32-36-char hex forms;
        // broccoli's policy is UUID-only (the single `is_canonical_uuid`
        // predicate the import check_uuid and the UI field validators call).
        for id in [
            "b831381d-6324-4d53-ad4f-8cda48b3081",
            "some-account-name",
            "not a uuid",
            "b831381d-6324-4d53-ad4f-8cda48b3081x",
        ] {
            let mut outbound = vless_canonical();
            let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
                unreachable!()
            };
            settings.id = id.into();
            let issues = validate_outbound(&outbound);
            let issue = finding(&issues, &ValidationCode::SettingsIdNotUuid)
                .unwrap_or_else(|| panic!("non-canonical id {id:?} must be refused: {issues:#?}"));
            assert_eq!(issue.severity, Severity::Error, "{issue:?}");
            assert_eq!(issue.path.as_deref(), Some("settings.id"));
        }
    }

    #[test]
    fn mux_vision_warning_still_fires_exactly_as_before() {
        // Regression guard: the VLESS additions must not disturb
        // the mux/vision Warning rule (same predicate, same path).
        let mut outbound = vless_canonical();
        let ProtocolSettings::Vless(settings) = &mut outbound.settings else {
            unreachable!()
        };
        settings.flow = "xtls-rprx-vision".into();
        // Vision needs TLS/REALITY to be error-free; the mux warning must
        // still be the only finding besides it.
        let _ = outbound.stream.select_security(Security::Tls);
        outbound.mux.enabled = true;
        outbound.mux.concurrency = Some(8);
        let issues = validate_outbound(&outbound);
        let mux_issue = finding(&issues, &ValidationCode::MuxWithVisionFlow)
            .unwrap_or_else(|| panic!("mux+vision must keep warning: {issues:#?}"));
        assert_eq!(mux_issue.severity, Severity::Warning, "{mux_issue:?}");
        assert_eq!(mux_issue.path.as_deref(), Some("mux"));
        // The canonical profile stays error-free end to end.
        assert!(
            !issues.iter().any(|issue| issue.severity == Severity::Error),
            "no Error may fire on the canonical mux+vision profile: {issues:#?}"
        );
    }

    #[test]
    fn moved_editor_predicates_keep_their_vocabularies() {
        for accepted in ["origin", "srcip", "127.0.0.1", "10.0.0.0/8", "fd00::/64"] {
            assert!(send_through_supported(accepted), "{accepted:?}");
        }
        for refused in ["bogus", "", "10.0.0.0/33"] {
            assert!(!send_through_supported(refused), "{refused:?}");
        }

        for accepted in ["allow", "block", "ALLOW", "Block"] {
            assert!(freedom_final_rule_supported(accepted), "{accepted:?}");
        }
        for refused in ["", "proxy", "deny"] {
            assert!(!freedom_final_rule_supported(refused), "{refused:?}");
        }

        for accepted in DNS_OUT_ACTIONS {
            assert!(dns_out_action_supported(accepted), "{accepted:?}");
        }
        // The core lowercases the action before its switch, so a case variant
        // and a folded `İ` spelling are the same action to it.
        for accepted in ["Direct", "h\u{130}jack"] {
            assert!(dns_out_action_supported(accepted), "{accepted:?}");
        }
        for refused in ["", "proxy", "direct4"] {
            assert!(!dns_out_action_supported(refused), "{refused:?}");
        }
    }
}
