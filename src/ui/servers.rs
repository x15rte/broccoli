//! Servers screen: profile list with latency badges on the
//! left, tabbed full-coverage outbound editor on the right. Covers all 12
//! protocols, all 7 transports, TLS/REALITY, mux, and the advanced envelope
//! (sendThrough / targetStrategy / finalmask / sockopt).

use base64::Engine as _;
use std::fmt::Write as _;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use egui::{Color32, RichText, Stroke, StrokeKind};

use crate::i18n::{Key, t, t_fmt, validation_issue_message, validation_message};
use crate::links;
use crate::model::inbound::{BLOCK_OUTBOUND_TAG, DIRECT_OUTBOUND_TAG};
use crate::model::outbound::{
    BlackholeResponse, DnsOutRule, Fragment, FreedomFinalRule, MuxModel, Noise, VlessReverse,
    WireguardPeer, blackhole_custom_response_data_decodes, blackhole_response_is_custom,
    blackhole_response_type_supported, is_valid_wireguard_key,
};
use crate::model::settings::Language;
use crate::model::stream::{MAX_XHTTP_DOWNLOAD_DEPTH, MasqueradeCfg};
use crate::model::validation::{
    self, DNS_OUT_ACTIONS, Severity, ValidationCode, ValidationIssue, XUDP_PROXY_UDP443_MODES,
    dns_out_action_supported, freedom_final_rule_supported, mux_conflicts_with_vision_flow,
    pinned_peer_cert_sha256_valid, reality_mldsa65_verify_valid, reality_public_key_valid,
    send_through_supported, server_name_implausible, tls_version_rank, validate_finalmask,
    validate_outbound, validate_sockopt, vmess_security_supported,
};
use crate::model::{
    CustomSockopt, FinalmaskTcpMask, FinalmaskUdpMask, HappyEyeballs, HttpCamouflageRequest,
    HttpCamouflageResponse, Int32Range, Network, OutboundModel, Protocol, ProtocolSettings,
    RawHeader, Security, ServerProfile, ServersFile, Settings, Sniffing, SockoptModel, StreamModel,
    TlsCert, WsSettings, XmuxConfig,
};
use crate::rt::{
    CoreCmd, LatencyProbeResult, ProfileValidationOrigin, ProfileValidationReply,
    ProfileValidationRequest, ToolTarget,
};
use crate::ui::inbounds::sniffing_editor;
use crate::ui::request::{Request, Terminal};
use crate::ui::status::{StatusColors, status_colors_of};
use crate::ui::widgets;
use crate::ui::{
    FeedbackLevel, UiCtx, format_latency_probe_feedback, format_single_latency_probe_feedback,
};

mod finalmask_editors;
mod keygen;
mod raw_editor;
mod validators;

use finalmask_editors::{
    finalmask_move_buttons, finalmask_quic_editor, finalmask_tcp_settings_editor,
    finalmask_udp_settings_editor,
};
use keygen::{
    PRIV_PREFIXES, PUB_PREFIXES, ca_pins_from_probe_output, gen_short_id, keygen_value,
    leaf_pin_from_probe_output, run_xray_bounded,
};
use raw_editor::{FieldKey, PemBuf, RawBuffers, RawField, evict_owned_buffers, pem_lines_editor};
use validators::{
    v_optional_wg_key, v_required, v_uuid, v_uuid_required, v_vless_encryption,
    v_vless_encryption_required, v_wg_key, v_wg_remote_dns_entry,
};

/// Editor-selectable uTLS fingerprint options for the TLS and realm-TLS
/// combos, in display order — the canonical model vocabulary's editor table
/// (src/model/fingerprint.rs), which excludes the wire-only names the editor
/// has never offered. The REALITY combo offers its own trimmed option set
/// ([`fingerprint_allowed`]).
const FINGERPRINTS: &[&str] = crate::model::fingerprint::FINGERPRINTS;

// The combo tables below are the model's own field vocabularies
// (src/model/validation.rs), where the predicate that judges each value
// lives: an alias where the wire vocabulary includes the combo's empty
// "(default)" entry, and the same vocabulary spelled element-wise behind that
// entry where the empty string is not a value the rule accepts (a fresh
// profile's field is empty, and the combo must still offer the way back to
// it). A field's spellings live in the model, never here.
const TARGET_STRATEGIES: &[&str] = validation::TARGET_STRATEGY_OPTIONS;
const WG_TARGET_STRATEGIES: &[&str] = validation::WG_TARGET_STRATEGY_OPTIONS;
const VMESS_SECURITY: &[&str] = validation::VMESS_SECURITY_OPTIONS;
const XHTTP_MODES: &[&str] = validation::XHTTP_MODE_OPTIONS;
const X_PADDING_PLACEMENTS: &[&str] = validation::X_PADDING_PLACEMENT_OPTIONS;
const SESSION_PLACEMENTS: &[&str] = validation::SESSION_ID_PLACEMENT_OPTIONS;
const UPLINK_PLACEMENTS: &[&str] = validation::UPLINK_DATA_PLACEMENT_OPTIONS;
const PADDING_METHODS: &[&str] = validation::XPADDING_METHOD_OPTIONS;

/// The Shadowsocks method combo's display options: the empty "(default)"
/// entry a fresh profile starts from, then the model method vocabulary
/// spelled element-wise so the two can never drift.
const SS_METHODS: [&str; validation::SS_METHOD_OPTIONS.len() + 1] = [
    "",
    validation::SS_METHOD_OPTIONS[0],
    validation::SS_METHOD_OPTIONS[1],
    validation::SS_METHOD_OPTIONS[2],
    validation::SS_METHOD_OPTIONS[3],
    validation::SS_METHOD_OPTIONS[4],
    validation::SS_METHOD_OPTIONS[5],
    validation::SS_METHOD_OPTIONS[6],
];

/// The TLS min/max version combos' display options: the empty "(default)"
/// entry, then the model version vocabulary element-wise.
const TLS_VERSIONS: [&str; validation::TLS_VERSION_OPTIONS.len() + 1] = [
    "",
    validation::TLS_VERSION_OPTIONS[0],
    validation::TLS_VERSION_OPTIONS[1],
    validation::TLS_VERSION_OPTIONS[2],
    validation::TLS_VERSION_OPTIONS[3],
];

/// The VLESS flow combo's display options: the empty "(default)" entry a
/// plain profile carries, then the model's vision-flow vocabulary
/// element-wise (the two XRV spellings Xray's servers accept).
const VLESS_FLOW: [&str; validation::VISION_FLOW_OPTIONS.len() + 1] = [
    "",
    validation::VISION_FLOW_OPTIONS[0],
    validation::VISION_FLOW_OPTIONS[1],
];

/// The uplink placement options the combos off `packet-up` offer: the model
/// vocabulary minus the placements the cross-field rule refuses there
/// (cookies and headers carry the upload only in the packet-up form), so the
/// stream-up/stream-one tables are the first entries of the model list.
const UPLINK_STREAM_PLACEMENTS: [&str; 3] = [
    validation::UPLINK_DATA_PLACEMENT_OPTIONS[0],
    validation::UPLINK_DATA_PLACEMENT_OPTIONS[1],
    validation::UPLINK_DATA_PLACEMENT_OPTIONS[2],
];

// ---------- delete-confirmation reference scan ----------

fn server_reference_paths(
    servers: &ServersFile,
    settings: &Settings,
    profile_id: &str,
) -> Vec<String> {
    let Some(tag) = servers
        .profiles
        .iter()
        .find(|profile| profile.id == profile_id)
        .map(ServerProfile::tag)
    else {
        return Vec::new();
    };
    let mut references = Vec::new();
    for (index, rule) in settings.routing.rules.iter().enumerate() {
        if rule.outbound_tag == tag {
            references.push(format!("routing.rules[{}].outboundTag", index + 1));
        }
    }
    for (index, balancer) in settings.routing.balancers.iter().enumerate() {
        if balancer.fallback_tag == tag {
            references.push(format!("routing.balancers[{}].fallbackTag", index + 1));
        }
    }
    for (index, profile) in servers.profiles.iter().enumerate() {
        if profile.id == profile_id {
            continue;
        }
        let label = if profile.name.is_empty() {
            profile.tag()
        } else {
            profile.name.clone()
        };
        if profile
            .outbound
            .stream
            .sockopt
            .as_ref()
            .is_some_and(|sockopt| sockopt.dialer_proxy == tag)
        {
            references.push(format!(
                "servers[{}] ({label}).streamSettings.sockopt.dialerProxy",
                index + 1
            ));
        }
    }
    references
}

// ---------- editor validation sweep ----------

/// A server draft's address field must carry something: a fresh draft starts
/// empty and the editor refuses to commit it. Protocols whose model rule
/// judges the address themselves (Trojan/Shadowsocks completeness) do not
/// reach here.
fn require_address(blocking: &mut Vec<ValidationIssue>, address: &str) {
    if address.trim().is_empty() {
        blocking.push(ValidationIssue::error(
            ValidationCode::ServerAddressRequired,
        ));
    }
}

/// Empty-address / port-0 draft essentials for the protocols with no model
/// rule for them (the VLESS/VMess port-0 and non-UUID-id pushes are the
/// model's `SettingsPortZero` / `SettingsIdNotUuid` instead — one message
/// channel per value).
fn require_remote(blocking: &mut Vec<ValidationIssue>, address: &str, port: u16) {
    require_address(blocking, address);
    if port == 0 {
        blocking.push(ValidationIssue::error(ValidationCode::ServerPortRequired));
    }
}

fn runnable_fragment() -> Fragment {
    Fragment {
        length: Some(Int32Range::single(100)),
        interval: Some(Int32Range::single(10)),
        ..Default::default()
    }
}

fn fragment_is_valid(fragment: &Fragment) -> bool {
    let packets_valid = matches!(
        fragment.packets.to_ascii_lowercase().as_str(),
        "" | "tlshello"
    ) || Int32Range::parse(&fragment.packets)
        .is_some_and(|range| range.from > 0 && range.to >= range.from);
    let length_valid = fragment
        .length
        .is_some_and(|range| range.from > 0 && range.to >= range.from);
    let interval_valid = fragment
        .interval
        .is_some_and(|range| range.from >= 0 && range.to >= range.from);
    packets_valid && length_valid && interval_valid
}

fn runnable_noise() -> Noise {
    Noise {
        r#type: "str".into(),
        packet: "padding".into(),
        ..Default::default()
    }
}

fn noise_is_valid(noise: &Noise) -> bool {
    let packet_valid = match noise.r#type.as_str() {
        "rand" => Int32Range::parse(&noise.packet)
            .is_some_and(|range| range.from > 0 && range.to >= range.from),
        "str" => true,
        "hex" => {
            noise.packet.len().is_multiple_of(2)
                && noise.packet.bytes().all(|byte| byte.is_ascii_hexdigit())
        }
        "base64" => {
            let normalized = noise
                .packet
                .replace('+', "-")
                .replace('/', "_")
                .replace('=', "");
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(normalized)
                .is_ok()
        }
        _ => false,
    };
    let apply_to_valid = matches!(
        noise.apply_to.to_ascii_lowercase().as_str(),
        "" | "ip" | "all" | "ipv4" | "ipv6"
    );
    packet_valid && apply_to_valid
}

fn runnable_final_rule() -> FreedomFinalRule {
    FreedomFinalRule {
        action: "allow".into(),
        ..Default::default()
    }
}

/// The DNS-rule action combo's display options: the empty "(default)"
/// entry the combo shows for a fresh rule (the rule itself rejects the
/// empty action), then the model vocabulary [`DNS_OUT_ACTIONS`] spelled
/// element-wise so the two can never drift.
const DNS_RULE_ACTION_OPTIONS: [&str; DNS_OUT_ACTIONS.len() + 1] = [
    "",
    DNS_OUT_ACTIONS[0],
    DNS_OUT_ACTIONS[1],
    DNS_OUT_ACTIONS[2],
    DNS_OUT_ACTIONS[3],
];

/// One full editor validation sweep, as findings: the model rules for the
/// outbound, its stream security and the transport's own blocks, plus the
/// draft requirements the editor owns — the empty state a fresh draft starts
/// from, and the value only the widget being typed in can judge. Nothing here
/// is rendered; [`EditorValidationFindings::render`] turns a sweep into the
/// strings the lists and the inline verdicts show, once per (draft
/// generation, language).
#[derive(Default)]
struct EditorValidationFindings {
    /// Blocking findings (Severity::Error) — the only half that gates
    /// Validate-and-save and the leave modal's Save.
    blocking: Vec<ValidationIssue>,
    /// Advisory findings (Severity::Warning) — rendered amber under their own
    /// header; never gate anything.
    advisory: Vec<ValidationIssue>,
    /// The Advanced tab's inline finalmask verdict: `validate_finalmask`
    /// findings in model order (TCP masks, UDP masks, QUIC params).
    finalmask: Vec<ValidationIssue>,
    /// The Advanced tab's inline `stream.sockopt` verdict.
    stream_sockopt: Vec<ValidationIssue>,
    /// The Security tab's inline verdict for the TLS settings' ECH DNS-query
    /// socket options (`stream.tlsSettings.echSockopt`).
    ech_sockopt: Vec<ValidationIssue>,
}

/// The rendered form of one sweep: one `path: message` string per finding, in
/// the sweep's order. Rebuilt when the draft generation or the language
/// moves, so no paint path renders a finding.
#[derive(Default)]
struct EditorValidationRender {
    blocking: Vec<String>,
    advisory: Vec<String>,
    finalmask: Vec<String>,
    stream_sockopt: Vec<String>,
    ech_sockopt: Vec<String>,
    /// The Basic tab's inline outbound verdicts: the blocking findings whose
    /// code names a public-endpoint transport-security rule.
    basic_inline: Vec<String>,
}

/// Render one finding list through the shared i18n seam.
fn render_findings<'a>(
    findings: impl Iterator<Item = &'a ValidationIssue>,
    lang: Language,
) -> Vec<String> {
    findings
        .map(|issue| validation_issue_message(issue, lang))
        .collect()
}

/// True for the public-endpoint transport-security rules the Basic tab
/// renders inline at the fields they name — the same findings the error list
/// carries, filtered by code where they render instead of re-derived.
fn basic_tab_inline_verdict(code: &ValidationCode) -> bool {
    matches!(
        code,
        ValidationCode::VisionRequiresTlsOrReality
            | ValidationCode::PublicVlessRequiresTlsOrEncryption
            | ValidationCode::PublicTrojanRequiresTlsOrReality
    )
}

impl EditorValidationFindings {
    /// The strings the editor shows for this sweep, in its own order.
    fn render(&self, lang: Language) -> EditorValidationRender {
        EditorValidationRender {
            blocking: render_findings(self.blocking.iter(), lang),
            advisory: render_findings(self.advisory.iter(), lang),
            finalmask: render_findings(self.finalmask.iter(), lang),
            stream_sockopt: render_findings(self.stream_sockopt.iter(), lang),
            ech_sockopt: render_findings(self.ech_sockopt.iter(), lang),
            basic_inline: render_findings(
                self.blocking
                    .iter()
                    .filter(|issue| basic_tab_inline_verdict(&issue.code)),
                lang,
            ),
        }
    }
}

/// The Advanced tab's inline finalmask verdict, in model order (TCP masks,
/// UDP masks, QUIC params) — the exact findings the tab renders under the
/// mask list.
fn finalmask_findings(profile: &ServerProfile) -> Vec<ValidationIssue> {
    profile
        .outbound
        .stream
        .finalmask
        .as_ref()
        .map_or_else(Vec::new, validate_finalmask)
}

/// `validate_sockopt` findings for one sockopt block, under the wire path
/// prefix its usage mounts it at.
fn sockopt_findings(sockopt: &SockoptModel, usage: SockoptUsage) -> Vec<ValidationIssue> {
    validate_sockopt(sockopt, usage.path_prefix())
}

/// The sockopt blocks' inline verdicts for one draft: the stream's own
/// `stream.sockopt` block and — when TLS carries ECH — the
/// `stream.tlsSettings.echSockopt` block.
fn sockopt_findings_for(profile: &ServerProfile) -> (Vec<ValidationIssue>, Vec<ValidationIssue>) {
    let stream = &profile.outbound.stream;
    let stream_findings = stream
        .sockopt
        .as_ref()
        .map(|sockopt| sockopt_findings(sockopt, SockoptUsage::Stream))
        .unwrap_or_default();
    // Only the TLS security mode renders the ECH block, mirroring the model
    // sweep's condition in `validate_outbound`.
    let ech_findings = stream
        .tls_settings
        .as_ref()
        .filter(|_| stream.security == Security::Tls)
        .and_then(|tls| tls.ech_sockopt.as_ref())
        .map(|sockopt| sockopt_findings(sockopt, SockoptUsage::EchDnsQuery))
        .unwrap_or_default();
    (stream_findings, ech_findings)
}

fn editor_validation_findings(profile: &ServerProfile) -> EditorValidationFindings {
    let mut blocking: Vec<ValidationIssue> = Vec::new();
    let mut advisory: Vec<ValidationIssue> = Vec::new();
    let (stream_sockopt, ech_sockopt) = sockopt_findings_for(profile);
    let finalmask = finalmask_findings(profile);
    if profile.outbound.protocol != profile.outbound.settings.protocol() {
        return EditorValidationFindings {
            blocking: vec![ValidationIssue::error(
                ValidationCode::ProtocolSettingsMismatch,
            )],
            advisory,
            finalmask,
            stream_sockopt,
            ech_sockopt,
        };
    }

    match &profile.outbound.settings {
        ProtocolSettings::Vless(settings) => {
            // Port 0, out-of-vocab flow/encryption, and non-UUID ids are
            // model rules below; only the empty-address draft requirement and
            // the empty-value "must choose" states are editor rules (the
            // model deliberately accepts "" as the default/empty state).
            require_address(&mut blocking, &settings.address);
            if settings.id.is_empty() {
                blocking.push(ValidationIssue::error(ValidationCode::VlessIdRequired));
            }
            if settings.encryption.is_empty() {
                blocking.push(ValidationIssue::error(
                    ValidationCode::VlessEncryptionRequired,
                ));
            }
            if settings
                .reverse
                .as_ref()
                .is_some_and(|reverse| reverse.tag.trim().is_empty())
            {
                blocking.push(ValidationIssue::error(
                    ValidationCode::VlessReverseTagRequired,
                ));
            }
        }
        ProtocolSettings::Vmess(settings) => {
            // Port 0 and non-UUID ids are model rules below; the
            // empty-address draft requirement and the empty-id "required"
            // state are editor rules.
            require_address(&mut blocking, &settings.address);
            if settings.id.is_empty() {
                blocking.push(ValidationIssue::error(ValidationCode::VmessIdRequired));
            }
            if !vmess_security_supported(&settings.security) {
                blocking.push(ValidationIssue::error(
                    ValidationCode::VmessSecurityUnsupported,
                ));
            }
        }
        ProtocolSettings::Trojan(_) => {
            // Server essentials (empty address/password, port 0) are model
            // rules below — the editor pushes were duplicates of the same
            // predicates on the same values.
        }
        ProtocolSettings::Shadowsocks(_) => {
            // Method vocabulary, SS-2022 key material, and server essentials
            // (address/password/port) are model rules below — the editor
            // pushes were duplicates; the level range is a model invariant
            // too.
        }
        ProtocolSettings::Socks(settings) => {
            require_remote(&mut blocking, &settings.address, settings.port);
        }
        ProtocolSettings::Http(settings) => {
            require_remote(&mut blocking, &settings.address, settings.port);
        }
        ProtocolSettings::Wireguard(settings) => {
            if !is_valid_wireguard_key(&settings.secret_key) {
                blocking.push(ValidationIssue::error(
                    ValidationCode::WireguardSecretKeyInvalid,
                ));
            }
            if settings
                .reserved
                .as_ref()
                .is_some_and(|reserved| reserved.len() != 3)
            {
                blocking.push(ValidationIssue::error(
                    ValidationCode::WireguardReservedKeyBytes,
                ));
            }
            if settings.peers.is_empty() {
                blocking.push(ValidationIssue::error(
                    ValidationCode::WireguardPeersRequired,
                ));
            }
            if settings
                .peers
                .iter()
                .any(|peer| !is_valid_wireguard_key(&peer.public_key))
            {
                blocking.push(ValidationIssue::error(
                    ValidationCode::WireguardPeerPublicKeyRequired,
                ));
            }
            if settings
                .peers
                .iter()
                .any(|peer| peer.endpoint.trim().is_empty())
            {
                blocking.push(ValidationIssue::error(
                    ValidationCode::WireguardPeerEndpointRequired,
                ));
            }
            if settings.peers.iter().any(|peer| {
                !peer.pre_shared_key.is_empty() && !is_valid_wireguard_key(&peer.pre_shared_key)
            }) {
                blocking.push(ValidationIssue::error(
                    ValidationCode::WireguardPresharedKeyInvalid,
                ));
            }
        }
        ProtocolSettings::Freedom(settings) => {
            if settings
                .fragment
                .as_ref()
                .is_some_and(|fragment| !fragment_is_valid(fragment))
            {
                blocking.push(ValidationIssue::error(
                    ValidationCode::FreedomFragmentInvalid,
                ));
            }
            if settings.noises.iter().any(|noise| !noise_is_valid(noise)) {
                blocking.push(ValidationIssue::error(ValidationCode::FreedomNoiseInvalid));
            }
            // finalRules actions are a model rule below (validate_outbound).
        }
        ProtocolSettings::Blackhole(_) => {
            // The response type is a model invariant reported below.
        }
        ProtocolSettings::Dns(_) => {
            // The rule actions are a model rule below (validate_outbound).
        }
        ProtocolSettings::Loopback(settings) => {
            if settings.inbound_tag.trim().is_empty() {
                blocking.push(ValidationIssue::error(ValidationCode::LoopbackTagRequired));
            }
        }
        ProtocolSettings::Hysteria(settings) => {
            require_remote(&mut blocking, &settings.address, settings.port);
            // version is a model invariant reported below.
        }
    }
    // Model validation pass: protocol + stream + transport security in one
    // sweep. Advisory findings (Severity::Warning) never block save — they
    // render amber in the warnings list instead of the error list.
    for issue in validate_outbound(&profile.outbound) {
        match issue.severity {
            Severity::Warning => advisory.push(issue),
            Severity::Error => blocking.push(issue),
        }
    }

    let stream = &profile.outbound.stream;
    // Editor stream checks not modeled by the validation pass: a header map's
    // JSON values (the model keeps header maps as JSON values and judges only
    // the ws/httpupgrade pair) and two keystroke-only rules. The xhttp enum
    // vocabulary, the cookie/header-placement and uplink-GET mode cross-field
    // rules, the xmux exclusivity rule, and the sessionID room/table
    // constraints are model rules above (validate_outbound), one message
    // channel per value.
    if stream
        .xhttp_settings
        .as_ref()
        .is_some_and(|settings| settings.headers.values().any(|value| !value.is_string()))
    {
        blocking.push(ValidationIssue::error(
            ValidationCode::HeaderValueNotString(Network::Xhttp),
        ));
    }
    if stream
        .ws_settings
        .as_ref()
        .is_some_and(|settings| settings.headers.values().any(|value| !value.is_string()))
    {
        blocking.push(ValidationIssue::error(
            ValidationCode::HeaderValueNotString(Network::Ws),
        ));
    }
    if stream
        .httpupgrade_settings
        .as_ref()
        .is_some_and(|settings| settings.headers.values().any(|value| !value.is_string()))
    {
        blocking.push(ValidationIssue::error(
            ValidationCode::HeaderValueNotString(Network::Httpupgrade),
        ));
    }

    // Keystroke-only stream checks the model cannot express: TLS/REALITY
    // fingerprint / publicKey / shortId / spiderX / mldsa65Verify /
    // pinnedPeerCertSha256 formats and the TLS version vocabulary are model
    // rules above (validate_outbound), and the in-range min > max inversion is
    // `TlsMinExceedsMax`. What stays here is the fromMitm ALPN interaction and
    // the cert-file-or-PEM presence rule — the model cannot know which
    // certificate row the user is editing.
    if stream.security == Security::Tls
        && let Some(tls) = &stream.tls_settings
    {
        if tls.alpn.len() > 1 && tls.alpn.iter().any(|value| value == "fromMitm") {
            blocking.push(ValidationIssue::error(ValidationCode::TlsFromMitmAlpnShort));
        }
        if tls.certificates.iter().any(|certificate| {
            certificate.certificate_file.trim().is_empty()
                && certificate
                    .certificate
                    .iter()
                    .all(|line| line.trim().is_empty())
        }) {
            blocking.push(ValidationIssue::error(
                ValidationCode::TlsCertificateRequired,
            ));
        }
    }

    EditorValidationFindings {
        blocking,
        advisory,
        finalmask,
        stream_sockopt,
        ech_sockopt,
    }
}

/// Editor combo membership for one fingerprint value: the TLS and realm-TLS
/// combos list the canonical vocabulary's editor table
/// (`src/model/fingerprint.rs`); the REALITY combo lists only
/// [`REALITY_EDITOR_OPTIONS`](crate::model::fingerprint::REALITY_EDITOR_OPTIONS),
/// the empty default plus the browser names upstream's own tests exercise.
/// This filters which options the combo lists — validation itself is the
/// model pass (the fingerprint codes) and the inline verdict in
/// [`fingerprint_editor`] uses the same wire predicates the model runs, so a
/// stored name outside the option set still displays and round-trips
/// unchanged.
fn fingerprint_allowed(name: &str, reality: bool) -> bool {
    if reality {
        crate::model::fingerprint::REALITY_EDITOR_OPTIONS.contains(&name)
    } else {
        crate::model::fingerprint::FINGERPRINTS.contains(&name)
    }
}

/// Fingerprint combo with inline verdict and repair. `reject_code` is the
/// model code whose predicate and message govern this fingerprint context —
/// the stream TLS block (`TlsFingerprintUnsupported`), the stream REALITY
/// block (`RealityFingerprintUnsupported`, the only context that excludes
/// `unsafe`/`hellogolang`), or the finalmask realm-TLS block
/// (`FinalmaskRealmFingerprintUnknown`). The inline hint renders that code's
/// own message (the single i18n text), so the combo can never disagree with
/// the model about a loaded value. The REALITY context additionally shows
/// the `RealityFingerprintUntested` advisory for a wire-valid value outside
/// the known-good set the combo offers — amber, never a gate, with the same
/// message the editor's warnings list renders.
fn fingerprint_editor(
    ui: &mut egui::Ui,
    lang: Language,
    v: &mut String,
    reject_code: ValidationCode,
) -> bool {
    let reality = reject_code == ValidationCode::RealityFingerprintUnsupported;
    let allowed = |name: &str| fingerprint_allowed(name, reality);
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label("fingerprint");
        let default = t(lang, Key::SrvDefault);
        let shown = if v.is_empty() { default } else { v.as_str() };
        egui::ComboBox::from_id_salt(ui.auto_id_with(("fingerprint", reality)))
            .selected_text(shown)
            .show_ui(ui, |ui| {
                for option in FINGERPRINTS.iter().copied().filter(|name| allowed(name)) {
                    let text = if option.is_empty() { default } else { option };
                    changed |= ui.selectable_value(v, option.to_string(), text).changed();
                }
            });
    });
    // Inline verdict from the same predicates the model validation pass runs
    // (wire vocabulary, ASCII-case-insensitive; REALITY additionally
    // excludes unsafe/hellogolang) — values the combo cannot offer (loaded
    // profiles) still surface the model message here and next to the field.
    let rejected = if reality {
        !crate::model::fingerprint::reality_wire_supported(v)
    } else {
        !crate::model::fingerprint::wire_validation_supported(v)
    };
    if rejected {
        ui.horizontal(|ui| {
            ui.colored_label(
                status_colors_of(ui).err,
                validation_message(&reject_code, lang),
            );
            if ui.small_button(t(lang, Key::SrvUseDefault)).clicked() {
                v.clear();
                changed = true;
            }
        });
    } else if reality && crate::model::fingerprint::reality_fingerprint_outside_known_good(v) {
        // Advisory verdict (Severity::Warning, never a gate): the wire
        // accepts the name and the profile keeps it, but upstream's REALITY
        // scenarios exercise only the known-good three, so the field shows
        // the same model message the editor's warnings list renders.
        let stored: &dyn std::fmt::Display = v;
        ui.colored_label(
            status_colors_of(ui).warn,
            t_fmt(lang, Key::OutboundRealityFingerprintUntested, &[stored]),
        );
    }
    changed
}

/// Optional string combo; `None` is "(unset)".
fn opt_combo_str(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    v: &mut Option<String>,
    options: &[&str],
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label(label);
        let shown = v.as_deref().unwrap_or_else(|| t(lang, Key::SrvUnset));
        egui::ComboBox::from_id_salt(ui.auto_id_with(label))
            .selected_text(shown)
            .show_ui(ui, |ui| {
                if ui
                    .selectable_label(v.is_none(), t(lang, Key::SrvUnset))
                    .clicked()
                {
                    *v = None;
                    changed = true;
                }
                for opt in options {
                    let sel = v.as_deref() == Some(*opt);
                    if ui.selectable_label(sel, *opt).clicked() {
                        *v = Some((*opt).to_string());
                        changed = true;
                    }
                }
            });
    });
    changed
}

/// Optional string: "set" checkbox + text field.
fn opt_string(ui: &mut egui::Ui, label: &str, v: &mut Option<String>, hint: &str) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        let mut set = v.is_some();
        if ui.checkbox(&mut set, label).changed() {
            *v = if set { Some(String::new()) } else { None };
            changed = true;
        }
        if let Some(s) = v.as_mut() {
            changed |= ui
                .add(
                    egui::TextEdit::singleline(s)
                        .hint_text(hint)
                        .desired_width(f32::INFINITY),
                )
                .changed();
        }
    });
    changed
}

const SOCKOPT_DOMAIN_STRATEGIES: &[&str] = validation::SOCKOPT_DOMAIN_STRATEGY_OPTIONS;
const SOCKOPT_ADDRESS_PORT_STRATEGIES: &[&str] = validation::SOCKOPT_ADDRESS_PORT_STRATEGY_OPTIONS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TcpFastOpenMode {
    Unset,
    Enabled,
    Disabled,
    Number,
    Invalid,
}

fn tcp_fast_open_editor(
    ui: &mut egui::Ui,
    lang: Language,
    value: &mut Option<serde_json::Value>,
) -> bool {
    let mut mode = match value.as_ref() {
        None => TcpFastOpenMode::Unset,
        Some(serde_json::Value::Bool(true)) => TcpFastOpenMode::Enabled,
        Some(serde_json::Value::Bool(false)) => TcpFastOpenMode::Disabled,
        Some(serde_json::Value::Number(_)) => TcpFastOpenMode::Number,
        Some(_) => TcpFastOpenMode::Invalid,
    };
    let original_mode = mode;
    ui.horizontal(|ui| {
        ui.label("tcpFastOpen");
        let selected = match mode {
            TcpFastOpenMode::Unset => t(lang, Key::SrvUnset),
            TcpFastOpenMode::Enabled => t(lang, Key::SrvTrueEnable),
            TcpFastOpenMode::Disabled => t(lang, Key::SrvFalseDisable),
            TcpFastOpenMode::Number => t(lang, Key::SrvNumericWindow),
            TcpFastOpenMode::Invalid => t(lang, Key::SrvInvalidImportedValue),
        };
        egui::ComboBox::from_id_salt(ui.auto_id_with("tcp-fast-open-mode"))
            .selected_text(selected)
            .show_ui(ui, |ui| {
                if original_mode == TcpFastOpenMode::Invalid {
                    ui.selectable_value(
                        &mut mode,
                        TcpFastOpenMode::Invalid,
                        t(lang, Key::SrvInvalidImportedValue),
                    );
                }
                ui.selectable_value(&mut mode, TcpFastOpenMode::Unset, t(lang, Key::SrvUnset));
                ui.selectable_value(
                    &mut mode,
                    TcpFastOpenMode::Enabled,
                    t(lang, Key::SrvTrueEnable),
                );
                ui.selectable_value(
                    &mut mode,
                    TcpFastOpenMode::Disabled,
                    t(lang, Key::SrvFalseDisable),
                );
                ui.selectable_value(
                    &mut mode,
                    TcpFastOpenMode::Number,
                    t(lang, Key::SrvNumericWindow),
                );
            });
    });

    let mut changed = mode != original_mode;
    if changed {
        *value = match mode {
            TcpFastOpenMode::Unset => None,
            TcpFastOpenMode::Enabled => Some(serde_json::Value::Bool(true)),
            TcpFastOpenMode::Disabled => Some(serde_json::Value::Bool(false)),
            TcpFastOpenMode::Number => Some(serde_json::Value::from(0)),
            TcpFastOpenMode::Invalid => value.clone(),
        };
    }

    if mode == TcpFastOpenMode::Number {
        let mut number = value
            .as_ref()
            .and_then(serde_json::Value::as_f64)
            .unwrap_or_default();
        ui.horizontal(|ui| {
            ui.add_space(ui.spacing().indent);
            ui.label(t(lang, Key::SrvWindow));
            if ui
                .add(egui::DragValue::new(&mut number).speed(1.0))
                .changed()
                && let Some(number) = serde_json::Number::from_f64(number)
            {
                *value = Some(serde_json::Value::Number(number));
                changed = true;
            }
        });
    } else if mode == TcpFastOpenMode::Invalid
        && let Some(value) = value.as_ref()
    {
        ui.horizontal(|ui| {
            ui.add_space(ui.spacing().indent);
            ui.monospace(t_fmt(lang, Key::SrvPreserved, &[&value.to_string()]));
        });
    }
    changed
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SockoptUsage {
    Stream,
    EchDnsQuery,
    Mask,
}

impl SockoptUsage {
    /// The wire path prefix the block's findings are scoped with. The ECH
    /// DNS-query block lives under the TLS settings, not `stream.sockopt`
    /// (the model's `validate_outbound` sweep scopes it the same way), so
    /// the inline verdict names the field the user can actually find. A
    /// mask's block is numbered by its mask index, which this fixed prefix
    /// cannot name — the memoized finalmask error list carries those paths.
    fn path_prefix(self) -> &'static str {
        match self {
            Self::Stream => "stream.sockopt",
            Self::EchDnsQuery => "stream.tlsSettings.echSockopt",
            Self::Mask => "finalmask.udp[].settings.sockopt",
        }
    }
}

/// Outbound-role socket options (stream, ECH DNS query, UDP mask). Options the
/// Windows outbound path never reads render no widget here: the Linux-only
/// knobs (`mark`, `tproxy`, `tcpCongestion`, `tcpWindowClamp`, `tcpMaxSeg`,
/// `tcpUserTimeout`), `tcpMptcp` (Go's dialer consumes it on Linux only), and
/// the listener-only values (`v6only`, `acceptProxyProtocol`,
/// `trustedXForwardedFor`, which only listeners consume). The model keeps them
/// so a hand-edited profile round-trips unchanged. Every widget below has a
/// reader in the core this app runs.
fn sockopt_editor(
    ui: &mut egui::Ui,
    lang: Language,
    sockopt: &mut SockoptModel,
    usage: SockoptUsage,
    // The stream block is the chain surface: its `dialerProxy` renders as a
    // picker over the caller's chain-target options. The ECH DNS-query block
    // and the mask blocks embed the same struct but sit in editors with no
    // profile list, so they keep the free-text field (`None`).
    dialer_proxy_options: Option<&[String]>,
    // The block's memoized `validate_sockopt` verdicts (its usage's wire
    // path in the message), rendered under the fields.
    errors: &[String],
) -> bool {
    let mut changed = false;
    changed |= widgets::combo_str_labeled(
        ui,
        "domainStrategy",
        &mut sockopt.domain_strategy,
        SOCKOPT_DOMAIN_STRATEGIES,
        t(lang, Key::SrvDefault),
        false,
    );
    changed |= match dialer_proxy_options {
        Some(options) => widgets::combo_str_labeled(
            ui,
            "dialerProxy",
            &mut sockopt.dialer_proxy,
            options,
            t(lang, Key::NoneSelected),
            true,
        ),
        None => widgets::text_field(ui, "dialerProxy", &mut sockopt.dialer_proxy, "outbound tag"),
    };
    changed |= widgets::text_field(
        ui,
        t(lang, Key::SrvInterfaceBindNic),
        &mut sockopt.interface,
        "",
    );
    changed |= tcp_fast_open_editor(ui, lang, &mut sockopt.tcp_fast_open);
    changed |= widgets::opt_num(
        ui,
        t(lang, Key::SrvTcpKeepAliveIdleS),
        &mut sockopt.tcp_keep_alive_idle,
        i32::MIN..=i32::MAX,
    );
    changed |= widgets::opt_num(
        ui,
        t(lang, Key::SrvTcpKeepAliveIntervalS),
        &mut sockopt.tcp_keep_alive_interval,
        i32::MIN..=i32::MAX,
    );
    changed |= widgets::combo_str_labeled(
        ui,
        "addressPortStrategy",
        &mut sockopt.address_port_strategy,
        SOCKOPT_ADDRESS_PORT_STRATEGIES,
        t(lang, Key::SrvDefault),
        false,
    );
    let mut happy_eyeballs = sockopt.happy_eyeballs.is_some();
    if ui
        .checkbox(&mut happy_eyeballs, t(lang, Key::SrvHappyEyeballs))
        .changed()
    {
        sockopt.happy_eyeballs = if happy_eyeballs {
            Some(HappyEyeballs::default())
        } else {
            None
        };
        changed = true;
    }
    if let Some(settings) = sockopt.happy_eyeballs.as_mut() {
        changed |= widgets::opt_bool(
            ui,
            "prioritizeIPv6",
            &mut settings.prioritize_ipv6,
            t(lang, Key::SrvUnset),
        );
        changed |= widgets::opt_num(ui, "tryDelayMs", &mut settings.try_delay_ms, 0..=u64::MAX);
        changed |= widgets::opt_num(ui, "interleave", &mut settings.interleave, 0..=u32::MAX);
        changed |= widgets::opt_num(
            ui,
            "maxConcurrentTry",
            &mut settings.max_concurrent_try,
            0..=u32::MAX,
        );
        if !settings.extra.is_empty() {
            ui.weak(t_fmt(
                lang,
                Key::SrvUnknownFutureFieldsCustom,
                &[&settings.extra.len()],
            ));
        }
    }

    match usage {
        SockoptUsage::Stream => {
            changed |= widgets::opt_bool(
                ui,
                t(lang, Key::SrvPenetrateInherit),
                &mut sockopt.penetrate,
                t(lang, Key::SrvUnset),
            );
            ui.weak(t(lang, Key::SrvPenetrateNote));
        }
        SockoptUsage::EchDnsQuery => {
            ui.add_enabled_ui(false, |ui| {
                changed |= widgets::opt_bool(
                    ui,
                    t(lang, Key::SrvPenetrateDownloadOnly),
                    &mut sockopt.penetrate,
                    t(lang, Key::SrvUnset),
                );
            });
            ui.weak(t(lang, Key::SrvPenetrateEchNote));
        }
        SockoptUsage::Mask => {
            ui.add_enabled_ui(false, |ui| {
                changed |= widgets::opt_bool(
                    ui,
                    t(lang, Key::SrvPenetrateDownloadOnly),
                    &mut sockopt.penetrate,
                    t(lang, Key::SrvUnset),
                );
            });
            ui.weak(t(lang, Key::SrvPenetrateMaskNote));
        }
    }

    if ui.button(t(lang, Key::SrvAddCustomSockopt)).clicked() {
        sockopt.custom_sockopt.push(CustomSockopt::default());
        changed = true;
    }
    let mut remove_custom = None;
    for (index, custom) in sockopt.custom_sockopt.iter_mut().enumerate() {
        ui.push_id(("custom-sockopt", index), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(t_fmt(lang, Key::SrvCustomSockoptN, &[&(index + 1)]));
                    if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                        remove_custom = Some(index);
                    }
                });
                changed |=
                    widgets::text_field(ui, "system", &mut custom.system, "windows/linux/darwin");
                changed |= widgets::text_field(ui, "network", &mut custom.network, "tcp/udp");
                changed |=
                    widgets::text_field(ui, "level", &mut custom.level, "numeric socket level");
                changed |= widgets::combo_str_labeled(
                    ui,
                    "type",
                    &mut custom.r#type,
                    &["", "int", "str"],
                    t(lang, Key::SrvDefault),
                    false,
                );
                changed |= widgets::text_field(ui, "opt", &mut custom.opt, "numeric socket option");
                changed |= widgets::text_field(ui, "value", &mut custom.value, "");
                if !custom.extra.is_empty() {
                    ui.weak(t_fmt(
                        lang,
                        Key::SrvUnknownFutureFields,
                        &[&custom.extra.len()],
                    ));
                }
            });
        });
    }
    if let Some(index) = remove_custom {
        sockopt.custom_sockopt.remove(index);
        changed = true;
    }

    // The block's verdicts ride the memoized validation sweep (keyed on the
    // draft generation + language): identical messages, zero re-validation
    // on idle repaint frames.
    for error in errors {
        ui.colored_label(status_colors_of(ui).err, error.as_str());
    }
    if !sockopt.extra.is_empty() {
        ui.weak(t_fmt(
            lang,
            Key::SrvUnknownFutureFieldsSockopt,
            &[&sockopt.extra.len()],
        ));
    }
    changed
}

/// The ECH DNS-query socket options block. `errors` are the block's
/// memoized `stream.tlsSettings.echSockopt` verdicts from the enclosing
/// editor's validation cache; a context whose sockopt block is not part of
/// that cache (a nested/imported TLS config) passes an empty slice and
/// relies on the memoized error list, which already carries the same
/// findings under their own wire path.
fn ech_sockopt_editor(
    ui: &mut egui::Ui,
    lang: Language,
    sockopt: &mut Option<SockoptModel>,
    errors: &[String],
) -> bool {
    let mut changed = false;
    let mut enabled = sockopt.is_some();
    if ui
        .checkbox(&mut enabled, t(lang, Key::SrvEchDnsQuerySockopt))
        .changed()
    {
        *sockopt = if enabled {
            Some(SockoptModel::default())
        } else {
            None
        };
        changed = true;
    }
    if let Some(sockopt) = sockopt.as_mut() {
        ui.indent("ech-dns-query-sockopt", |ui| {
            ui.weak(t(lang, Key::SrvEchSockoptNote));
            changed |= sockopt_editor(ui, lang, sockopt, SockoptUsage::EchDnsQuery, None, errors);
        });
    }
    changed
}

/// The per-mask socket-options block of a `udphop` UDP mask: the socket the
/// hop dials (`settings.sockopt`). The block's findings ride the memoized
/// finalmask sweep (`validate_finalmask` validates the same field under its
/// mask-scoped path), which renders them under the mask list.
fn mask_sockopt_editor(
    ui: &mut egui::Ui,
    lang: Language,
    sockopt: &mut Option<SockoptModel>,
) -> bool {
    let mut changed = false;
    let mut enabled = sockopt.is_some();
    if ui.checkbox(&mut enabled, "sockopt").changed() {
        *sockopt = enabled.then(SockoptModel::default);
        changed = true;
    }
    if let Some(sockopt) = sockopt.as_mut() {
        ui.indent("mask-sockopt", |ui| {
            ui.weak(t(lang, Key::SrvMaskSockoptNote));
            changed |= sockopt_editor(ui, lang, sockopt, SockoptUsage::Mask, None, &[]);
        });
    }
    changed
}

/// The trailing action button of a keygen row: its label and hover tooltip.
struct KeygenButton<'a> {
    label: &'a str,
    hover: &'a str,
}

/// Validated text field with a trailing action button on the same row.
/// Returns (value_changed, button_clicked).
fn keygen_field(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    validate: impl Fn(&str) -> Option<String>,
    button: &KeygenButton<'_>,
) -> (bool, bool) {
    let error = validate(value);
    let mut clicked = false;
    let (changed, _rect) = ui
        .horizontal(|ui| {
            ui.label(label);
            let btn_w = 72.0 + ui.spacing().item_spacing.x;
            let w = (ui.available_width() - btn_w).max(100.0);
            let r = ui.add(
                egui::TextEdit::singleline(value)
                    .hint_text(hint)
                    .desired_width(w),
            );
            let r = match &error {
                Some(m) => r.on_hover_text(m),
                None => r,
            };
            if error.is_some() {
                ui.painter().rect_stroke(
                    r.rect,
                    ui.style().visuals.widgets.inactive.corner_radius,
                    Stroke::new(1.5, status_colors_of(ui).err),
                    StrokeKind::Inside,
                );
            }
            if ui
                .button(button.label)
                .on_hover_text(button.hover)
                .clicked()
            {
                clicked = true;
            }
            (r.changed(), r.rect)
        })
        .inner;
    if let Some(m) = &error {
        ui.horizontal(|ui| {
            ui.add_space(ui.spacing().indent);
            ui.colored_label(status_colors_of(ui).err, RichText::new(m).small());
        });
    }
    (changed, clicked)
}

/// Key→value editor over a `serde_json::Map<String, Value>` (Xray StringList
/// headers). Edited values become JSON strings; untouched non-string values
/// round-trip unchanged.
///
/// `scratch` is the screen's shared edit buffer for the key column and the
/// non-string value rows: the widgets need a `&mut String` for the frame,
/// and an owned buffer per row would allocate on every repaint. It is seeded
/// before each widget and read back only when that widget reports an edit.
fn json_map_kv(
    ui: &mut egui::Ui,
    lang: Language,
    map: &mut serde_json::Map<String, serde_json::Value>,
    key_hint: &str,
    val_hint: &str,
    scratch: &mut String,
) -> bool {
    let mut changed = false;
    let mut remove: Option<String> = None;
    let mut rename: Option<(String, String)> = None;
    // Iterate the map by borrow: the per-frame key snapshot existed only to
    // survive the rename/remove mutations, which are already deferred until
    // after the grid, so idle repaints never copy every key into a fresh
    // buffer. The duplicate-key check moves to the rename apply site for the
    // same reason.
    egui::Grid::new(ui.auto_id_with("json_kv"))
        .num_columns(2)
        .min_col_width(150.0)
        .show(ui, |ui| {
            for (k, v) in map.iter_mut() {
                // Seed the shared buffer with the row's key and read it back
                // only on an edit: the rename pair is built on the edit path.
                scratch.clear();
                scratch.push_str(k);
                let kr = ui.add(
                    egui::TextEdit::singleline(scratch)
                        .hint_text(key_hint)
                        .desired_width(150.0),
                );
                if kr.changed() && !scratch.is_empty() && scratch.as_str() != k.as_str() {
                    rename = Some((k.clone(), scratch.clone()));
                }
                // Right-to-left: the remove button pins to the row's right
                // edge and the value field fills exactly the remaining
                // width. The value field must live in the last column —
                // egui grids size non-last columns from the previous frame's
                // width, and a TextEdit clamps to that, freezing the field
                // at the first frame's width forever (see the kv_table
                // regression test).
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("🗑").clicked() {
                        remove = Some(k.clone());
                    }
                    // A JSON string is edited in place — the widget writes
                    // the model's own text only on a real edit.
                    if let serde_json::Value::String(text) = v {
                        changed |= ui
                            .add(
                                egui::TextEdit::singleline(text)
                                    .hint_text(val_hint)
                                    .desired_width(f32::INFINITY),
                            )
                            .changed();
                    } else {
                        // Every other value round-trips through the shared
                        // buffer (fmt::Write for a String is infallible) and
                        // becomes a string only when it is edited.
                        scratch.clear();
                        let _ = write!(scratch, "{v}");
                        if ui
                            .add(
                                egui::TextEdit::singleline(scratch)
                                    .hint_text(val_hint)
                                    .desired_width(f32::INFINITY),
                            )
                            .changed()
                        {
                            *v = serde_json::Value::String(scratch.clone());
                            changed = true;
                        }
                    }
                });
                ui.end_row();
            }
        });
    if let Some(k) = remove {
        map.remove(&k);
        changed = true;
    }
    if let Some((old, new)) = rename
        && !map.contains_key(&new)
        && let Some(v) = map.remove(&old)
    {
        map.insert(new, v);
        changed = true;
    }
    if ui.button(t(lang, Key::SrvAddRow)).clicked() {
        let mut i = 1;
        let mut k = format!("key{i}");
        while map.contains_key(&k) {
            i += 1;
            k = format!("key{i}");
        }
        map.insert(k, serde_json::Value::String(String::new()));
        changed = true;
    }
    changed
}

fn transport_headers(
    ui: &mut egui::Ui,
    lang: Language,
    map: &mut serde_json::Map<String, serde_json::Value>,
    scratch: &mut String,
) -> bool {
    let had_host = map.keys().any(|key| key.eq_ignore_ascii_case("host"));
    let mut changed = json_map_kv(
        ui,
        lang,
        map,
        t(lang, Key::HeaderHint),
        t(lang, Key::ValueHint),
        scratch,
    );
    if let Some(key) = map
        .keys()
        .find(|key| key.eq_ignore_ascii_case("host"))
        .cloned()
    {
        if !had_host || changed {
            map.remove(&key);
            changed = true;
        }
        ui.colored_label(status_colors_of(ui).err, t(lang, Key::SrvHostReserved));
    }
    changed
}
fn websocket_transport_headers(
    ui: &mut egui::Ui,
    lang: Language,
    settings: &mut WsSettings,
    scratch: &mut String,
) -> bool {
    let mut changed = json_map_kv(
        ui,
        lang,
        &mut settings.headers,
        t(lang, Key::HeaderHint),
        t(lang, Key::ValueHint),
        scratch,
    );
    let has_legacy_host = settings
        .headers
        .keys()
        .any(|key| key.eq_ignore_ascii_case("host"));
    if !has_legacy_host {
        return changed;
    }

    ui.colored_label(status_colors_of(ui).warn, t(lang, Key::SrvWsHostDeprecated));
    let action = if settings.host.is_empty() {
        t(lang, Key::SrvMoveHostToHost)
    } else {
        t(lang, Key::SrvRemoveLegacyHost)
    };
    let migrate_clicked = ui.small_button(action).clicked();
    if changed || migrate_clicked {
        match settings.migrate_legacy_host_header() {
            Ok(migrated) => changed |= migrated,
            Err(error) => {
                ui.colored_label(status_colors_of(ui).err, error);
            }
        }
    }
    changed
}

fn path_field(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    value: &mut String,
    save: bool,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label(label);
        let edit_width = (ui.available_width() - 80.0).max(120.0);
        changed |= ui
            .add(egui::TextEdit::singleline(value).desired_width(edit_width))
            .changed();
        if ui.small_button(t(lang, Key::SrvBrowse)).clicked() {
            let dialog = rfd::FileDialog::new();
            let selected = if save {
                dialog
                    .set_file_name(t(lang, Key::ShellMasterKeyLogFileName))
                    .save_file()
            } else {
                dialog.pick_file()
            };
            if let Some(path) = selected {
                *value = path.to_string_lossy().into_owned();
                changed = true;
            }
        }
    });
    changed
}

// ---------- screen state ----------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum EditorTab {
    #[default]
    Basic,
    Transport,
    Security,
    Mux,
    Advanced,
}

const TABS: &[EditorTab] = &[
    EditorTab::Basic,
    EditorTab::Transport,
    EditorTab::Security,
    EditorTab::Mux,
    EditorTab::Advanced,
];

impl EditorTab {
    fn label(self, lang: Language) -> &'static str {
        match self {
            Self::Basic => t(lang, Key::SrvTabBasic),
            Self::Transport => t(lang, Key::SrvTabTransport),
            Self::Security => t(lang, Key::SrvTabSecurity),
            Self::Mux => t(lang, Key::SrvTabMux),
            Self::Advanced => t(lang, Key::SrvTabAdvanced),
        }
    }
}

impl ToolTarget {
    /// Build the owned target for a draft, cloning the profile id only on the
    /// click path (keygen/tool requests, derive dialog) instead of per frame.
    fn draft(kind: DraftTargetKind, profile_id: &str, generation: u64) -> Self {
        match kind {
            DraftTargetKind::Existing => ToolTarget::ExistingDraft {
                profile_id: profile_id.to_owned(),
                generation,
            },
            DraftTargetKind::Add => ToolTarget::AddDraft {
                profile_id: profile_id.to_owned(),
                generation,
            },
        }
    }
}

/// Which draft a keygen/tool request targets: the in-progress add-draft or
/// the selected profile's editor draft. The tab closures pass a borrowed id
/// plus generation, and the owned [`ToolTarget`] is built only on the click
/// path, so repaints never allocate the 36-char profile id.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DraftTargetKind {
    Existing,
    Add,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum XrayToolKind {
    Uuid,
    VlessEncryption,
    WireguardSecret,
    Mldsa65Verify,
    TlsPin,
    TlsPing,
    /// In-app QUIC certificate capture: the transcript has the
    /// same "Cert's leaf SHA256:" shape as `xray tls ping`, so the TlsPing
    /// success/error handling applies unchanged.
    TlsPingQuic,
    RealityPublicKey,
}

struct XrayToolJob {
    target: ToolTarget,
    kind: XrayToolKind,
    request: Request<Result<String, String>>,
}

struct ExistingProfileDraft {
    /// The profile id, mirrored from `profile.id`. Profile ids are immutable
    /// (a rename changes only the display name), so this never drifts. The
    /// copy lets the tab closures borrow the id (for tool targets and the
    /// tag list) without either cloning `self.selected` per repaint or
    /// overlapping `&mut draft.profile`.
    id: String,
    /// The `srv-<id8>` display tag, computed once at draft creation: the
    /// tag derives from the immutable id, so it never changes while the
    /// draft lives. The copy keeps the editor header row allocation-free on
    /// idle repaints.
    tag: String,
    profile: ServerProfile,
    source: serde_json::Value,
    generation: u64,
}

/// Memoized editor validation for one existing draft: the findings (swept
/// once per draft generation, bumped on every edit and tool application) and
/// the strings they render to (rebuilt when the generation or the language
/// moves, so a language change re-renders instead of re-validating). Both
/// live here so `show_editor` never serializes or validates the whole profile
/// on a repaint.
struct EditorValidationCache {
    /// The draft generation the findings were computed from.
    generation: u64,
    /// The sweep's findings, unrendered — the blocking half gates
    /// Validate-and-save and the leave modal's Save.
    findings: EditorValidationFindings,
    /// The language `rendered` was built in.
    rendered_language: Language,
    /// The strings the error list, the warnings list, and the tabs' inline
    /// verdicts show — the same sweep, rendered once per (generation,
    /// language).
    rendered: EditorValidationRender,
    /// The draft differs from its committed source (see
    /// [`existing_draft_gate`]).
    changed_from_source: bool,
}

/// Memoized add-draft validation, mirroring [`EditorValidationCache`] for the
/// Add-server window: the full sweep (validators, base64url decodes, hex
/// scans) runs once per draft generation, and its strings render once per
/// (generation, language) — never per repaint of the modal.
struct AddDraftValidationCache {
    /// The add-draft generation the findings were computed from.
    generation: u64,
    /// The sweep's findings, unrendered — the blocking half gates
    /// Validate-and-add and the leave modal's Save.
    findings: EditorValidationFindings,
    /// The language `rendered` was built in.
    rendered_language: Language,
    /// The strings the error list, the warnings list, and the tabs' inline
    /// verdicts show.
    rendered: EditorValidationRender,
    /// The draft differs from an empty profile carrying the draft's id. An
    /// add draft has no committed source, so this is the add-draft dirty
    /// flag (a fresh add draft is unsaved by definition).
    changed_from_source: bool,
}

/// The facts every draft control reads, built where the draft's findings are.
/// The two memoized facts — whether the draft differs from its committed
/// profile, and whether an error-severity finding blocks it — come from the
/// validation cache the sweep produced, so a generation bump updates the
/// verdicts and those facts together. The three facts that move without a
/// draft edit (a raw buffer's uncommitted text, the profile validation job,
/// and the busy window) are read where the control renders.
#[derive(Clone, Copy, Default)]
struct DraftGate {
    /// The draft differs from its committed profile (an add draft: from an
    /// empty profile carrying its id).
    changed_from_source: bool,
    /// A raw finalmask/PEM buffer of this draft holds text that never reached
    /// the draft.
    raw_buffers_dirty: bool,
    /// An error-severity finding exists.
    blocking: bool,
    /// The profile validation job is in flight.
    validating: bool,
    /// An exclusive job holds the busy window.
    busy: bool,
}

impl DraftGate {
    /// The draft holds unsaved changes: it differs from its committed profile,
    /// or a raw buffer holds text that never reached it. The "Unsaved
    /// changes" dot, the Discard button, and the leave guard read this.
    fn dirty(self) -> bool {
        self.changed_from_source || self.raw_buffers_dirty
    }

    /// The draft may commit: it differs from its committed profile and no
    /// error-severity finding blocks it. Validate-and-save and the leave
    /// modal's Save read this. A buffer-only dirty state is deliberately not
    /// committable — the raw text never parsed, so committing would be a
    /// no-op that leaves the unsaved indicator on.
    fn committable(self) -> bool {
        self.changed_from_source && !self.blocking
    }
}

/// The chain-target (`dialerProxy`) picker's options for one editor: every
/// other profile's `srv-<id8>` tag in server-list order, then the built-in
/// `direct`/`block` targets validation accepts. Memoized per editor — a
/// rebuild costs one tag format per profile — so it reruns only when the
/// profile-set signal `(config_revision, dirty, profile count)` or the
/// rendered profile advances; idle repaint frames reuse the snapshot.
struct DialerProxyOptions {
    generation: (u64, bool, usize),
    /// The profile whose own tag the options exclude — a chain to itself
    /// could only produce a cycle.
    own_id: String,
    options: Vec<String>,
}

/// Refresh `slot` when its signal moved and hand back the options it holds.
/// Each editor keeps its own slot: the existing-draft editor and the
/// add-server dialog may render in one frame, and they exclude different
/// profiles. The cached slot's generation is the rebuild key — idle frames
/// reuse the options it holds.
fn refresh_dialer_proxy_options<'a>(
    slot: &'a mut Option<DialerProxyOptions>,
    set_key: (u64, bool, usize),
    own_id: &str,
    profiles: &[ServerProfile],
) -> &'a [String] {
    let unchanged = slot
        .as_ref()
        .is_some_and(|cached| cached.generation == set_key && cached.own_id.as_str() == own_id);
    if !unchanged {
        let options = profiles
            .iter()
            .filter(|profile| profile.id.as_str() != own_id)
            .map(ServerProfile::tag)
            .chain([
                DIRECT_OUTBOUND_TAG.to_string(),
                BLOCK_OUTBOUND_TAG.to_string(),
            ])
            .collect();
        *slot = Some(DialerProxyOptions {
            generation: set_key,
            own_id: own_id.to_owned(),
            options,
        });
    }
    slot.as_ref()
        .map_or(&[], |cached| cached.options.as_slice())
}

/// Trailing context for [`ServersScreen::advanced_tab`]:
/// the profile-set signal the chain-target options memoize on, the memoized
/// finalmask verdicts, the memoized `stream.sockopt` verdict, and the
/// per-editor raw JSON/PEM buffers. Bundled so the tab stays
/// under clippy's argument-count ceiling without a lint suppression
/// (zero-suppression repo contract).
struct AdvancedTabCtx<'a> {
    set_key: (u64, bool, usize),
    finalmask_errors: &'a [String],
    stream_sockopt_errors: &'a [String],
    /// The chain-target picker's memo slot for the editor rendering this
    /// tab (see [`DialerProxyOptions`]).
    dialer_proxy_options: &'a mut Option<DialerProxyOptions>,
    finalmask_raw: &'a mut RawBuffers,
    pem_buffers: &'a mut std::collections::HashMap<egui::Id, PemBuf>,
}

/// The chain target the draft was loaded with: the dial-through tag the
/// committed profile carried (`streamSettings.sockopt.dialerProxy`), read
/// from the draft's serialized source. `None` when the source had none.
fn source_chain_target(source: &serde_json::Value) -> Option<&str> {
    source
        .get("outbound")?
        .get("streamSettings")?
        .get("sockopt")?
        .get("dialerProxy")?
        .as_str()
        .filter(|tag| !tag.is_empty())
}

/// True when the profile's `quicParams` still carries the retired `udpHop`
/// key (any JSON shape) — the state that gates and that the finding row's
/// dismissal control clears.
fn retired_udp_hop_present(profile: &ServerProfile) -> bool {
    profile
        .outbound
        .stream
        .finalmask
        .as_ref()
        .and_then(|finalmask| finalmask.quic_params.as_ref())
        .is_some_and(|quic| quic.retired_udp_hop.is_some())
}

/// True when the profile's UDP mask list carries a `udphop` entry. The
/// cheap repaint-path form of the hop state: [`udphop_masks`] serializes the
/// entries for the mutation-time comparison, which is too much work for an
/// idle frame of the finding row.
fn profile_has_udphop_mask(profile: &ServerProfile) -> bool {
    profile
        .outbound
        .stream
        .finalmask
        .as_ref()
        .is_some_and(|finalmask| {
            finalmask
                .udp
                .iter()
                .any(|mask| matches!(mask, FinalmaskUdpMask::Udphop { .. }))
        })
}

/// The `udphop` masks a profile carries, serialized the way the settings
/// file writes them — the hop state a retired `quicParams.udpHop` key
/// resolves against. Empty when the profile has no finalmask block and no
/// `udphop` entry.
fn udphop_masks(profile: &ServerProfile) -> Vec<serde_json::Value> {
    profile
        .outbound
        .stream
        .finalmask
        .iter()
        .flat_map(|finalmask| &finalmask.udp)
        .filter(|mask| mask.known_type() == Some("udphop"))
        .map(|mask| {
            serde_json::to_value(mask).expect(
                "model serialization is infallible: a finalmask envelope holds string map \
                 keys only",
            )
        })
        .collect()
}

/// The same state read from the draft's serialized source. An entry that
/// cannot serialize was never written by this app, so it never matches.
fn source_udphop_masks(source: &serde_json::Value) -> Vec<serde_json::Value> {
    source
        .get("outbound")
        .and_then(|outbound| outbound.get("streamSettings"))
        .and_then(|stream| stream.get("finalmask"))
        .and_then(|finalmask| finalmask.get("udp"))
        .and_then(serde_json::Value::as_array)
        .map(|masks| {
            masks
                .iter()
                .filter(|mask| {
                    mask.get("type").and_then(serde_json::Value::as_str) == Some("udphop")
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// True when a raw finalmask/PEM buffer of `profile_id` holds text that never
/// reached the draft: invalid JSON never commits, so the draft stays clean
/// while the editor shows the unparsed text (the condition that enables
/// Discard in that state). Entries exist only while a profile has an open raw
/// editor, and the scan short-circuits on the first dirty buffer.
fn raw_buffers_hold_uncommitted(finalmask_raw: &RawBuffers, profile_id: &str) -> bool {
    finalmask_raw
        .values()
        .any(|buffer| buffer.profile == profile_id && buffer.dirty)
}

/// Serialized comparison of an add draft against an empty profile carrying
/// the draft's id: an add draft has no committed source, so "changed" means
/// differing from the empty template.
fn add_draft_differs_from_empty(draft: &ServerProfile) -> bool {
    let default = ServerProfile {
        id: draft.id.clone(),
        ..ServerProfile::default()
    };
    serde_json::to_value(draft)
        .map(|current| current != serde_json::to_value(default).unwrap_or_default())
        .unwrap_or(true)
}

/// Bring the existing-draft validation cache up to date: sweep the draft only
/// when its generation moved, render the findings it holds only when the
/// generation or the language moved. A language change therefore re-renders
/// without re-validating, and an idle frame does neither.
fn refresh_editor_validation(
    cache: &mut Option<EditorValidationCache>,
    draft: &ExistingProfileDraft,
    lang: Language,
) {
    let covered = cache
        .as_ref()
        .is_some_and(|cached| cached.generation == draft.generation);
    if !covered {
        let findings = editor_validation_findings(&draft.profile);
        let rendered = findings.render(lang);
        *cache = Some(EditorValidationCache {
            generation: draft.generation,
            findings,
            rendered_language: lang,
            rendered,
            changed_from_source: serde_json::to_value(&draft.profile)
                .map(|current| current != draft.source)
                .unwrap_or(true),
        });
        return;
    }
    if let Some(cached) = cache.as_mut()
        && cached.rendered_language != lang
    {
        let rendered = cached.findings.render(lang);
        cached.rendered = rendered;
        cached.rendered_language = lang;
    }
}

/// Add-draft twin of [`refresh_editor_validation`]: the add draft's
/// generation counter lives on the screen, so it is passed in.
fn refresh_add_draft_validation(
    cache: &mut Option<AddDraftValidationCache>,
    generation: u64,
    draft: &ServerProfile,
    lang: Language,
) {
    let covered = cache
        .as_ref()
        .is_some_and(|cached| cached.generation == generation);
    if !covered {
        let findings = editor_validation_findings(draft);
        let rendered = findings.render(lang);
        *cache = Some(AddDraftValidationCache {
            generation,
            findings,
            rendered_language: lang,
            rendered,
            // An add draft has no committed source; "changed" means differing
            // from an empty profile carrying the draft's id (a fresh add
            // draft is unsaved by definition).
            changed_from_source: add_draft_differs_from_empty(draft),
        });
        return;
    }
    if let Some(cached) = cache.as_mut()
        && cached.rendered_language != lang
    {
        let rendered = cached.findings.render(lang);
        cached.rendered = rendered;
        cached.rendered_language = lang;
    }
}

/// The existing draft's gate for one frame: the draft's own facts as the
/// validation refresh computed them (recomputed inline when the cache does
/// not cover the draft's generation — a tool-applied edit can land after the
/// refresh, and the topbar chip reads this before the editor renders), plus
/// the raw-buffer scan and the frame's validation/busy facts.
fn existing_draft_gate(
    draft: &ExistingProfileDraft,
    cache: Option<&EditorValidationCache>,
    finalmask_raw: &RawBuffers,
    validating: bool,
    busy: bool,
) -> DraftGate {
    // The draft-against-source fact: the memoized answer when the cache covers
    // the draft's generation, recomputed inline (one serialize) when it does
    // not — a mutation applied outside the render that refreshed the cache
    // (e.g. a TLS pin fetched by a tool) must still answer same-frame
    // accurately, and the topbar chip reads this before the editor renders.
    // An absent cache is never changed: a fresh draft is seeded from its
    // persisted source.
    let changed_from_source = match cache {
        Some(cached) if cached.generation == draft.generation => cached.changed_from_source,
        Some(_) => serde_json::to_value(&draft.profile)
            .map(|current| current != draft.source)
            .unwrap_or(true),
        None => false,
    };
    DraftGate {
        changed_from_source,
        raw_buffers_dirty: raw_buffers_hold_uncommitted(finalmask_raw, &draft.profile.id),
        blocking: cache.is_some_and(|cached| !cached.findings.blocking.is_empty()),
        validating,
        busy,
    }
}

/// The add draft's gate, mirroring [`existing_draft_gate`] over the add
/// draft's substrate. Its `changed_from_source` is the add-draft fact
/// (differing from the empty template) and its raw-buffer scan covers the
/// buffers seeded for the dialog's own draft id; the add draft's controls
/// read `changed_from_source` and `blocking`, never its raw-buffer half.
fn add_draft_gate(
    draft: &ServerProfile,
    generation: u64,
    cache: Option<&AddDraftValidationCache>,
    finalmask_raw: &RawBuffers,
    validating: bool,
    busy: bool,
) -> DraftGate {
    // The add draft's counterpart fact: it has no committed source, so
    // "changed" means differing from the empty profile carrying its id.
    // Memoized with the findings; recomputed (two serializations — the draft
    // and the empty baseline) when the cache does not cover the generation,
    // and never changed while the dialog has not rendered yet.
    let changed_from_source = match cache {
        Some(cached) if cached.generation == generation => cached.changed_from_source,
        Some(_) => add_draft_differs_from_empty(draft),
        None => false,
    };
    DraftGate {
        changed_from_source,
        raw_buffers_dirty: raw_buffers_hold_uncommitted(finalmask_raw, &draft.id),
        blocking: cache.is_some_and(|cached| !cached.findings.blocking.is_empty()),
        validating,
        busy,
    }
}

struct QrDialog {
    name: String,
    link: String,
    tex: Option<egui::TextureHandle>,
}

/// State captured once when the delete-confirmation dialog opens. The dialog
/// is modal: its inputs (the profile set, routing rules, balancers) cannot
/// change while it is open, so the name and the reference scan are computed a
/// single time instead of on every repaint.
struct DeleteDialog {
    id: String,
    name: String,
    references: Vec<String>,
}

struct DeriveDialog {
    target: ToolTarget,
    private_key: String,
    error: Option<String>,
    pending: bool,
}

/// A status toast is shown for at most this long after it was set; once the
/// window elapses the toast is cleared so a stale message can never linger
/// over the screen.
const STATUS_TOAST_AUTO_CLEAR: Duration = Duration::from_secs(6);

/// A status toast auto-clears once `now - shown_at` reaches `ttl`. All
/// status-set sites share this single clear decision.
fn status_toast_expired(shown_at: Instant, now: Instant, ttl: Duration) -> bool {
    now.duration_since(shown_at) >= ttl
}

struct StatusLine {
    text: String,
    is_error: bool,
}

impl StatusLine {
    fn ok(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: false,
        }
    }
    fn err(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
        }
    }
}

enum ListAction {
    Select(String),
    SetActive(String),
    Duplicate(String),
    Export(String),
    Delete(String),
    ProbeLatency(String),
    /// Move the dragged profile to the gap its drop proposed (an index in
    /// the list as drawn; see [`reorder_target`]).
    Reorder {
        id: String,
        gap: usize,
    },
}

/// A deferred Servers-screen action awaiting the unsaved-changes modal:
/// switching the selection, closing the Add-server dialog, or quitting the
/// app. The modal's Save/Discard resolution performs the action; the commit
/// handlers clear the staged action on success, and a rejected validation
/// clears it too.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaveAction {
    /// Switch the selected profile after resolution.
    Select(String),
    /// Close the Add-server dialog after resolution.
    CloseAdd,
    /// The app may proceed with quitting after resolution.
    Quit,
}

/// The button pressed in the unsaved-changes leave modal this frame.
enum LeaveDecision {
    Save,
    Discard,
    Cancel,
}

/// One formatted import-preview row: the text the list paints, and whether it
/// reports a failed link (which only decides its color and its tooltip).
struct ImportPreviewRow {
    text: String,
    error: bool,
}

/// Memoized pretty print of one preserved over-limit `downloadSettings`
/// subtree: its header body re-runs on every frame it stays open, and the
/// subtree is as large as the configuration behind it. The key is the draft
/// the text belongs to — kind, profile or add-draft id, and edit generation,
/// which every editor change advances — plus the nesting depth, so the text is
/// rebuilt exactly when the subtree it describes can have moved.
struct OverLimitJson {
    /// `None` for a render-only caller with no draft identity to key on: the
    /// text is refilled on every such call and never reused.
    key: Option<(DraftTargetKind, String, u64, u32, Language)>,
    text: String,
}

/// The import dialog's formatted preview, built once per parse result and per
/// language. The paste cap allows a subscription blob with tens of thousands
/// of entries, so formatting a row inside the paint loop would make the frame
/// cost scale with the paste; the rows are also painted through a virtualized
/// list, so only the ones on screen are laid out. Rebuilt (not validated) when
/// `import_parsed` changes — both writers of that vector clear this slot.
struct ImportPreview {
    lang: Language,
    /// How many entries parsed into a profile: the count the caption and the
    /// "validate and add" gate read.
    ok: usize,
    rows: Vec<ImportPreviewRow>,
}

#[derive(Default)]
pub struct ServersScreen {
    selected: Option<String>,
    /// In-flight row drag-reorder (see [`ListDrag`]); `None` whenever no row
    /// is being dragged.
    list_drag: Option<ListDrag>,
    /// Memoized latency badges keyed by profile id: the list
    /// paints one badge per visible row per frame, but a badge's text is a
    /// function of the row's measured latency, the language, and the status
    /// palette — all near-constant inputs (latency changes only on probe/
    /// observatory results). A row renders from this cache and re-formats
    /// only when an input moved; entries are dropped with their profile on
    /// delete.
    latency_badges: std::collections::HashMap<String, LatencyBadge>,
    tab: EditorTab,
    draft_tab: EditorTab,
    existing_draft: Option<ExistingProfileDraft>,
    editor_validation_cache: Option<EditorValidationCache>,
    /// The chain-target picker's option memo for the existing-draft editor
    /// and the add-server dialog — one slot each, since both may render in
    /// one frame and they exclude different profiles (see
    /// [`DialerProxyOptions`]).
    dialer_proxy_options: Option<DialerProxyOptions>,
    add_dialer_proxy_options: Option<DialerProxyOptions>,
    add_draft: Option<ServerProfile>,
    add_draft_generation: u64,
    add_draft_validation_cache: Option<AddDraftValidationCache>,
    import_open: bool,
    import_text: String,
    import_parsed: Vec<Result<ServerProfile, links::LinkError>>,
    import_parsed_source: Option<String>,
    /// Formatted preview of `import_parsed` (see [`ImportPreview`]), built on
    /// the first frame that shows it and reused until the parse result or the
    /// language moves.
    import_preview: Option<ImportPreview>,
    /// Pretty print of the preserved over-limit `downloadSettings` subtree of
    /// one draft (see [`Self::over_limit_json_for`]): the transport tab walks
    /// it every frame while the header is open.
    over_limit_json: Option<OverLimitJson>,
    /// In-flight background parse of `import_text` (spawned on Parse click,
    /// polled every frame in `show`); idle while none runs.
    import_parse_job: Request<ImportParseResult>,
    /// Rejection message for input refused before parsing (size cap), or a
    /// worker failure; shown inline in the import dialog.
    import_parse_error: Option<String>,
    qr_dialog: Option<QrDialog>,
    delete_pending: Option<DeleteDialog>,
    derive_dialog: Option<DeriveDialog>,
    /// Staged leave action awaiting the unsaved-changes modal (see
    /// [`LeaveAction`]): the modal renders while this is `Some`, and the
    /// commit handlers clear it once the staged action resolves.
    leave_pending: Option<LeaveAction>,
    /// Set once when a staged Quit may proceed (all dirty drafts committed
    /// via Save, or discarded); consumed by the app shell via
    /// [`ServersScreen::take_quit_resume`].
    quit_resume: bool,
    status: Option<StatusLine>,
    /// When the current status toast was set; the toast auto-clears once
    /// [`STATUS_TOAST_AUTO_CLEAR`] has elapsed (see `show_status_toast`).
    status_set_at: Option<Instant>,
    tls_probe_domain: String,
    tls_probe_ip: String,
    tls_tool_output: Option<String>,
    tls_tool_error: Option<String>,
    /// Leaf SHA256 pin parsed from the last successful TLS probe output.
    tls_probe_leaf_pin: Option<String>,
    /// CA (name, pin) rows parsed from the last successful TLS probe output.
    tls_probe_ca_pins: Vec<(String, String)>,
    /// Whether the last TLS probe completed a handshake; gates the pin panel.
    /// Cleared when a new probe starts or fails; pins render only for the
    /// profile that produced them (see `tls_probe_profile`).
    tls_probe_handshake_ok: bool,
    /// Profile id whose probe produced `tls_probe_leaf_pin`; the pin panel
    /// renders and Apply is reachable only while the editor targets that same
    /// profile, so a pin can never be applied to a different node.
    tls_probe_profile: Option<String>,
    /// Whether the raw probe output window is open (drawn in `show_dialogs`).
    show_tls_probe_output: bool,
    tool_job: Option<XrayToolJob>,
    /// Raw-JSON editor buffers, keyed by the field's egui `Id` (per-field
    /// buffer identity, stable across frames, no per-frame key allocation),
    /// beside the parse count their idle-frame test reads.
    finalmask_raw: RawBuffers,
    /// PEM editor buffers (certificate/key line lists), keyed the same way;
    /// evicted with the owning profile in `evict_raw_buffers`.
    pem_buffers: std::collections::HashMap<egui::Id, PemBuf>,
    /// Reused edit buffer for the header key/value tables (`json_map_kv`):
    /// the key column and the non-string value rows need a `&mut String`
    /// for the frame, and one owned buffer per row would allocate on every
    /// repaint. Seeded from the row's own text before each widget and read
    /// back only when that widget reports an edit.
    json_key_scratch: String,
    profile_validation_origin: Option<ProfileValidationOrigin>,
    profile_validation_count: usize,
    /// In-flight profile validation: the request's own reply channel,
    /// polled per frame. The runtime owns the worker, its scratch-config
    /// guard and its cooperative cancellation; this screen only parks the
    /// verdict until its frame picks it up (the runtime pokes the repaint
    /// after the terminal send).
    profile_validation_request: Request<ProfileValidationReply>,
    /// Single-scope flag of the in-flight latency probe: the pending gate.
    /// `true` only for a per-row probe (probe scope "one"); `false` for the
    /// all-scope toolbar probe. No correlation id — the outcome pairs
    /// structurally through the app's parked probe-feedback slot, which the
    /// `ShellParked` [`latency_probe`](Self::latency_probe) request adopts.
    pending_latency_probe: Option<bool>,
    /// The `ShellParked` request behind `pending_latency_probe`: started
    /// when the probe command goes out and finished by adopting the shell's
    /// parked outcome (exactly one at a time).
    latency_probe: Request<LatencyProbeResult>,
    latency_probe_feedback: Option<(FeedbackLevel, String)>,
    profile_validation_report: Option<String>,
}

/// One delivered link-parse result: a cancelled parse is never delivered
/// (the worker checks its stop flag before returning, and the request's
/// receiver is dropped on cancel), so a delivered result always carries
/// `parsed` for the paste it read.
struct ImportParseResult {
    source: String,
    parsed: Vec<Result<ServerProfile, links::LinkError>>,
}

impl ServersScreen {
    fn invalidate_import_preview(&mut self) {
        self.import_parsed.clear();
        self.import_parsed_source = None;
        self.import_preview = None;
    }

    /// Format the import preview once for the current parse result and
    /// language: the dialog paints it every frame, and the parsed list is as
    /// large as the paste allows. A no-op while the cached preview's language
    /// still stands — every path that replaces `import_parsed` clears the
    /// slot, so the language is the only input this memo can go stale on.
    fn refresh_import_preview(&mut self, lang: Language) {
        if self
            .import_preview
            .as_ref()
            .is_some_and(|preview| preview.lang == lang)
        {
            return;
        }
        let mut ok = 0;
        let rows = self
            .import_parsed
            .iter()
            .map(|result| match result {
                Ok(profile) => {
                    ok += 1;
                    ImportPreviewRow {
                        text: t_fmt(
                            lang,
                            Key::SrvImportOkMark,
                            &[&profile.name, &profile.outbound.protocol.as_str()],
                        ),
                        error: false,
                    }
                }
                Err(error) => ImportPreviewRow {
                    text: t_fmt(lang, Key::SrvImportErrMark, &[&error.text(lang)]),
                    error: true,
                },
            })
            .collect();
        self.import_preview = Some(ImportPreview { lang, ok, rows });
    }

    /// Evict every raw-editor buffer owned by `profile_id`:
    /// that profile is gone, so its buffers are dead weight. The raw-JSON
    /// and PEM maps share the one retain rule in
    /// [`raw_editor::evict_owned_buffers`]. Click-time only — never on idle
    /// frames.
    fn evict_raw_buffers(&mut self, profile_id: &str) {
        evict_owned_buffers(&mut self.finalmask_raw, &mut self.pem_buffers, profile_id);
    }

    fn import_preview_is_current(&self) -> bool {
        self.import_parsed_source.as_deref() == Some(self.import_text.as_str())
    }

    /// Parse the import buffer on a worker thread. Inputs over
    /// [`links::MAX_BULK_LEN`] are refused up front with a message and never
    /// reach the worker. The UI stays responsive; `poll_import_parse`
    /// applies the result once it lands.
    fn start_import_parse(&mut self, lang: Language, repaint: egui::Context) {
        self.import_parse_error = None;
        self.invalidate_import_preview();
        if self.import_text.len() > links::MAX_BULK_LEN {
            self.import_parse_error = Some(t_fmt(
                lang,
                Key::SrvImportTooLarge,
                &[&self.import_text.len(), &links::MAX_BULK_LEN],
            ));
            return;
        }
        let text = self.import_text.clone();
        match Request::worker("broccoli-link-parse", &repaint, move |stop| {
            // A cancelled parse is never delivered: `cancel_import_parse`
            // has already flipped the stop flag and dropped the receiver, so
            // returning early keeps the invariant that a delivered result
            // always carries `parsed`.
            let parsed = links::parse_bulk_cancellable(&text, stop)?;
            Some(ImportParseResult {
                source: text,
                parsed,
            })
        }) {
            Ok(job) => self.import_parse_job = job,
            Err(error) => {
                self.import_parse_error = Some(t_fmt(lang, Key::SrvParseWorkerFailed, &[&error]));
            }
        }
    }

    /// Drain one finished parse result per frame. Stale results (the paste
    /// changed while the worker ran) are discarded; cancelled parses leave
    /// the preview empty, and a worker that exited without a result surfaces
    /// the generic failure text.
    fn poll_import_parse(&mut self, lang: Language) {
        let Some(terminal) = self.import_parse_job.poll() else {
            return;
        };
        let result = match terminal {
            Terminal::Answered(result) => result,
            Terminal::Exited => {
                self.import_parse_error = Some(t(lang, Key::WorkerExitedWithoutResult).to_string());
                return;
            }
        };
        if result.source != self.import_text {
            // The user edited the paste while the worker ran; keep the
            // preview invalidated instead of applying stale results.
            return;
        }
        self.import_parsed = result.parsed;
        self.import_parsed_source = Some(result.source);
        // The formatted preview belongs to the previous result.
        self.import_preview = None;
    }

    /// Request a cooperative stop of the in-flight parse and drop the job so
    /// the busy indicator clears immediately. The request flips the worker's
    /// stop flag and stops listening, so its result is never applied.
    fn cancel_import_parse(&mut self) {
        self.import_parse_job.cancel();
    }

    fn profile_validation_in_progress(&self, origin: ProfileValidationOrigin) -> bool {
        self.profile_validation_origin == Some(origin)
            && self.profile_validation_request.is_pending()
    }
    fn start_profile_validation(
        &mut self,
        lang: Language,
        origin: ProfileValidationOrigin,
        profiles: Vec<ServerProfile>,
        draft_target: Option<ToolTarget>,
        ctx: &UiCtx<'_>,
    ) -> Result<(), String> {
        if self.profile_validation_request.is_pending() {
            return Err(t(lang, Key::SrvValidationAlreadyRunning).into());
        }
        let count = profiles.len();
        if count == 0 {
            return Err(t(lang, Key::SrvNoProfilesToValidate).into());
        }
        let servers = ctx.servers.clone();
        let mut scratch_settings = ctx.settings.clone();
        if origin == ProfileValidationOrigin::Draft && draft_target.is_none() {
            return Err(t(lang, Key::SrvDraftValidationRequiresIdentity).into());
        }
        // A raw override bypasses GUI outbounds entirely; disable it only in
        // this request-local scratch model so the staged profile is exercised.
        scratch_settings.raw_override = None;
        let import_source =
            (origin == ProfileValidationOrigin::Import).then(|| self.import_text.clone());
        // One oneshot channel per request: the runtime sends the terminal
        // verdict back on the request's own reply and this screen adopts it
        // as the request's channel, polled per frame (the runtime pokes the
        // repaint after the send). The runtime owns the worker too — the
        // scratch-config guard, the `xray -test` child and the cooperative
        // cancellation — so this thread never waits on a validation, and no
        // scratch config can be stranded by a screen that stops polling.
        let (reply, rx) = tokio::sync::oneshot::channel();
        self.profile_validation_origin = Some(origin);
        self.profile_validation_count = count;
        self.profile_validation_report = None;
        if let Err(error) = ctx.cmd.send(CoreCmd::ValidateProfiles {
            request: Box::new(ProfileValidationRequest {
                origin,
                lang,
                profiles,
                draft_target,
                import_source,
                servers,
                settings: scratch_settings,
            }),
            reply,
        }) {
            // Runtime went away: no terminal can arrive, so nothing may stay
            // pending.
            self.profile_validation_origin = None;
            self.profile_validation_count = 0;
            return Err(t_fmt(lang, Key::SrvStartValidationFailed, &[&error]));
        }
        self.profile_validation_request = Request::reply(rx);
        Ok(())
    }

    fn poll_profile_validation(&mut self, lang: Language, uictx: &mut UiCtx) {
        // Per-frame poll of the request's own reply channel: the runtime
        // pokes the repaint after every send, so the terminal is picked up
        // on the next frame. A closed channel without a terminal means the
        // runtime went away mid-run.
        let Some(terminal) = self.profile_validation_request.poll() else {
            return;
        };
        let origin = self.profile_validation_origin.take();
        self.profile_validation_count = 0;
        let result = match terminal {
            Terminal::Answered(Ok(result)) => result,
            Terminal::Answered(Err(error)) => {
                // A runtime-owned terminal (busy reject, runtime stopping,
                // cancellation, join failure): the keyed chain renders in
                // the active language as the whole verdict and nothing may
                // commit.
                let text = error.text(lang);
                self.profile_validation_report = Some(text.clone());
                self.set_status(StatusLine::err(text));
                return;
            }
            Terminal::Exited => {
                // A vanished runtime has no terminal to give.
                let error = t(lang, Key::SrvWorkerExitedWithoutResult).to_string();
                self.profile_validation_report = Some(error.clone());
                self.set_status(StatusLine::err(error));
                return;
            }
        };
        if origin != Some(result.origin) {
            let error = t(lang, Key::SrvDiscardedMismatchedResult).to_string();
            self.profile_validation_report = Some(error.clone());
            self.set_status(StatusLine::err(error));
            return;
        }
        if result.origin == ProfileValidationOrigin::Import
            && result.import_source.as_deref() != Some(self.import_text.as_str())
        {
            let error = t(lang, Key::SrvDiscardedStaleImport).to_string();
            self.profile_validation_report = Some(error.clone());
            self.set_status(StatusLine::err(error));
            return;
        }

        let report = if result.rejected.is_empty() {
            None
        } else {
            Some(
                result
                    .rejected
                    .iter()
                    .map(|(name, output)| format!("{name}:\n{output}"))
                    .collect::<Vec<_>>()
                    .join("\n\n"),
            )
        };
        match result.origin {
            ProfileValidationOrigin::Draft => {
                let Some(target) = result.draft_target.as_ref() else {
                    let error = t(lang, Key::SrvDraftValidationWithoutIdentity).to_string();
                    self.profile_validation_report = Some(error.clone());
                    self.set_status(StatusLine::err(error));
                    return;
                };
                if !self.target_is_current(target) {
                    return;
                }
                let Some(profile) = result.accepted.into_iter().next() else {
                    self.profile_validation_report = report;
                    self.set_status(StatusLine::err(t(lang, Key::SrvXrayRejectedServer)));
                    // Xray rejected the staged save: the leave action is
                    // cancelled — stay in the editor with the error (for
                    // Quit this cancels the quit).
                    self.leave_pending = None;
                    return;
                };
                match target {
                    ToolTarget::AddDraft { .. } => {
                        let id = profile.id.clone();
                        self.add_draft = None;
                        self.add_draft_generation = self.add_draft_generation.wrapping_add(1);
                        uictx.servers.profiles.push(profile);
                        if uictx.servers.active.is_none() {
                            // No choice yet: the first row is the default
                            // server (see `ServersFile::activate`).
                            uictx.servers.active =
                                uictx.servers.profiles.first().map(|p| p.id.clone());
                        }
                        // The switch to the newly added profile is guarded
                        // like any other selection change: with unsaved
                        // changes elsewhere (the existing draft) the leave
                        // modal stages instead.
                        if self.guard_select(id) {
                            // The switch happened immediately (nothing else
                            // was dirty): a Select staged while only the add
                            // draft was dirty is resolved by this switch —
                            // clear it, or the leave modal would reopen over
                            // a clean state.
                            if matches!(self.leave_pending, Some(LeaveAction::Select(_))) {
                                self.leave_pending = None;
                            }
                        }
                        self.profile_validation_report = None;
                        self.set_status(StatusLine::ok(t(lang, Key::SrvServerValidatedAndAdded)));
                        uictx.mark_dirty();
                        // The leave modal's Save committed the add draft:
                        // resume the staged action. CloseAdd is fully
                        // resolved; Quit proceeds once no dirty draft
                        // remains (the existing draft is saved first, so
                        // this is normally the final step). A Select staged
                        // by the guard above stays staged — its resolution
                        // (save the existing draft or discard) performs the
                        // switch.
                        let staged = self.leave_pending.clone();
                        match staged {
                            Some(LeaveAction::CloseAdd) => {
                                self.leave_pending = None;
                            }
                            Some(LeaveAction::Quit) => {
                                self.leave_pending = None;
                                if self
                                    .existing_gate(uictx.operation.is_some())
                                    .is_some_and(DraftGate::dirty)
                                {
                                    self.leave_pending = Some(LeaveAction::Quit);
                                } else {
                                    self.quit_resume = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    ToolTarget::ExistingDraft { profile_id, .. } => {
                        let Some(index) = uictx
                            .servers
                            .profiles
                            .iter()
                            .position(|persisted| persisted.id == *profile_id)
                        else {
                            self.profile_validation_report =
                                Some(t(lang, Key::SrvServerDeletedWhileValidating).into());
                            return;
                        };
                        uictx.servers.profiles[index] = profile;
                        self.existing_draft = None;
                        self.profile_validation_report = None;
                        self.set_status(StatusLine::ok(t(lang, Key::SrvServerValidatedAndSaved)));
                        uictx.mark_dirty();
                        // The leave modal's Save committed the existing
                        // draft: resume the staged action. Select switches
                        // now; Quit proceeds when no dirty draft remains
                        // (otherwise the modal stays staged for the next
                        // Save); CloseAdd keeps the modal staged so the next
                        // Save targets the add draft.
                        let staged = self.leave_pending.clone();
                        match staged {
                            Some(LeaveAction::Select(id)) => {
                                self.leave_pending = None;
                                self.selected = Some(id);
                            }
                            Some(LeaveAction::Quit) => {
                                self.leave_pending = None;
                                if self
                                    .add_gate(uictx.operation.is_some())
                                    .is_some_and(|gate| gate.changed_from_source)
                                {
                                    self.leave_pending = Some(LeaveAction::Quit);
                                } else {
                                    self.quit_resume = true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            ProfileValidationOrigin::Import => {
                let accepted_count = result.accepted.len();
                if accepted_count > 0 {
                    let first_id = result.accepted[0].id.clone();
                    for profile in result.accepted {
                        if let Some(index) = uictx
                            .servers
                            .profiles
                            .iter()
                            .position(|existing| existing.id == profile.id)
                        {
                            uictx.servers.profiles[index] = profile;
                        } else {
                            uictx.servers.profiles.push(profile);
                        }
                    }
                    if uictx.servers.active.is_none() {
                        // No choice yet: the first row is the default server
                        // (see `ServersFile::activate`).
                        uictx.servers.active = uictx.servers.profiles.first().map(|p| p.id.clone());
                    }
                    // The selection switch to the first imported profile is
                    // guarded like any other (a dirty draft stages the
                    // leave modal instead).
                    self.guard_select(first_id);
                    uictx.mark_dirty();
                }
                self.invalidate_import_preview();
                self.profile_validation_report = report;
                if self.profile_validation_report.is_none() {
                    self.import_text.clear();
                    self.import_open = false;
                    self.set_status(StatusLine::ok(t_fmt(
                        lang,
                        Key::SrvImportedCount,
                        &[&accepted_count],
                    )));
                } else {
                    self.set_status(StatusLine::err(t_fmt(
                        lang,
                        Key::SrvImportOutcome,
                        &[&accepted_count, &result.rejected.len()],
                    )));
                }
            }
        }
    }
    fn queue_xray_tool(
        &mut self,
        lang: Language,
        repaint: egui::Context,
        target: ToolTarget,
        kind: XrayToolKind,
        args: Vec<String>,
    ) -> Result<(), String> {
        if self.tool_job.is_some() {
            return Err(t(lang, Key::SrvAnotherToolRunning).into());
        }
        // The cooperative stop flag ends a cancelled run: `run_xray_bounded`
        // kills its child on the same flag, and a verdict for a cancelled
        // request is dropped here instead of delivered, so the screen's
        // stale-target check never sees it.
        let request = Request::worker("broccoli-xray-tool", &repaint, move |stop| {
            if stop.load(Ordering::Acquire) {
                return None;
            }
            let result = if kind == XrayToolKind::TlsPingQuic {
                crate::quic_probe::run(lang, &args)
            } else {
                run_xray_bounded(lang, &args, stop)
            };
            if stop.load(Ordering::Acquire) {
                return None;
            }
            Some(result)
        })
        .map_err(|error| t_fmt(lang, Key::SrvSpawnToolFailed, &[&error]))?;
        self.tool_job = Some(XrayToolJob {
            target,
            kind,
            request,
        });
        Ok(())
    }

    fn target_is_current(&self, target: &ToolTarget) -> bool {
        match target {
            ToolTarget::ExistingDraft {
                profile_id,
                generation,
            } => self.existing_draft.as_ref().is_some_and(|draft| {
                draft.profile.id == *profile_id && draft.generation == *generation
            }),
            ToolTarget::AddDraft {
                profile_id,
                generation,
            } => self.add_draft.as_ref().is_some_and(|draft| {
                draft.id == *profile_id && self.add_draft_generation == *generation
            }),
        }
    }

    fn profile_for_target_mut(&mut self, target: &ToolTarget) -> Option<&mut ServerProfile> {
        match target {
            ToolTarget::ExistingDraft { profile_id, .. } => self
                .existing_draft
                .as_mut()
                .filter(|draft| draft.profile.id == *profile_id)
                .map(|draft| &mut draft.profile),
            ToolTarget::AddDraft { profile_id, .. } => self
                .add_draft
                .as_mut()
                .filter(|draft| draft.id == *profile_id),
        }
    }

    fn advance_target_generation(&mut self, target: &ToolTarget) {
        match target {
            ToolTarget::ExistingDraft { profile_id, .. } => {
                if let Some(draft) = self
                    .existing_draft
                    .as_mut()
                    .filter(|draft| draft.profile.id == *profile_id)
                {
                    draft.generation = draft.generation.wrapping_add(1);
                }
            }
            ToolTarget::AddDraft { profile_id, .. } => {
                if self
                    .add_draft
                    .as_ref()
                    .is_some_and(|draft| draft.id == *profile_id)
                {
                    self.add_draft_generation = self.add_draft_generation.wrapping_add(1);
                }
            }
        }
    }

    fn report_tool_error(&mut self, kind: XrayToolKind, error: String) {
        match kind {
            XrayToolKind::TlsPin => self.tls_tool_error = Some(error),
            XrayToolKind::TlsPing | XrayToolKind::TlsPingQuic => {
                self.tls_tool_error = Some(error);
                // A failed probe leaves no current handshake to pin.
                self.tls_probe_handshake_ok = false;
                self.tls_probe_profile = None;
            }
            XrayToolKind::RealityPublicKey => {
                if let Some(dialog) = &mut self.derive_dialog {
                    dialog.pending = false;
                    dialog.error = Some(error);
                }
            }
            _ => self.set_status(StatusLine::err(error)),
        }
    }

    fn apply_tool_output(
        &mut self,
        lang: Language,
        target: &ToolTarget,
        kind: XrayToolKind,
        output: String,
    ) {
        let mut applied = false;
        let result = match kind {
            XrayToolKind::Uuid => {
                let value = output.trim();
                if v_uuid(lang, value).is_some() {
                    Err(t(lang, Key::SrvUuidInvalid).to_string())
                } else if let Some(profile) = self.profile_for_target_mut(target) {
                    match &mut profile.outbound.settings {
                        ProtocolSettings::Vless(settings) => settings.id = value.to_owned(),
                        ProtocolSettings::Vmess(settings) => settings.id = value.to_owned(),
                        _ => {
                            return self
                                .report_tool_error(kind, t(lang, Key::SrvUuidTargetNoId).into());
                        }
                    }
                    applied = true;
                    Ok(t(lang, Key::SrvUuidGenerated).to_string())
                } else {
                    Err(t(lang, Key::SrvToolTargetFieldNotFound).to_string())
                }
            }
            XrayToolKind::VlessEncryption => match keygen_value(&output, &["\"encryption\":"]) {
                Some(value) => {
                    let value = value.trim_matches('"').to_string();
                    if v_vless_encryption(lang, &value).is_some() {
                        Err(t(lang, Key::SrvVlessencInvalid).into())
                    } else if let Some(profile) = self.profile_for_target_mut(target) {
                        if let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings {
                            settings.encryption = value;
                            applied = true;
                            Ok(t(lang, Key::SrvClientEncryptionGenerated).to_string())
                        } else {
                            Err(t(lang, Key::SrvVlessencTargetFieldNotFound).into())
                        }
                    } else {
                        Err(t(lang, Key::SrvToolTargetFieldNotFound).into())
                    }
                }
                None => Err(t(lang, Key::SrvVlessencNoValue).into()),
            },
            XrayToolKind::WireguardSecret => match keygen_value(&output, PRIV_PREFIXES) {
                Some(value) if v_wg_key(lang, &value).is_none() => {
                    if let Some(profile) = self.profile_for_target_mut(target) {
                        if let ProtocolSettings::Wireguard(settings) =
                            &mut profile.outbound.settings
                        {
                            settings.secret_key = value;
                            applied = true;
                            Ok(t(lang, Key::SrvWgSecretGenerated).to_string())
                        } else {
                            Err(t(lang, Key::SrvWgTargetFieldNotFound).into())
                        }
                    } else {
                        Err(t(lang, Key::SrvToolTargetFieldNotFound).into())
                    }
                }
                Some(_) => Err(t(lang, Key::SrvWgInvalidPrivateKey).into()),
                None => Err(t(lang, Key::SrvWgCouldNotParse).into()),
            },
            XrayToolKind::Mldsa65Verify => match keygen_value(&output, &["Verify:", "verify:"]) {
                Some(value) if reality_mldsa65_verify_valid(&value) => {
                    if let Some(profile) = self.profile_for_target_mut(target) {
                        if let Some(reality) = profile.outbound.stream.reality_settings.as_mut() {
                            reality.mldsa65_verify = value;
                            applied = true;
                            Ok(t(lang, Key::SrvMldsa65Generated).to_string())
                        } else {
                            Err(t(lang, Key::SrvMldsa65TargetFieldNotFound).into())
                        }
                    } else {
                        Err(t(lang, Key::SrvToolTargetFieldNotFound).into())
                    }
                }
                Some(_) => Err(t(lang, Key::SrvMldsa65InvalidKey).into()),
                None => Err(t(lang, Key::SrvMldsa65CouldNotParse).into()),
            },
            XrayToolKind::TlsPin => match keygen_value(&output, &["Leaf SHA256:"]) {
                Some(value) if pinned_peer_cert_sha256_valid(&value) => {
                    if let Some(profile) = self.profile_for_target_mut(target) {
                        if let Some(tls) = profile.outbound.stream.tls_settings.as_mut() {
                            tls.pinned_peer_cert_sha256 = value.clone();
                            self.tls_tool_output =
                                Some(t_fmt(lang, Key::SrvTlsPinComputedLeaf, &[&value]));
                            self.tls_tool_error = None;
                            applied = true;
                            Ok(t(lang, Key::SrvTlsPinComputed).to_string())
                        } else {
                            Err(t(lang, Key::SrvTlsPinTargetFieldNotFound).into())
                        }
                    } else {
                        Err(t(lang, Key::SrvToolTargetFieldNotFound).into())
                    }
                }
                Some(_) => Err(t(lang, Key::SrvTlsPinMalformed).into()),
                None => Err(t(lang, Key::SrvTlsPinNoHash).into()),
            },
            XrayToolKind::TlsPing | XrayToolKind::TlsPingQuic => {
                if output.contains("Handshake succeeded") {
                    self.tls_probe_leaf_pin = leaf_pin_from_probe_output(&output);
                    self.tls_probe_ca_pins = ca_pins_from_probe_output(&output);
                    self.tls_probe_profile = Some(match &target {
                        ToolTarget::ExistingDraft { profile_id, .. }
                        | ToolTarget::AddDraft { profile_id, .. } => profile_id.clone(),
                    });
                    self.tls_probe_handshake_ok = true;
                    self.tls_tool_output = Some(output);
                    self.tls_tool_error = None;
                    Ok(t(lang, Key::SrvTlsHandshakeSucceeded).to_string())
                } else {
                    self.tls_probe_handshake_ok = false;
                    Err(t_fmt(lang, Key::SrvTlsProbeNoHandshake, &[&output.trim()]))
                }
            }
            XrayToolKind::RealityPublicKey => match keygen_value(&output, PUB_PREFIXES) {
                Some(value) if reality_public_key_valid(&value) => {
                    if let Some(profile) = self.profile_for_target_mut(target) {
                        if let Some(reality) = profile.outbound.stream.reality_settings.as_mut() {
                            reality.password = value;
                            applied = true;
                            if let Some(dialog) = &mut self.derive_dialog {
                                dialog.pending = false;
                            }
                            Ok(t(lang, Key::SrvRealityPubKeyDerived).to_string())
                        } else {
                            Err(t(lang, Key::SrvRealityTargetFieldNotFound).into())
                        }
                    } else {
                        Err(t(lang, Key::SrvToolTargetFieldNotFound).into())
                    }
                }
                Some(_) => Err(t(lang, Key::SrvX25519InvalidPublicKey).into()),
                None => Err(t(lang, Key::SrvX25519CouldNotParse).into()),
            },
        };
        match result {
            Ok(message) => {
                if applied {
                    self.advance_target_generation(target);
                }
                if kind == XrayToolKind::RealityPublicKey {
                    self.derive_dialog = None;
                }
                if !matches!(
                    kind,
                    XrayToolKind::TlsPin | XrayToolKind::TlsPing | XrayToolKind::TlsPingQuic
                ) {
                    self.set_status(StatusLine::ok(message));
                }
            }
            Err(error) => self.report_tool_error(kind, error),
        }
    }

    fn poll_xray_tool(&mut self, lang: Language) {
        let terminal = match self.tool_job.as_mut() {
            Some(job) => job.request.poll(),
            None => return,
        };
        let Some(terminal) = terminal else {
            return;
        };
        let Some(job) = self.tool_job.take() else {
            return;
        };
        if !self.target_is_current(&job.target) {
            return;
        }
        match terminal {
            Terminal::Answered(Ok(output)) => {
                self.apply_tool_output(lang, &job.target, job.kind, output)
            }
            Terminal::Answered(Err(error)) => self.report_tool_error(job.kind, error),
            Terminal::Exited => {
                self.report_tool_error(job.kind, t(lang, Key::SrvToolStoppedWithoutResult).into())
            }
        }
    }

    pub fn show(&mut self, ui: &mut egui::Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        self.poll_profile_validation(lang, ctx);
        self.poll_import_parse(lang);
        self.poll_xray_tool(lang);
        self.consume_latency_probe_result(ctx);
        // Keep the selection pointing at a real profile.
        if let Some(id) = &self.selected
            && !ctx.servers.profiles.iter().any(|profile| &profile.id == id)
        {
            self.selected = None;
            self.existing_draft = None;
        }
        if self.selected.is_none() {
            self.selected = ctx
                .servers
                .active
                .clone()
                .filter(|id| ctx.servers.profiles.iter().any(|profile| &profile.id == id))
                .or_else(|| {
                    ctx.servers
                        .profiles
                        .first()
                        .map(|profile| profile.id.clone())
                });
        }

        egui::Panel::left(ui.auto_id_with("servers.list"))
            .resizable(true)
            .default_size(200.0)
            .size_range(160.0..=300.0)
            .show(ui, |ui| self.show_list(ui, ctx));
        egui::CentralPanel::default().show(ui, |ui| self.show_editor(ui, ctx));
        self.show_dialogs(ui.ctx(), ctx);
    }

    // ---------- left: profile list ----------

    fn show_list(&mut self, ui: &mut egui::Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        ui.add_space(4.0);
        ui.heading(t(lang, Key::ScreenServers));
        ui.separator();

        // One-probe-at-a-time gate shared by the toolbar button and every
        // per-row probe button.
        let probe_gate = if self.pending_latency_probe.is_some() {
            (false, t(lang, Key::SrvLatencyTestAlreadyRunning))
        } else if ctx.operation.is_some() {
            (false, t(lang, Key::SrvAnotherOperationWorking))
        } else {
            (true, "")
        };
        let mut action: Option<ListAction> = None;
        let list_height = (ui.available_height() - 120.0).max(80.0);
        // Virtualized profile list: only the visible index
        // band is laid out, hit-tested, and painted per frame; egui clipping
        // is not layout. Rows are uniform single-line rows: the tallest
        // widget per row is the non-small selectable name button, whose
        // height is clamped to `interact_size.y` (a 14 px single-line body
        // galley of 16 px plus the 2 px net button frame margin is below it;
        // the small delete/probe buttons and the latency label never exceed
        // it), so `row_height = spacing.interact_size.y` — the same
        // derivation the geodata picker's virtualized lists use
        // (`routing.rs`). `show_rows` adds `item_spacing.y` between rows,
        // reproducing the old sequential layout row-for-row (only the
        // trailing row spacing is trimmed from the content height, the
        // standard `show_rows` convention), and keeps the same scroll-state
        // id (same `id_salt` as the empty-state `show` below), so the scroll
        // offset is preserved across the switch.
        let row_height = ui.spacing().interact_size.y;
        let profiles = &ctx.servers.profiles;
        if profiles.is_empty() {
            egui::ScrollArea::vertical()
                .id_salt(ui.auto_id_with("servers.list.scroll"))
                .max_height(list_height)
                .show(ui, |ui| {
                    ui.label(RichText::new(t(lang, Key::NoServersYet)).weak());
                });
        } else {
            egui::ScrollArea::vertical()
                .id_salt(ui.auto_id_with("servers.list.scroll"))
                .max_height(list_height)
                .show_rows(ui, row_height, profiles.len(), |ui, rows| {
                    let colors = status_colors_of(ui);
                    // One frame of drag-reorder state: the pointer (only
                    // while it is inside the list viewport), the proposed
                    // drop — its gap index and the y its insertion line
                    // paints at — and the band geometry both are derived
                    // from. Recomputing this from the laid-out band every
                    // frame keeps a scrolled virtualized list dropping at
                    // real row boundaries.
                    let viewport = ui.clip_rect();
                    let spacing = ui.spacing().item_spacing.y;
                    let drag_pos = self
                        .list_drag
                        .is_some()
                        .then(|| ui.input(|i| i.pointer.interact_pos()))
                        .flatten()
                        .filter(|pos| viewport.contains(*pos));
                    let mut drop_mark: Option<(usize, f32)> = None;
                    let mut last_row_bottom: Option<f32> = None;
                    for index in rows.clone() {
                        let p = &profiles[index];
                        let is_sel = self.selected.as_deref() == Some(p.id.as_str());
                        let is_active = ctx.servers.active.as_deref() == Some(p.id.as_str());
                        // Latency badge text is memoized per profile:
                        // formatting runs only when the row's latency,
                        // the language, or the theme palette moved — a
                        // near-constant input, so idle rows pay a hash
                        // lookup plus a value compare, never a `t_fmt`.
                        if !self
                            .latency_badges
                            .get(p.id.as_str())
                            .is_some_and(|badge| badge.matches(p.latency_ms, lang, colors))
                        {
                            self.latency_badges.insert(
                                p.id.clone(),
                                LatencyBadge::new(p.latency_ms, lang, colors),
                            );
                        }
                        let badge = self
                            .latency_badges
                            .get(p.id.as_str())
                            .expect("badge inserted above");
                        // The dragged row dims in place; the insertion line
                        // carries the drop position. The opacity round-trips
                        // through this ui's painter, so the rows around it
                        // paint untouched.
                        let dimmed = self.list_drag.as_ref().is_some_and(|drag| drag.id == p.id);
                        let previous_opacity = ui.opacity();
                        if dimmed {
                            ui.multiply_opacity(DRAGGED_ROW_OPACITY);
                        }
                        let clicks = server_list_row(
                            ui,
                            lang,
                            &p.name,
                            is_sel,
                            is_active,
                            badge,
                            RowProbeState {
                                enabled: probe_gate.0,
                                disabled_hint: probe_gate.1,
                            },
                        );
                        ui.set_opacity(previous_opacity);
                        if clicks.probe {
                            action = Some(ListAction::ProbeLatency(p.id.clone()));
                        } else if clicks.delete {
                            action = Some(ListAction::Delete(p.id.clone()));
                        } else if clicks.name.clicked() || clicks.row.clicked() {
                            action = Some(ListAction::Select(p.id.clone()));
                        }
                        // A primary press that grows past egui's click
                        // threshold lifts this row; its id is cloned once per
                        // drag, never per frame. Other buttons never lift a
                        // row (egui reports drags for any button, but only a
                        // primary release can complete the move).
                        if clicks.row.drag_started_by(egui::PointerButton::Primary) {
                            self.list_drag = Some(ListDrag {
                                id: p.id.clone(),
                                gap: None,
                            });
                        }
                        // The row under the pointer proposes the gap: above
                        // its midline inserts before it, below inserts after
                        // it. Comparing midlines (not rects) leaves no dead
                        // band in the rows' spacing.
                        if let Some(pos) = drag_pos
                            && drop_mark.is_none()
                            && pos.y <= clicks.row.rect.center().y
                        {
                            drop_mark = Some((index, clicks.row.rect.top() - spacing * 0.5));
                        }
                        last_row_bottom = Some(clicks.row.rect.bottom());
                        // The menu clones the id only when an action is actually
                        // clicked, so borrow the row's id instead of cloning the
                        // 36-char String on every repaint.
                        let id = &p.id;
                        let mut menu = |ui: &mut egui::Ui| {
                            if ui.button(t(lang, Key::SrvSetActive)).clicked() {
                                action = Some(ListAction::SetActive(id.clone()));
                                ui.close();
                            }
                            if ui.button(t(lang, Key::SrvDuplicate)).clicked() {
                                action = Some(ListAction::Duplicate(id.clone()));
                                ui.close();
                            }
                            if ui.button(t(lang, Key::SrvExportLinkQr)).clicked() {
                                action = Some(ListAction::Export(id.clone()));
                                ui.close();
                            }
                            if ui.button(t(lang, Key::SrvDeleteEllipsis)).clicked() {
                                action = Some(ListAction::Delete(id.clone()));
                                ui.close();
                            }
                        };
                        // The name button fills the row (it truncates to the
                        // remaining width), so both it and the row background
                        // open the context menu.
                        clicks.row.context_menu(|ui| menu(ui));
                        clicks.name.context_menu(|ui| menu(ui));
                    }
                    // Below every laid-out row's midline the drop lands at
                    // the band's end: the visible tail of a scrolled list, or
                    // the empty space under a short one.
                    if drag_pos.is_some()
                        && drop_mark.is_none()
                        && let Some(bottom) = last_row_bottom
                    {
                        drop_mark = Some((rows.end, bottom + spacing * 0.5));
                    }
                    if let Some(drag) = &mut self.list_drag {
                        drag.gap = drop_mark.map(|(gap, _)| gap);
                    }
                    // The insertion line paints over the rows, clamped into
                    // the viewport so a band-edge drop stays visible.
                    if let Some((_, y)) = drop_mark {
                        let y = y.clamp(viewport.top() + 1.0, viewport.bottom() - 1.0);
                        ui.painter().hline(
                            ui.max_rect().x_range(),
                            y,
                            egui::Stroke::new(2.0, ui.visuals().selection.bg_fill),
                        );
                    }
                    // Edge auto-scroll keeps rows beyond the band reachable
                    // mid-drag: the wheel is inert while a widget is dragged.
                    if let Some(pos) = drag_pos {
                        let delta =
                            drag_scroll_delta(viewport, pos, ui.input(|i| i.stable_dt).min(0.1));
                        if delta != 0.0 {
                            ui.scroll_with_delta(egui::vec2(0.0, delta));
                            ui.ctx().request_repaint();
                        }
                    }
                });
        }
        // A finished row drag performs its move at the gap the pointer last
        // proposed; a release that ended away from the rows, or a drag whose
        // button state vanished (window focus loss), cancels.
        if let Some(drag) = self.list_drag.take() {
            let (primary_down, released) = ui.input(|i| {
                (
                    i.pointer.primary_down(),
                    i.pointer.button_released(egui::PointerButton::Primary),
                )
            });
            if released {
                if let Some(gap) = drag.gap {
                    action = Some(ListAction::Reorder { id: drag.id, gap });
                }
            } else if primary_down {
                self.list_drag = Some(drag);
            }
        }
        ui.separator();
        let mut add_proto: Option<Protocol> = None;
        ui.add_enabled_ui(self.add_draft.is_none(), |ui| {
            ui.menu_button(t(lang, Key::SrvAddServer), |ui| {
                for protocol in Protocol::ALL {
                    if ui.button(protocol.as_str()).clicked() {
                        add_proto = Some(protocol);
                        ui.close();
                    }
                }
            });
        });
        if let Some(protocol) = add_proto {
            self.draft_tab = EditorTab::Basic;
            self.add_draft = Some(ServerProfile::new(
                t_fmt(lang, Key::SrvNewDraftName, &[&protocol.as_str()]),
                OutboundModel::new(protocol),
            ));
            // A new draft is a fresh validation subject even if the
            // generation counter did not move (the previous draft may have
            // been cancelled without a bump).
            self.add_draft_validation_cache = None;
            self.profile_validation_report = None;
        }
        if ui.button(t(lang, Key::SrvImportLinks)).clicked() {
            self.import_open = true;
            self.profile_validation_report = None;
        }
        // The toolbar button is gated like the rows, plus the no-profiles case.
        let can_test_latency = if !probe_gate.0 {
            probe_gate
        } else if ctx.servers.profiles.is_empty() {
            (false, t(lang, Key::SrvAddServerBeforeLatency))
        } else {
            (true, "")
        };
        let test_latency = if can_test_latency.0 {
            ui.button(t(lang, Key::TestLatency))
                .on_hover_text(t(lang, Key::SrvTestLatencyHint))
        } else {
            ui.add_enabled(false, egui::Button::new(t(lang, Key::TestLatency)))
                .on_disabled_hover_text(can_test_latency.1)
        };
        if test_latency.clicked() {
            self.latency_probe_feedback = None;
            match ctx.request_latency_probe() {
                Ok(()) => {
                    self.pending_latency_probe = Some(false);
                    self.latency_probe = Request::park_in_shell();
                }
                Err(error) => self.latency_probe_feedback = Some((FeedbackLevel::Err, error)),
            }
        }
        if self.pending_latency_probe.is_some() {
            ui.spinner();
            ui.label(t(lang, Key::SrvTestingLatencyIsolated));
        }
        if let Some((level, message)) = &self.latency_probe_feedback {
            let color = match level {
                FeedbackLevel::Ok => status_colors_of(ui).ok,
                FeedbackLevel::Warn => status_colors_of(ui).warn,
                FeedbackLevel::Err => status_colors_of(ui).err,
            };
            ui.colored_label(color, message);
        }
        if ui.button(t(lang, Key::SrvSortByLatency)).clicked() {
            // Ascending latency; timeouts and never-measured last. The first
            // row is the default server (the config's first outbound), so it
            // keeps its slot: a sort must not hand the default route to
            // another server.
            let default = ctx.servers.profiles.first().map(|p| p.id.clone());
            ctx.servers.profiles.sort_by_key(|p| match p.latency_ms {
                Some(v) if v >= 0 => (0, v),
                _ => (1, i64::MAX),
            });
            if let Some(id) = default {
                ctx.servers.activate(&id);
            }
            ctx.mark_dirty();
        }

        // apply deferred list actions (needs &mut profiles)
        match action {
            Some(ListAction::Select(id)) => {
                // A dirty draft guards the switch: the leave modal stages
                // and its resolution performs the selection.
                self.guard_select(id);
            }
            Some(ListAction::ProbeLatency(id)) => {
                // One clone ends the immutable profile borrow so the mutable
                // request can go out; the probe owns the profile from here.
                if let Some(profile) = ctx.servers.profiles.iter().find(|p| p.id == id).cloned() {
                    self.latency_probe_feedback = None;
                    match ctx.request_latency_probe_for(profile) {
                        Ok(()) => {
                            self.pending_latency_probe = Some(true);
                            self.latency_probe = Request::park_in_shell();
                        }
                        Err(error) => {
                            self.latency_probe_feedback = Some((FeedbackLevel::Err, error))
                        }
                    }
                }
            }
            Some(ListAction::SetActive(id)) => {
                // The active profile is the list's first row (the config's
                // default route), so choosing it moves it there.
                ctx.servers.activate(&id);
                ctx.mark_dirty();
            }
            Some(ListAction::Reorder { id, gap }) => {
                if let Some(from) = ctx.servers.profiles.iter().position(|p| p.id == id) {
                    let to = reorder_target(from, gap);
                    if to != from {
                        let profile = ctx.servers.profiles.remove(from);
                        ctx.servers.profiles.insert(to, profile);
                        // A drop can lift a different profile into the first
                        // slot: the top row is the default server, so the
                        // active marker follows it.
                        if let Some(first) = ctx.servers.profiles.first().map(|p| p.id.clone()) {
                            ctx.servers.activate(&first);
                        }
                        ctx.mark_dirty();
                    }
                }
            }
            Some(ListAction::Duplicate(id)) => {
                if let Some(idx) = ctx.servers.profiles.iter().position(|p| p.id == id) {
                    let mut copy = ctx.servers.profiles[idx].clone();
                    copy.id = uuid::Uuid::new_v4().simple().to_string();
                    copy.name = t_fmt(lang, Key::SrvCopySuffix, &[&copy.name]);
                    ctx.servers.profiles.insert(idx + 1, copy.clone());
                    // The switch to the copy is guarded like any other
                    // selection change (the copy is already inserted; the
                    // guard only defers the selection).
                    self.guard_select(copy.id);
                    ctx.mark_dirty();
                }
            }
            Some(ListAction::Export(id)) => {
                if let Some(p) = ctx.servers.profiles.iter().find(|p| p.id == id) {
                    match links::to_link(p) {
                        Ok(link) => {
                            ui.ctx().copy_text(link.clone());
                            self.qr_dialog = Some(QrDialog {
                                name: p.name.clone(),
                                link,
                                tex: None,
                            });
                            self.set_status(StatusLine::ok(t(lang, Key::SrvLinkCopiedToClipboard)));
                        }
                        Err(e) => {
                            self.set_status(StatusLine::err(t_fmt(
                                lang,
                                Key::SrvExportFailed,
                                &[&e.text(lang)],
                            )));
                        }
                    }
                }
            }
            Some(ListAction::Delete(id)) if self.delete_pending.is_none() => {
                // Snapshot everything the confirmation dialog needs at open
                // time: the dialog is modal, so its inputs (profile set,
                // routing rules, balancers) cannot change while it is open,
                // and the linear reference scan must not repeat per repaint.
                self.delete_pending = Some(DeleteDialog {
                    name: ctx
                        .servers
                        .profiles
                        .iter()
                        .find(|p| p.id == id)
                        .map(|p| p.name.clone())
                        .unwrap_or_default(),
                    references: server_reference_paths(ctx.servers, ctx.settings, &id),
                    id,
                });
            }
            Some(ListAction::Delete(_)) => {}
            None => {}
        }
    }
    fn consume_latency_probe_result(&mut self, ctx: &mut UiCtx) {
        let Some(single) = self.pending_latency_probe else {
            return;
        };
        let Some(result) = self.latency_probe.take_parked(ctx.probe_feedback) else {
            return;
        };
        self.pending_latency_probe = None;
        self.latency_probe_feedback = Some(if single {
            format_single_latency_probe_feedback(
                ctx.settings.language,
                result,
                &ctx.servers.profiles,
            )
        } else {
            format_latency_probe_feedback(ctx.settings.language, result, &ctx.servers.profiles)
        });
    }

    // ---------- unsaved-changes guard ----------

    /// Stage a leave action; the Save/Discard/Cancel modal renders on
    /// subsequent frames (from `App::ui`, every frame, any screen). If an
    /// action is already staged, the new one replaces it (the modal is
    /// exclusive; commit handlers clear the staged action before anything
    /// else can stage).
    pub fn stage_leave(&mut self, action: LeaveAction) {
        self.leave_pending = Some(action);
    }

    /// The existing draft's gate as this frame sees it (see
    /// [`existing_draft_gate`]); `None` while no draft is open. `busy` is the
    /// frame's own fact — a caller with no frame (the topbar chip's per-frame
    /// check) passes `false` and reads only a composition that ignores it.
    fn existing_gate(&self, busy: bool) -> Option<DraftGate> {
        self.existing_draft.as_ref().map(|draft| {
            existing_draft_gate(
                draft,
                self.editor_validation_cache.as_ref(),
                &self.finalmask_raw,
                self.profile_validation_in_progress(ProfileValidationOrigin::Draft),
                busy,
            )
        })
    }

    /// The add draft's gate as this frame sees it (see [`add_draft_gate`]);
    /// `None` while the add dialog is closed.
    fn add_gate(&self, busy: bool) -> Option<DraftGate> {
        self.add_draft.as_ref().map(|draft| {
            add_draft_gate(
                draft,
                self.add_draft_generation,
                self.add_draft_validation_cache.as_ref(),
                &self.finalmask_raw,
                self.profile_validation_in_progress(ProfileValidationOrigin::Draft),
                busy,
            )
        })
    }

    /// True when the existing-draft (selected server) or the add-draft
    /// holds uncommitted changes. Cheap: reads the memoized validation
    /// caches; if a draft's cache generation is stale relative to the draft
    /// generation, recompute the changed flag inline (one serialize). Must
    /// be same-frame accurate for the topbar chip (called before/after the
    /// Servers screen renders this frame).
    pub fn unsaved_changes(&self) -> bool {
        // The dirty composition reads only the draft's own facts, and this
        // per-frame chip check runs without a frame: nothing read below
        // consults the busy window.
        if self.existing_gate(false).is_some_and(DraftGate::dirty) {
            return true;
        }
        self.add_gate(false)
            .is_some_and(|gate| gate.changed_from_source)
    }

    /// True exactly once when a staged Quit may proceed (all dirty drafts
    /// committed via Save, or discarded). Consumed by the app shell, which
    /// then runs its normal quit path.
    pub fn take_quit_resume(&mut self) -> bool {
        std::mem::take(&mut self.quit_resume)
    }

    /// Guard a selection switch to `id`: when a draft holds uncommitted
    /// changes, stage the leave modal instead of switching (the modal's
    /// Save/Discard resolution performs the switch); otherwise switch
    /// immediately. Returns true when the selection was switched now.
    /// The delete-confirmation dialog is its own gate, so while it is open
    /// the guard never stages. A click on the already-selected profile
    /// changes nothing and is never guarded.
    fn guard_select(&mut self, id: String) -> bool {
        if self.selected.as_deref() == Some(id.as_str()) {
            return true;
        }
        if self.delete_pending.is_some() {
            self.selected = Some(id);
            return true;
        }
        if self.unsaved_changes() {
            self.stage_leave(LeaveAction::Select(id));
            false
        } else {
            self.selected = Some(id);
            true
        }
    }

    /// The Add-server dialog was closed or cancelled without commit. A derive
    /// dialog targeting this draft cannot outlive it (its apply would
    /// reference a draft that no longer exists), so it is cleared first. The
    /// draft then takes the shared close guard: stage the leave modal when it
    /// holds changes (an add draft is always unsaved — it has no committed
    /// source), otherwise drop it and evict its seeded raw-editor buffers
    /// (dead weight).
    fn close_add_draft(&mut self, draft: ServerProfile) {
        if self.derive_dialog.as_ref().is_some_and(|dialog| {
            matches!(
                &dialog.target,
                ToolTarget::AddDraft { profile_id, .. } if profile_id == &draft.id
            )
        }) {
            self.derive_dialog = None;
        }
        if self.delete_pending.is_none()
            && add_draft_gate(
                &draft,
                self.add_draft_generation,
                self.add_draft_validation_cache.as_ref(),
                &self.finalmask_raw,
                self.profile_validation_in_progress(ProfileValidationOrigin::Draft),
                false,
            )
            .changed_from_source
        {
            self.stage_leave(LeaveAction::CloseAdd);
            self.add_draft = Some(draft);
        } else {
            self.evict_raw_buffers(&draft.id);
        }
    }

    /// Revert the existing editor draft to its persisted profile: drop the
    /// draft, the seeded raw-JSON/PEM editor buffers, and the transient
    /// TLS-probe state tied to it (the cleanup the editor's Discard button
    /// performs).
    fn discard_existing_draft(&mut self) {
        self.existing_draft = None;
        self.derive_dialog = None;
        self.tls_tool_error = None;
        self.tls_tool_output = None;
        self.tls_probe_handshake_ok = false;
        self.tls_probe_leaf_pin = None;
        self.tls_probe_ca_pins.clear();
        self.tls_probe_profile = None;
        self.show_tls_probe_output = false;
        self.profile_validation_report = None;
        // The draft reverts to the persisted profile, so seeded finalmask
        // raw-JSON and PEM editor buffers (both keyed by profile id) would
        // show the discarded text; drop them so the editors re-seed from
        // the reverted draft. Click-time only.
        self.finalmask_raw.clear();
        self.pem_buffers.clear();
    }

    /// Discard resolution of the leave modal: drop the staged action's
    /// draft(s) (existing draft → revert + raw-buffer clear; add draft →
    /// drop + evict; Quit discards both), then perform the action.
    fn discard_leave_action(&mut self, action: LeaveAction) {
        match action {
            LeaveAction::Select(id) => {
                self.discard_existing_draft();
                self.selected = Some(id);
            }
            LeaveAction::CloseAdd => {
                if let Some(draft) = self.add_draft.take() {
                    self.evict_raw_buffers(&draft.id);
                }
            }
            LeaveAction::Quit => {
                self.discard_existing_draft();
                if let Some(draft) = self.add_draft.take() {
                    self.evict_raw_buffers(&draft.id);
                }
                self.quit_resume = true;
            }
        }
    }

    /// Save resolution of the leave modal: start the existing validation
    /// pipeline for the dirty draft (the existing draft first, then the add
    /// draft) and keep the action staged — the commit handler resumes it on
    /// success or clears it on rejection. Failure to start clears the
    /// staged action and shows the status error.
    fn save_leave_action(&mut self, action: LeaveAction, lang: Language, uictx: &mut UiCtx) {
        let busy = uictx.operation.is_some();
        let target = if let Some(draft) = &self.existing_draft
            && self
                .existing_gate(busy)
                .is_some_and(|gate| gate.changed_from_source)
        {
            Some(ToolTarget::ExistingDraft {
                profile_id: draft.profile.id.clone(),
                generation: draft.generation,
            })
        } else if let Some(draft) = &self.add_draft
            && self
                .add_gate(busy)
                .is_some_and(|gate| gate.changed_from_source)
        {
            Some(ToolTarget::AddDraft {
                profile_id: draft.id.clone(),
                generation: self.add_draft_generation,
            })
        } else {
            None
        };
        let Some(target) = target else {
            // Every dirty draft was already committed while the modal was
            // staged; the deferred action is safe to perform now.
            match action {
                LeaveAction::Select(id) => self.selected = Some(id),
                LeaveAction::CloseAdd => {}
                LeaveAction::Quit => self.quit_resume = true,
            }
            return;
        };
        let profile = match &target {
            ToolTarget::ExistingDraft { profile_id, .. } => self
                .existing_draft
                .as_ref()
                .filter(|draft| draft.profile.id == *profile_id)
                .map(|draft| draft.profile.clone()),
            ToolTarget::AddDraft { profile_id, .. } => self
                .add_draft
                .as_ref()
                .filter(|draft| draft.id == *profile_id)
                .cloned(),
        };
        let Some(profile) = profile else {
            self.leave_pending = None;
            return;
        };
        match self.start_profile_validation(
            lang,
            ProfileValidationOrigin::Draft,
            vec![profile],
            Some(target),
            uictx,
        ) {
            Ok(()) => {
                // Keep the action staged: the commit handler resumes it on
                // success, or clears it on rejection.
                self.leave_pending = Some(action);
            }
            Err(error) => {
                self.leave_pending = None;
                self.profile_validation_report = Some(error.clone());
                self.set_status(StatusLine::err(error));
            }
        }
    }

    /// Render the leave modal if an action is staged; no-op otherwise. Safe
    /// to call every frame from `App::ui` (overlays every screen, like the
    /// safety-ack modal). Backdrop click or Escape dismisses it like
    /// Cancel: the staged action is cleared without performing it.
    pub fn show_leave_modal(&mut self, egui_ctx: &egui::Context, uictx: &mut UiCtx) {
        if self.leave_pending.is_none() {
            return;
        }
        let lang = uictx.settings.language;
        let validating = self.profile_validation_in_progress(ProfileValidationOrigin::Draft);
        // Each draft's Save reads the same gate as its editor's own commit
        // control: `committable` refuses a raw-buffer-only dirty state, whose
        // commit would be a no-op that leaves the unsaved indicator on.
        let busy = uictx.operation.is_some();
        let existing_saveable = self.existing_gate(busy).is_some_and(DraftGate::committable);
        let add_saveable = self.add_gate(busy).is_some_and(DraftGate::committable);
        let saveable = existing_saveable || add_saveable;
        let mut decision: Option<LeaveDecision> = None;
        let modal =
            egui::Modal::new(egui::Id::new("broccoli-unsaved-leave")).show(egui_ctx, |ui| {
                ui.set_max_width(520.0);
                ui.heading(t(lang, Key::SrvUnsavedChanges));
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(RichText::new(t(lang, Key::SrvUnsavedLeaveBody)).weak())
                        .wrap(),
                );
                ui.add_space(10.0);
                if validating {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(t(lang, Key::SrvValidatingXrayTest));
                    });
                }
                if ui
                    .add_enabled(
                        saveable && !validating && !busy,
                        egui::Button::new(t(lang, Key::SrvUnsavedLeaveSave)),
                    )
                    .clicked()
                {
                    decision = Some(LeaveDecision::Save);
                }
                ui.add_space(8.0);
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button(t(lang, Key::SrvDiscardChanges)).clicked() {
                        decision = Some(LeaveDecision::Discard);
                    }
                    if ui.button(t(lang, Key::Cancel)).clicked() {
                        decision = Some(LeaveDecision::Cancel);
                    }
                });
            });
        if let Some(decision) = decision {
            // The action resolves only through the modal's buttons; the
            // backdrop/Escape dismissal below clears it without performing
            // it. The modal renders only while an action is staged, so the
            // take never comes up empty here.
            let action = self.leave_pending.take();
            match decision {
                LeaveDecision::Save => {
                    if let Some(action) = action {
                        self.save_leave_action(action, lang, uictx);
                    }
                }
                LeaveDecision::Discard => {
                    if let Some(action) = action {
                        self.discard_leave_action(action);
                    }
                }
                // Cancel: change nothing beyond clearing the staged action.
                LeaveDecision::Cancel => {}
            }
        } else if modal.should_close() {
            self.leave_pending = None;
        }
    }
}

/// One memoized latency badge: the badge text and color are
/// formatted once per input change — measured latency, language, status
/// palette — and reused by every painted row whose inputs still match.
/// [`ServersScreen::latency_badges`] holds one per listed profile.
struct LatencyBadge {
    latency_ms: Option<i64>,
    lang: Language,
    colors: StatusColors,
    text: String,
    color: Color32,
}

impl LatencyBadge {
    fn new(latency_ms: Option<i64>, lang: Language, colors: StatusColors) -> Self {
        let (text, color) = match latency_ms {
            None => (t(lang, Key::EmDash).into(), Color32::GRAY),
            Some(v) if v < 0 => (t(lang, Key::LatencyTimeout).into(), colors.err),
            Some(v) if v < 300 => (t_fmt(lang, Key::LatencyMs, &[&v]), colors.ok),
            Some(v) if v < 1000 => (t_fmt(lang, Key::LatencyMs, &[&v]), colors.warn),
            Some(v) => (t_fmt(lang, Key::LatencyMs, &[&v]), colors.err),
        };
        Self {
            latency_ms,
            lang,
            colors,
            text,
            color,
        }
    }

    /// The memo still covers a row whose inputs are `latency_ms`/`lang`/
    /// `colors` — an allocation-free per-row compare.
    fn matches(&self, latency_ms: Option<i64>, lang: Language, colors: StatusColors) -> bool {
        self.latency_ms == latency_ms && self.lang == lang && self.colors == colors
    }
}

/// Per-frame inputs of one list row's probe button: whether it is enabled,
/// and the hint shown while it is disabled.
struct RowProbeState<'a> {
    enabled: bool,
    disabled_hint: &'a str,
}

/// What a rendered list row reported: the row's own response
/// (click/right-click/drag anywhere on the row), the name button's response,
/// and whether the probe or delete button was clicked.
struct RowClicks {
    row: egui::Response,
    name: egui::Response,
    delete: bool,
    probe: bool,
}

/// An in-flight list drag-reorder: the profile being moved (its id is cloned
/// once at drag start, never per frame) and the gap the drop would insert it
/// at — an index in the list as drawn (`0..=len`), recomputed from the
/// pointer every frame, `None` while the pointer is off the rows (a release
/// then cancels the move).
struct ListDrag {
    id: String,
    gap: Option<usize>,
}

/// Opacity of the row being dragged: the source stays in place and dims,
/// while the insertion line carries the drop position.
const DRAGGED_ROW_OPACITY: f32 = 0.4;

/// Distance from the list viewport's top/bottom edge (points) at which a row
/// drag starts auto-scrolling, and the speed the scroll ramps to at the very
/// edge (points per second). The band is wider than one row — the row height
/// is `interact_size.y` (18 points by default) plus spacing — so a pointer
/// held at the last visible row's center sits inside it.
const DRAG_SCROLL_EDGE: f32 = 32.0;
const DRAG_SCROLL_MAX_SPEED: f32 = 600.0;

/// Where a dragged row lands: `gap` indexes the list as drawn, so a gap past
/// the row's own slot shifts down one once the row is lifted out; the two
/// gaps adjacent to its slot are no-ops.
fn reorder_target(from: usize, gap: usize) -> usize {
    if gap > from { gap - 1 } else { gap }
}

/// Auto-scroll delta (points, signed like [`egui::Ui::scroll_with_delta`]:
/// positive scrolls toward the top) for a row drag hovering at `pos` for
/// `dt` seconds. Zero outside the viewport and away from its edges; inside
/// the [`DRAG_SCROLL_EDGE`] band the speed ramps up to
/// [`DRAG_SCROLL_MAX_SPEED`] as the pointer approaches the edge, so rows
/// beyond the visible band stay reachable mid-drag (the wheel is inert while
/// a widget is dragged).
fn drag_scroll_delta(viewport: egui::Rect, pos: egui::Pos2, dt: f32) -> f32 {
    if !viewport.contains(pos) {
        return 0.0;
    }
    let ramp = |edge_distance: f32| {
        ((DRAG_SCROLL_EDGE - edge_distance) / DRAG_SCROLL_EDGE).clamp(0.0, 1.0)
    };
    let toward_top = ramp(pos.y - viewport.top());
    let toward_bottom = ramp(viewport.bottom() - pos.y);
    (toward_top - toward_bottom) * DRAG_SCROLL_MAX_SPEED * dt
}

/// One row in the servers list: the name on the left, and the latency badge,
/// probe button, and delete button pinned to the right edge. Returns the row
/// [`egui::Response`] (click/right-click/drag anywhere on the row), the name
/// button's response (it fills the row, so it must be treated as a select
/// target too), and whether the probe or delete button was clicked.
///
/// A plain `ui.horizontal` lets an over-long name overflow its allocated
/// width and paint over the latency badge and the delete button, hiding both.
/// So the name is laid out with `Sides::shrink_left().truncate()`: the right
/// block is measured and placed first, and the name is clamped to the
/// remaining width, truncating with "…" instead of colliding.
///
/// The row's interaction is registered by the surrounding `ui.horizontal`
/// *before* the probe and delete buttons, so a click on them routes to the
/// button and not the row — the caller must check those clicks first. The
/// row's drag sense sits below them the same way, and the buttons sense
/// clicks only, so a press-and-move that starts on any of them (or on the
/// name button) routes to the row and reorders it. A touch swipe over a row
/// claims the drag the same way (egui routes a drag to the topmost
/// drag-sensing widget), so on a touch screen a swipe lifts the row instead
/// of scrolling the list; the wheel and swipes over the empty tail below the
/// rows still scroll.
fn server_list_row(
    ui: &mut egui::Ui,
    lang: Language,
    name: &str,
    selected: bool,
    active: bool,
    latency: &LatencyBadge,
    probe: RowProbeState<'_>,
) -> RowClicks {
    let inner = ui.horizontal(|ui| {
        egui::containers::Sides::new()
            .shrink_left()
            .truncate()
            .show(
                ui,
                |ui| {
                    // Text atoms instead of `format!("● {name}")` /
                    // `name.to_string()`: no heap allocation per row per
                    // repaint. The atoms render as one adjacent run.
                    let button = if name.is_empty() {
                        egui::Button::selectable(selected, t(lang, Key::SrvUnnamed))
                    } else if active {
                        egui::Button::selectable(selected, ("● ", name))
                    } else {
                        egui::Button::selectable(selected, name)
                    };
                    ui.add(button.truncate())
                        .on_hover_text(t(lang, Key::SrvDragToReorder))
                },
                |ui| {
                    let delete = ui
                        .small_button(t(lang, Key::DeleteRow))
                        .on_hover_text(t(lang, Key::DeleteServer));
                    let probe_button = if probe.enabled {
                        ui.small_button(t(lang, Key::ProbeRow))
                            .on_hover_text(t(lang, Key::SrvProbeServerLatencyHint))
                    } else {
                        // Same small sizing as the enabled variant: a gated
                        // button must not grow the row while a probe runs.
                        ui.add_enabled(false, egui::Button::new(t(lang, Key::ProbeRow)).small())
                            .on_disabled_hover_text(probe.disabled_hint)
                    };
                    // The badge text/color come from the row's memoized
                    // [`LatencyBadge`] — borrowed, never
                    // re-formatted per painted row.
                    // Not selectable: `interaction.selectable_labels` defaults to
                    // true, and a click-sensing label would sit on top of the
                    // row's click target, making the latency area unclickable.
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(latency.text.as_str()).color(latency.color),
                        )
                        .selectable(false),
                    );
                    (delete, probe_button)
                },
            )
    });
    let (name_resp, (delete_resp, probe_resp)) = inner.inner;
    let delete_clicked = delete_resp.clicked();
    let probe_clicked = probe_resp.clicked();
    let resp = inner.response.interact(egui::Sense::click_and_drag());
    RowClicks {
        row: resp,
        name: name_resp,
        delete: delete_clicked,
        probe: probe_clicked,
    }
}

impl ServersScreen {
    // ---------- editor (right side) ----------

    /// Rebuild the memoized existing-draft findings when the draft generation
    /// moved on, and their strings when the generation or the UI language
    /// moved on; a no-op while both still cover the draft. One real sweep per
    /// generation, one render per (generation, language) — never per frame.
    fn refresh_editor_validation_cache(&mut self, draft: &ExistingProfileDraft, lang: Language) {
        refresh_editor_validation(&mut self.editor_validation_cache, draft, lang);
    }

    /// Add-draft twin of [`Self::refresh_editor_validation_cache`].
    fn refresh_add_draft_validation_cache(&mut self, draft: &ServerProfile, lang: Language) {
        refresh_add_draft_validation(
            &mut self.add_draft_validation_cache,
            self.add_draft_generation,
            draft,
            lang,
        );
    }

    /// Run `render` with the memoized existing-draft verdicts moved out of
    /// the screen and handed to it for the call. The Basic and Security tabs
    /// borrow a memoized slice from the cache while calling screen methods
    /// that borrow the screen mutably; moving the cache out (and restoring it
    /// right after) keeps those messages borrowed instead of cloned per
    /// frame.
    fn with_editor_validation<R>(
        &mut self,
        render: impl FnOnce(&mut Self, Option<&EditorValidationCache>) -> R,
    ) -> R {
        let cache = self.editor_validation_cache.take();
        let result = render(self, cache.as_ref());
        self.editor_validation_cache = cache;
        result
    }

    /// Add-draft twin of [`Self::with_editor_validation`].
    fn with_add_draft_validation<R>(
        &mut self,
        render: impl FnOnce(&mut Self, Option<&AddDraftValidationCache>) -> R,
    ) -> R {
        let cache = self.add_draft_validation_cache.take();
        let result = render(self, cache.as_ref());
        self.add_draft_validation_cache = cache;
        result
    }

    fn show_editor(&mut self, ui: &mut egui::Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        // Borrow the selected id instead of cloning the 36-char String on
        // every repaint (see show_list). The borrow is confined to the
        // reseed check below: the tab closures re-borrow the id from the
        // owned draft, whose profile id always mirrors the selection.
        let Some(id) = self.selected.as_deref() else {
            ui.centered_and_justified(|ui| {
                ui.weak(t(lang, Key::SrvSelectServerOrAdd));
            });
            return;
        };

        if self
            .existing_draft
            .as_ref()
            .is_none_or(|draft| draft.profile.id != id)
        {
            let Some(persisted) = ctx.servers.profiles.iter().find(|profile| profile.id == id)
            else {
                return;
            };
            let source = match serde_json::to_value(persisted) {
                Ok(source) => source,
                Err(error) => {
                    self.set_status(StatusLine::err(t_fmt(
                        lang,
                        Key::SrvPrepareDraftFailed,
                        &[&error],
                    )));
                    return;
                }
            };
            self.existing_draft = Some(ExistingProfileDraft {
                id: id.to_owned(),
                tag: persisted.tag(),
                profile: persisted.clone(),
                source,
                generation: 0,
            });
            // A fresh draft (or one for a different profile) invalidates the
            // memoized validation: the cache is keyed on the generation
            // counter, which restarts at zero for every new draft.
            self.editor_validation_cache = None;
            self.profile_validation_report = None;
        }

        let Some(mut draft) = self.existing_draft.take() else {
            return;
        };
        // The validation blocks below — the dot, the Advanced tab's inline
        // finalmask verdict, the error list, the Validate gate — render from
        // the memoized cache, so a draft whose generation or language moved
        // outside this frame's content edits (fresh open, tool application,
        // language switch) must carry a current cache before anything
        // renders. Content edits bump the generation after the tab content
        // and refresh again below; idle frames hit only the cheap freshness
        // check here and there.
        self.refresh_editor_validation_cache(&draft, lang);
        // The two gate facts that move without a draft edit: the profile
        // validation job (read here so the dot, the tabs' gates and the
        // action row all see one value) and the busy window.
        let validating = self.profile_validation_in_progress(ProfileValidationOrigin::Draft);
        let busy = ctx.operation.is_some();
        let mut changed = false;
        ui.horizontal(|ui| {
            ui.label(t(lang, Key::SrvName));
            changed |= ui
                .add(egui::TextEdit::singleline(&mut draft.profile.name).desired_width(220.0))
                .changed();
            ui.separator();
            ui.monospace(draft.tag.as_str());
            // Unsaved-changes dot: the draft differs from its committed
            // source or a raw buffer holds uncommitted text (the same
            // condition that enables Discard). Only the existing draft gets
            // the dot — an add draft is unsaved by definition.
            if existing_draft_gate(
                &draft,
                self.editor_validation_cache.as_ref(),
                &self.finalmask_raw,
                validating,
                busy,
            )
            .dirty()
            {
                ui.add(
                    egui::Label::new(RichText::new("●").color(status_colors_of(ui).warn))
                        .selectable(false),
                )
                .on_hover_text(t(lang, Key::SrvUnsavedChanges));
            }
            ui.separator();
            let current = draft.profile.outbound.protocol.as_str();
            egui::ComboBox::from_id_salt("proto")
                .selected_text(current)
                .show_ui(ui, |ui| {
                    for protocol in Protocol::ALL {
                        if ui
                            .selectable_label(
                                draft.profile.outbound.protocol == protocol,
                                protocol.as_str(),
                            )
                            .clicked()
                            && draft.profile.outbound.protocol != protocol
                        {
                            draft.profile.outbound.select_protocol(protocol);
                            changed = true;
                        }
                    }
                });
        });
        ui.separator();
        ui.horizontal(|ui| {
            for &tab in TABS {
                ui.selectable_value(&mut self.tab, tab, tab.label(lang));
            }
        });
        ui.separator();
        // The action row below (validation block + Validate/Discard buttons)
        // is laid out after the tab content; reserve its worst-case height
        // (errors capped in their own scroll below) so the buttons stay
        // visible and clickable at any window size, and the tab content
        // scrolls inside the remainder instead of expanding past the panel
        // edge (mirrors the servers.list reserve above and the add-draft
        // dialog's fixed cap).
        let tab_height = (ui.available_height() - 240.0).max(160.0);
        egui::ScrollArea::vertical()
            .id_salt("servers.editor.scroll")
            .max_height(tab_height)
            .show(ui, |ui| {
                changed |= match self.tab {
                    EditorTab::Basic => self.with_editor_validation(|screen, cache| {
                        let inline_errors = cache
                            .map(|cached| cached.rendered.basic_inline.as_slice())
                            .unwrap_or(&[]);
                        screen.basic_tab_for_target(
                            ui,
                            lang,
                            &mut draft.profile,
                            Some((
                                DraftTargetKind::Existing,
                                draft.id.as_str(),
                                draft.generation,
                            )),
                            inline_errors,
                        )
                    }),
                    EditorTab::Transport => self.transport_tab(
                        ui,
                        lang,
                        &mut draft.profile.outbound.stream,
                        0,
                        Some((
                            DraftTargetKind::Existing,
                            draft.id.as_str(),
                            draft.generation,
                        )),
                    ),
                    EditorTab::Security => {
                        let address = draft.profile.server_address();
                        self.with_editor_validation(|screen, cache| {
                            let ech_sockopt_errors = cache
                                .map(|cached| cached.rendered.ech_sockopt.as_slice())
                                .unwrap_or(&[]);
                            screen.security_tab_for_target(
                                ui,
                                lang,
                                Some((
                                    DraftTargetKind::Existing,
                                    draft.id.as_str(),
                                    draft.generation,
                                )),
                                &mut draft.profile.outbound.stream,
                                address.as_deref(),
                                ech_sockopt_errors,
                            )
                        })
                    }
                    EditorTab::Mux => {
                        let flow = vless_flow(&draft.profile.outbound.settings);
                        mux_tab(ui, lang, &mut draft.profile.outbound.mux, flow)
                    }
                    EditorTab::Advanced => {
                        // The inline finalmask and sockopt verdicts ride the
                        // memoized validation cache (refreshed above whenever
                        // the draft generation or language moved): identical
                        // messages, zero re-validation on idle frames.
                        let finalmask_errors: &[String] = self
                            .editor_validation_cache
                            .as_ref()
                            .map(|cached| cached.rendered.finalmask.as_slice())
                            .unwrap_or(&[]);
                        let stream_sockopt_errors: &[String] = self
                            .editor_validation_cache
                            .as_ref()
                            .map(|cached| cached.rendered.stream_sockopt.as_slice())
                            .unwrap_or(&[]);
                        ServersScreen::advanced_tab(
                            ui,
                            lang,
                            &mut draft.profile,
                            &ctx.servers.profiles,
                            AdvancedTabCtx {
                                set_key: (
                                    ctx.config_revision,
                                    *ctx.dirty,
                                    ctx.servers.profiles.len(),
                                ),
                                finalmask_errors,
                                stream_sockopt_errors,
                                dialer_proxy_options: &mut self.dialer_proxy_options,
                                finalmask_raw: &mut self.finalmask_raw,
                                pem_buffers: &mut self.pem_buffers,
                            },
                        )
                    }
                };
            });
        if changed {
            // The retired `proxySettings` key needs a chain decision, not any
            // edit: the profile stops gating when its chain target differs
            // from the loaded source's, or when the user dismisses the key on
            // the finding row. An unrelated edit (a rename, a port) leaves
            // the gate in place, so a save can never drop a chain the user
            // never looked at.
            if draft.profile.chain_target() != source_chain_target(&draft.source) {
                draft.profile.outbound.retired_proxy_settings = None;
            }
            // The retired `quicParams.udpHop` key clears the same way: the
            // user rebuilds the hop as a `udphop` UDP mask (the mask list
            // moved away from the loaded source's), or dismisses the key on
            // the finding row. Editing an unrelated mask leaves the gate.
            if udphop_masks(&draft.profile) != source_udphop_masks(&draft.source)
                && let Some(quic) = draft
                    .profile
                    .outbound
                    .stream
                    .finalmask
                    .as_mut()
                    .and_then(|finalmask| finalmask.quic_params.as_mut())
            {
                quic.retired_udp_hop = None;
            }
            draft.generation = draft.generation.wrapping_add(1);
            self.profile_validation_report = None;
        }
        // Content edits bumped the generation above; refresh the memoized
        // verdicts (validation errors, finalmask issues, changed-from-source)
        // once for the new generation. Idle frames hit the cheap freshness
        // check only.
        self.refresh_editor_validation_cache(&draft, lang);
        let Some(cached) = self.editor_validation_cache.as_ref() else {
            return;
        };
        let validation_errors = &cached.rendered.blocking;
        let validation_warnings = &cached.rendered.advisory;

        let mut dismissed_retired_key = false;
        let mut dismissed_retired_hop = false;
        if !validation_errors.is_empty() {
            ui.separator();
            ui.colored_label(status_colors_of(ui).err, t(lang, Key::SrvFixBeforeValidate));
            // Bound the list so a long error set can never push the action
            // row off the panel; the list scrolls within its own area
            // (mirrors the validation-output block below).
            egui::ScrollArea::vertical()
                .id_salt("servers.editor.validation-errors")
                .max_height(140.0)
                .show(ui, |ui| {
                    for error in validation_errors {
                        ui.colored_label(
                            status_colors_of(ui).err,
                            t_fmt(lang, Key::ErrorBullet, &[error]),
                        );
                    }
                });
            // The retired `proxySettings` finding's other way out: a user who
            // wants no chain at all drops the key here instead of setting a
            // target. The note states what that costs, so it renders only
            // when the profile will keep no chain; the control is the finding
            // row's own and never appears for any other rule.
            if draft.profile.outbound.retired_proxy_settings.is_some() {
                ui.horizontal(|ui| {
                    if draft.profile.chain_target().is_none() {
                        ui.weak(t(lang, Key::SrvRemoveProxySettingsKeyNote));
                    }
                    if ui.button(t(lang, Key::SrvRemoveProxySettingsKey)).clicked() {
                        dismissed_retired_key = true;
                    }
                });
            }
            // The retired `quicParams.udpHop` finding's other way out: a user
            // who wants no hop at all drops the key here instead of building
            // the mask. The note states what that costs, so it renders only
            // when the profile keeps no `udphop` mask; the control is the
            // finding row's own and never appears for any other rule.
            if retired_udp_hop_present(&draft.profile) {
                ui.horizontal(|ui| {
                    if !profile_has_udphop_mask(&draft.profile) {
                        ui.weak(t(lang, Key::SrvRemoveUdpHopKeyNote));
                    }
                    if ui.button(t(lang, Key::SrvRemoveUdpHopKey)).clicked() {
                        dismissed_retired_hop = true;
                    }
                });
            }
        }
        // Configuration warnings render amber under their own header;
        // unlike the error block above they never gate Validate-and-save.
        if !validation_warnings.is_empty() {
            ui.separator();
            ui.colored_label(
                status_colors_of(ui).warn,
                t(lang, Key::SrvConfigurationWarningsHeader),
            );
            egui::ScrollArea::vertical()
                .id_salt("servers.editor.validation-warnings")
                .max_height(140.0)
                .show(ui, |ui| {
                    for warning in validation_warnings {
                        ui.colored_label(
                            status_colors_of(ui).warn,
                            t_fmt(lang, Key::ErrorBullet, &[warning]),
                        );
                    }
                });
        }
        ui.separator();
        // One gate for the action row: Validate-and-save commits a changed
        // draft that nothing blocks, which is only meaningful for the source
        // this draft owns, and it waits out both the validation job and the
        // busy window. Discard is the dirty composition — it must also be
        // available while a raw buffer of this profile holds text that never
        // parsed into the draft, or the user would be stuck with the error
        // text.
        let gate = existing_draft_gate(
            &draft,
            self.editor_validation_cache.as_ref(),
            &self.finalmask_raw,
            validating,
            busy,
        );
        let mut validate_clicked = false;
        let mut discard_clicked = false;
        ui.horizontal(|ui| {
            validate_clicked = ui
                .add_enabled(
                    gate.committable() && !gate.validating && !gate.busy,
                    egui::Button::new(t(lang, Key::SrvValidateAndSave)),
                )
                .on_hover_text(t(lang, Key::SrvValidateAndSaveHint))
                .clicked();
            discard_clicked = ui
                .add_enabled(
                    gate.dirty() && !gate.validating,
                    egui::Button::new(t(lang, Key::SrvDiscardChanges)),
                )
                .clicked();
            if validating {
                ui.spinner();
                ui.weak(t(lang, Key::SrvValidatingXrayTest));
            }
        });
        // Dismissing the retired key changes the draft without touching any
        // field: the next frame's sweep drops the finding, and the next save
        // writes the profile without the key.
        if dismissed_retired_key {
            draft.profile.outbound.retired_proxy_settings = None;
            draft.generation = draft.generation.wrapping_add(1);
            self.profile_validation_report = None;
        }
        if dismissed_retired_hop
            && let Some(quic) = draft
                .profile
                .outbound
                .stream
                .finalmask
                .as_mut()
                .and_then(|finalmask| finalmask.quic_params.as_mut())
        {
            quic.retired_udp_hop = None;
            draft.generation = draft.generation.wrapping_add(1);
            self.profile_validation_report = None;
        }
        // The whole-profile snapshot is needed only when the user actually
        // clicks "Validate and save", not on every repaint.
        let validation_profile = validate_clicked.then(|| draft.profile.clone());
        let validation_target = validate_clicked.then(|| ToolTarget::ExistingDraft {
            profile_id: draft.profile.id.clone(),
            generation: draft.generation,
        });
        self.existing_draft = Some(draft);
        if validate_clicked
            && let (Some(validation_profile), Some(validation_target)) =
                (validation_profile, validation_target)
            && let Err(error) = self.start_profile_validation(
                lang,
                ProfileValidationOrigin::Draft,
                vec![validation_profile],
                Some(validation_target),
                ctx,
            )
        {
            self.profile_validation_report = Some(error.clone());
            self.set_status(StatusLine::err(error));
        }
        if discard_clicked {
            self.discard_existing_draft();
        }
        if let Some(report) = &self.profile_validation_report {
            ui.separator();
            ui.colored_label(
                status_colors_of(ui).err,
                t(lang, Key::SrvValidationFailedColon),
            );
            egui::ScrollArea::vertical()
                .id_salt("servers.editor.validation-output")
                .max_height(140.0)
                .show(ui, |ui| ui.monospace(report));
        }
    }

    // ---------- Basic tab: per-protocol settings ----------

    fn basic_tab_for_target(
        &mut self,
        ui: &mut egui::Ui,
        lang: Language,
        profile: &mut ServerProfile,
        target: Option<(DraftTargetKind, &str, u64)>,
        // The Basic tab's memoized inline outbound verdicts (the
        // public-endpoint TLS rules), rendered under the protocol fields.
        inline_errors: &[String],
    ) -> bool {
        let mut changed = false;
        match &mut profile.outbound.settings {
            ProtocolSettings::Vless(settings) => {
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port);
                let (field_changed, generate) = keygen_field(
                    ui,
                    t(lang, Key::SrvIdUuid),
                    &mut settings.id,
                    "uuid",
                    |v| v_uuid_required(lang, v),
                    &KeygenButton {
                        label: t(lang, Key::Generate),
                        hover: t(lang, Key::SrvGenerateUuidHint),
                    },
                );
                changed |= field_changed;
                if generate {
                    self.request_tool(ui, lang, target, XrayToolKind::Uuid, vec!["uuid".into()]);
                }
                changed |= widgets::combo_str_labeled(
                    ui,
                    "flow",
                    &mut settings.flow,
                    &VLESS_FLOW,
                    t(lang, Key::SrvDefault),
                    false,
                );
                // Warn inline at the flow
                // trigger when the profile's mux would carry TCP under a
                // vision flow. The predicate is the model's own, so this
                // can never drift from the sweep (message + fix live in
                // i18n). Disjoint field read: settings is borrowed mutably,
                // mux is a sibling field of the same outbound.
                if mux_conflicts_with_vision_flow(
                    &settings.flow,
                    profile.outbound.mux.enabled,
                    profile.outbound.mux.concurrency,
                ) {
                    ui.colored_label(
                        status_colors_of(ui).warn,
                        validation_message(&ValidationCode::MuxWithVisionFlow, lang),
                    );
                }
                // Informational copy: what the two vision variants do
                // with UDP/443 (no validation, no gating).
                ui.weak(t(lang, Key::SrvVisionUdp443Hint));
                let (field_changed, generate) = keygen_field(
                    ui,
                    "encryption",
                    &mut settings.encryption,
                    "none | mlkem768x25519plus…",
                    |v| v_vless_encryption_required(lang, v),
                    &KeygenButton {
                        label: t(lang, Key::Generate),
                        hover: t(lang, Key::SrvGenerateVlessencHint),
                    },
                );
                changed |= field_changed;
                if generate {
                    self.request_tool(
                        ui,
                        lang,
                        target,
                        XrayToolKind::VlessEncryption,
                        vec!["vlessenc".into()],
                    );
                }
                changed |= widgets::opt_num(ui, "level", &mut settings.level, 0..=u32::MAX);
                let mut reverse = settings.reverse.is_some();
                if ui
                    .checkbox(&mut reverse, t(lang, Key::SrvReverseProxy))
                    .changed()
                {
                    settings.reverse = reverse.then(VlessReverse::default);
                    changed = true;
                }
                if let Some(reverse) = settings.reverse.as_mut() {
                    changed |= widgets::validated_field(
                        ui,
                        t(lang, Key::SrvReverseTag),
                        &mut reverse.tag,
                        "inbound tag to reverse-dial",
                        |v| v_required(lang, v),
                    );
                    let mut sniffing = reverse.sniffing.is_some();
                    if ui
                        .checkbox(&mut sniffing, t(lang, Key::SrvReverseSniffing))
                        .changed()
                    {
                        reverse.sniffing = sniffing.then(Sniffing::default);
                        changed = true;
                    }
                    if let Some(sniffing) = reverse.sniffing.as_mut() {
                        changed |= sniffing_editor(ui, lang, sniffing, false);
                    }
                }
            }
            ProtocolSettings::Vmess(settings) => {
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port);
                let (field_changed, generate) = keygen_field(
                    ui,
                    t(lang, Key::SrvIdUuid),
                    &mut settings.id,
                    "uuid",
                    |v| v_uuid_required(lang, v),
                    &KeygenButton {
                        label: t(lang, Key::Generate),
                        hover: t(lang, Key::SrvGenerateUuidHint),
                    },
                );
                changed |= field_changed;
                if generate {
                    self.request_tool(ui, lang, target, XrayToolKind::Uuid, vec!["uuid".into()]);
                }
                changed |= widgets::combo_str_labeled(
                    ui,
                    "security",
                    &mut settings.security,
                    VMESS_SECURITY,
                    t(lang, Key::SrvDefault),
                    false,
                );
                changed |= widgets::text_field(
                    ui,
                    "experiments",
                    &mut settings.experiments,
                    "AuthenticatedLength,NoTerminationSignal",
                );
                changed |= widgets::opt_num(ui, "level", &mut settings.level, 0..=u32::MAX);
            }
            ProtocolSettings::Trojan(settings) => {
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port);
                changed |=
                    widgets::validated_field(ui, "password", &mut settings.password, "", |v| {
                        v_required(lang, v)
                    });
                changed |= widgets::opt_num(ui, "level", &mut settings.level, 0..=u32::MAX);
            }
            ProtocolSettings::Shadowsocks(settings) => {
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port);
                changed |= widgets::combo_str_labeled(
                    ui,
                    "method",
                    &mut settings.method,
                    &SS_METHODS,
                    t(lang, Key::SrvDefault),
                    false,
                );
                if settings.method.is_empty() {
                    ui.colored_label(
                        status_colors_of(ui).err,
                        t(lang, Key::SrvShadowsocksMethodRequired),
                    );
                }
                changed |= widgets::validated_field(
                    ui,
                    "password",
                    &mut settings.password,
                    "2022 methods: base64 key of exact length",
                    |v| v_required(lang, v),
                );
                changed |= widgets::opt_num(ui, "level", &mut settings.level, 0..=u8::MAX.into());
                if settings.level.is_some_and(|level| level > u8::MAX.into()) {
                    ui.colored_label(
                        status_colors_of(ui).err,
                        t(lang, Key::SrvShadowsocksLevelRange),
                    );
                }
            }
            ProtocolSettings::Socks(settings) => {
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port);
                changed |= widgets::text_field(ui, "user", &mut settings.user, "");
                changed |= widgets::text_field(ui, "pass", &mut settings.pass, "");
                changed |= widgets::opt_num(ui, "level", &mut settings.level, 0..=u32::MAX);
            }
            ProtocolSettings::Http(settings) => {
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port);
                changed |= widgets::text_field(ui, "user", &mut settings.user, "");
                changed |= widgets::text_field(ui, "pass", &mut settings.pass, "");
                changed |= json_map_kv(
                    ui,
                    lang,
                    &mut settings.headers,
                    t(lang, Key::HeaderHint),
                    t(lang, Key::ValueHint),
                    &mut self.json_key_scratch,
                );
                changed |= widgets::opt_num(ui, "level", &mut settings.level, 0..=u32::MAX);
            }
            ProtocolSettings::Wireguard(settings) => {
                let (field_changed, generate) = keygen_field(
                    ui,
                    t(lang, Key::SrvSecretKey),
                    &mut settings.secret_key,
                    "base64, 32 bytes",
                    |v| v_wg_key(lang, v),
                    &KeygenButton {
                        label: t(lang, Key::Generate),
                        hover: t(lang, Key::SrvGenerateWgHint),
                    },
                );
                changed |= field_changed;
                if generate {
                    self.request_tool(
                        ui,
                        lang,
                        target,
                        XrayToolKind::WireguardSecret,
                        vec!["wg".into()],
                    );
                }
                changed |= widgets::string_list(
                    ui,
                    lang,
                    t(lang, Key::SrvLocalAddresses),
                    &mut settings.address,
                    "10.0.0.2/32",
                );
                // The widget hands each row the list length, so the sentinel
                // verdict follows the list as rows come and go.
                changed |= widgets::validated_string_list(
                    ui,
                    lang,
                    t(lang, Key::SrvWgRemoteDns),
                    &mut settings.remote_dns,
                    t(lang, Key::SrvWgRemoteDnsHint),
                    |entry, list_len| v_wg_remote_dns_entry(lang, entry, list_len),
                );
                ui.small(t(lang, Key::SrvWgRemoteDnsNote));
                let mut mtu = (settings.mtu != 0).then_some(settings.mtu);
                if widgets::opt_num(ui, "mtu", &mut mtu, 576..=1500) {
                    settings.mtu = mtu.unwrap_or_default();
                    changed = true;
                }
                changed |= widgets::combo_str_labeled(
                    ui,
                    t(lang, Key::SrvDomainStrategy),
                    &mut settings.domain_strategy,
                    WG_TARGET_STRATEGIES,
                    t(lang, Key::SrvDefault),
                    false,
                );
                let mut has_reserved = settings.reserved.is_some();
                if ui
                    .checkbox(&mut has_reserved, t(lang, Key::SrvReservedBytes))
                    .changed()
                {
                    settings.reserved = has_reserved.then(|| vec![0; 3]);
                    changed = true;
                }
                match settings.reserved.as_mut() {
                    Some(reserved) if reserved.len() == 3 => {
                        ui.horizontal(|ui| {
                            ui.label(t(lang, Key::SrvReservedColon));
                            for byte in reserved {
                                changed |=
                                    ui.add(egui::DragValue::new(byte).range(0..=255)).changed();
                            }
                        });
                    }
                    Some(reserved) => {
                        ui.horizontal(|ui| {
                            ui.colored_label(
                                status_colors_of(ui).err,
                                t_fmt(lang, Key::SrvReservedBytesFound, &[&reserved.len()]),
                            );
                            if ui
                                .small_button(t(lang, Key::SrvResetThreeZeroBytes))
                                .clicked()
                            {
                                *reserved = vec![0; 3];
                                changed = true;
                            }
                        });
                    }
                    None => {}
                }
                ui.label(t(lang, Key::SrvPeersColon));
                if settings.peers.is_empty() {
                    ui.colored_label(status_colors_of(ui).err, t(lang, Key::SrvAtLeastOneWgPeer));
                }
                let mut remove_peer = None;
                for (index, peer) in settings.peers.iter_mut().enumerate() {
                    ui.push_id(index, |ui| {
                        ui.group(|ui| {
                            changed |= widgets::validated_field(
                                ui,
                                t(lang, Key::SrvPublicKey),
                                &mut peer.public_key,
                                "remote peer public key",
                                |v| v_wg_key(lang, v),
                            );
                            ui.small(t(lang, Key::SrvWgPeerPublicKeyNote));
                            changed |= widgets::validated_field(
                                ui,
                                "endpoint",
                                &mut peer.endpoint,
                                "host:51820",
                                |v| v_required(lang, v),
                            );
                            changed |= widgets::validated_field(
                                ui,
                                t(lang, Key::SrvPreSharedKey),
                                &mut peer.pre_shared_key,
                                "(optional)",
                                |v| v_optional_wg_key(lang, v),
                            );
                            changed |= widgets::string_list(
                                ui,
                                lang,
                                "allowed IPs",
                                &mut peer.allowed_ips,
                                "0.0.0.0/0",
                            );
                            changed |= widgets::opt_num(
                                ui,
                                t(lang, Key::SrvKeepaliveS),
                                &mut peer.keep_alive,
                                0..=3600,
                            );
                            changed |= widgets::opt_num(ui, "level", &mut peer.level, 0..=u32::MAX);
                            if ui.button(t(lang, Key::SrvRemovePeer)).clicked() {
                                remove_peer = Some(index);
                            }
                        });
                    });
                }
                if ui.button(t(lang, Key::SrvAddPeer)).clicked() {
                    settings.peers.push(WireguardPeer {
                        allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
                        ..Default::default()
                    });
                    changed = true;
                }
                if let Some(index) = remove_peer {
                    settings.peers.remove(index);
                    changed = true;
                }
            }
            ProtocolSettings::Freedom(settings) => {
                changed |= widgets::combo_str_labeled(
                    ui,
                    t(lang, Key::SrvTargetStrategy),
                    &mut settings.target_strategy,
                    TARGET_STRATEGIES,
                    t(lang, Key::SrvDefault),
                    false,
                );
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::UserLevel),
                    &mut settings.user_level,
                    0..=u32::MAX,
                );
                let mut fragmentation = settings.fragment.is_some();
                if ui
                    .checkbox(&mut fragmentation, t(lang, Key::SrvTcpFragmentation))
                    .changed()
                {
                    settings.fragment = fragmentation.then(runnable_fragment);
                    changed = true;
                }
                if let Some(fragment) = settings.fragment.as_mut() {
                    changed |= widgets::text_field(
                        ui,
                        "packets",
                        &mut fragment.packets,
                        "tlshello | 1-3 | empty = all",
                    );
                    changed |= widgets::opt_range(ui, "length", &mut fragment.length, 1..=1500);
                    changed |= widgets::opt_range(
                        ui,
                        t(lang, Key::SrvIntervalMs),
                        &mut fragment.interval,
                        0..=500,
                    );
                    changed |= widgets::opt_range(
                        ui,
                        t(lang, Key::SrvMaxSplit),
                        &mut fragment.max_split,
                        1..=1000,
                    );
                    if !fragment_is_valid(fragment) {
                        ui.colored_label(
                            status_colors_of(ui).err,
                            t(lang, Key::SrvFragmentationInvalid),
                        );
                    }
                }
                changed |= noises_editor(ui, lang, &mut settings.noises);
                changed |= final_rules_editor(ui, lang, &mut settings.final_rules);
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvProxyProtocol),
                    &mut settings.proxy_protocol,
                    1..=2,
                );
            }
            ProtocolSettings::Blackhole(settings) => {
                let mut has_response = settings.response.is_some();
                if ui
                    .checkbox(&mut has_response, t(lang, Key::SrvCustomResponse))
                    .changed()
                {
                    settings.response = has_response.then(|| BlackholeResponse {
                        r#type: "none".into(),
                        ..Default::default()
                    });
                    changed = true;
                }
                if let Some(response) = settings.response.as_mut() {
                    changed |= widgets::combo_str_labeled(
                        ui,
                        t(lang, Key::SrvResponseType),
                        &mut response.r#type,
                        &["none", "http", "custom"],
                        t(lang, Key::SrvDefault),
                        false,
                    );
                    if !blackhole_response_type_supported(&response.r#type) {
                        ui.colored_label(
                            status_colors_of(ui).err,
                            t(lang, Key::SrvBlackholeResponseInvalid),
                        );
                    }
                    if blackhole_response_is_custom(&response.r#type) {
                        // The payload is a base64 string of arbitrary length;
                        // the field's verdict is the core's own decode rule
                        // (infra/conf/blackhole.go:31), so an invalid payload
                        // reports inline before the finding sweep.
                        changed |= widgets::validated_field(
                            ui,
                            t(lang, Key::SrvCustomResponseData),
                            &mut response.custom_response_data,
                            "base64 (standard alphabet, = padded)",
                            |value| {
                                if blackhole_custom_response_data_decodes(value) {
                                    return None;
                                }
                                Some(t(lang, Key::SrvBlackholeCustomDataInvalid).to_string())
                            },
                        );
                    }
                }
            }
            ProtocolSettings::Dns(settings) => {
                changed |= widgets::combo_str_labeled(
                    ui,
                    t(lang, Key::SrvRewriteNetwork),
                    &mut settings.rewrite_network,
                    &["", "tcp", "udp"],
                    t(lang, Key::SrvDefault),
                    false,
                );
                changed |= widgets::text_field(
                    ui,
                    t(lang, Key::SrvRewriteAddress),
                    &mut settings.rewrite_address,
                    "(optional)",
                );
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvRewritePort),
                    &mut settings.rewrite_port,
                    1..=65535,
                );
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::UserLevel),
                    &mut settings.user_level,
                    0..=u32::MAX,
                );
                ui.label(t(lang, Key::SrvRulesColon));
                let mut remove_rule = None;
                for (index, rule) in settings.rules.iter_mut().enumerate() {
                    ui.push_id(index, |ui| {
                        ui.horizontal(|ui| {
                            changed |= widgets::combo_str_labeled(
                                ui,
                                "action",
                                &mut rule.action,
                                &DNS_RULE_ACTION_OPTIONS,
                                t(lang, Key::SrvDefault),
                                false,
                            );
                            changed |=
                                widgets::text_field(ui, "qType", &mut rule.q_type, "1,28 or 1-10");
                            changed |= widgets::opt_num(ui, "rCode", &mut rule.r_code, 0..=65_535);
                            if ui.button(t(lang, Key::SrvRemove)).clicked() {
                                remove_rule = Some(index);
                            }
                        });
                        if !dns_out_action_supported(&rule.action) {
                            ui.colored_label(
                                status_colors_of(ui).err,
                                t(lang, Key::SrvDnsRuleActionRequired),
                            );
                        }
                        changed |= widgets::string_list(
                            ui,
                            lang,
                            "domains",
                            &mut rule.domain,
                            "domain:example.com",
                        );
                    });
                }
                if let Some(index) = remove_rule {
                    settings.rules.remove(index);
                    changed = true;
                }
                if ui.button(t(lang, Key::SrvAddDnsRule)).clicked() {
                    settings.rules.push(DnsOutRule::default());
                    changed = true;
                }
            }
            ProtocolSettings::Loopback(settings) => {
                changed |= widgets::validated_field(
                    ui,
                    t(lang, Key::SrvInboundTag),
                    &mut settings.inbound_tag,
                    "in-socks",
                    |v| v_required(lang, v),
                );
                let mut sniffing = settings.sniffing.is_some();
                if ui
                    .checkbox(&mut sniffing, t(lang, Key::SrvSniffing))
                    .changed()
                {
                    settings.sniffing = sniffing.then(Sniffing::default);
                    changed = true;
                }
                if let Some(sniffing) = settings.sniffing.as_mut() {
                    changed |= sniffing_editor(ui, lang, sniffing, false);
                }
            }
            ProtocolSettings::Hysteria(settings) => {
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port);
                ui.weak(t(lang, Key::SrvHysteriaNote));
            }
        }
        // The public-endpoint TLS rules render from the memoized validation
        // cache (keyed on the draft generation + language), never from a
        // per-repaint sweep; same text and order as the error list's
        // `validate_outbound` pass.
        for message in inline_errors {
            ui.colored_label(status_colors_of(ui).err, message.as_str());
        }
        changed
    }

    fn request_tool(
        &mut self,
        ui: &egui::Ui,
        lang: Language,
        target: Option<(DraftTargetKind, &str, u64)>,
        kind: XrayToolKind,
        args: Vec<String>,
    ) {
        let Some((target_kind, profile_id, generation)) = target else {
            self.set_status(StatusLine::err(t(lang, Key::SrvKeygenDraftOnly)));
            return;
        };
        // The owned target is built only on the click path; repaints just
        // pass a borrowed id and the generation.
        let target = ToolTarget::draft(target_kind, profile_id, generation);
        if let Err(error) = self.queue_xray_tool(lang, ui.ctx().clone(), target, kind, args) {
            self.set_status(StatusLine::err(error));
        }
    }

    fn security_tab_for_target(
        &mut self,
        ui: &mut egui::Ui,
        lang: Language,
        target: Option<(DraftTargetKind, &str, u64)>,
        stream: &mut StreamModel,
        server_address: Option<&str>,
        ech_sockopt_errors: &[String],
    ) -> bool {
        self.security_tab(ui, lang, target, stream, server_address, ech_sockopt_errors)
    }

    // ---------- Transport tab (recursive for downloadSettings) ----------

    /// The pretty-printed text of one preserved over-limit `downloadSettings`
    /// subtree, serialized only when the draft it belongs to or the depth it
    /// sits at moved (see [`OverLimitJson`]). Callers with no draft identity
    /// to key on get a fresh serialization for the frame instead of another
    /// draft's text.
    fn over_limit_json_for(
        &mut self,
        target: Option<(DraftTargetKind, &str, u64)>,
        depth: u32,
        lang: Language,
        download: &StreamModel,
    ) -> &str {
        // The cached key's fields are compared in place — nothing is
        // allocated on a hit, and the header body runs every frame it stays
        // open.
        let unchanged = match (target, self.over_limit_json.as_ref()) {
            (Some((kind, id, generation)), Some(cached)) => {
                cached.key.as_ref().is_some_and(|key| {
                    key.0 == kind && key.1 == id && key.2 == generation && key.3 == depth
                })
            }
            _ => false,
        };
        if !unchanged {
            let text = serde_json::to_string_pretty(download)
                .unwrap_or_else(|error| t_fmt(lang, Key::SrvSerializationError, &[&error]));
            self.over_limit_json = Some(OverLimitJson {
                key: target
                    .map(|(kind, id, generation)| (kind, id.to_owned(), generation, depth, lang)),
                text,
            });
        }
        self.over_limit_json
            .as_ref()
            .map_or("", |cached| cached.text.as_str())
    }

    fn transport_tab(
        &mut self,
        ui: &mut egui::Ui,
        lang: Language,
        st: &mut StreamModel,
        depth: u32,
        target: Option<(DraftTargetKind, &str, u64)>,
    ) -> bool {
        let mut changed = false;
        ui.horizontal(|ui| {
            ui.label(t(lang, Key::SrvNetwork));
            for n in [
                Network::Raw,
                Network::Xhttp,
                Network::Kcp,
                Network::Grpc,
                Network::Ws,
                Network::Httpupgrade,
                Network::Hysteria,
            ] {
                let allowed = st.security != Security::Reality
                    || n.supports_reality()
                    || n == Network::Hysteria;
                let response = ui
                    .add_enabled_ui(allowed, |ui| {
                        ui.selectable_label(st.network == n, n.as_str())
                    })
                    .inner;
                let response = if !allowed {
                    response.on_disabled_hover_text(t(lang, Key::SrvSwitchAwayReality))
                } else if n == Network::Hysteria && st.security == Security::Reality {
                    response.on_hover_text(t(lang, Key::SrvHysteriaSelectsTls))
                } else {
                    response
                };
                if response.clicked() && st.network != n && st.select_network(n).is_ok() {
                    changed = true;
                }
            }
        });
        ui.separator();
        if st.security == Security::Reality
            && st.network != Network::Hysteria
            && !st.network.supports_reality()
        {
            ui.colored_label(
                status_colors_of(ui).err,
                validation_message(&ValidationCode::RealityRequiresTransport, lang),
            );
        }
        if st.network == Network::Hysteria && st.security != Security::Tls {
            ui.horizontal(|ui| {
                ui.colored_label(
                    status_colors_of(ui).err,
                    t(lang, Key::SrvHysteriaRequiresTls),
                );
                if ui.small_button(t(lang, Key::SrvSwitchToTls)).clicked()
                    && st.select_security(Security::Tls).is_ok()
                {
                    changed = true;
                }
            });
        }
        match st.network {
            Network::Raw => {
                let had_settings = st.raw_settings.is_some();
                let mut s = st.raw_settings.take().unwrap_or_default();
                let mut hdr = s.header.is_some();
                if ui
                    .checkbox(&mut hdr, t(lang, Key::SrvHttpCamouflageHeader))
                    .changed()
                {
                    s.header = if hdr {
                        Some(RawHeader {
                            r#type: "http".into(),
                            ..Default::default()
                        })
                    } else {
                        None
                    };
                    changed = true;
                }
                if let Some(h) = s.header.as_mut() {
                    let mut req = h.request.is_some();
                    if ui
                        .checkbox(&mut req, t(lang, Key::SrvRequestCamouflage))
                        .changed()
                    {
                        h.request = if req {
                            Some(HttpCamouflageRequest::default())
                        } else {
                            None
                        };
                        changed = true;
                    }
                    if let Some(r) = h.request.as_mut() {
                        changed |= widgets::text_field(ui, "version", &mut r.version, "1.1");
                        changed |= widgets::text_field(ui, "method", &mut r.method, "GET");
                        changed |= widgets::string_list(ui, lang, "paths", &mut r.path, "/");
                        changed |= json_map_kv(
                            ui,
                            lang,
                            &mut r.headers,
                            t(lang, Key::HeaderHint),
                            t(lang, Key::ValueHint),
                            &mut self.json_key_scratch,
                        );
                    }
                    let mut resp = h.response.is_some();
                    if ui
                        .checkbox(&mut resp, t(lang, Key::SrvResponseCamouflage))
                        .changed()
                    {
                        h.response = if resp {
                            Some(HttpCamouflageResponse::default())
                        } else {
                            None
                        };
                        changed = true;
                    }
                    if let Some(r) = h.response.as_mut() {
                        changed |= widgets::text_field(ui, "version", &mut r.version, "1.1");
                        changed |= widgets::text_field(ui, "status", &mut r.status, "200");
                        changed |= widgets::text_field(ui, "reason", &mut r.reason, "OK");
                        changed |= json_map_kv(
                            ui,
                            lang,
                            &mut r.headers,
                            t(lang, Key::HeaderHint),
                            t(lang, Key::ValueHint),
                            &mut self.json_key_scratch,
                        );
                    }
                }
                if had_settings || changed {
                    st.raw_settings = Some(s);
                }
            }
            Network::Xhttp => {
                let had_settings = st.xhttp_settings.is_some();
                let mut s = st.xhttp_settings.take().unwrap_or_default();
                let mut mode_changed = false;
                widgets::section(ui, t(lang, Key::SrvBasics), |ui| {
                    changed |= widgets::text_field(ui, "host", &mut s.host, "example.com");
                    changed |= widgets::text_field(ui, "path", &mut s.path, "/");
                    mode_changed = widgets::combo_str_labeled(
                        ui,
                        "mode",
                        &mut s.mode,
                        XHTTP_MODES,
                        t(lang, Key::SrvDefault),
                        false,
                    );
                    changed |= mode_changed;
                    changed |=
                        transport_headers(ui, lang, &mut s.headers, &mut self.json_key_scratch);
                });
                widgets::section(ui, t(lang, Key::SrvPadding), |ui| {
                    changed |=
                        widgets::opt_range(ui, "xPaddingBytes", &mut s.x_padding_bytes, 1..=4096);
                    changed |= widgets::opt_bool(
                        ui,
                        "xPaddingObfsMode",
                        &mut s.x_padding_obfs_mode,
                        t(lang, Key::SrvUnset),
                    );
                    changed |= widgets::text_field(ui, "xPaddingKey", &mut s.x_padding_key, "");
                    changed |=
                        widgets::text_field(ui, "xPaddingHeader", &mut s.x_padding_header, "");
                    changed |= widgets::combo_str_labeled(
                        ui,
                        "xPaddingPlacement",
                        &mut s.x_padding_placement,
                        X_PADDING_PLACEMENTS,
                        t(lang, Key::SrvDefault),
                        false,
                    );
                    changed |= widgets::combo_str_labeled(
                        ui,
                        "xPaddingMethod",
                        &mut s.x_padding_method,
                        PADDING_METHODS,
                        t(lang, Key::SrvDefault),
                        false,
                    );
                });
                widgets::section(ui, t(lang, Key::SrvUpload), |ui| {
                    changed |= widgets::text_field(
                        ui,
                        "uplinkHTTPMethod",
                        &mut s.uplink_http_method,
                        "POST",
                    );
                    let incompatible_placement = s.mode != "packet-up"
                        && !validation::uplink_placement_mode_supported(
                            &s.uplink_data_placement,
                            &s.mode,
                        );
                    if mode_changed && incompatible_placement {
                        s.uplink_data_placement.clear();
                    }
                    let placements: &[&str] = if s.mode == "packet-up" {
                        UPLINK_PLACEMENTS
                    } else {
                        &UPLINK_STREAM_PLACEMENTS
                    };
                    changed |= widgets::combo_str_labeled(
                        ui,
                        "uplinkDataPlacement",
                        &mut s.uplink_data_placement,
                        placements,
                        t(lang, Key::SrvDefault),
                        false,
                    );
                    if s.mode != "packet-up"
                        && !validation::uplink_placement_mode_supported(
                            &s.uplink_data_placement,
                            &s.mode,
                        )
                    {
                        ui.horizontal(|ui| {
                            ui.colored_label(
                                status_colors_of(ui).err,
                                t(lang, Key::SrvCookieHeaderNeedsPacketUp),
                            );
                            if ui.small_button(t(lang, Key::SrvUseAuto)).clicked() {
                                s.uplink_data_placement.clear();
                                changed = true;
                            }
                        });
                    }
                    changed |= widgets::text_field(ui, "uplinkDataKey", &mut s.uplink_data_key, "");
                    changed |= widgets::opt_range(
                        ui,
                        "uplinkChunkSize",
                        &mut s.uplink_chunk_size,
                        1..=1_000_000,
                    );
                    changed |= widgets::opt_bool(
                        ui,
                        "noGRPCHeader",
                        &mut s.no_grpc_header,
                        t(lang, Key::SrvUnset),
                    );
                    changed |= widgets::opt_bool(
                        ui,
                        "noSSEHeader",
                        &mut s.no_sse_header,
                        t(lang, Key::SrvUnset),
                    );
                });
                widgets::section(ui, t(lang, Key::SrvSession), |ui| {
                    changed |= widgets::combo_str_labeled(
                        ui,
                        "sessionIDPlacement",
                        &mut s.session_id_placement,
                        SESSION_PLACEMENTS,
                        t(lang, Key::SrvDefault),
                        false,
                    );
                    changed |= widgets::text_field(ui, "sessionIDKey", &mut s.session_id_key, "");
                    changed |=
                        widgets::text_field(ui, "sessionIDTable", &mut s.session_id_table, "");
                    changed |=
                        widgets::opt_range(ui, "sessionIDLength", &mut s.session_id_length, 1..=64);
                    changed |= widgets::combo_str_labeled(
                        ui,
                        "seqPlacement",
                        &mut s.seq_placement,
                        SESSION_PLACEMENTS,
                        t(lang, Key::SrvDefault),
                        false,
                    );
                    changed |= widgets::text_field(ui, "seqKey", &mut s.seq_key, "");
                });
                widgets::section(ui, t(lang, Key::SrvLimits), |ui| {
                    changed |= widgets::opt_range(
                        ui,
                        "scMaxEachPostBytes",
                        &mut s.sc_max_each_post_bytes,
                        1000..=10_000_000,
                    );
                    changed |= widgets::opt_range(
                        ui,
                        "scMinPostsIntervalMs",
                        &mut s.sc_min_posts_interval_ms,
                        0..=10_000,
                    );
                    changed |= widgets::opt_num(
                        ui,
                        "scMaxBufferedPosts",
                        &mut s.sc_max_buffered_posts,
                        1..=1000,
                    );
                    changed |= widgets::opt_range(
                        ui,
                        "scStreamUpServerSecs",
                        &mut s.sc_stream_up_server_secs,
                        0..=3600,
                    );
                    changed |= widgets::opt_num(
                        ui,
                        "serverMaxHeaderBytes",
                        &mut s.server_max_header_bytes,
                        1024..=1_048_576,
                    );
                });
                widgets::section(ui, t(lang, Key::SrvXmux), |ui| {
                    let mut has = s.xmux.is_some();
                    if ui.checkbox(&mut has, t(lang, Key::SrvEnableXmux)).changed() {
                        s.xmux = if has {
                            Some(XmuxConfig::default())
                        } else {
                            None
                        };
                        changed = true;
                    }
                    if let Some(x) = s.xmux.as_mut() {
                        let original_choice =
                            match (x.max_concurrency.is_some(), x.max_connections.is_some()) {
                                (false, false) => 0,
                                (true, false) => 1,
                                (false, true) => 2,
                                (true, true) => 3,
                            };
                        let mut choice = original_choice;
                        let mut choice_changed = false;
                        ui.horizontal(|ui| {
                            ui.label(t(lang, Key::SrvConnectionLimit));
                            choice_changed |= ui
                                .radio_value(&mut choice, 0, t(lang, Key::SrvCoreDefaults))
                                .changed();
                            choice_changed |= ui
                                .radio_value(&mut choice, 1, t(lang, Key::SrvMaxConcurrency))
                                .changed();
                            choice_changed |= ui
                                .radio_value(&mut choice, 2, t(lang, Key::SrvMaxConnections))
                                .changed();
                        });
                        if choice_changed {
                            match choice {
                                0 => {
                                    x.max_concurrency = None;
                                    x.max_connections = None;
                                }
                                1 => {
                                    x.max_connections = None;
                                    x.max_concurrency
                                        .get_or_insert_with(|| Int32Range::single(1));
                                }
                                2 => {
                                    x.max_concurrency = None;
                                    x.max_connections
                                        .get_or_insert_with(|| Int32Range::single(1));
                                }
                                _ => unreachable!(),
                            }
                            changed = true;
                        } else if original_choice == 3 {
                            ui.colored_label(
                                status_colors_of(ui).err,
                                t(lang, Key::SrvMutuallyExclusive),
                            );
                        }
                        match choice {
                            1 => {
                                changed |= widgets::opt_range(
                                    ui,
                                    "maxConcurrency",
                                    &mut x.max_concurrency,
                                    1..=1024,
                                );
                            }
                            2 => {
                                changed |= widgets::opt_range(
                                    ui,
                                    "maxConnections",
                                    &mut x.max_connections,
                                    1..=1024,
                                );
                            }
                            _ => {}
                        }
                        changed |= widgets::opt_range(
                            ui,
                            "cMaxReuseTimes",
                            &mut x.c_max_reuse_times,
                            1..=10_000,
                        );
                        changed |= widgets::opt_range(
                            ui,
                            "hMaxRequestTimes",
                            &mut x.h_max_request_times,
                            1..=10_000,
                        );
                        changed |= widgets::opt_range(
                            ui,
                            "hMaxReusableSecs",
                            &mut x.h_max_reusable_secs,
                            1..=86_400,
                        );
                        changed |= widgets::opt_num(
                            ui,
                            t(lang, Key::SrvHKeepAlivePeriodS),
                            &mut x.h_keep_alive_period,
                            0..=3600,
                        );
                    }
                });
                if mode_changed && s.mode == "stream-one" {
                    s.download_settings = None;
                }
                if s.mode == "stream-one" && s.download_settings.is_some() {
                    ui.horizontal(|ui| {
                        ui.colored_label(
                            status_colors_of(ui).err,
                            t(lang, Key::SrvDownloadNotAllowed),
                        );
                        if ui
                            .small_button(t(lang, Key::SrvRemoveSplitDownload))
                            .clicked()
                        {
                            s.download_settings = None;
                            changed = true;
                        }
                    });
                }
                if (depth as usize) < MAX_XHTTP_DOWNLOAD_DEPTH {
                    widgets::section(
                        ui,
                        &t_fmt(lang, Key::SrvDownloadDepth, &[&(depth + 1)]),
                        |ui| {
                            if s.mode == "stream-one" {
                                ui.weak(t(lang, Key::SrvUnavailableStreamOne));
                                return;
                            }
                            let mut has = s.download_settings.is_some();
                            if ui
                                .checkbox(&mut has, t(lang, Key::SrvSeparateDownlinkStream))
                                .changed()
                            {
                                s.download_settings = if has {
                                    Some(Box::new(StreamModel::default()))
                                } else {
                                    None
                                };
                                changed = true;
                            }
                            if let Some(download) = s.download_settings.as_mut() {
                                ui.indent(("download", depth), |ui| {
                                    changed |=
                                        self.transport_tab(ui, lang, download, depth + 1, target);
                                    changed |= self.security_tab_readonly(ui, lang, download);
                                });
                            }
                        },
                    );
                } else if let Some(download) = s.download_settings.as_ref() {
                    ui.colored_label(
                        status_colors_of(ui).err,
                        t_fmt(lang, Key::SrvDepthExceeded, &[&MAX_XHTTP_DOWNLOAD_DEPTH]),
                    );
                    egui::CollapsingHeader::new(t(lang, Key::SrvPreservedOverLimit))
                        .id_salt(ui.auto_id_with(("download-over-limit", depth)))
                        .show(ui, |ui| {
                            let json = self.over_limit_json_for(target, depth, lang, download);
                            egui::ScrollArea::vertical()
                                .max_height(180.0)
                                .show(ui, |ui| {
                                    ui.monospace(json);
                                });
                        });
                }
                if had_settings || changed {
                    st.xhttp_settings = Some(s);
                }
            }
            Network::Kcp => {
                let had_settings = st.kcp_settings.is_some();
                let mut s = st.kcp_settings.take().unwrap_or_default();
                changed |= widgets::opt_num(ui, "mtu", &mut s.mtu, 576..=9000);
                changed |= widgets::opt_num(ui, t(lang, Key::SrvTtiMs), &mut s.tti, 10..=200);
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvUplinkCapacity),
                    &mut s.uplink_capacity,
                    0..=10_000,
                );
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvDownlinkCapacity),
                    &mut s.downlink_capacity,
                    0..=10_000,
                );
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvCwndMultiplier),
                    &mut s.cwnd_multiplier,
                    1..=16,
                );
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvMaxSendingWindow),
                    &mut s.max_sending_window,
                    1..=10_000,
                );
                if had_settings || changed {
                    st.kcp_settings = Some(s);
                }
            }
            Network::Grpc => {
                let had_settings = st.grpc_settings.is_some();
                let mut s = st.grpc_settings.take().unwrap_or_default();
                changed |= widgets::text_field(ui, "serviceName", &mut s.service_name, "grpc");
                changed |= widgets::text_field(ui, "authority", &mut s.authority, "example.com");
                changed |=
                    widgets::opt_bool(ui, "multiMode", &mut s.multi_mode, t(lang, Key::SrvUnset));
                // Informational copy (docs grpc.md: multiMode is
                // experimental/BETA — no stability promise).
                ui.weak(t(lang, Key::SrvGrpcMultiModeHint));
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvIdleTimeoutS),
                    &mut s.idle_timeout,
                    0..=3600,
                );
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvHealthCheckTimeoutS),
                    &mut s.health_check_timeout,
                    0..=600,
                );
                changed |= widgets::opt_bool(
                    ui,
                    "permit_without_stream",
                    &mut s.permit_without_stream,
                    t(lang, Key::SrvUnset),
                );
                changed |= widgets::opt_num(
                    ui,
                    "initial_windows_size",
                    &mut s.initial_windows_size,
                    0..=16_777_215,
                );
                changed |= opt_string(ui, "user_agent", &mut s.user_agent, "");
                // Informational copy (docs grpc.md: gRPC/HTTP-2
                // already multiplexes — mux.cool on top is not recommended).
                ui.weak(t(lang, Key::SrvGrpcMuxHint));
                ui.weak(t(lang, Key::SrvGrpcDeprecated));
                if had_settings || changed {
                    st.grpc_settings = Some(s);
                }
            }
            Network::Ws => {
                let had_settings = st.ws_settings.is_some();
                let mut s = st.ws_settings.take().unwrap_or_default();
                changed |= widgets::text_field(ui, "host", &mut s.host, "example.com");
                changed |= widgets::text_field(ui, "path", &mut s.path, "/?ed=2048");
                changed |=
                    websocket_transport_headers(ui, lang, &mut s, &mut self.json_key_scratch);
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvHeartbeatPeriodS),
                    &mut s.heartbeat_period,
                    0..=600,
                );
                ui.weak(t(lang, Key::SrvWsDeprecated));
                if had_settings || changed {
                    st.ws_settings = Some(s);
                }
            }
            Network::Httpupgrade => {
                let had_settings = st.httpupgrade_settings.is_some();
                let mut s = st.httpupgrade_settings.take().unwrap_or_default();
                changed |= widgets::text_field(ui, "host", &mut s.host, "example.com");
                changed |= widgets::text_field(ui, "path", &mut s.path, "/?ed=2048");
                changed |= transport_headers(ui, lang, &mut s.headers, &mut self.json_key_scratch);
                ui.weak(t(lang, Key::SrvHttpupgradeDeprecated));
                if had_settings || changed {
                    st.httpupgrade_settings = Some(s);
                }
            }
            Network::Hysteria => {
                let had_settings = st.hysteria_settings.is_some();
                let mut s = st.hysteria_settings.take().unwrap_or_default();
                if s.version != 2 {
                    ui.horizontal(|ui| {
                        ui.colored_label(status_colors_of(ui).err, t(lang, Key::SrvOnlyHysteria2));
                        if ui.small_button(t(lang, Key::SrvUseVersion2)).clicked() {
                            s.version = 2;
                            changed = true;
                        }
                    });
                }
                changed |= widgets::text_field(ui, t(lang, Key::SrvAuthPassword), &mut s.auth, "");
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvUdpIdleTimeoutS),
                    &mut s.udp_idle_timeout,
                    2..=600,
                );
                let mut has = s.masquerade.is_some();
                if ui.checkbox(&mut has, t(lang, Key::SrvMasquerade)).changed() {
                    s.masquerade = if has {
                        Some(MasqueradeCfg::default())
                    } else {
                        None
                    };
                    changed = true;
                }
                if let Some(m) = s.masquerade.as_mut() {
                    changed |= widgets::combo_str_labeled(
                        ui,
                        "type",
                        &mut m.r#type,
                        &["", "file", "proxy", "string"],
                        t(lang, Key::SrvDefault),
                        false,
                    );
                    match m.r#type.as_str() {
                        "file" => {
                            changed |= widgets::text_field(ui, "dir", &mut m.dir, "C:\\\\web");
                        }
                        "proxy" => {
                            changed |=
                                widgets::text_field(ui, "url", &mut m.url, "https://example.com");
                            changed |= ui
                                .checkbox(&mut m.rewrite_host, t(lang, Key::SrvRewriteHost))
                                .changed();
                            changed |= ui
                                .checkbox(&mut m.x_forwarded, t(lang, Key::SrvXForwarded))
                                .changed();
                            ui.weak(t(lang, Key::SrvXForwardedNote));
                            changed |= ui
                                .checkbox(&mut m.insecure, t(lang, Key::SrvSkipTlsVerify))
                                .changed();
                        }
                        "string" => {
                            changed |= widgets::text_field(ui, "content", &mut m.content, "");
                            changed |= json_map_kv(
                                ui,
                                lang,
                                &mut m.headers,
                                t(lang, Key::HeaderHint),
                                t(lang, Key::ValueHint),
                                &mut self.json_key_scratch,
                            );
                            let mut sc = m.status_code;
                            if widgets::opt_num(ui, t(lang, Key::SrvStatusCode), &mut sc, 100..=599)
                            {
                                m.status_code = sc;
                                changed = true;
                            }
                        }
                        _ => {}
                    }
                }
                ui.weak(t(lang, Key::SrvCongestionNote));
                if had_settings || changed {
                    st.hysteria_settings = Some(s);
                }
            }
        }
        changed
    }

    /// Security editor without keygen buttons (downloadSettings context).
    /// Security editor for nested downloadSettings, where core helpers cannot
    /// safely update a profile draft.
    fn security_tab_readonly(
        &mut self,
        ui: &mut egui::Ui,
        lang: Language,
        st: &mut StreamModel,
    ) -> bool {
        // Nested downloadSettings: the enclosing editor's memoized verdicts
        // describe the top-level stream, not this block, so the ECH inline
        // line yields to the memoized error list (which revalidates the
        // nested stream under its own path).
        self.security_tab(ui, lang, None, st, None, &[])
    }

    // ---------- Security tab ----------

    fn security_tab(
        &mut self,
        ui: &mut egui::Ui,
        lang: Language,
        target: Option<(DraftTargetKind, &str, u64)>,
        st: &mut StreamModel,
        // The edited profile's server endpoint (`host:port`, IPv6-bracketed)
        // for the probe panel's "Use server address:port" fill; `None` when
        // no profile draft is in scope (nested/readonly settings) or the
        // profile carries no endpoint.
        server_address: Option<&str>,
        // The TLS settings' memoized ECH-sockopt verdicts
        // (`stream.tlsSettings.echSockopt`), rendered inline under the ECH
        // block. A nested/imported stream whose sockopt is not part of the
        // enclosing editor's cache passes an empty slice.
        ech_sockopt_errors: &[String],
    ) -> bool {
        let mut changed = false;
        if st.network == Network::Hysteria && st.security != Security::Tls {
            ui.colored_label(
                status_colors_of(ui).err,
                t(lang, Key::SrvHysteria2RequiresTlsSelectBelow),
            );
        } else if st.security == Security::Reality && !st.network.supports_reality() {
            ui.colored_label(
                status_colors_of(ui).err,
                validation_message(&ValidationCode::RealityRequiresTransport, lang),
            );
        }
        ui.horizontal(|ui| {
            ui.label(t(lang, Key::SrvSecurity));
            for sec in [Security::None, Security::Tls, Security::Reality] {
                let label = match sec {
                    Security::None => "none",
                    Security::Tls => "tls",
                    Security::Reality => "reality",
                };
                let allowed = if st.network == Network::Hysteria {
                    sec == Security::Tls
                } else {
                    sec != Security::Reality || st.network.supports_reality()
                };
                let response = ui
                    .add_enabled_ui(allowed, |ui| ui.selectable_label(st.security == sec, label))
                    .inner;
                let response = if allowed {
                    response
                } else if st.network == Network::Hysteria {
                    response.on_disabled_hover_text(t(lang, Key::SrvHysteria2RequiresTls))
                } else {
                    response.on_disabled_hover_text(validation_message(
                        &ValidationCode::RealityRequiresTransport,
                        lang,
                    ))
                };
                if response.clicked() && st.security != sec && st.select_security(sec).is_ok() {
                    changed = true;
                }
            }
        });
        ui.separator();
        match st.security {
            Security::Tls => {
                let had_settings = st.tls_settings.is_some();
                let mut s = st.tls_settings.take().unwrap_or_default();
                let tool_working = self.tool_job.is_some();
                changed |= widgets::text_field(
                    ui,
                    t(lang, Key::SrvServerNameSni),
                    &mut s.server_name,
                    "example.com",
                );
                // Warn inline at the field when
                // the value cannot plausibly be a hostname — the model's own
                // predicate, so the inline hint can never drift from the
                // sweep. Empty stays untouched (out of scope by design).
                if server_name_implausible(&s.server_name) {
                    ui.colored_label(
                        status_colors_of(ui).warn,
                        validation_message(&ValidationCode::ServerNameImplausible, lang),
                    );
                }
                // Informational copy: empty falls back to the dial
                // address as the SNI (Xray tls WithDestination; diagnostics
                // note, not a rule).
                ui.weak(t(lang, Key::SrvTlsServerNameEmptyHint));
                changed |= widgets::string_list(
                    ui,
                    lang,
                    t(lang, Key::SrvAlpn),
                    &mut s.alpn,
                    "h2, http/1.1",
                );
                changed |= fingerprint_editor(
                    ui,
                    lang,
                    &mut s.fingerprint,
                    ValidationCode::TlsFingerprintUnsupported,
                );
                // Informational copy: fingerprint option semantics
                // (empty ≠ no imitation).
                ui.weak(t(lang, Key::SrvTlsFingerprintHint));
                changed |= widgets::combo_str_labeled(
                    ui,
                    t(lang, Key::SrvMinVersion),
                    &mut s.min_version,
                    &TLS_VERSIONS,
                    t(lang, Key::SrvDefault),
                    false,
                );
                changed |= widgets::combo_str_labeled(
                    ui,
                    t(lang, Key::SrvMaxVersion),
                    &mut s.max_version,
                    &TLS_VERSIONS,
                    t(lang, Key::SrvDefault),
                    false,
                );
                if let (Some(min), Some(max)) = (
                    tls_version_rank(&s.min_version),
                    tls_version_rank(&s.max_version),
                ) && min > max
                {
                    ui.colored_label(
                        status_colors_of(ui).warn,
                        validation_message(&ValidationCode::TlsMinExceedsMax, lang),
                    );
                }
                changed |= widgets::text_field(
                    ui,
                    t(lang, Key::SrvCipherSuites),
                    &mut s.cipher_suites,
                    "colon-separated Go names",
                );
                changed |= widgets::string_list(
                    ui,
                    lang,
                    t(lang, Key::SrvCurvePreferences),
                    &mut s.curve_preferences,
                    "X25519MLKEM768",
                );
                changed |= widgets::opt_bool(
                    ui,
                    "disableSystemRoot",
                    &mut s.disable_system_root,
                    t(lang, Key::SrvUnset),
                );
                changed |= widgets::opt_bool(
                    ui,
                    "enableSessionResumption",
                    &mut s.enable_session_resumption,
                    t(lang, Key::SrvUnset),
                );
                changed |= widgets::text_field(
                    ui,
                    "pinnedPeerCertSha256",
                    &mut s.pinned_peer_cert_sha256,
                    "comma-separated 32-byte hex pins — replaces allowInsecure",
                );
                if ui
                    .add_enabled(
                        !tool_working && target.is_some(),
                        egui::Button::new(t(lang, Key::SrvComputePinFromCert)),
                    )
                    .on_hover_text(t(lang, Key::SrvComputePinHint))
                    .clicked()
                    && let Some(path) = rfd::FileDialog::new()
                        .add_filter(
                            t(lang, Key::ShellCertificateFilter),
                            &["pem", "crt", "cer", "der"],
                        )
                        .pick_file()
                {
                    self.request_tool(
                        ui,
                        lang,
                        target,
                        XrayToolKind::TlsPin,
                        vec![
                            "tls".into(),
                            "hash".into(),
                            "--cert".into(),
                            path.display().to_string(),
                        ],
                    );
                }
                egui::CollapsingHeader::new(t(lang, Key::SrvProbeTlsCertificate))
                    .id_salt(ui.auto_id_with("tls-probe"))
                    .show(ui, |ui| {
                        let _ = widgets::text_field(
                            ui,
                            "domain",
                            &mut self.tls_probe_domain,
                            "example.com or example.com:8443",
                        );
                        let _ = widgets::text_field(
                            ui,
                            "IP override",
                            &mut self.tls_probe_ip,
                            "optional",
                        );
                        ui.horizontal(|ui| {
                            if !s.server_name.is_empty()
                                && ui.small_button(t(lang, Key::SrvUseServerName)).clicked()
                            {
                                // Unlike the address fill below, this keeps
                                // the IP override: for a CDN-fronted server
                                // the override is the deliberate dial target
                                // while the server name is the SNI. Clearing
                                // it would wipe a paired override on every
                                // SNI fill.
                                self.tls_probe_domain = s.server_name.clone();
                            }
                            if let Some(address) = server_address
                                && ui.small_button(t(lang, Key::SrvUseServerAddress)).clicked()
                            {
                                // A fill re-targets the probe: replace the
                                // domain and drop a stale IP override so the
                                // next handshake dials exactly this address.
                                self.tls_probe_domain = address.to_owned();
                                self.tls_probe_ip.clear();
                            }
                        });
                        if ui
                            .add_enabled(
                                !tool_working,
                                egui::Button::new(t(lang, Key::SrvProbeTlsHandshake)),
                            )
                            .on_hover_text(t(lang, Key::SrvProbeTlsHint))
                            .clicked()
                        {
                            // A fresh probe invalidates any previous pin
                            // panel until its result lands.
                            self.tls_probe_handshake_ok = false;
                            self.tls_probe_profile = None;
                            let domain = self.tls_probe_domain.trim().to_string();
                            let ip = self.tls_probe_ip.trim().to_string();
                            if domain.is_empty() {
                                self.tls_tool_error =
                                    Some(t(lang, Key::SrvTlsProbeDomainRequired).into());
                            } else if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_err() {
                                self.tls_tool_error =
                                    Some(t(lang, Key::SrvTlsProbeIpInvalid).into());
                            } else {
                                let mut args = vec!["tls".into(), "ping".into()];
                                if !ip.is_empty() {
                                    args.push("-ip".into());
                                    args.push(ip);
                                }
                                args.push(domain);
                                self.request_tool(ui, lang, target, XrayToolKind::TlsPing, args);
                            }
                        }
                        // The QUIC probe covers servers that answer no TCP
                        // port at all (Hysteria2): the in-app capture
                        // handshakes over UDP with the same domain/IP
                        // fields and feeds the same pin panel.
                        if ui
                            .add_enabled(
                                !tool_working,
                                egui::Button::new(t(lang, Key::SrvProbeQuicHandshake)),
                            )
                            .on_hover_text(t(lang, Key::SrvProbeQuicHint))
                            .clicked()
                        {
                            self.tls_probe_handshake_ok = false;
                            self.tls_probe_profile = None;
                            let domain = self.tls_probe_domain.trim().to_string();
                            let ip = self.tls_probe_ip.trim().to_string();
                            if domain.is_empty() {
                                self.tls_tool_error =
                                    Some(t(lang, Key::SrvTlsProbeDomainRequired).into());
                            } else if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_err() {
                                self.tls_tool_error =
                                    Some(t(lang, Key::SrvTlsProbeIpInvalid).into());
                            } else {
                                self.request_tool(
                                    ui,
                                    lang,
                                    target,
                                    XrayToolKind::TlsPingQuic,
                                    vec![domain, ip],
                                );
                            }
                        }
                        let probe_is_for_target =
                            self.tls_probe_profile.as_deref().is_some_and(|id| {
                                target.is_some_and(|(_, target_id, _)| target_id == id)
                            });
                        if self.tls_probe_handshake_ok && probe_is_for_target {
                            match &self.tls_probe_leaf_pin {
                                Some(pin) => {
                                    let mut apply_clicked = false;
                                    ui.horizontal(|ui| {
                                        ui.label(t(lang, Key::SrvLeafPin));
                                        if ui.small_button(t(lang, Key::SrvCopyPin)).clicked() {
                                            ui.ctx().copy_text(pin.clone());
                                        }
                                        apply_clicked = ui
                                            .add_enabled(
                                                !tool_working && target.is_some(),
                                                egui::Button::new(t(lang, Key::SrvApplyPin)),
                                            )
                                            .clicked();
                                    });
                                    // The pin gets its own full-width line so
                                    // the 64-hex value never collides with the
                                    // row controls.
                                    ui.monospace(pin);
                                    if !self.tls_probe_ca_pins.is_empty() {
                                        ui.label(t(lang, Key::SrvCaPins));
                                        for (name, ca_pin) in &self.tls_probe_ca_pins {
                                            ui.horizontal(|ui| {
                                                ui.label(name);
                                                if ui
                                                    .small_button(t(lang, Key::SrvCopyPin))
                                                    .clicked()
                                                {
                                                    ui.ctx().copy_text(ca_pin.clone());
                                                }
                                            });
                                            ui.monospace(ca_pin);
                                        }
                                    }
                                    ui.colored_label(
                                        status_colors_of(ui).warn,
                                        t(lang, Key::SrvPinCaution),
                                    );
                                    if apply_clicked {
                                        // Owned on the click path only, so the
                                        // &mut self calls below do not overlap
                                        // the borrow of the pinned string.
                                        let pin = pin.clone();
                                        if !pinned_peer_cert_sha256_valid(&pin) {
                                            self.set_status(StatusLine::err(t(
                                                lang,
                                                Key::SrvCertPinHex,
                                            )));
                                        } else if !had_settings {
                                            self.set_status(StatusLine::err(t(
                                                lang,
                                                Key::SrvTlsPinTargetFieldNotFound,
                                            )));
                                        } else {
                                            s.pinned_peer_cert_sha256 = pin;
                                            changed = true;
                                            self.set_status(StatusLine::ok(t(
                                                lang,
                                                Key::SrvPinApplied,
                                            )));
                                        }
                                    }
                                }
                                None => {
                                    ui.colored_label(
                                        status_colors_of(ui).err,
                                        t(lang, Key::SrvProbeNoPin),
                                    );
                                }
                            }
                        }
                    });
                if tool_working {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.weak(t(lang, Key::SrvTlsProbeRunning));
                    });
                }
                if let Some(error) = &self.tls_tool_error {
                    ui.colored_label(status_colors_of(ui).err, error);
                }
                if self.tls_tool_output.is_some()
                    && ui.small_button(t(lang, Key::SrvShowProbeOutput)).clicked()
                {
                    self.show_tls_probe_output = true;
                }
                changed |= widgets::text_field(
                    ui,
                    "verifyPeerCertByName",
                    &mut s.verify_peer_cert_by_name,
                    "",
                );
                changed |= path_field(ui, lang, "masterKeyLog", &mut s.master_key_log, true);
                changed |= widgets::text_field(
                    ui,
                    "echConfigList",
                    &mut s.ech_config_list,
                    "base64 ECHConfigList or https://1.1.1.1/dns-query",
                );
                changed |= ech_sockopt_editor(ui, lang, &mut s.ech_sockopt, ech_sockopt_errors);
                if s.alpn.len() > 1 && s.alpn.iter().any(|value| value == "fromMitm") {
                    ui.colored_label(status_colors_of(ui).err, t(lang, Key::SrvFromMitmOnlyAlpn));
                }
                let mut certs = !s.certificates.is_empty();
                if ui
                    .checkbox(&mut certs, t(lang, Key::SrvCustomCertificate))
                    .changed()
                {
                    s.certificates = if certs {
                        vec![TlsCert::default()]
                    } else {
                        Vec::new()
                    };
                    changed = true;
                }
                let mut remove_cert: Option<usize> = None;
                // The profile id is part of the id salt so widgets inside the
                // group (including the seeded PEM editor buffers) re-seed
                // when the draft switches to another profile.
                let profile_id = target.map_or("", |(_, id, _)| id);
                for (i, c) in s.certificates.iter_mut().enumerate() {
                    ui.push_id(("tls-cert", profile_id, i), |ui| {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(t_fmt(lang, Key::SrvCertificateN, &[&(i + 1)]));
                                if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                                    remove_cert = Some(i);
                                }
                            });
                            changed |= path_field(
                                ui,
                                lang,
                                t(lang, Key::SrvCertificateFile),
                                &mut c.certificate_file,
                                false,
                            );
                            changed |= path_field(
                                ui,
                                lang,
                                t(lang, Key::SrvKeyFile),
                                &mut c.key_file,
                                false,
                            );
                            changed |= pem_lines_editor(
                                ui,
                                t(lang, Key::SrvCertificatePem),
                                profile_id,
                                &mut c.certificate,
                                "-----BEGIN CERTIFICATE-----",
                                &mut self.pem_buffers,
                            );
                            changed |= pem_lines_editor(
                                ui,
                                t(lang, Key::SrvKeyPem),
                                profile_id,
                                &mut c.key,
                                "-----BEGIN PRIVATE KEY-----",
                                &mut self.pem_buffers,
                            );
                            changed |= widgets::combo_str_labeled(
                                ui,
                                "usage",
                                &mut c.usage,
                                &["", "encipherment", "verify", "issue"],
                                t(lang, Key::SrvDefault),
                                false,
                            );
                            changed |= widgets::opt_num(
                                ui,
                                t(lang, Key::SrvOcspStaplingS),
                                &mut c.ocsp_stapling,
                                0..=u64::MAX,
                            );
                            changed |= widgets::opt_bool(
                                ui,
                                "oneTimeLoading",
                                &mut c.one_time_loading,
                                t(lang, Key::SrvUnset),
                            );
                            changed |= widgets::opt_bool(
                                ui,
                                "buildChain",
                                &mut c.build_chain,
                                t(lang, Key::SrvUnset),
                            );
                            if c.certificate_file.trim().is_empty()
                                && c.certificate.iter().all(|line| line.trim().is_empty())
                            {
                                ui.colored_label(
                                    status_colors_of(ui).err,
                                    t(lang, Key::SrvCertificateFileRequired),
                                );
                            }
                        });
                    });
                }
                if let Some(i) = remove_cert {
                    s.certificates.remove(i);
                    changed = true;
                }
                if ui.button(t(lang, Key::SrvAddCertificate)).clicked() {
                    s.certificates.push(TlsCert::default());
                    changed = true;
                }
                if had_settings || changed {
                    st.tls_settings = Some(s);
                }
            }
            Security::Reality => {
                let had_settings = st.reality_settings.is_some();
                let mut s = st.reality_settings.take().unwrap_or_default();
                changed |= widgets::text_field(
                    ui,
                    t(lang, Key::SrvServerNameTarget),
                    &mut s.server_name,
                    "example.com",
                );
                // Warn inline at the field when
                // the value cannot plausibly be a hostname (mirrors the TLS
                // block above). Empty stays untouched (out of scope).
                if server_name_implausible(&s.server_name) {
                    ui.colored_label(
                        status_colors_of(ui).warn,
                        validation_message(&ValidationCode::ServerNameImplausible, lang),
                    );
                }
                // Informational copy: empty falls back to the dial
                // address as the SNI, which must then be in the server's
                // serverNames (diagnostics-class note, not a rule).
                ui.weak(t(lang, Key::SrvRealityServerNameEmptyHint));
                changed |= fingerprint_editor(
                    ui,
                    lang,
                    &mut s.fingerprint,
                    ValidationCode::RealityFingerprintUnsupported,
                );
                // Informational copy: fingerprint option semantics
                // for REALITY (excluded names are rejected by Xray's Build).
                ui.weak(t(lang, Key::SrvRealityFingerprintHint));
                // These fields keep their keygen rows but
                // drop the per-keystroke validator closures — format
                // findings on the same values now fire from the model pass
                // (`RealityPublicKeyInvalid` / `RealityShortIdInvalid` /
                // `RealitySpiderXInvalid` / `RealityMldsa65Invalid`) and
                // render in the issue list through the shared i18n seam.
                // The tool-output guards in `apply_tool_output` still vet
                // generated values with the same model predicates.
                let (c, g) = keygen_field(
                    ui,
                    t(lang, Key::SrvPublicKeyPassword),
                    &mut s.password,
                    "unpadded base64url X25519 public key",
                    |_| None,
                    &KeygenButton {
                        label: t(lang, Key::SrvDerive),
                        hover: "xray x25519 -i <private key>",
                    },
                );
                changed |= c;
                if g {
                    if let Some((target_kind, profile_id, generation)) = target {
                        self.derive_dialog = Some(DeriveDialog {
                            target: ToolTarget::draft(target_kind, profile_id, generation),
                            private_key: String::new(),
                            error: None,
                            pending: false,
                        });
                    } else {
                        self.set_status(StatusLine::err(t(
                            lang,
                            Key::SrvPublicKeyDerivationDraftOnly,
                        )));
                    }
                }
                let (c, g) = keygen_field(
                    ui,
                    "shortId",
                    &mut s.short_id,
                    "hex, ≤ 16 chars",
                    |_| None,
                    &KeygenButton {
                        label: t(lang, Key::Generate),
                        hover: t(lang, Key::SrvRandomHexHint),
                    },
                );
                changed |= c;
                if g {
                    s.short_id = gen_short_id();
                    changed = true;
                }
                changed |= widgets::text_field(ui, "spiderX", &mut s.spider_x, "/");
                let (field_changed, generate) = keygen_field(
                    ui,
                    "mldsa65Verify",
                    &mut s.mldsa65_verify,
                    "base64url ML-DSA-65 seed→verify",
                    |_| None,
                    &KeygenButton {
                        label: t(lang, Key::Generate),
                        hover: t(lang, Key::SrvGenerateMldsa65Hint),
                    },
                );
                changed |= field_changed;
                if generate {
                    self.request_tool(
                        ui,
                        lang,
                        target,
                        XrayToolKind::Mldsa65Verify,
                        vec!["mldsa65".into()],
                    );
                }
                changed |= widgets::opt_bool(
                    ui,
                    t(lang, Key::SrvShowDebug),
                    &mut s.show,
                    t(lang, Key::SrvUnset),
                );
                changed |= path_field(ui, lang, "masterKeyLog", &mut s.master_key_log, true);
                if had_settings || changed {
                    st.reality_settings = Some(s);
                }
            }
            Security::None => {
                ui.weak(t(lang, Key::SrvPlaintextNote));
            }
        }
        changed
    }

    // ---------- Advanced tab ----------

    /// Renders the Advanced tab — shared by the existing-draft editor and
    /// the add-server dialog (the add draft is not yet in the profile set,
    /// so excluding its id from the tag options is inert there).
    ///
    /// Idle-frame purity: the inline finalmask verdict
    /// renders from the caller's memoized validation cache (`show_editor` /
    /// `show_add_draft` refresh it ahead of the content), and the proxy-tag
    /// options rebuild only when the profile-set signal advances.
    fn advanced_tab(
        ui: &mut egui::Ui,
        lang: Language,
        p: &mut ServerProfile,
        // The sibling profiles the chain-target picker may offer: their tags
        // (minus `p`'s own) plus the built-in targets.
        profiles: &[ServerProfile],
        ctx: AdvancedTabCtx<'_>,
    ) -> bool {
        let AdvancedTabCtx {
            set_key,
            finalmask_errors,
            stream_sockopt_errors,
            dialer_proxy_options,
            finalmask_raw,
            pem_buffers,
        } = ctx;
        let mut changed = false;
        let o = &mut p.outbound;
        // Borrow the profile id: the raw-editor buffer keys are derived from
        // it per frame, and cloning the 36-char String would allocate on
        // every repaint of the Advanced tab.
        let key = p.id.as_str();
        // The chain-target picker's options memoize on the profile-set
        // signal: idle frames reuse the cached snapshot, and a rebuild costs
        // O(profiles) only when the set actually changed.
        let dialer_proxy_options =
            refresh_dialer_proxy_options(dialer_proxy_options, set_key, key, profiles);

        widgets::section(ui, t(lang, Key::SrvEnvelope), |ui| {
            changed |= opt_string(
                ui,
                "sendThrough",
                &mut o.send_through,
                "local IP, CIDR, origin, or srcip",
            );
            if let Some(value) = o.send_through.as_mut() {
                changed |= widgets::combo_str_labeled(
                    ui,
                    t(lang, Key::SrvOfficialSourceToken),
                    value,
                    &["origin", "srcip"],
                    t(lang, Key::SrvDefault),
                    false,
                );
                if !send_through_supported(value) {
                    ui.colored_label(
                        status_colors_of(ui).err,
                        t(lang, Key::SrvSendThroughInvalid),
                    );
                }
            }
            changed |= opt_combo_str(
                ui,
                lang,
                "targetStrategy",
                &mut o.target_strategy,
                TARGET_STRATEGIES,
            );
        });

        widgets::section(ui, t(lang, Key::SrvFinalmask), |ui| {
            let had_finalmask = o.stream.finalmask.is_some();
            let mut fm = o.stream.finalmask.take().unwrap_or_default();

            ui.heading(t(lang, Key::SrvTcpMasks));
            ui.weak(t(lang, Key::SrvTcpMaskOrderCaption));
            let tcp_len = fm.tcp.len();
            let mut tcp_remove = None;
            let mut tcp_move = None;
            for (index, mask) in fm.tcp.iter_mut().enumerate() {
                ui.push_id(("finalmask-tcp", key, index), |ui| {
                    ui.group(|ui| {
                        let known = mask.known_type();
                        // Known masks display their &'static type name — no
                        // per-frame allocation; the translated placeholder is
                        // built only for unknown envelopes.
                        let selected: std::borrow::Cow<'static, str> = match known {
                            Some(kind) => std::borrow::Cow::Borrowed(kind),
                            None => std::borrow::Cow::Owned(t_fmt(
                                lang,
                                Key::SrvUnknownType,
                                &[&mask.discriminator().unwrap_or(t(lang, Key::SrvMissingType))],
                            )),
                        };
                        let mut picked: Option<&'static str> = None;
                        ui.horizontal(|ui| {
                            ui.label(t_fmt(lang, Key::SrvTcpN, &[&(index + 1)]));
                            egui::ComboBox::from_id_salt("type")
                                .selected_text(selected.as_ref())
                                .show_ui(ui, |ui| {
                                    for kind in FinalmaskTcpMask::TYPES {
                                        if ui
                                            .selectable_label(
                                                mask.known_type() == Some(*kind),
                                                *kind,
                                            )
                                            .clicked()
                                        {
                                            picked = Some(*kind);
                                        }
                                    }
                                    if known.is_none() {
                                        // Keep-the-unknown row: clicking it
                                        // must not replace the unknown
                                        // envelope with a known type.
                                        ui.selectable_label(true, selected.as_ref()).clicked();
                                    }
                                });
                            finalmask_move_buttons(
                                ui,
                                lang,
                                index,
                                tcp_len,
                                &mut tcp_move,
                                &mut tcp_remove,
                            );
                        });
                        if picked != mask.known_type()
                            && let Some(replacement) =
                                picked.and_then(FinalmaskTcpMask::from_known_type)
                        {
                            *mask = replacement;
                            changed = true;
                        }
                        changed |= finalmask_tcp_settings_editor(
                            ui,
                            lang,
                            mask,
                            egui::Id::new(("fm", key, "tcp", index)),
                            key,
                            finalmask_raw,
                        );
                    });
                });
            }
            if let Some((from, to)) = tcp_move {
                fm.tcp.swap(from, to);
                changed = true;
            }
            if let Some(index) = tcp_remove {
                fm.tcp.remove(index);
                changed = true;
            }
            if ui.button(t(lang, Key::SrvAddTcpMask)).clicked() {
                fm.tcp.push(
                    FinalmaskTcpMask::from_known_type("header-custom")
                        .expect("registered finalmask TCP type"),
                );
                changed = true;
            }

            ui.separator();
            ui.heading(t(lang, Key::SrvUdpMasks));
            ui.weak(t(lang, Key::SrvUdpMaskOrderCaption));
            let udp_len = fm.udp.len();
            let mut udp_remove = None;
            let mut udp_move = None;
            for (index, mask) in fm.udp.iter_mut().enumerate() {
                ui.push_id(("finalmask-udp", key, index), |ui| {
                    ui.group(|ui| {
                        let known = mask.known_type();
                        // Known masks display their &'static type name — no
                        // per-frame allocation; the translated placeholder is
                        // built only for unknown envelopes.
                        let selected: std::borrow::Cow<'static, str> = match known {
                            Some(kind) => std::borrow::Cow::Borrowed(kind),
                            None => std::borrow::Cow::Owned(t_fmt(
                                lang,
                                Key::SrvUnknownType,
                                &[&mask.discriminator().unwrap_or(t(lang, Key::SrvMissingType))],
                            )),
                        };
                        let mut picked: Option<&'static str> = None;
                        ui.horizontal(|ui| {
                            ui.label(t_fmt(lang, Key::SrvUdpN, &[&(index + 1)]));
                            egui::ComboBox::from_id_salt("type")
                                .selected_text(selected.as_ref())
                                .show_ui(ui, |ui| {
                                    for kind in FinalmaskUdpMask::TYPES {
                                        if ui
                                            .selectable_label(
                                                mask.known_type() == Some(*kind),
                                                *kind,
                                            )
                                            .clicked()
                                        {
                                            picked = Some(*kind);
                                        }
                                    }
                                    if known.is_none() {
                                        // Keep-the-unknown row: clicking it
                                        // must not replace the unknown
                                        // envelope with a known type.
                                        ui.selectable_label(true, selected.as_ref()).clicked();
                                    }
                                });
                            finalmask_move_buttons(
                                ui,
                                lang,
                                index,
                                udp_len,
                                &mut udp_move,
                                &mut udp_remove,
                            );
                        });
                        if picked != mask.known_type()
                            && let Some(replacement) =
                                picked.and_then(FinalmaskUdpMask::from_known_type)
                        {
                            *mask = replacement;
                            changed = true;
                        }
                        changed |= finalmask_udp_settings_editor(
                            ui,
                            lang,
                            mask,
                            RawField {
                                id: FieldKey {
                                    key: egui::Id::new(("fm", key, "udp", index)),
                                    profile: key,
                                },
                                buffers: &mut *finalmask_raw,
                            },
                            pem_buffers,
                        );
                    });
                });
            }
            if let Some((from, to)) = udp_move {
                fm.udp.swap(from, to);
                changed = true;
            }
            if let Some(index) = udp_remove {
                fm.udp.remove(index);
                changed = true;
            }
            if ui.button(t(lang, Key::SrvAddUdpMask)).clicked() {
                fm.udp.push(
                    FinalmaskUdpMask::from_known_type("header-custom")
                        .expect("registered finalmask UDP type"),
                );
                changed = true;
            }

            ui.separator();
            changed |= finalmask_quic_editor(ui, lang, &mut fm.quic_params);
            // Finalmask issues ride the memoized validation sweep (keyed on
            // draft generation + language): identical messages with zero
            // re-validation on idle repaint frames.
            for message in finalmask_errors {
                ui.colored_label(status_colors_of(ui).err, message.as_str());
            }
            if had_finalmask || !fm.is_empty() {
                o.stream.finalmask = Some(fm);
            }
        });

        widgets::section(ui, t(lang, Key::SrvSockopt), |ui| {
            let had_sockopt = o.stream.sockopt.is_some();
            let mut sockopt = o.stream.sockopt.take().unwrap_or_default();
            changed |= sockopt_editor(
                ui,
                lang,
                &mut sockopt,
                SockoptUsage::Stream,
                Some(dialer_proxy_options),
                stream_sockopt_errors,
            );
            if had_sockopt || !sockopt.is_empty() {
                o.stream.sockopt = Some(sockopt);
            }
        });
        changed
    }

    // ---------- dialogs ----------

    fn show_add_draft(&mut self, ctx: &egui::Context, uictx: &mut UiCtx) {
        let Some(mut draft) = self.add_draft.take() else {
            return;
        };
        let draft_id = draft.id.clone();
        let lang = uictx.settings.language;
        let validating = self.profile_validation_in_progress(ProfileValidationOrigin::Draft);
        let mut open = true;
        let mut validate_clicked = false;
        let mut cancel = false;
        let window = egui::Window::new(t(lang, Key::SrvAddServerWindow))
            .id(egui::Id::new("servers.add-draft"))
            .collapsible(false)
            .resizable(true)
            .default_size([680.0, 600.0]);
        let window = if validating {
            window
        } else {
            window.open(&mut open)
        };
        window.show(ctx, |ui| {
            // The validation blocks inside render from the memoized cache
            // (mirrors show_editor): refresh before the content so a fresh
            // dialog, a tool application, or a language switch renders
            // same-frame accurate verdicts.
            self.refresh_add_draft_validation_cache(&draft, lang);
            ui.add_enabled_ui(!validating, |ui| {
                ui.horizontal(|ui| {
                    ui.label(t(lang, Key::SrvName));
                    ui.add(egui::TextEdit::singleline(&mut draft.name).desired_width(260.0));
                    ui.separator();
                    ui.label(t(lang, Key::SrvProtocol));
                    ui.monospace(draft.outbound.protocol.as_str());
                });
                ui.separator();
                ui.horizontal(|ui| {
                    for &tab in TABS {
                        ui.selectable_value(&mut self.draft_tab, tab, tab.label(lang));
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("servers.add-draft.scroll")
                    .max_height(430.0)
                    .show(ui, |ui| {
                        let changed = match self.draft_tab {
                            EditorTab::Basic => self.with_add_draft_validation(|screen, cache| {
                                let inline_errors = cache
                                    .map(|cached| cached.rendered.basic_inline.as_slice())
                                    .unwrap_or(&[]);
                                screen.basic_tab_for_target(
                                    ui,
                                    lang,
                                    &mut draft,
                                    Some((
                                        DraftTargetKind::Add,
                                        draft_id.as_str(),
                                        screen.add_draft_generation,
                                    )),
                                    inline_errors,
                                )
                            }),
                            EditorTab::Transport => self.transport_tab(
                                ui,
                                lang,
                                &mut draft.outbound.stream,
                                0,
                                Some((
                                    DraftTargetKind::Add,
                                    draft_id.as_str(),
                                    self.add_draft_generation,
                                )),
                            ),
                            EditorTab::Security => {
                                let address = draft.server_address();
                                self.with_add_draft_validation(|screen, cache| {
                                    let ech_sockopt_errors = cache
                                        .map(|cached| cached.rendered.ech_sockopt.as_slice())
                                        .unwrap_or(&[]);
                                    screen.security_tab_for_target(
                                        ui,
                                        lang,
                                        Some((
                                            DraftTargetKind::Add,
                                            draft_id.as_str(),
                                            screen.add_draft_generation,
                                        )),
                                        &mut draft.outbound.stream,
                                        address.as_deref(),
                                        ech_sockopt_errors,
                                    )
                                })
                            }
                            EditorTab::Mux => {
                                let flow = vless_flow(&draft.outbound.settings);
                                mux_tab(ui, lang, &mut draft.outbound.mux, flow)
                            }
                            EditorTab::Advanced => {
                                // The inline finalmask and sockopt verdicts
                                // ride the memoized add-draft validation
                                // cache (refreshed above whenever the draft
                                // generation or language moved): identical
                                // messages, zero re-validation on idle
                                // frames.
                                let finalmask_errors: &[String] = self
                                    .add_draft_validation_cache
                                    .as_ref()
                                    .map(|cached| cached.rendered.finalmask.as_slice())
                                    .unwrap_or(&[]);
                                let stream_sockopt_errors: &[String] = self
                                    .add_draft_validation_cache
                                    .as_ref()
                                    .map(|cached| cached.rendered.stream_sockopt.as_slice())
                                    .unwrap_or(&[]);
                                ServersScreen::advanced_tab(
                                    ui,
                                    lang,
                                    &mut draft,
                                    &uictx.servers.profiles,
                                    AdvancedTabCtx {
                                        set_key: (
                                            uictx.config_revision,
                                            *uictx.dirty,
                                            uictx.servers.profiles.len(),
                                        ),
                                        finalmask_errors,
                                        stream_sockopt_errors,
                                        dialer_proxy_options: &mut self.add_dialer_proxy_options,
                                        finalmask_raw: &mut self.finalmask_raw,
                                        pem_buffers: &mut self.pem_buffers,
                                    },
                                )
                            }
                        };
                        // The draft changed this frame; bump the generation so
                        // the memoized validation below recomputes (mirrors
                        // show_editor).
                        if changed {
                            self.add_draft_generation = self.add_draft_generation.wrapping_add(1);
                        }
                    });

                // Content edits bumped the generation above; refresh the
                // memoized verdicts once for the new generation (mirrors the
                // editor path).
                self.refresh_add_draft_validation_cache(&draft, lang);
                let Some(cached) = self.add_draft_validation_cache.as_ref() else {
                    return;
                };
                let errors = &cached.rendered.blocking;
                let warnings = &cached.rendered.advisory;
                let gate = add_draft_gate(
                    &draft,
                    self.add_draft_generation,
                    self.add_draft_validation_cache.as_ref(),
                    &self.finalmask_raw,
                    validating,
                    uictx.operation.is_some(),
                );
                if !errors.is_empty() {
                    ui.separator();
                    ui.colored_label(status_colors_of(ui).err, t(lang, Key::SrvCompleteRequired));
                    for error in errors {
                        ui.colored_label(
                            status_colors_of(ui).err,
                            t_fmt(lang, Key::ErrorBullet, &[&error]),
                        );
                    }
                }
                // Configuration warnings never gate Validate-and-add;
                // they render amber under their own header.
                if !warnings.is_empty() {
                    ui.separator();
                    ui.colored_label(
                        status_colors_of(ui).warn,
                        t(lang, Key::SrvConfigurationWarningsHeader),
                    );
                    for warning in warnings {
                        ui.colored_label(
                            status_colors_of(ui).warn,
                            t_fmt(lang, Key::ErrorBullet, &[&warning]),
                        );
                    }
                }
                if uictx.operation.is_some() {
                    ui.colored_label(
                        status_colors_of(ui).warn,
                        t(lang, Key::SrvWaitCoreOperation),
                    );
                }
                ui.separator();
                ui.horizontal(|ui| {
                    // Validate-and-add gates on the blocking half alone: an
                    // add draft is unsaved by definition, so there is nothing
                    // for a changed-from-source test to refuse.
                    if ui
                        .add_enabled(
                            !gate.blocking && !gate.busy,
                            egui::Button::new(t(lang, Key::SrvValidateAndAdd)),
                        )
                        .on_hover_text(t(lang, Key::SrvValidateAndAddHint))
                        .clicked()
                    {
                        validate_clicked = true;
                    }
                    if ui.button(t(lang, Key::Cancel)).clicked() {
                        cancel = true;
                    }
                });
            });
            if validating {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(t(lang, Key::SrvValidatingXrayTest));
                });
            }
            if let Some(report) = &self.profile_validation_report {
                ui.separator();
                ui.colored_label(
                    status_colors_of(ui).err,
                    t(lang, Key::SrvValidationFailedColon),
                );
                egui::ScrollArea::vertical()
                    .id_salt("servers.add-draft.validation-output")
                    .max_height(140.0)
                    .show(ui, |ui| {
                        ui.monospace(report);
                    });
            }
        });

        if validate_clicked {
            let target = ToolTarget::AddDraft {
                profile_id: draft.id.clone(),
                generation: self.add_draft_generation,
            };
            match self.start_profile_validation(
                lang,
                ProfileValidationOrigin::Draft,
                vec![draft.clone()],
                Some(target),
                uictx,
            ) {
                Ok(()) => self.add_draft = Some(draft),
                Err(error) => {
                    self.profile_validation_report = Some(error.clone());
                    self.set_status(StatusLine::err(error));
                    self.add_draft = Some(draft);
                }
            }
        } else if validating || (open && !cancel) {
            self.add_draft = Some(draft);
        } else {
            // The draft was closed or cancelled without commit: the close
            // guard clears a derive dialog targeting it, stages the leave
            // modal when the draft is dirty, and otherwise drops the draft
            // with its seeded raw buffers.
            self.close_add_draft(draft);
        }
    }

    /// The raw `tls ping` transcript in a resizable pop-up window, so the
    /// Security tab stays compact while the full output stays available.
    ///
    /// The window-closed gate runs before the transcript is even borrowed:
    /// after a successful probe the transcript is a KB-scale allocation
    /// that persists for the session, and the output window is closed most
    /// frames — cloning it per frame while closed was a per-frame
    /// allocation on the Servers screen's idle path. While the
    /// window is open the transcript is only borrowed for painting, and the
    /// copy button clones it at click time.
    fn probe_output_window(&mut self, ctx: &egui::Context, lang: Language) {
        if !self.show_tls_probe_output {
            return;
        }
        // No transcript to show (e.g. a discard cleared it while the window
        // was open): clear the flag so this branch stops running — the
        // open/close gate above keeps idle frames off the transcript.
        let Some(output) = &self.tls_tool_output else {
            self.show_tls_probe_output = false;
            return;
        };
        let mut open = true;
        let mut close_clicked = false;
        egui::Window::new(t(lang, Key::SrvProbeOutputTitle))
            .collapsible(false)
            .resizable(true)
            .default_size([560.0, 380.0])
            .open(&mut open)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui.button(t(lang, Key::SrvCopyPin)).clicked() {
                        ui.ctx().copy_text(output.clone());
                    }
                    if ui.button(t(lang, Key::Close)).clicked() {
                        close_clicked = true;
                    }
                });
                egui::ScrollArea::vertical()
                    .id_salt(ui.auto_id_with("tls-probe-output-window"))
                    .max_height(340.0)
                    .show(ui, |ui| {
                        ui.monospace(output.as_str());
                    });
            });
        if close_clicked {
            open = false;
        }
        self.show_tls_probe_output = open;
    }

    fn show_dialogs(&mut self, ctx: &egui::Context, uictx: &mut UiCtx) {
        let lang = uictx.settings.language;
        self.probe_output_window(ctx, lang);
        self.show_add_draft(ctx, uictx);
        // Import links.
        if self.import_open {
            let validating = self.profile_validation_in_progress(ProfileValidationOrigin::Import);
            let mut open = self.import_open;
            let mut validate_profiles: Option<Vec<ServerProfile>> = None;
            let window = egui::Window::new(t(lang, Key::SrvImportShareLinks))
                .collapsible(false)
                .resizable(true)
                .default_size([520.0, 420.0]);
            let window = if validating {
                window
            } else {
                window.open(&mut open)
            };
            window.show(ctx, |ui| {
                ui.add_enabled_ui(!validating, |ui| {
                    ui.label(t(lang, Key::SrvImportHint));
                    let source_changed = ui
                        .add(
                            egui::TextEdit::multiline(&mut self.import_text)
                                .desired_rows(6)
                                .desired_width(f32::INFINITY)
                                .hint_text(t(lang, Key::SrvImportPasteHint)),
                        )
                        .changed();
                    if source_changed {
                        self.invalidate_import_preview();
                        self.profile_validation_report = None;
                        self.import_parse_error = None;
                        self.cancel_import_parse();
                    }
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                !self.import_parse_job.is_pending() && !self.import_text.is_empty(),
                                egui::Button::new(t(lang, Key::SrvParse)),
                            )
                            .clicked()
                        {
                            self.start_import_parse(lang, ui.ctx().clone());
                        }
                        ui.weak(t(lang, Key::SrvPasteCtrlV));
                    });
                    if self.import_parse_job.is_pending() {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.label(t(lang, Key::SrvParsingLinks));
                            if ui.button(t(lang, Key::Cancel)).clicked() {
                                self.cancel_import_parse();
                            }
                        });
                    }
                    if let Some(message) = &self.import_parse_error {
                        ui.colored_label(status_colors_of(ui).err, message);
                    }
                    if self.import_preview_is_current() && !self.import_parsed.is_empty() {
                        self.refresh_import_preview(lang);
                        let preview = self
                            .import_preview
                            .as_ref()
                            .expect("the preview was built for this frame");
                        let ok = preview.ok;
                        ui.label(t_fmt(lang, Key::SrvOkTotal, &[&ok, &preview.rows.len()]));
                        // One truncated line per entry, laid out only for the
                        // rows the scroll viewport shows: a subscription
                        // paste can hold tens of thousands of links, and egui
                        // lays out every child of a plain `show`. The full
                        // error text stays reachable as the row's tooltip.
                        let row_height = ui.text_style_height(&egui::TextStyle::Body);
                        egui::ScrollArea::vertical().max_height(140.0).show_rows(
                            ui,
                            row_height,
                            preview.rows.len(),
                            |ui, rows| {
                                let error_color = status_colors_of(ui).err;
                                for row in &preview.rows[rows] {
                                    let text = if row.error {
                                        RichText::new(row.text.as_str()).color(error_color)
                                    } else {
                                        RichText::new(row.text.as_str())
                                    };
                                    let response = ui.add(egui::Label::new(text).truncate());
                                    if row.error {
                                        response.on_hover_text(row.text.as_str());
                                    }
                                }
                            },
                        );
                        if uictx.operation.is_some() {
                            ui.colored_label(
                                status_colors_of(ui).warn,
                                t(lang, Key::SrvWaitCoreOperationImports),
                            );
                        }
                        if ui
                            .add_enabled(
                                ok > 0 && uictx.operation.is_none(),
                                egui::Button::new(t_fmt(
                                    lang,
                                    Key::SrvValidateAndAddServers,
                                    &[&ok],
                                )),
                            )
                            .on_hover_text(t(lang, Key::SrvValidateAndAddServersHint))
                            .clicked()
                        {
                            validate_profiles = Some(
                                self.import_parsed
                                    .iter()
                                    .filter_map(|result| result.as_ref().ok().cloned())
                                    .collect(),
                            );
                        }
                    }
                });
                if validating {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(t_fmt(
                            lang,
                            Key::SrvValidatingProfiles,
                            &[&self.profile_validation_count],
                        ));
                    });
                }
                if let Some(report) = &self.profile_validation_report {
                    ui.separator();
                    ui.colored_label(
                        status_colors_of(ui).err,
                        t(lang, Key::SrvRejectedProfileDetails),
                    );
                    egui::ScrollArea::vertical()
                        .id_salt("servers.import.validation-output")
                        .max_height(160.0)
                        .show(ui, |ui| {
                            ui.monospace(report);
                        });
                }
            });
            if let Some(profiles) = validate_profiles
                && let Err(error) = self.start_profile_validation(
                    lang,
                    ProfileValidationOrigin::Import,
                    profiles,
                    None,
                    uictx,
                )
            {
                self.profile_validation_report = Some(error.clone());
                self.set_status(StatusLine::err(error));
            }
            self.import_open = (open
                || validating
                || self.profile_validation_in_progress(ProfileValidationOrigin::Import))
                && self.import_open;
            if !self.import_open {
                self.cancel_import_parse();
            }
        }

        // QR export.
        if let Some(qr) = &mut self.qr_dialog {
            let mut open = true;
            let mut close_clicked = false;
            egui::Window::new(t_fmt(lang, Key::SrvShareTitle, &[&qr.name]))
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    if qr.tex.is_none() {
                        qr.tex = links::qr_color_image(&qr.link).map(|img| {
                            ui.ctx()
                                .load_texture("qr", img, egui::TextureOptions::NEAREST)
                        });
                    }
                    if let Some(tex) = &qr.tex {
                        ui.image(tex);
                    } else {
                        ui.label(t(lang, Key::SrvQrTooLong));
                    }
                    ui.add(
                        egui::TextEdit::multiline(&mut qr.link.as_str())
                            .desired_width(300.0)
                            .desired_rows(2),
                    );
                    ui.horizontal(|ui| {
                        if ui.button(t(lang, Key::CopyLink)).clicked() {
                            ui.ctx().copy_text(qr.link.clone());
                        }
                        if ui.button(t(lang, Key::Close)).clicked() {
                            close_clicked = true;
                        }
                    });
                });
            if !open || close_clicked {
                self.qr_dialog = None;
            }
        }

        // Delete confirmation.
        if self.delete_pending.as_ref().is_some_and(|dialog| {
            !uictx
                .servers
                .profiles
                .iter()
                .any(|profile| profile.id.as_str() == dialog.id.as_str())
        }) {
            self.delete_pending = None;
        }
        if let Some(dialog) = &self.delete_pending {
            let mut open = true;
            let mut decision: Option<bool> = None;
            egui::Window::new(t(lang, Key::DeleteServer))
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .open(&mut open)
                .show(ctx, |ui| {
                    if dialog.references.is_empty() {
                        ui.label(t_fmt(lang, Key::SrvDeleteCannotUndone, &[&dialog.name]));
                        ui.horizontal(|ui| {
                            if ui.button(t(lang, Key::Delete)).clicked() {
                                decision = Some(true);
                            }
                            if ui.button(t(lang, Key::Cancel)).clicked() {
                                decision = Some(false);
                            }
                        });
                    } else {
                        ui.colored_label(
                            status_colors_of(ui).err,
                            t_fmt(
                                lang,
                                Key::SrvCannotDeleteReferences,
                                &[&dialog.name, &dialog.references.len()],
                            ),
                        );
                        for reference in &dialog.references {
                            ui.monospace(format!("• {reference}"));
                        }
                        if ui.button(t(lang, Key::Close)).clicked() {
                            decision = Some(false);
                        }
                    }
                });
            if decision == Some(true) {
                // Owned copy: the confirm block also mutates `self`
                // (eviction), which the `dialog` borrow would otherwise block.
                let deleted_id = dialog.id.clone();
                uictx.servers.profiles.retain(|p| p.id != deleted_id);
                if uictx.servers.active.as_deref() == Some(deleted_id.as_str()) {
                    uictx.servers.active = uictx.servers.profiles.first().map(|p| p.id.clone());
                }
                if self.selected.as_deref() == Some(deleted_id.as_str()) {
                    self.selected = None;
                }
                self.evict_raw_buffers(&deleted_id);
                // The deleted profile's memoized latency badge is dead
                // weight; the row loop would never re-insert it
                // because the id no longer renders.
                self.latency_badges.remove(&deleted_id);
                uictx.mark_dirty();
            }
            if !open || decision.is_some() {
                self.delete_pending = None;
            }
        }

        if self.profile_validation_request.is_pending() {
            self.derive_dialog = None;
        }
        // REALITY x25519 public-key derivation. The private key stays in this
        // transient dialog; the result is applied only to its still-current draft.
        if let Some(mut dialog) = self.derive_dialog.take() {
            let mut open = true;
            let mut close_clicked = false;
            let mut derive_clicked = false;
            egui::Window::new(t(lang, Key::SrvDerivePublicKey))
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.label(t(lang, Key::SrvPrivateKeyLabel));
                    ui.add(
                        egui::TextEdit::singleline(&mut dialog.private_key)
                            .desired_width(320.0)
                            .hint_text(t(lang, Key::SrvPrivateKeyHint)),
                    );
                    if let Some(error) = &dialog.error {
                        ui.colored_label(status_colors_of(ui).err, error);
                    }
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                !dialog.pending && self.tool_job.is_none(),
                                egui::Button::new(t(lang, Key::SrvDerive)),
                            )
                            .clicked()
                        {
                            derive_clicked = true;
                        }
                        if ui.button(t(lang, Key::Cancel)).clicked() {
                            close_clicked = true;
                        }
                    });
                    if dialog.pending {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            ui.weak(t(lang, Key::SrvDerivingXray));
                        });
                    }
                });
            if derive_clicked {
                let private_key = dialog.private_key.trim().to_string();
                if private_key.is_empty() {
                    dialog.error = Some(t(lang, Key::SrvPrivateKeyRequired).into());
                } else if let Err(error) = self.queue_xray_tool(
                    lang,
                    ctx.clone(),
                    dialog.target.clone(),
                    XrayToolKind::RealityPublicKey,
                    vec!["x25519".into(), "-i".into(), private_key],
                ) {
                    dialog.error = Some(error);
                } else {
                    dialog.pending = true;
                    dialog.error = None;
                }
            }
            if open && !close_clicked {
                self.derive_dialog = Some(dialog);
            }
        }

        self.show_status_toast(ctx);
    }

    /// Record the status toast, restarting its auto-clear window. Every
    /// status-set site in the screen routes through this one method, so all
    /// of them share the single clear mechanism.
    fn set_status(&mut self, status: StatusLine) {
        self.status_set_at = Some(Instant::now());
        self.status = Some(status);
    }

    /// Render the status toast window. A toast is shown for at most
    /// [`STATUS_TOAST_AUTO_CLEAR`] after it was set; once the window elapses
    /// the toast is cleared, so a stale message can never linger over the
    /// screen (the window used to render forever after the first status).
    fn show_status_toast(&mut self, ctx: &egui::Context) {
        let expired = self.status_set_at.is_none_or(|shown_at| {
            status_toast_expired(shown_at, Instant::now(), STATUS_TOAST_AUTO_CLEAR)
        });
        if expired {
            self.status = None;
            return;
        }
        let Some(st) = &self.status else {
            return;
        };
        egui::Window::new("servers-status")
            .title_bar(false)
            .resizable(false)
            .anchor(egui::Align2::RIGHT_BOTTOM, [-12.0, -12.0])
            .show(ctx, |ui| {
                let colors = status_colors_of(ui);
                ui.colored_label(if st.is_error { colors.err } else { colors.ok }, &st.text);
            });
    }
}

// ---------- editor free helpers ----------

fn addr_port(ui: &mut egui::Ui, lang: Language, address: &mut String, port: &mut u16) -> bool {
    let mut changed = widgets::validated_field(
        ui,
        t(lang, Key::AddressLower),
        address,
        "example.com",
        |v| v_required(lang, v),
    );
    // Port 0 is enforced by the model (SettingsPortZero /
    // TrojanSettingsIncomplete / ShadowsocksSettingsIncomplete) and
    // rendered once through the shared i18n seam — no inline duplicate.
    changed |= widgets::port_field(ui, "port", port);
    changed
}

/// The VLESS `settings.flow` of a VLESS outbound's settings (`None` for
/// every other protocol) — passed to [`mux_tab`] so its rule-01 inline
/// warning reuses the model's shared predicate instead of re-deriving the
/// protocol state. Takes only the settings, so the caller can hold the mux
/// field mutably at the same time (disjoint borrows stay disjoint).
fn vless_flow(settings: &ProtocolSettings) -> Option<&str> {
    match settings {
        ProtocolSettings::Vless(settings) => Some(settings.flow.as_str()),
        _ => None,
    }
}

fn mux_tab(ui: &mut egui::Ui, lang: Language, m: &mut MuxModel, flow: Option<&str>) -> bool {
    let mut changed = false;
    changed |= ui
        .checkbox(&mut m.enabled, t(lang, Key::SrvEnableXmux))
        .changed();
    // Warn inline at the mux trigger when a
    // vision flow would ride TCP over smux — same shared predicate as the
    // validation sweep, same i18n message as the editor's warning list.
    if flow.is_some_and(|flow| mux_conflicts_with_vision_flow(flow, m.enabled, m.concurrency)) {
        ui.colored_label(
            status_colors_of(ui).warn,
            validation_message(&ValidationCode::MuxWithVisionFlow, lang),
        );
    }
    changed |= widgets::opt_num(
        ui,
        t(lang, Key::SrvConcurrencyLegacy),
        &mut m.concurrency,
        -1..=1024,
    );
    changed |= widgets::opt_num(ui, "xudpConcurrency", &mut m.xudp_concurrency, -1..=1024);
    changed |= opt_combo_str(
        ui,
        lang,
        "xudpProxyUDP443",
        &mut m.xudp_proxy_udp443,
        XUDP_PROXY_UDP443_MODES,
    );
    // Informational copy: the (unset)/empty default means reject
    // (Xray's MuxConfig.Build normalizes "" to reject).
    ui.weak(t(lang, Key::SrvXudpProxyUdp443Hint));
    ui.weak(t(lang, Key::SrvMuxDeprecatedHint));
    changed
}

fn noises_editor(ui: &mut egui::Ui, lang: Language, noises: &mut Vec<Noise>) -> bool {
    let mut changed = false;
    ui.label(t(lang, Key::SrvNoisesUdpObfuscation));
    let mut del: Option<usize> = None;
    for (i, n) in noises.iter_mut().enumerate() {
        ui.push_id(i, |ui| {
            ui.group(|ui| {
                changed |= widgets::combo_str_labeled(
                    ui,
                    "type",
                    &mut n.r#type,
                    &["rand", "str", "hex", "base64"],
                    t(lang, Key::SrvDefault),
                    false,
                );
                changed |= widgets::text_field(ui, "packet", &mut n.packet, "payload or range");
                changed |=
                    widgets::opt_range(ui, t(lang, Key::SrvDelayMs), &mut n.delay, 0..=10_000);
                changed |= widgets::combo_str_labeled(
                    ui,
                    "applyTo",
                    &mut n.apply_to,
                    &["", "ip", "all", "ipv4", "ipv6"],
                    t(lang, Key::SrvDefault),
                    false,
                );
                if !noise_is_valid(n) {
                    ui.colored_label(status_colors_of(ui).err, t(lang, Key::SrvNoiseInvalid));
                }
                if ui.button(t(lang, Key::SrvRemoveNoise)).clicked() {
                    del = Some(i);
                }
            });
        });
    }
    if let Some(i) = del {
        noises.remove(i);
        changed = true;
    }
    if ui.button(t(lang, Key::SrvAddNoise)).clicked() {
        noises.push(runnable_noise());
        changed = true;
    }
    changed
}

fn final_rules_editor(
    ui: &mut egui::Ui,
    lang: Language,
    rules: &mut Vec<FreedomFinalRule>,
) -> bool {
    let mut changed = false;
    ui.label(t(lang, Key::SrvFinalRulesPostFragment));
    let mut del: Option<usize> = None;
    for (i, r) in rules.iter_mut().enumerate() {
        ui.push_id(i, |ui| {
            ui.group(|ui| {
                changed |= widgets::combo_str_labeled(
                    ui,
                    "action",
                    &mut r.action,
                    &["allow", "block"],
                    t(lang, Key::SrvDefault),
                    false,
                );
                if !freedom_final_rule_supported(&r.action) {
                    ui.colored_label(
                        status_colors_of(ui).err,
                        t(lang, Key::SrvFinalRuleActionInvalid),
                    );
                }
                changed |= widgets::text_field(ui, "network", &mut r.network, "tcp,udp");
                changed |= widgets::text_field(ui, "port", &mut r.port, "1-65535");
                changed |= widgets::string_list(ui, lang, t(lang, Key::Ips), &mut r.ip, "geoip:cn");
                changed |= widgets::opt_range(
                    ui,
                    t(lang, Key::SrvBlockDelayMs),
                    &mut r.block_delay,
                    0..=60_000,
                );
                if ui.button(t(lang, Key::SrvRemoveRule)).clicked() {
                    del = Some(i);
                }
            });
        });
    }
    if let Some(i) = del {
        rules.remove(i);
        changed = true;
    }
    if ui.button(t(lang, Key::SrvAddFinalRule)).clicked() {
        rules.push(runnable_final_rule());
        changed = true;
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::keygen::{
        ca_pins_from_probe_output, keygen_value, leaf_pin_from_probe_output, redacted_tool_args,
    };
    use super::raw_editor::JsonBuf;
    use super::{
        AddDraftValidationCache, AdvancedTabCtx, DRAG_SCROLL_MAX_SPEED, DeriveDialog, DraftGate,
        DraftTargetKind, EditorTab, EditorValidationCache, EditorValidationFindings,
        EditorValidationRender, ExistingProfileDraft, FINGERPRINTS, FeedbackLevel, FieldKey,
        Language, LatencyBadge, LeaveAction, RawBuffers, RawField, Request, RowProbeState,
        STATUS_TOAST_AUTO_CLEAR, ServerProfile, ServersScreen, SockoptUsage, StatusLine,
        basic_tab_inline_verdict, drag_scroll_delta, ech_sockopt_editor,
        editor_validation_findings, final_rules_editor, finalmask_udp_settings_editor,
        fingerprint_allowed, mux_tab, noises_editor, refresh_add_draft_validation,
        refresh_editor_validation, reorder_target, server_list_row, sockopt_findings,
        status_colors_of, status_toast_expired,
    };
    use crate::diag::{Diag, DiagError};
    use crate::i18n::{Key, t, t_fmt, validation_issue_message, validation_message};
    use crate::links;
    use crate::model::stream::MasqueradeCfg;
    use crate::model::validation::{ValidationCode, ValidationIssue};
    use crate::model::{
        BlackholeResponse, CustomSockopt, FinalmaskHeaderCustomTcp, FinalmaskModel,
        FinalmaskQuicParams, FinalmaskRealm, FinalmaskTcpItem, FinalmaskTcpMask, FinalmaskUdpMask,
        FreedomFinalRule, HysteriaTransport, Network, Noise, OutboundModel, Protocol,
        ProtocolSettings, RealityModel, Security, SockoptModel, StreamModel, TlsModel, WsSettings,
        XhttpSettings,
    };
    use crate::rt::{
        CoreCmd, LatencyProbeResult, OutboundStatusView, ProfileValidationOrigin,
        ProfileValidationResult, ToolTarget,
    };
    use crate::ui::test_rig::UiTestRig;
    use egui_kittest::{Harness, kittest::NodeT as _, kittest::Queryable};
    use serde_json::json;
    use std::time::{Duration, Instant};
    use std::{cell::RefCell, rc::Rc};

    /// The codes of one finding list, in the sweep's order.
    fn codes_of(findings: &[ValidationIssue]) -> Vec<ValidationCode> {
        findings.iter().map(|issue| issue.code.clone()).collect()
    }

    /// The one finding carrying `code`, or a panic listing what the sweep
    /// produced instead.
    fn finding(findings: &[ValidationIssue], code: ValidationCode) -> ValidationIssue {
        findings
            .iter()
            .find(|issue| issue.code == code)
            .cloned()
            .expect("the sweep reports the rule")
    }

    #[test]
    fn vlessenc_extracts_client_encryption_not_server_decryption() {
        let stdout = r#"Choose one Authentication to use, do not mix them.

Authentication: X25519, not Post-Quantum
"decryption": "mlkem768x25519plus.native.600s.server-secret"
"encryption": "mlkem768x25519plus.native.0rtt.client-public"

Authentication: ML-KEM-768, Post-Quantum
"decryption": "mlkem768x25519plus.native.600s.pq-server-secret"
"encryption": "mlkem768x25519plus.native.0rtt.pq-client-public"
"#;

        let value = keygen_value(stdout, &["\"encryption\":"]).unwrap();
        assert_eq!(
            value.trim_matches('"'),
            "mlkem768x25519plus.native.0rtt.client-public"
        );
    }

    #[test]
    fn redacted_tool_args_masks_the_x25519_private_key() {
        let args = vec![
            "x25519".into(),
            "-i".into(),
            "secret-private-key-bytes".into(),
        ];
        let display = redacted_tool_args(&args);
        assert!(
            !display.contains("secret-private-key-bytes"),
            "the command line shown in an error message must not contain the private key: {display:?}"
        );
        assert!(
            display.contains("x25519") && display.contains("-i"),
            "the command shape must remain readable: {display:?}"
        );
        assert!(
            display.contains("redacted"),
            "the masked value must be replaced by a placeholder: {display:?}"
        );
    }

    #[test]
    fn redacted_tool_args_leaves_secret_free_invocations_unchanged() {
        assert_eq!(redacted_tool_args(&["uuid".into()]), "uuid");
        assert_eq!(
            redacted_tool_args(&[
                "tls".into(),
                "hash".into(),
                "--cert".into(),
                r"C:\certs\leaf.pem".into(),
            ]),
            "tls hash --cert C:\\certs\\leaf.pem"
        );
    }
    #[test]
    fn leaf_pin_from_probe_output_parses_the_golden_probe_output() {
        // Realistic `xray tls ping` output: the tabwriter (padding 2, space
        // padchar) aligns every value column; both the without-SNI and the
        // with-SNI connection print the same chain. The hex literals below
        // are the fixture's own values (independent source of truth).
        let output = r#"TLS ping:  example.com
Using IP:  93.184.216.34:443
-------------------
Pinging without SNI
Handshake succeeded
TLS Version:                                          TLS 1.3
TLS Post-Quantum key exchange:                        false (RSA Exchange)
Certificate chain's total length:                     2144 (certs count: 2)
Cert's signature algorithm:                           SHA256-RSA
Cert's publicKey algorithm:                           RSA
Cert's leaf SHA256:                                   7f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
Cert's CA <DigiCert TLS RSA SHA256 2020 CA1> SHA256:  a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
Cert's CA <DigiCert Global Root R11> SHA256:          c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2
Cert's allowed domains:                               [example.com]
-------------------
Pinging with SNI
Handshake succeeded
TLS Version:                                          TLS 1.3
TLS Post-Quantum key exchange:                        false (RSA Exchange)
Certificate chain's total length:                     2144 (certs count: 2)
Cert's signature algorithm:                           SHA256-RSA
Cert's publicKey algorithm:                           RSA
Cert's leaf SHA256:                                   7f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
Cert's CA <DigiCert TLS RSA SHA256 2020 CA1> SHA256:  a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
Cert's CA <DigiCert Global Root R11> SHA256:          c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2
Cert's allowed domains:                               [example.com]
-------------------
TLS ping finished"#;
        assert_eq!(
            leaf_pin_from_probe_output(output),
            Some("7f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9".to_owned())
        );
    }

    #[test]
    fn leaf_pin_from_probe_output_none_without_a_leaf_line() {
        // A successful handshake whose chain has no leaf with DNSNames
        // prints no certificate detail lines at all.
        let output = r#"TLS ping:  10.0.0.5
Using IP:  10.0.0.5:443
-------------------
Pinging without SNI
Handshake succeeded
TLS Version:                       TLS 1.3
TLS Post-Quantum key exchange:     false (RSA Exchange)
Certificate chain's total length:  1024 (certs count: 1)
-------------------
Pinging with SNI
Handshake succeeded
TLS Version:                       TLS 1.3
TLS Post-Quantum key exchange:     false (RSA Exchange)
Certificate chain's total length:  1024 (certs count: 1)
-------------------
TLS ping finished"#;
        assert_eq!(leaf_pin_from_probe_output(output), None);
    }

    #[test]
    fn ca_pins_from_probe_output_parses_every_ca_line_in_order() {
        let output = r#"TLS ping:  example.com
Using IP:  93.184.216.34:443
-------------------
Pinging without SNI
Handshake succeeded
TLS Version:                                          TLS 1.3
TLS Post-Quantum key exchange:                        false (RSA Exchange)
Certificate chain's total length:                     2144 (certs count: 2)
Cert's signature algorithm:                           SHA256-RSA
Cert's publicKey algorithm:                           RSA
Cert's leaf SHA256:                                   7f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
Cert's CA <DigiCert TLS RSA SHA256 2020 CA1> SHA256:  a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
Cert's CA <DigiCert Global Root R11> SHA256:          c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2
Cert's allowed domains:                               [example.com]
-------------------
Pinging with SNI
Handshake succeeded
TLS Version:                                          TLS 1.3
TLS Post-Quantum key exchange:                        false (RSA Exchange)
Certificate chain's total length:                     2144 (certs count: 2)
Cert's signature algorithm:                           SHA256-RSA
Cert's publicKey algorithm:                           RSA
Cert's leaf SHA256:                                   7f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
Cert's CA <DigiCert TLS RSA SHA256 2020 CA1> SHA256:  a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
Cert's CA <DigiCert Global Root R11> SHA256:          c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2
Cert's allowed domains:                               [example.com]
-------------------
TLS ping finished"#;
        assert_eq!(
            ca_pins_from_probe_output(output),
            vec![
                (
                    "DigiCert TLS RSA SHA256 2020 CA1".to_owned(),
                    "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_owned(),
                ),
                (
                    "DigiCert Global Root R11".to_owned(),
                    "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2".to_owned(),
                ),
                (
                    "DigiCert TLS RSA SHA256 2020 CA1".to_owned(),
                    "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_owned(),
                ),
                (
                    "DigiCert Global Root R11".to_owned(),
                    "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2".to_owned(),
                ),
            ]
        );
    }

    #[test]
    fn ca_pins_from_probe_output_empty_without_ca_lines() {
        let output = r#"TLS ping:  10.0.0.5
Using IP:  10.0.0.5:443
-------------------
Pinging without SNI
Handshake succeeded
TLS Version:                       TLS 1.3
TLS Post-Quantum key exchange:     false (RSA Exchange)
Certificate chain's total length:  1024 (certs count: 1)
-------------------
Pinging with SNI
Handshake succeeded
TLS Version:                       TLS 1.3
TLS Post-Quantum key exchange:     false (RSA Exchange)
Certificate chain's total length:  1024 (certs count: 1)
-------------------
TLS ping finished"#;
        assert!(ca_pins_from_probe_output(output).is_empty());
    }

    #[test]
    fn start_profile_validation_sends_the_verb_with_a_raw_override_free_snapshot() {
        // The runtime owns the scratch write, the guard, the child and the
        // timeout; the screen's half is the request: the profiles to
        // validate, the servers snapshot they are staged into, and scratch
        // settings whose raw override is cleared so the staged profile is
        // generated instead of the passthrough. The parked receiver is that
        // request's own reply channel — one terminal settles it.
        let mut screen = ServersScreen::default();
        let mut rig = UiTestRig::default();
        rig.settings.raw_override = Some("{\"from\":\"file\"}".to_string());
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        {
            let ctx = rig.ctx();
            screen
                .start_profile_validation(
                    Language::En,
                    ProfileValidationOrigin::Import,
                    vec![tokyo.clone()],
                    None,
                    &ctx,
                )
                .expect("an idle screen accepts a validation request");
        }
        let command = rig
            ._cmd_rx
            .try_recv()
            .expect("a validation request must reach the runtime");
        match command {
            CoreCmd::ValidateProfiles { request, reply } => {
                assert_eq!(request.origin, ProfileValidationOrigin::Import);
                assert_eq!(request.profiles.len(), 1);
                assert_eq!(request.profiles[0].id, tokyo.id);
                assert!(
                    request.settings.raw_override.is_none(),
                    "the scratch settings must clear the raw override"
                );
                // The screen polls exactly this channel: the terminal the
                // runtime sends on it is what the next frame renders.
                let reject = Diag::new(Key::RtFrameCommandRejectedBusy)
                    .arg_message(Diag::new(Key::OperationApplyConfig));
                let reject_text = reject.text(Language::En);
                reply
                    .send(Err(DiagError::from(reject)))
                    .expect("the request's channel stays open for the screen");
                assert!(screen.profile_validation_request.is_pending());
                screen.poll_profile_validation(Language::En, &mut rig.ctx());
                assert_eq!(
                    screen.profile_validation_report.as_deref(),
                    Some(reject_text.as_str()),
                    "the request's own reply channel is the one the screen polls"
                );
                assert!(!screen.profile_validation_request.is_pending());
            }
            other => panic!("expected ValidateProfiles, got {other:?}"),
        }
    }

    #[test]
    fn poll_reports_a_vanished_runtime_with_the_declared_text() {
        // The runtime dropped the request's reply sender without a terminal:
        // the request's declared worker-exited text is the whole verdict, and
        // every pending slot clears so a later validation starts clean.
        let mut screen = ServersScreen {
            profile_validation_origin: Some(ProfileValidationOrigin::Draft),
            profile_validation_count: 1,
            ..Default::default()
        };
        let mut rig = UiTestRig::default();
        let (tx, rx) = tokio::sync::oneshot::channel();
        screen.profile_validation_request = Request::reply(rx);
        drop(tx);

        screen.poll_profile_validation(Language::En, &mut rig.ctx());

        assert_eq!(
            screen.profile_validation_report.as_deref(),
            Some(t(Language::En, Key::SrvWorkerExitedWithoutResult)),
            "a vanished runtime must surface the request's declared text"
        );
        assert!(
            !screen.profile_validation_request.is_pending()
                && screen.profile_validation_origin.is_none()
                && screen.profile_validation_count == 0,
            "the exit must clear every pending slot"
        );
    }

    #[test]
    fn poll_takes_the_terminal_and_clears_the_pending_slots() {
        // A delivered terminal means the runtime's worker is done with the
        // request; the screen must clear its pending slots so a later
        // validation starts clean and the next poll never re-reads a spent
        // reply channel.
        let mut screen = ServersScreen {
            profile_validation_count: 1,
            ..Default::default()
        };
        let mut rig = UiTestRig::default();
        let (tx, rx) = tokio::sync::oneshot::channel();
        screen.profile_validation_request = Request::reply(rx);
        screen.profile_validation_origin = Some(ProfileValidationOrigin::Draft);
        tx.send(Ok(ProfileValidationResult {
            origin: ProfileValidationOrigin::Draft,
            accepted: Vec::new(),
            rejected: Vec::new(),
            import_source: None,
            draft_target: None,
        }))
        .unwrap();
        screen.poll_profile_validation(Language::En, &mut rig.ctx());
        assert!(
            !screen.profile_validation_request.is_pending()
                && screen.profile_validation_origin.is_none()
                && screen.profile_validation_count == 0,
            "a delivered terminal must clear every pending slot"
        );
    }

    #[test]
    fn poll_renders_a_runtime_owned_terminal_without_committing() {
        // The runtime answers a request it never ran (busy window, stopping,
        // cooperative cancel, join failure) with the text on the request's
        // own channel; the screen renders it as the validation error and
        // leaves the model alone.
        let mut screen = ServersScreen::default();
        let mut rig = UiTestRig::default();
        let (tx, rx) = tokio::sync::oneshot::channel();
        screen.profile_validation_request = Request::reply(rx);
        screen.profile_validation_origin = Some(ProfileValidationOrigin::Draft);
        let reject = Diag::new(Key::RtFrameCommandRejectedBusy)
            .arg_message(Diag::new(Key::OperationApplyConfig));
        let reject_text = reject.text(Language::En);
        tx.send(Err(DiagError::from(reject))).unwrap();
        screen.poll_profile_validation(Language::En, &mut rig.ctx());
        assert_eq!(
            screen.profile_validation_report.as_deref(),
            Some(reject_text.as_str()),
            "the runtime's terminal must be rendered as the validation verdict"
        );
        assert!(!screen.profile_validation_request.is_pending());
    }

    #[test]
    fn reality_fingerprint_options_are_the_trimmed_known_good_set() {
        use crate::model::fingerprint::REALITY_EDITOR_OPTIONS;
        // The REALITY combo filters the same candidate table the TLS combos
        // use down to the trimmed option set; the visible list equals the
        // option set, so every option is reachable and nothing else leaks in.
        let offered = FINGERPRINTS
            .iter()
            .copied()
            .filter(|name| fingerprint_allowed(name, true))
            .collect::<Vec<_>>();
        assert_eq!(offered, REALITY_EDITOR_OPTIONS);
        // The TLS and realm-TLS contexts keep the full editor table,
        // including every name the REALITY trim dropped.
        for &name in FINGERPRINTS {
            assert!(fingerprint_allowed(name, false), "TLS combo hides {name:?}");
        }
        for name in ["ios", "edge", "qq", "randomized"] {
            assert!(fingerprint_allowed(name, false));
            assert!(
                !fingerprint_allowed(name, true),
                "the REALITY combo must not offer {name:?}"
            );
        }
    }

    #[test]
    fn reality_fingerprint_combo_keeps_a_stored_name_outside_the_option_set() {
        // A profile that already stores a dropped name must show it and save
        // it untouched: the trimmed combo never blanks or rewrites a loaded
        // value.
        for stored in ["ios", "edge", "qq"] {
            let stream = Rc::new(RefCell::new(StreamModel {
                security: Security::Reality,
                reality_settings: Some(RealityModel {
                    fingerprint: stored.into(),
                    ..Default::default()
                }),
                ..Default::default()
            }));
            let before = serde_json::to_value(&*stream.borrow()).unwrap();
            let stream_for_ui = Rc::clone(&stream);
            let screen = Rc::new(RefCell::new(ServersScreen::default()));
            let screen_for_ui = Rc::clone(&screen);
            let changed = Rc::new(RefCell::new(false));
            let changed_for_ui = Rc::clone(&changed);
            let mut harness = Harness::new_ui(move |ui| {
                *changed_for_ui.borrow_mut() = screen_for_ui.borrow_mut().security_tab(
                    ui,
                    Language::En,
                    None,
                    &mut stream_for_ui.borrow_mut(),
                    None,
                    &[],
                );
            });
            harness.run();
            assert!(
                harness
                    .get_all_by_role(egui::accesskit::Role::ComboBox)
                    .into_iter()
                    .any(|node| node.value().as_deref() == Some(stored)),
                "the REALITY combo must display the stored fingerprint {stored:?}"
            );
            assert!(
                !*changed.borrow(),
                "an untouched frame must not report an edit for {stored:?}"
            );
            drop(harness);
            assert_eq!(
                serde_json::to_value(&*stream.borrow()).unwrap(),
                before,
                "saving a profile must not rewrite {stored:?}"
            );
        }
    }

    #[test]
    fn reality_fingerprint_combo_lists_only_the_trimmed_options() {
        use crate::model::fingerprint::REALITY_EDITOR_OPTIONS;
        use egui_kittest::kittest::NodeT as _;
        let stream = Rc::new(RefCell::new(StreamModel {
            security: Security::Reality,
            reality_settings: Some(RealityModel {
                fingerprint: "ios".into(),
                ..Default::default()
            }),
            ..Default::default()
        }));
        let stream_for_ui = Rc::clone(&stream);
        let screen = Rc::new(RefCell::new(ServersScreen::default()));
        let screen_for_ui = Rc::clone(&screen);
        let mut harness = Harness::new_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().security_tab(
                ui,
                Language::En,
                None,
                &mut stream_for_ui.borrow_mut(),
                None,
                &[],
            );
        });
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .into_iter()
            .find(|node| node.value().as_deref() == Some("ios"))
            .expect("the REALITY combo shows the stored fingerprint")
            .click();
        harness.run();
        // The open popup's option rows are buttons; every row that names a
        // canonical fingerprint must be one of the trimmed options, and the
        // stored value itself is displayed, never offered.
        let rows = harness
            .root()
            .children_recursive()
            .filter(|node| node.accesskit_node().role() == egui::accesskit::Role::Button)
            .filter_map(|node| node.accesskit_node().label())
            .collect::<Vec<_>>();
        let default = t(Language::En, Key::SrvDefault);
        for &option in REALITY_EDITOR_OPTIONS {
            let label = if option.is_empty() { default } else { option };
            assert!(
                rows.iter().any(|row| row == label),
                "the REALITY popup must offer {option:?}"
            );
        }
        for &name in FINGERPRINTS {
            if name.is_empty() {
                continue;
            }
            assert!(
                !rows.iter().any(|row| row == name) || REALITY_EDITOR_OPTIONS.contains(&name),
                "the REALITY popup offers {name:?} outside the trimmed option set"
            );
        }
    }

    #[test]
    fn delete_glyph_is_renderable_by_the_default_fonts() {
        // The servers-list delete button is a bare "🗑"; if no loaded font had
        // the glyph it would paint as a blank/tofu box and look like there is
        // no delete button at all. (The previous "✕" U+2715 was missing from
        // every default font, which is exactly what made the button invisible.)
        let mut renderable = false;
        Harness::new_ui(|ui| {
            renderable = ui
                .ctx()
                .fonts_mut(|fonts| fonts.has_glyph(&egui::FontId::proportional(14.0), '🗑'));
        })
        .run();
        assert!(renderable, "🗑 (U+1F5D1) has no glyph in the default fonts");
    }

    #[test]
    fn status_toast_expires_exactly_at_the_auto_clear_window() {
        // The pure clear decision: a toast stays until the bounded window
        // elapses and disappears from that point on.
        let ttl = STATUS_TOAST_AUTO_CLEAR;
        let now = Instant::now();
        assert!(
            !status_toast_expired(now, now, ttl),
            "a just-set status must still render"
        );
        assert!(
            !status_toast_expired(now - Duration::from_secs(1), now, ttl),
            "a status inside the window must still render"
        );
        assert!(
            status_toast_expired(now - ttl, now, ttl),
            "the window boundary must clear the toast"
        );
        assert!(
            status_toast_expired(now - ttl - Duration::from_secs(60), now, ttl),
            "an old status must never render"
        );
    }

    #[test]
    fn status_toast_auto_clears_after_the_bounded_window() {
        // A status set on any action (error or success) disappears once the
        // auto-clear window elapses: the toast used to render forever after
        // the first status.
        let screen = Rc::new(RefCell::new(ServersScreen::default()));
        let screen_for_ui = Rc::clone(&screen);
        let mut harness = Harness::new_ui(move |ui| {
            screen_for_ui.borrow_mut().show_status_toast(ui.ctx());
        });
        screen.borrow_mut().set_status(StatusLine::ok("done"));
        harness.run();
        assert!(
            harness.query_by_label("done").is_some(),
            "a fresh status must render as a toast"
        );
        // Age the toast past the auto-clear window and run another frame:
        // the stale toast must be gone and the window render with it.
        screen.borrow_mut().status_set_at =
            Some(Instant::now() - STATUS_TOAST_AUTO_CLEAR - Duration::from_secs(1));
        harness.run();
        assert!(
            harness.query_by_label("done").is_none(),
            "an expired status must not render forever"
        );
        assert!(
            screen.borrow().status.is_none(),
            "the expired toast must be cleared, not just hidden"
        );
    }

    #[test]
    fn server_row_truncates_long_name_so_right_block_stays_clear() {
        let long_name = "tokyo-edge-01.example.com very long server name that used to overlap the latency badge and the delete button";
        let mut harness = Harness::builder()
            .with_size(egui::vec2(240.0, 100.0))
            .build_ui(|ui| {
                let badge = LatencyBadge::new(Some(12), Language::En, status_colors_of(ui));
                let _ = server_list_row(
                    ui,
                    Language::En,
                    long_name,
                    false,
                    false,
                    &badge,
                    RowProbeState {
                        enabled: true,
                        disabled_hint: "",
                    },
                );
            });
        harness.run();

        let name = harness.get_by_label(long_name);
        let latency = harness.get_by_label("12 ms");
        let probe = harness.get_by_label("⚡");
        let delete = harness.get_by_label("🗑");
        assert!(
            name.rect().max.x <= latency.rect().min.x,
            "long name overlaps the latency badge: name ends at x={}, latency starts at x={}",
            name.rect().max.x,
            latency.rect().min.x,
        );
        assert!(
            latency.rect().max.x <= probe.rect().min.x,
            "latency badge overlaps the probe button"
        );
        assert!(
            probe.rect().max.x <= delete.rect().min.x,
            "probe button overlaps the delete button"
        );
        assert!(
            delete.rect().max.x <= 240.0 + 0.5,
            "delete button is pushed outside the panel"
        );
    }

    /// Drive a `server_list_row` in a harness, click the node found by
    /// `click_label`, and return (did_any_row_widget_click, did_delete_click,
    /// did_probe_click).
    ///
    /// The flags accumulate over frames: kittest runs one frame per pointer
    /// event and egui may repaint afterwards, so reading only the last frame
    /// would miss the click.
    fn drive_row_click(click_label: &str) -> (bool, bool, bool) {
        let clicked = Rc::new(RefCell::new((false, false, false)));
        let clicked_ui = Rc::clone(&clicked);
        let mut harness = Harness::new_ui(move |ui| {
            let badge = LatencyBadge::new(Some(12), Language::En, status_colors_of(ui));
            let clicks = server_list_row(
                ui,
                Language::En,
                "A server",
                false,
                false,
                &badge,
                RowProbeState {
                    enabled: true,
                    disabled_hint: "",
                },
            );
            let mut c = clicked_ui.borrow_mut();
            c.0 |= clicks.row.clicked() || clicks.name.clicked();
            c.1 |= clicks.delete;
            c.2 |= clicks.probe;
        });
        harness.get_by_label(click_label).click();
        harness.run();
        let c = clicked.borrow();
        (c.0, c.1, c.2)
    }

    #[test]
    fn server_row_clicking_delete_does_not_select_the_row() {
        // Clicking "🗑" must delete, never select: the delete click wins because
        // the row's click target is registered before the button.
        let (row_clicked, delete_clicked, probe_clicked) = drive_row_click("🗑");
        assert!(delete_clicked, "delete button click did not register");
        assert!(
            !row_clicked,
            "clicking the delete button also selected the row"
        );
        assert!(!probe_clicked, "clicking the delete button also probed");
    }

    #[test]
    fn server_row_clicking_the_row_selects_it() {
        // Clicking the latency badge area (part of the row but not a widget
        // that senses clicks) must select the row.
        let (row_clicked, delete_clicked, probe_clicked) = drive_row_click("12 ms");
        assert!(row_clicked, "clicking the row did not register as select");
        assert!(!delete_clicked);
        assert!(!probe_clicked);
    }

    #[test]
    fn server_row_clicking_the_name_selects_it() {
        // The name button fills the row (it truncates to the remaining width),
        // so clicking it must count as selecting the row.
        let (row_clicked, delete_clicked, probe_clicked) = drive_row_click("A server");
        assert!(row_clicked, "clicking the name did not register as select");
        assert!(!delete_clicked);
        assert!(!probe_clicked);
    }

    #[test]
    fn server_row_clicking_probe_does_not_select_the_row() {
        // Clicking "⚡" must probe, never select or delete: the probe click
        // wins because the row's click target is registered before the button.
        let (row_clicked, delete_clicked, probe_clicked) = drive_row_click("⚡");
        assert!(probe_clicked, "probe button click did not register");
        assert!(
            !row_clicked,
            "clicking the probe button also selected the row"
        );
        assert!(!delete_clicked, "clicking the probe button also deleted");
    }

    #[test]
    fn server_row_disabled_probe_button_does_not_fire() {
        // A probe button behind the one-probe-at-a-time gate must not fire.
        let clicked = Rc::new(RefCell::new(false));
        let clicked_ui = Rc::clone(&clicked);
        let mut harness = Harness::new_ui(move |ui| {
            let badge = LatencyBadge::new(Some(12), Language::En, status_colors_of(ui));
            let clicks = server_list_row(
                ui,
                Language::En,
                "A server",
                false,
                false,
                &badge,
                RowProbeState {
                    enabled: false,
                    disabled_hint: "busy",
                },
            );
            *clicked_ui.borrow_mut() |= clicks.probe;
        });
        harness.get_by_label("⚡").click();
        harness.run();
        assert!(
            !*clicked.borrow(),
            "a probe button behind the gate must not fire"
        );
    }

    // ---------- list drag-reorder ----------

    /// The list's profile names in order, for order assertions.
    fn profile_names(rig: &UiTestRig) -> Vec<&str> {
        rig.servers
            .profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect()
    }

    /// A three-profile rig, all rows visible, in list order
    /// Alpha → Bravo → Charlie.
    fn drag_rig() -> UiTestRig {
        let mut rig = UiTestRig::default();
        for name in ["Alpha", "Bravo", "Charlie"] {
            rig.servers.profiles.push(ServerProfile::new(
                name,
                OutboundModel::new(Protocol::Freedom),
            ));
        }
        rig
    }

    fn drag_harness(rig: UiTestRig) -> Harness<'static, (ServersScreen, UiTestRig)> {
        Harness::new_ui_state(
            |ui, state: &mut (ServersScreen, UiTestRig)| {
                state.0.show(ui, &mut state.1.ctx());
            },
            (ServersScreen::default(), rig),
        )
    }

    /// Press `from` and move past egui's click threshold, leaving a row drag
    /// in flight at the pointer.
    fn begin_row_drag(
        harness: &mut Harness<'static, (ServersScreen, UiTestRig)>,
        from: egui::Pos2,
    ) {
        harness.hover_at(from);
        harness.step();
        harness.drag_at(from);
        harness.step();
        harness.hover_at(from + egui::vec2(0.0, 8.0));
        harness.step();
    }

    /// Run one row drag through the harness: press the source, then hover the
    /// drop point and release there. `step` (not `run`) keeps every frame of
    /// the gesture explicit: the press frame seeds the hit test, the move
    /// frame starts the drag, and the release frame drops it.
    fn drag_list_row(
        harness: &mut Harness<'static, (ServersScreen, UiTestRig)>,
        from: egui::Pos2,
        to: egui::Pos2,
    ) {
        begin_row_drag(harness, from);
        harness.hover_at(to);
        harness.step();
        harness.drop_at(to);
        harness.step();
    }

    #[test]
    fn reorder_target_lifts_the_row_out_before_inserting_it() {
        // The two gaps adjacent to the dragged row's own slot are no-ops.
        assert_eq!(reorder_target(0, 0), 0);
        assert_eq!(reorder_target(0, 1), 0);
        assert_eq!(reorder_target(5, 5), 5);
        assert_eq!(reorder_target(5, 6), 5);
        // A gap past the slot shifts down one once the row is removed.
        assert_eq!(reorder_target(0, 3), 2);
        assert_eq!(reorder_target(2, 0), 0);
        assert_eq!(reorder_target(2, 5), 4);
    }

    #[test]
    fn drag_scroll_speeds_up_toward_the_viewport_edges_and_is_inert_elsewhere() {
        let viewport = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(200.0, 300.0));
        let dt = 0.1;
        // Inert outside the viewport and in its middle.
        assert_eq!(
            drag_scroll_delta(viewport, egui::pos2(-1.0, 150.0), dt),
            0.0
        );
        assert_eq!(
            drag_scroll_delta(viewport, egui::pos2(100.0, 150.0), dt),
            0.0
        );
        // Near the top edge the delta scrolls toward the top (positive);
        // near the bottom edge it scrolls down (negative); both ramp up.
        let near_top = drag_scroll_delta(viewport, egui::pos2(100.0, 8.0), dt);
        let at_top = drag_scroll_delta(viewport, egui::pos2(100.0, 0.0), dt);
        assert!(
            near_top > 0.0 && near_top < at_top,
            "the top band must ramp: {near_top} vs {at_top}"
        );
        assert!((at_top - DRAG_SCROLL_MAX_SPEED * dt).abs() < 1e-3);
        let near_bottom = drag_scroll_delta(viewport, egui::pos2(100.0, 292.0), dt);
        let at_bottom = drag_scroll_delta(viewport, egui::pos2(100.0, 300.0), dt);
        assert!(
            near_bottom < 0.0 && near_bottom > at_bottom,
            "the bottom band must ramp: {near_bottom} vs {at_bottom}"
        );
        assert!((at_bottom + DRAG_SCROLL_MAX_SPEED * dt).abs() < 1e-3);
    }

    #[test]
    fn dragging_a_row_to_the_tail_moves_it_and_marks_the_model_dirty() {
        let mut harness = drag_harness(drag_rig());
        harness.run();
        let selected_before = harness.state().0.selected.clone();
        // The drag targets a row that is not the selected one, so the
        // selection assertion below can fail.
        let bravo_id = harness
            .state()
            .1
            .servers
            .profiles
            .iter()
            .find(|profile| profile.name == "Bravo")
            .expect("the rig lists Bravo")
            .id
            .clone();
        assert_ne!(
            selected_before.as_deref(),
            Some(bravo_id.as_str()),
            "the dragged row must not be the selected one"
        );
        let bravo = harness.get_by_label("Bravo").rect();
        let charlie = harness.get_by_label("Charlie").rect();
        // Below the last row: the drop lands at the list's end.
        drag_list_row(
            &mut harness,
            bravo.center(),
            egui::pos2(charlie.center().x, charlie.bottom() + 8.0),
        );
        assert_eq!(
            profile_names(&harness.state().1),
            ["Alpha", "Charlie", "Bravo"]
        );
        assert!(
            harness.state().1.dirty,
            "a reorder must mark the model dirty"
        );
        assert!(
            harness.state().0.list_drag.is_none(),
            "the release must end the drag"
        );
        assert_eq!(
            harness.state().0.selected,
            selected_before,
            "a drag must not change the selection"
        );
    }

    #[test]
    fn dragging_the_last_row_above_the_first_inserts_before_it_and_activates_it() {
        let mut harness = drag_harness(drag_rig());
        harness.run();
        let alpha = harness.get_by_label("Alpha").rect();
        let charlie = harness.get_by_label("Charlie").rect();
        // On the first row's upper half: the drop lands before it.
        drag_list_row(
            &mut harness,
            charlie.center(),
            egui::pos2(alpha.center().x, alpha.top() + 2.0),
        );
        assert_eq!(
            profile_names(&harness.state().1),
            ["Charlie", "Alpha", "Bravo"]
        );
        assert!(harness.state().1.dirty);
        // The first slot is the default server — the config's first outbound,
        // Xray's default route — so the dragged row takes it.
        let rig = &harness.state().1;
        assert_eq!(
            rig.servers.active.as_deref(),
            Some(rig.servers.profiles[0].id.as_str()),
            "the top row must be the active (default) server"
        );
    }

    #[test]
    fn dragging_the_default_row_down_hands_the_default_to_the_new_top_row() {
        let mut harness = drag_harness(drag_rig());
        harness.run();
        let alpha = harness.get_by_label("Alpha").rect();
        let charlie = harness.get_by_label("Charlie").rect();
        let tags_before: Vec<String> = harness
            .state()
            .1
            .servers
            .profiles
            .iter()
            .map(ServerProfile::tag)
            .collect();
        // Below the last row: the leading row lands at the list's end.
        drag_list_row(
            &mut harness,
            alpha.center(),
            egui::pos2(charlie.center().x, charlie.bottom() + 8.0),
        );
        let rig = &harness.state().1;
        assert_eq!(profile_names(rig), ["Bravo", "Charlie", "Alpha"]);
        assert_eq!(
            rig.servers.active.as_deref(),
            Some(rig.servers.profiles[0].id.as_str()),
            "the new top row is the default server"
        );
        assert_eq!(rig.servers.profiles[0].name, "Bravo");
        // ... and the config follows: the emitted outbounds lead with the new
        // top row, so Xray's default route moved with the drop.
        let config = crate::r#gen::generate_with_api_port(&rig.servers, &rig.settings, 10853)
            .expect("generate config");
        let emitted: Vec<&str> = config["outbounds"]
            .as_array()
            .expect("outbounds is an array")
            .iter()
            .take(3)
            .filter_map(|outbound| outbound["tag"].as_str())
            .collect();
        assert_eq!(
            emitted,
            [
                tags_before[1].as_str(),
                tags_before[2].as_str(),
                tags_before[0].as_str()
            ]
        );
    }

    #[test]
    fn set_active_moves_the_chosen_row_to_the_front() {
        let mut harness = drag_harness(drag_rig());
        harness.run();
        harness.get_by_label("Charlie").click_secondary();
        harness.step();
        harness
            .get_by_label(t(Language::En, Key::SrvSetActive))
            .click();
        harness.run();
        let rig = &harness.state().1;
        assert_eq!(
            profile_names(rig),
            ["Charlie", "Alpha", "Bravo"],
            "the chosen default server leads the list"
        );
        assert_eq!(
            rig.servers.active.as_deref(),
            Some(rig.servers.profiles[0].id.as_str())
        );
        assert!(rig.dirty);
    }

    #[test]
    fn sorting_by_latency_keeps_the_default_server_in_its_slot() {
        let mut rig = drag_rig();
        rig.servers.active = Some(rig.servers.profiles[0].id.clone());
        // The default server is the slowest, so a whole-list sort would move
        // it off the first slot and silently change the default route.
        rig.servers.profiles[0].latency_ms = Some(300);
        rig.servers.profiles[1].latency_ms = Some(40);
        rig.servers.profiles[2].latency_ms = Some(20);
        let mut harness = drag_harness(rig);
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvSortByLatency))
            .click();
        harness.run();
        let rig = &harness.state().1;
        assert_eq!(
            profile_names(rig),
            ["Alpha", "Charlie", "Bravo"],
            "the default row keeps the first slot; the rest sort by latency"
        );
        assert_eq!(
            rig.servers.active.as_deref(),
            Some(rig.servers.profiles[0].id.as_str())
        );
    }

    #[test]
    fn releasing_a_drag_away_from_the_list_keeps_the_order_and_the_model_clean() {
        let mut harness = drag_harness(drag_rig());
        harness.run();
        let alpha = harness.get_by_label("Alpha").rect();
        // The editor fills the window right of the list panel.
        drag_list_row(
            &mut harness,
            alpha.center(),
            egui::pos2(600.0, alpha.center().y),
        );
        assert_eq!(
            profile_names(&harness.state().1),
            ["Alpha", "Bravo", "Charlie"]
        );
        assert!(
            !harness.state().1.dirty,
            "a cancelled drag must not mark the model dirty"
        );
        assert!(
            harness.state().0.list_drag.is_none(),
            "the release must end the drag even when it cancels"
        );
    }

    #[test]
    fn holding_a_drag_at_the_lists_bottom_edge_auto_scrolls_and_drops_in_order() {
        let (rig, _ids) = seeded_rig(40);
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 600.0))
            .build_ui_state(
                |ui, state: &mut (ServersScreen, UiTestRig)| {
                    state.0.show(ui, &mut state.1.ctx());
                },
                (ServersScreen::default(), rig),
            );
        harness.run();
        let band = laid_out_list_rows(&harness) as usize;
        assert!(band < 40, "the list must be longer than the visible band");
        let first = harness.get_by_label("Server 00").rect();
        begin_row_drag(&mut harness, first.center());
        // Sweep the pointer toward the window's bottom edge while the drag is
        // held: the sweep crosses the viewport's bottom edge band — wherever
        // the harness' layout puts it — and the list must scroll the first
        // band out of view.
        let mut scrolled = false;
        let mut y = first.center().y;
        while !scrolled && y < 590.0 {
            y += 4.0;
            harness.hover_at(egui::pos2(first.center().x, y));
            harness.step();
            harness.step();
            scrolled = harness.query_by_label("Server 00").is_none();
        }
        assert!(
            scrolled,
            "holding the drag at the bottom edge must scroll the first band out of view"
        );
        // Keep scrolling a moment longer, then drop onto the middle row of
        // the scrolled band (clear of both edge bands). Its list index — read
        // off its own name — is the index the lifted row must land at, so the
        // resulting order is exact and no gap mis-mapping survives it.
        harness.run_steps(20);
        let band = laid_out_list_rows(&harness) as usize;
        let top_index = (1..40)
            .find(|index| {
                harness
                    .query_by_label(&format!("Server {index:02}"))
                    .is_some()
            })
            .expect("the scrolled band must still show rows");
        let target_index = top_index + band / 2;
        let target = harness
            .get_by_label(&format!("Server {target_index:02}"))
            .rect();
        let drop_pos = egui::pos2(target.center().x, target.center().y + 2.0);
        harness.hover_at(drop_pos);
        harness.step();
        harness.drop_at(drop_pos);
        harness.step();
        assert!(
            harness.state().0.list_drag.is_none(),
            "the release must end the drag"
        );
        assert!(
            harness.state().1.dirty,
            "the drop after an auto-scroll must still move the row"
        );
        let names = profile_names(&harness.state().1);
        let expected: Vec<String> = (0..names.len())
            .map(|index| {
                format!(
                    "Server {:02}",
                    match index.cmp(&target_index) {
                        std::cmp::Ordering::Less => index + 1,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => index,
                    }
                )
            })
            .collect();
        assert_eq!(
            names, expected,
            "the lifted row must land exactly at the scrolled drop gap"
        );
    }

    #[test]
    fn row_probe_button_requests_one_profile_and_shows_dedicated_feedback() {
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        let mut harness = Harness::new_ui_state(
            |ui, state: &mut (ServersScreen, UiTestRig)| {
                state.0.show(ui, &mut state.1.ctx());
            },
            (ServersScreen::default(), rig),
        );
        harness
            .get_all_by_label("⚡")
            .next()
            .expect("each row must render a probe button")
            .click();
        // `click` only queues events, and the pending flag is set at the end
        // of the frame that processes them, so the spinner needs one more
        // frame to appear. The spinner repaints forever, so `run` would never
        // settle — advance the frames by hand.
        harness.run_steps(2);

        // The row click sends exactly the first profile, tagged as single.
        let tag = {
            let cmd = harness
                .state_mut()
                .1
                ._cmd_rx
                .try_recv()
                .expect("a row probe must send a command");
            if let CoreCmd::ProbeLatency { profiles, .. } = cmd {
                assert_eq!(
                    profiles.len(),
                    1,
                    "a row probe must send exactly one profile"
                );
                profiles[0].tag()
            } else {
                panic!("expected ProbeLatency, got a different command");
            }
        };
        assert_eq!(
            tag,
            tokyo.tag(),
            "the first row must probe the first profile"
        );
        assert_eq!(
            harness.state().0.pending_latency_probe,
            Some(true),
            "the pending slot must record a single-scope probe"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvTestingLatencyIsolated))
                .is_some(),
            "a pending probe must render the spinner label"
        );

        // The toolbar button shares the gate: while a probe is pending it must
        // not send a second request.
        harness
            .get_by_label(t(Language::En, Key::TestLatency))
            .click();
        harness.step();
        assert!(
            harness.state_mut().1._cmd_rx.try_recv().is_err(),
            "the toolbar probe must be blocked while a probe is pending"
        );

        // Consuming the probe slot renders the dedicated copy (the rig's
        // probe-feedback slot mirrors the app drain's park).
        harness
            .state_mut()
            .1
            .probe_feedback
            .park(LatencyProbeResult {
                tags: vec![tag.clone()],
                result: Ok(vec![OutboundStatusView {
                    health_ping: None,
                    tag,
                    alive: true,
                    delay_ms: 23,
                    last_error: None,
                    diagnostics: None,
                }]),
            });
        harness.run();
        assert!(
            harness
                .query_by_label("Server 'Tokyo' responded in 23 ms.")
                .is_some(),
            "a single-probe result must render the dedicated name-based toast"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvTestingLatencyIsolated))
                .is_none(),
            "the spinner must clear once the result is consumed"
        );
    }

    #[test]
    fn row_probe_button_includes_chain_dependencies_in_the_child() {
        // A profile chaining via sockopt.dialerProxy references another
        // profile's outbound tag; the isolated probe child must contain the
        // whole chain or the core refuses to start.
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        tokyo.outbound.chain_via(osaka.tag());
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        let mut harness = Harness::new_ui_state(
            |ui, state: &mut (ServersScreen, UiTestRig)| {
                state.0.show(ui, &mut state.1.ctx());
            },
            (ServersScreen::default(), rig),
        );
        harness
            .get_all_by_label("⚡")
            .next()
            .expect("each row must render a probe button")
            .click();
        harness.run_steps(2);

        {
            let cmd = harness
                .state_mut()
                .1
                ._cmd_rx
                .try_recv()
                .expect("a row probe must send a command");
            if let CoreCmd::ProbeLatency { profiles, .. } = cmd {
                let tags: Vec<String> = profiles.iter().map(ServerProfile::tag).collect();
                assert_eq!(
                    tags,
                    vec![tokyo.tag(), osaka.tag()],
                    "the chain dependency must ride along, probed profile first"
                );
            } else {
                panic!("expected ProbeLatency, got a different command");
            }
        };

        // The child reports the chain dependency's status too; the toast must
        // still name and use the requested server's status.
        harness
            .state_mut()
            .1
            .probe_feedback
            .park(LatencyProbeResult {
                tags: vec![tokyo.tag()],
                result: Ok(vec![
                    OutboundStatusView {
                        health_ping: None,
                        tag: osaka.tag(),
                        alive: true,
                        delay_ms: 5,
                        last_error: None,
                        diagnostics: None,
                    },
                    OutboundStatusView {
                        health_ping: None,
                        tag: tokyo.tag(),
                        alive: true,
                        delay_ms: 23,
                        last_error: None,
                        diagnostics: None,
                    },
                ]),
            });
        harness.run();
        assert!(
            harness
                .query_by_label("Server 'Tokyo' responded in 23 ms.")
                .is_some(),
            "the chain dependency's status must not shadow the requested server's"
        );
    }

    #[test]
    fn toolbar_probe_requests_all_profiles_and_shows_count_feedback() {
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        let mut harness = Harness::new_ui_state(
            |ui, state: &mut (ServersScreen, UiTestRig)| {
                state.0.show(ui, &mut state.1.ctx());
            },
            (ServersScreen::default(), rig),
        );
        harness
            .get_by_label(t(Language::En, Key::TestLatency))
            .click();
        harness.step();

        {
            let cmd = harness
                .state_mut()
                .1
                ._cmd_rx
                .try_recv()
                .expect("the toolbar probe must send a command");
            if let CoreCmd::ProbeLatency { profiles, .. } = cmd {
                assert_eq!(
                    profiles.len(),
                    2,
                    "the toolbar probe must send every profile"
                );
            } else {
                panic!("expected ProbeLatency, got a different command");
            }
        };
        assert_eq!(
            harness.state().0.pending_latency_probe,
            Some(false),
            "the pending slot must record an all-scope probe"
        );

        harness
            .state_mut()
            .1
            .probe_feedback
            .park(LatencyProbeResult {
                tags: vec![tokyo.tag(), osaka.tag()],
                result: Ok(vec![
                    OutboundStatusView {
                        health_ping: None,
                        tag: tokyo.tag(),
                        alive: true,
                        delay_ms: 10,
                        last_error: None,
                        diagnostics: None,
                    },
                    OutboundStatusView {
                        health_ping: None,
                        tag: osaka.tag(),
                        alive: true,
                        delay_ms: 20,
                        last_error: None,
                        diagnostics: None,
                    },
                ]),
            });
        harness.run();
        assert!(
            harness
                .query_by_label("Latency test complete for 2 outbound(s).")
                .is_some(),
            "an all-scope result must render the count-based toast"
        );
    }
    #[test]
    fn toolbar_probe_with_dead_verdicts_renders_warn_summary() {
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Vless));
        let ProtocolSettings::Vless(settings) = &mut tokyo.outbound.settings else {
            unreachable!("Vless is the default protocol");
        };
        settings.address = "1.2.3.4".into();
        settings.port = 443;
        let osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        let mut harness = Harness::new_ui_state(
            |ui, state: &mut (ServersScreen, UiTestRig)| {
                state.0.show(ui, &mut state.1.ctx());
            },
            (ServersScreen::default(), rig),
        );
        harness
            .get_by_label(t(Language::En, Key::TestLatency))
            .click();
        harness.step();

        {
            let cmd = harness
                .state_mut()
                .1
                ._cmd_rx
                .try_recv()
                .expect("the toolbar probe must send a command");
            assert!(
                matches!(cmd, CoreCmd::ProbeLatency { .. }),
                "expected ProbeLatency, got a different command"
            );
        }
        harness
            .state_mut()
            .1
            .probe_feedback
            .park(LatencyProbeResult {
                tags: vec![tokyo.tag(), osaka.tag()],
                result: Ok(vec![
                    OutboundStatusView {
                        health_ping: None,
                        tag: tokyo.tag(),
                        alive: false,
                        delay_ms: 0,
                        last_error: Some("refused".into()),
                        diagnostics: None,
                    },
                    OutboundStatusView {
                        health_ping: None,
                        tag: osaka.tag(),
                        alive: true,
                        delay_ms: 15,
                        last_error: None,
                        diagnostics: None,
                    },
                ]),
            });
        harness.run();

        let expected = "1 of 2 outbounds responded.\n\
                        Server 'Tokyo' (1.2.3.4:443) did not respond: refused.";
        assert!(
            harness.query_by_label(expected).is_some(),
            "a probe-all result with a dead verdict must render the warn summary naming the server"
        );
        assert_eq!(
            harness.state().0.latency_probe_feedback,
            Some((FeedbackLevel::Warn, expected.to_string())),
            "the consumed verdict must carry the warn level for the render site"
        );
    }

    #[test]
    fn ech_sockopt_mouse_toggle_adds_and_removes_the_typed_model() {
        let sockopt = Rc::new(RefCell::new(None::<SockoptModel>));
        let sockopt_for_ui = Rc::clone(&sockopt);
        let mut harness = Harness::new_ui(move |ui| {
            let _ = ech_sockopt_editor(ui, Language::En, &mut sockopt_for_ui.borrow_mut(), &[]);
        });

        harness.get_by_label("ECH DNS-query socket options").click();
        harness.run();
        assert!(sockopt.borrow().is_some());

        harness.get_by_label("ECH DNS-query socket options").click();
        harness.run();
        assert!(sockopt.borrow().is_none());
    }

    #[test]
    fn ech_sockopt_helper_preserves_extensions_and_reports_malformed_values() {
        let custom = CustomSockopt {
            r#type: "bytes".into(),
            ..Default::default()
        };
        let modeled = SockoptModel {
            domain_strategy: "future-strategy".into(),
            tcp_fast_open: Some(json!("not bool or number")),
            tcp_keep_alive_idle: Some(-1),
            tcp_keep_alive_interval: Some(30),
            custom_sockopt: vec![custom],
            extra: serde_json::Map::from_iter([("futureSocketOption".into(), json!([1, 2]))]),
            ..Default::default()
        };
        let before = serde_json::to_value(&modeled).unwrap();
        let findings = sockopt_findings(&modeled, SockoptUsage::Stream);
        assert_eq!(
            codes_of(&findings),
            vec![
                ValidationCode::SockoptDomainStrategyInvalid,
                ValidationCode::SockoptTcpFastOpenType,
                ValidationCode::SockoptKeepaliveSigns,
                ValidationCode::SockoptCustomOptRequired,
                ValidationCode::SockoptCustomTypeInvalid,
            ],
            "{findings:#?}"
        );
        assert_eq!(
            findings
                .iter()
                .map(|issue| issue.path.as_deref())
                .collect::<Vec<_>>(),
            vec![
                Some("stream.sockopt.domainStrategy"),
                Some("stream.sockopt.tcpFastOpen"),
                Some("stream.sockopt.tcpKeepAliveIdle"),
                Some("stream.sockopt.customSockopt"),
                Some("stream.sockopt.customSockopt"),
            ],
        );

        let rendered = Rc::new(RefCell::new(Some(modeled)));
        let rendered_for_ui = Rc::clone(&rendered);
        let mut reported_changed = false;
        {
            let _harness = Harness::new_ui(|ui| {
                reported_changed |=
                    ech_sockopt_editor(ui, Language::En, &mut rendered_for_ui.borrow_mut(), &[]);
            });
        }
        assert!(!reported_changed);
        assert_eq!(
            serde_json::to_value(rendered.borrow().as_ref().unwrap()).unwrap(),
            before
        );
    }

    #[test]
    fn ech_sockopt_accepts_fractional_tcp_fast_open_like_xray_socket_config() {
        let modeled = SockoptModel {
            tcp_fast_open: Some(json!(12.75)),
            ..Default::default()
        };
        assert!(sockopt_findings(&modeled, SockoptUsage::Stream).is_empty());

        let rendered = Rc::new(RefCell::new(Some(modeled)));
        let rendered_for_ui = Rc::clone(&rendered);
        let mut reported_changed = false;
        {
            let _harness = Harness::new_ui(|ui| {
                reported_changed |=
                    ech_sockopt_editor(ui, Language::En, &mut rendered_for_ui.borrow_mut(), &[]);
            });
        }
        assert!(!reported_changed);
        assert_eq!(
            rendered.borrow().as_ref().unwrap().tcp_fast_open,
            Some(json!(12.75))
        );
    }

    #[test]
    fn sockopt_verdicts_are_scoped_to_the_usage_s_wire_path() {
        let modeled = SockoptModel {
            domain_strategy: "future-strategy".into(),
            ..Default::default()
        };
        let stream_findings = sockopt_findings(&modeled, SockoptUsage::Stream);
        assert_eq!(
            finding(
                &stream_findings,
                ValidationCode::SockoptDomainStrategyInvalid
            )
            .path
            .as_deref(),
            Some("stream.sockopt.domainStrategy"),
            "{stream_findings:#?}"
        );
        let ech_findings = sockopt_findings(&modeled, SockoptUsage::EchDnsQuery);
        assert_eq!(
            finding(&ech_findings, ValidationCode::SockoptDomainStrategyInvalid)
                .path
                .as_deref(),
            Some("stream.tlsSettings.echSockopt.domainStrategy"),
            "an ECH sockopt finding must name its own wire path: {ech_findings:#?}"
        );
        // The block paints exactly the memoized slice it is handed — the
        // corrected ECH path included, with no re-validation of its own.
        // The viewport is tall enough to keep the block's verdict lines on
        // screen for the harness.
        let mut rendered = Some(modeled);
        let messages: Vec<String> = ech_findings
            .iter()
            .map(|issue| validation_issue_message(issue, Language::En))
            .collect();
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 1200.0))
            .build_ui(|ui| {
                let _ = ech_sockopt_editor(ui, Language::En, &mut rendered, &messages);
            });
        harness.run();
        for message in &messages {
            assert!(
                harness.query_by_label(message.as_str()).is_some(),
                "the ECH block must render the verdict it is handed: {message:?}"
            );
        }
    }

    #[test]
    fn changing_import_source_invalidates_the_parsed_snapshot() {
        let mut screen = ServersScreen {
            import_text: "vless://first".into(),
            import_parsed: vec![Ok(ServerProfile::default())],
            import_parsed_source: Some("vless://first".into()),
            ..Default::default()
        };
        assert!(screen.import_preview_is_current());

        screen.import_text = "vless://second".into();
        assert!(!screen.import_preview_is_current());
        screen.invalidate_import_preview();
        assert!(screen.import_parsed.is_empty());
        assert!(screen.import_parsed_source.is_none());
    }

    #[test]
    fn invalid_new_server_draft_cannot_commit() {
        let invalid = ServerProfile::new("incomplete", OutboundModel::new(Protocol::Vless));
        assert!(
            !editor_validation_findings(&invalid).blocking.is_empty(),
            "a fresh VLESS draft must not be committable"
        );

        let valid = ServerProfile::new("direct", OutboundModel::new(Protocol::Freedom));
        let findings = editor_validation_findings(&valid);
        assert!(findings.blocking.is_empty());
        assert!(findings.advisory.is_empty());
    }

    /// One-channel regression guard:
    /// the UI-only pushes for VLESS/VMess port 0 and non-UUID ids were
    /// deleted — the model code + i18n key is the single message for those
    /// values. A re-introduced UI push would double-report the same value.
    #[test]
    fn port_zero_and_non_uuid_id_report_once_through_the_model_channel() {
        let mut profile = ServerProfile::new("vless", OutboundModel::new(Protocol::Vless));
        {
            let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
                unreachable!()
            };
            settings.address = "1.2.3.4".into();
            settings.port = 0;
            settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
            settings.encryption = "none".into();
        }
        let blocking = editor_validation_findings(&profile).blocking;
        assert_eq!(
            blocking
                .iter()
                .filter(|issue| issue.code == ValidationCode::SettingsPortZero)
                .count(),
            1,
            "port 0 must surface exactly one finding: {blocking:#?}"
        );
        assert_eq!(
            finding(&blocking, ValidationCode::SettingsPortZero)
                .path
                .as_deref(),
            Some("settings.port"),
        );
        assert!(
            !blocking
                .iter()
                .any(|issue| issue.code == ValidationCode::ServerPortRequired),
            "the deleted draft push must not be the channel: {blocking:#?}"
        );

        {
            let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
                unreachable!()
            };
            settings.port = 443;
            settings.id = "some-short-account".into();
        }
        let blocking = editor_validation_findings(&profile).blocking;
        assert_eq!(
            blocking
                .iter()
                .filter(|issue| issue.code == ValidationCode::SettingsIdNotUuid)
                .count(),
            1,
            "a non-UUID id must surface exactly one finding: {blocking:#?}"
        );
        let duplicate_id = finding(&blocking, ValidationCode::SettingsIdNotUuid);
        assert_eq!(duplicate_id.path.as_deref(), Some("settings.id"));
        assert!(
            validation_issue_message(&duplicate_id, Language::En).contains("canonical UUID"),
            "the message must name the constraint it enforces"
        );
    }

    /// One-channel guard for the VLESS encryption shape: a stored
    /// all-short-key value reports exactly one error line, and that line is
    /// the model's message naming the real constraint. The field-level
    /// format check (`v_vless_encryption`) stays a tool-output guard.
    #[test]
    fn short_vless_encryption_key_reports_the_model_message_once() {
        let mut profile = ServerProfile::new("vless", OutboundModel::new(Protocol::Vless));
        {
            let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
                unreachable!()
            };
            settings.address = "1.2.3.4".into();
            settings.port = 443;
            settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
            settings.encryption = "mlkem768x25519plus.native.1rtt.key".into();
        }
        let findings = editor_validation_findings(&profile);
        assert!(findings.advisory.is_empty(), "{:#?}", findings.advisory);
        assert_eq!(findings.blocking.len(), 1, "{:#?}", findings.blocking);
        let encryption = finding(
            &findings.blocking,
            ValidationCode::VlessEncryptionUnsupported,
        );
        assert_eq!(encryption.path.as_deref(), Some("settings.encryption"));
        let message = validation_issue_message(&encryption, Language::En);
        assert!(
            message.contains("at least one full key part"),
            "the message must name the real constraint: {message:?}"
        );
        assert!(
            message.contains("Padding parts come before the first key part"),
            "the message must explain where padding belongs: {message:?}"
        );
    }

    /// One-channel regression guard:
    /// the UI-only error-list pushes and keystroke validators for the
    /// TLS/REALITY security formats (fingerprints, publicKey, shortId,
    /// spiderX, mldsa65Verify, pinnedPeerCertSha256) were deleted — each of
    /// those values now surfaces exactly one line through the model pass
    /// (validate_outbound), and the TLS version-string rule warns in the
    /// advisory half instead of blocking.
    #[test]
    fn tls_reality_formats_report_once_through_the_model_channel() {
        fn base_profile() -> ServerProfile {
            let mut profile = ServerProfile::new("sec", OutboundModel::new(Protocol::Vless));
            let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
                unreachable!()
            };
            settings.address = "example.com".into();
            settings.port = 443;
            settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
            settings.encryption = "none".into();
            profile
        }
        // TLS block: an out-of-vocab fingerprint is one error line carrying
        // the wire path — a re-introduced UI push would double it.
        let mut profile = base_profile();
        let _ = profile.outbound.stream.select_security(Security::Tls);
        profile
            .outbound
            .stream
            .tls_settings
            .as_mut()
            .unwrap()
            .fingerprint = "bogus".into();
        let blocking = editor_validation_findings(&profile).blocking;
        assert_eq!(
            blocking
                .iter()
                .filter(|issue| issue.code == ValidationCode::TlsFingerprintUnsupported)
                .count(),
            1,
            "an out-of-vocab TLS fingerprint must surface exactly one finding: {blocking:#?}"
        );
        assert_eq!(
            finding(&blocking, ValidationCode::TlsFingerprintUnsupported)
                .path
                .as_deref(),
            Some("stream.tlsSettings.fingerprint"),
        );

        // Malformed cert pins: one line, on the pinnedPeerCertSha256 path.
        profile
            .outbound
            .stream
            .tls_settings
            .as_mut()
            .unwrap()
            .fingerprint = "chrome".into();
        profile
            .outbound
            .stream
            .tls_settings
            .as_mut()
            .unwrap()
            .pinned_peer_cert_sha256 = "zz".into();
        let blocking = editor_validation_findings(&profile).blocking;
        assert_eq!(
            blocking
                .iter()
                .filter(|issue| issue.code == ValidationCode::PinnedPeerCertSha256Invalid)
                .count(),
            1,
            "a malformed pin must surface exactly one finding: {blocking:#?}"
        );
        assert_eq!(
            finding(&blocking, ValidationCode::PinnedPeerCertSha256Invalid)
                .path
                .as_deref(),
            Some("stream.tlsSettings.pinnedPeerCertSha256"),
        );

        // Version strings outside {1.0..1.3} warn once per field and never
        // join the blocking list; in-range values stay silent.
        profile
            .outbound
            .stream
            .tls_settings
            .as_mut()
            .unwrap()
            .pinned_peer_cert_sha256 = String::new();
        profile
            .outbound
            .stream
            .tls_settings
            .as_mut()
            .unwrap()
            .min_version = "1.4".into();
        let findings = editor_validation_findings(&profile);
        assert!(
            findings.blocking.is_empty(),
            "a version warning must not block: {:#?}",
            findings.blocking
        );
        assert_eq!(
            findings
                .advisory
                .iter()
                .filter(|issue| issue.code == ValidationCode::TlsVersionRangeInvalid)
                .count(),
            1,
            "an out-of-range minVersion must warn exactly once: {:#?}",
            findings.advisory
        );
        assert_eq!(
            finding(&findings.advisory, ValidationCode::TlsVersionRangeInvalid)
                .path
                .as_deref(),
            Some("stream.tlsSettings.minVersion"),
        );

        // REALITY block: each malformed value is one error line with its
        // wire path (the other fields stay canonical so nothing else fires).
        for (field, value, code, path) in [
            (
                "fingerprint",
                "unsafe",
                ValidationCode::RealityFingerprintUnsupported,
                "stream.realitySettings.fingerprint",
            ),
            (
                "password",
                "AAA",
                ValidationCode::RealityPublicKeyInvalid,
                "stream.realitySettings.publicKey",
            ),
            (
                "short_id",
                "abc",
                ValidationCode::RealityShortIdInvalid,
                "stream.realitySettings.shortId",
            ),
            (
                "spider_x",
                "relative",
                ValidationCode::RealitySpiderXInvalid,
                "stream.realitySettings.spiderX",
            ),
            (
                "mldsa65_verify",
                "AAA",
                ValidationCode::RealityMldsa65Invalid,
                "stream.realitySettings.mldsa65Verify",
            ),
        ] {
            let mut profile = base_profile();
            let _ = profile.outbound.stream.select_security(Security::Reality);
            let mut reality = RealityModel {
                fingerprint: "chrome".into(),
                password: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".into(),
                ..Default::default()
            };
            match field {
                "fingerprint" => reality.fingerprint = value.into(),
                "password" => reality.password = value.into(),
                "short_id" => reality.short_id = value.into(),
                "spider_x" => reality.spider_x = value.into(),
                "mldsa65_verify" => reality.mldsa65_verify = value.into(),
                _ => unreachable!(),
            }
            profile.outbound.stream.reality_settings = Some(reality);
            let blocking = editor_validation_findings(&profile).blocking;
            assert_eq!(
                blocking.len(),
                1,
                "{field} = {value:?} must surface exactly one finding: {blocking:#?}"
            );
            assert_eq!(blocking[0].code, code, "{field} = {value:?}");
            assert_eq!(
                blocking[0].path.as_deref(),
                Some(path),
                "{field} = {value:?} must name {path}"
            );
        }
    }

    /// The profile behind the warning matrix below: VLESS + vision flow over
    /// TLS, mux enabled — everything valid except the advisory rules.
    fn vision_mux_profile() -> ServerProfile {
        let mut profile = ServerProfile::new("vision+mux", OutboundModel::new(Protocol::Vless));
        let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
            unreachable!()
        };
        settings.address = "example.com".into();
        settings.port = 443;
        settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
        settings.flow = "xtls-rprx-vision".into();
        settings.encryption = "none".into();
        let _ = profile.outbound.stream.select_security(Security::Tls);
        profile.outbound.mux.enabled = true;
        profile.outbound.mux.concurrency = Some(8);
        profile
    }

    /// Warning findings classify into the sweep's advisory half and
    /// never join the blocking list that gates save/add — and they clear
    /// live as the user resolves them (escape hatch or plausible value).
    #[test]
    fn configuration_warnings_never_join_the_blocking_validation_list() {
        let mut profile = vision_mux_profile();
        profile.outbound.stream.tls_settings = Some(TlsModel {
            server_name: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d".into(),
            ..Default::default()
        });
        let findings = editor_validation_findings(&profile);
        assert!(
            findings.blocking.is_empty(),
            "warnings must not block save: {:#?}",
            findings.blocking
        );
        assert_eq!(
            codes_of(&findings.advisory),
            vec![
                ValidationCode::MuxWithVisionFlow,
                ValidationCode::ServerNameImplausible
            ],
            "{:#?}",
            findings.advisory
        );
        assert_eq!(
            finding(&findings.advisory, ValidationCode::ServerNameImplausible)
                .path
                .as_deref(),
            Some("stream.tlsSettings.serverName"),
        );

        // The concurrency -1 escape hatch clears the mux warning only.
        profile.outbound.mux.concurrency = Some(-1);
        let findings = editor_validation_findings(&profile);
        assert!(findings.blocking.is_empty());
        assert_eq!(
            codes_of(&findings.advisory),
            vec![ValidationCode::ServerNameImplausible],
            "{:#?}",
            findings.advisory
        );

        // A plausible serverName clears the last warning.
        profile.outbound.stream.tls_settings = Some(TlsModel {
            server_name: "example.com".into(),
            ..Default::default()
        });
        let findings = editor_validation_findings(&profile);
        assert!(findings.blocking.is_empty());
        assert!(findings.advisory.is_empty());

        // A blocking finding still lands in the error half while a warning
        // stays advisory in its own half.
        let mut profile = vision_mux_profile();
        profile.outbound.stream.tls_settings = Some(TlsModel {
            server_name: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d".into(),
            master_key_log: "C:\\xray-keys.log".into(),
            ..Default::default()
        });
        let findings = editor_validation_findings(&profile);
        assert_eq!(
            codes_of(&findings.blocking),
            vec![ValidationCode::MasterKeyLogNotSupported],
            "{:#?}",
            findings.blocking
        );
        assert_eq!(
            findings.blocking[0].path.as_deref(),
            Some("stream.tlsSettings.masterKeyLog"),
        );
        assert_eq!(
            codes_of(&findings.advisory),
            vec![
                ValidationCode::MuxWithVisionFlow,
                ValidationCode::ServerNameImplausible
            ],
            "{:#?}",
            findings.advisory
        );
    }

    #[test]
    fn mux_tab_warns_inline_only_when_tcp_mux_conflicts_with_a_vision_flow() {
        let warning = t(Language::En, Key::OutboundMuxWithVisionFlow);
        let mut mux = crate::model::outbound::MuxModel {
            enabled: true,
            concurrency: Some(8),
            ..Default::default()
        };
        let mut harness = Harness::new_ui(|ui| {
            mux_tab(ui, Language::En, &mut mux, Some("xtls-rprx-vision"));
        });
        harness.run();
        assert!(
            harness.query_by_label(warning).is_some(),
            "enabled mux under a vision flow must warn inline on the mux tab"
        );
        drop(harness);

        // Concurrency -1 is the sanctioned escape hatch: no inline warning.
        mux.concurrency = Some(-1);
        let mut harness = Harness::new_ui(|ui| {
            mux_tab(ui, Language::En, &mut mux, Some("xtls-rprx-vision"));
        });
        harness.run();
        assert!(harness.query_by_label(warning).is_none());
        drop(harness);

        // Mux without mux, or a non-VLESS profile context, never warns.
        mux.concurrency = Some(8);
        mux.enabled = false;
        let mut harness = Harness::new_ui(|ui| {
            mux_tab(ui, Language::En, &mut mux, Some("xtls-rprx-vision"));
        });
        harness.run();
        assert!(harness.query_by_label(warning).is_none());
        drop(harness);

        mux.enabled = true;
        let mut harness = Harness::new_ui(|ui| {
            mux_tab(ui, Language::En, &mut mux, None);
        });
        harness.run();
        assert!(harness.query_by_label(warning).is_none());
    }

    #[test]
    fn basic_tab_warns_inline_at_the_flow_combo_for_vision_plus_mux() {
        let warning = t(Language::En, Key::OutboundMuxWithVisionFlow);
        let mut profile = vision_mux_profile();
        let mut screen = ServersScreen::default();
        let mut harness = Harness::new_ui(|ui| {
            let _ = screen.basic_tab_for_target(ui, Language::En, &mut profile, None, &[]);
        });
        harness.run();
        assert!(
            harness.query_by_label(warning).is_some(),
            "the flow combo must warn inline while mux carries TCP under vision"
        );
        drop(harness);
        // Flipping the mux escape hatch off the conflict clears it live.
        profile.outbound.mux.concurrency = Some(-1);
        let mut harness = Harness::new_ui(|ui| {
            let _ = screen.basic_tab_for_target(ui, Language::En, &mut profile, None, &[]);
        });
        harness.run();
        assert!(harness.query_by_label(warning).is_none());
    }

    #[test]
    fn basic_tab_inline_verdicts_ride_the_sweep_and_render_from_the_memo() {
        // A public VLESS endpoint without transport security: the sweep
        // reports the public-endpoint rule, and the Basic tab renders that
        // half inline under its protocol fields.
        let mut profile = ServerProfile::new("public-vless", OutboundModel::new(Protocol::Vless));
        {
            let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
                unreachable!("Vless is the default protocol");
            };
            settings.address = "example.com".into();
            settings.port = 443;
            settings.encryption = "none".into();
        }
        let findings = editor_validation_findings(&profile);
        let rendered = findings.render(Language::En);
        let public_endpoint = finding(
            &findings.blocking,
            ValidationCode::PublicVlessRequiresTlsOrEncryption,
        );
        assert!(
            basic_tab_inline_verdict(&public_endpoint.code),
            "the Basic tab must own the public-endpoint rule"
        );
        assert!(
            rendered
                .blocking
                .contains(&validation_issue_message(&public_endpoint, Language::En))
        );
        let inline = rendered.basic_inline;
        assert_eq!(
            inline,
            vec![validation_issue_message(&public_endpoint, Language::En)],
            "the Basic tab's verdict is the error list's finding, rendered the same"
        );
        let mut screen = ServersScreen::default();
        {
            let mut harness = Harness::new_ui(|ui| {
                let _ = screen.basic_tab_for_target(ui, Language::En, &mut profile, None, &inline);
            });
            harness.run();
            for message in &inline {
                assert!(
                    harness.query_by_label(message.as_str()).is_some(),
                    "the Basic tab must render the memoized verdict {message:?}"
                );
            }
        }
        // The tab renders exactly the slice it is handed: a sentinel slice
        // must paint the sentinel and must not re-run the sweep to surface
        // the profile's own finding.
        let sentinel = vec!["sentinel verdict".to_string()];
        let mut harness = Harness::new_ui(|ui| {
            let _ = screen.basic_tab_for_target(ui, Language::En, &mut profile, None, &sentinel);
        });
        harness.run();
        assert!(harness.query_by_label("sentinel verdict").is_some());
        for message in &inline {
            assert!(
                harness.query_by_label(message.as_str()).is_none(),
                "the Basic tab must render only its memoized verdicts, not re-validate"
            );
        }
    }

    #[test]
    fn security_tab_warns_inline_under_implausible_tls_and_reality_server_names() {
        let warning = t(Language::En, Key::OutboundServerNameImplausible);
        for security in [Security::Tls, Security::Reality] {
            let mut stream = StreamModel {
                security,
                ..Default::default()
            };
            match security {
                Security::Tls => {
                    stream.tls_settings = Some(TlsModel {
                        server_name: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d".into(),
                        ..Default::default()
                    });
                }
                Security::Reality => {
                    stream.reality_settings = Some(crate::model::stream::RealityModel {
                        server_name: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d".into(),
                        ..Default::default()
                    });
                }
                Security::None => unreachable!(),
            }
            let mut screen = ServersScreen::default();
            let mut harness = Harness::new_ui(|ui| {
                let _ = screen.security_tab(ui, Language::En, None, &mut stream, None, &[]);
            });
            harness.run();
            assert!(
                harness.query_by_label(warning).is_some(),
                "{security:?} must warn inline under a UUID serverName"
            );
            drop(harness);

            // The plausible value renders no warning; empty stays untouched.
            match security {
                Security::Tls => {
                    stream.tls_settings.as_mut().unwrap().server_name = "example.com".into();
                }
                Security::Reality => {
                    stream.reality_settings.as_mut().unwrap().server_name = "example.com".into();
                }
                Security::None => unreachable!(),
            }
            let mut harness = Harness::new_ui(|ui| {
                let _ = screen.security_tab(ui, Language::En, None, &mut stream, None, &[]);
            });
            harness.run();
            assert!(
                harness.query_by_label(warning).is_none(),
                "{security:?} must not warn under a plausible serverName"
            );
        }
    }

    /// A stored REALITY fingerprint outside the known-good set renders the
    /// advisory inline under its combo — amber and never blocking — while
    /// the empty default and the three known-good names render nothing and
    /// `unsafe` keeps its blocking message alone.
    #[test]
    fn security_tab_warns_inline_for_a_reality_fingerprint_outside_the_known_good_set() {
        let advisory = t_fmt(
            Language::En,
            Key::OutboundRealityFingerprintUntested,
            &[&"ios"],
        );
        let mut stream = StreamModel {
            security: Security::Reality,
            reality_settings: Some(RealityModel {
                fingerprint: "ios".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut screen = ServersScreen::default();
        let mut harness = Harness::new_ui(|ui| {
            let _ = screen.security_tab(ui, Language::En, None, &mut stream, None, &[]);
        });
        harness.run();
        assert!(
            harness.query_by_label(advisory.as_str()).is_some(),
            "a wire-valid REALITY fingerprint outside the known-good set must show the advisory"
        );
        drop(harness);

        for fingerprint in ["", "chrome", "firefox", "safari", "Chrome"] {
            stream.reality_settings.as_mut().unwrap().fingerprint = fingerprint.into();
            let mut harness = Harness::new_ui(|ui| {
                let _ = screen.security_tab(ui, Language::En, None, &mut stream, None, &[]);
            });
            harness.run();
            assert!(
                harness.query_by_label(advisory.as_str()).is_none(),
                "REALITY fingerprint {fingerprint:?} must not show the advisory"
            );
        }

        // `unsafe` stays a conf-load Error: its message renders and the
        // advisory never joins it.
        stream.reality_settings.as_mut().unwrap().fingerprint = "unsafe".into();
        let blocking =
            validation_message(&ValidationCode::RealityFingerprintUnsupported, Language::En);
        let mut harness = Harness::new_ui(|ui| {
            let _ = screen.security_tab(ui, Language::En, None, &mut stream, None, &[]);
        });
        harness.run();
        assert!(
            harness.query_by_label(blocking).is_some(),
            "unsafe must keep its blocking message"
        );
        assert!(
            harness.query_by_label(advisory.as_str()).is_none(),
            "the advisory must never accompany the blocking finding"
        );
    }

    /// The advisory rides the editor sweep's warning half — what the
    /// editor's warnings list renders — and never the blocking half, so a
    /// profile the core accepts stays validatable and saveable.
    #[test]
    fn reality_fingerprint_advisory_rides_the_editor_warning_half() {
        let mut profile =
            ServerProfile::new("ios-fingerprint", OutboundModel::new(Protocol::Vless));
        {
            let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
                unreachable!("Vless is the default protocol");
            };
            settings.address = "example.com".into();
            settings.port = 443;
            settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
            settings.encryption = "none".into();
        }
        let _ = profile.outbound.stream.select_security(Security::Reality);
        profile.outbound.stream.reality_settings = Some(RealityModel {
            fingerprint: "ios".into(),
            password: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".into(),
            ..Default::default()
        });
        let findings = editor_validation_findings(&profile);
        assert!(
            findings.blocking.is_empty(),
            "a wire-valid fingerprint must not block: {:#?}",
            findings.blocking
        );
        assert_eq!(findings.advisory.len(), 1, "{:#?}", findings.advisory);
        let advisory = &findings.advisory[0];
        assert_eq!(
            advisory.code,
            ValidationCode::RealityFingerprintUntested("ios".into())
        );
        assert_eq!(
            advisory.path.as_deref(),
            Some("stream.realitySettings.fingerprint"),
        );
        assert!(
            validation_issue_message(advisory, Language::En).contains("ios"),
            "the message must name the value it questions"
        );
    }

    #[test]
    fn info_hints_render_under_security_tab_rows() {
        // Static informational copy (no validation, no gating): the
        // TLS and REALITY serverName fields explain their empty fallback, and
        // each fingerprint combo explains its option semantics.
        for security in [Security::Tls, Security::Reality] {
            let mut stream = StreamModel {
                security,
                ..Default::default()
            };
            let mut screen = ServersScreen::default();
            let mut harness = Harness::new_ui(|ui| {
                let _ = screen.security_tab(ui, Language::En, None, &mut stream, None, &[]);
            });
            harness.run();
            let (server_name_hint, fingerprint_hint) = match security {
                Security::Tls => (
                    t(Language::En, Key::SrvTlsServerNameEmptyHint),
                    t(Language::En, Key::SrvTlsFingerprintHint),
                ),
                Security::Reality => (
                    t(Language::En, Key::SrvRealityServerNameEmptyHint),
                    t(Language::En, Key::SrvRealityFingerprintHint),
                ),
                Security::None => unreachable!(),
            };
            assert!(
                harness.query_by_label(server_name_hint).is_some(),
                "{security:?} serverName row must render its empty-fallback hint"
            );
            assert!(
                harness.query_by_label(fingerprint_hint).is_some(),
                "{security:?} fingerprint row must render its option-semantics hint"
            );
            drop(harness);
        }
    }

    #[test]
    fn info_hints_render_at_flow_xudp_and_grpc_rows() {
        // Basic tab → flow combo: the vision UDP/443 semantics.
        let mut profile = ServerProfile::new("flow-hints", OutboundModel::new(Protocol::Vless));
        let mut screen = ServersScreen::default();
        let mut harness = Harness::new_ui(|ui| {
            let _ = screen.basic_tab_for_target(ui, Language::En, &mut profile, None, &[]);
        });
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvVisionUdp443Hint))
                .is_some(),
            "the flow combo must render the vision UDP/443 semantics hint"
        );
        drop(harness);

        // Mux tab → the xudpProxyUDP443 combo's reject-default note.
        let mut mux = Default::default();
        let mut harness = Harness::new_ui(|ui| {
            mux_tab(ui, Language::En, &mut mux, None);
        });
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvXudpProxyUdp443Hint))
                .is_some(),
            "the xudpProxyUDP443 combo must render its reject-default hint"
        );
        drop(harness);

        // Transport tab → gRPC section: multiMode row + mux guidance.
        let mut stream = StreamModel {
            network: Network::Grpc,
            ..Default::default()
        };
        let mut screen = ServersScreen::default();
        let mut harness = Harness::new_ui(|ui| {
            let _ = screen.transport_tab(ui, Language::En, &mut stream, 0, None);
        });
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvGrpcMultiModeHint))
                .is_some(),
            "the gRPC multiMode row must render its experimental hint"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvGrpcMuxHint))
                .is_some(),
            "the gRPC section must render the mux guidance hint"
        );
    }

    #[test]
    fn every_basic_protocol_renders_without_mutating_the_profile() {
        for protocol in Protocol::ALL {
            let mut profile = ServerProfile::new(protocol.as_str(), OutboundModel::new(protocol));
            if let ProtocolSettings::Wireguard(settings) = &mut profile.outbound.settings {
                settings.reserved = Some(vec![1, 2]);
            }
            let before = serde_json::to_value(&profile).unwrap();
            let mut screen = ServersScreen::default();
            let mut reported_changed = false;
            {
                let _harness = Harness::new_ui(|ui| {
                    reported_changed |=
                        screen.basic_tab_for_target(ui, Language::En, &mut profile, None, &[]);
                });
            }
            assert_eq!(
                serde_json::to_value(&profile).unwrap(),
                before,
                "{}",
                protocol.as_str()
            );
        }
    }

    /// The preserved over-limit subtree is serialized once per draft state, not
    /// once per frame: its header body re-runs on every frame it stays open,
    /// and the subtree is as large as the configuration behind it. The same
    /// draft identity returns the same text, and an edit generation — which
    /// every editor change advances — rebuilds it from the new subtree.
    #[test]
    fn over_limit_subtree_json_is_memoized_per_draft_state() {
        let subtree = |path: &str| StreamModel {
            network: Network::Ws,
            ws_settings: Some(WsSettings {
                path: path.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let id = "0123456789abcdef";
        let mut screen = ServersScreen::default();
        let preserved = subtree("/preserved");
        let target = || Some((DraftTargetKind::Existing, id, 7));

        let first = {
            let text = screen.over_limit_json_for(target(), 2, Language::En, &preserved);
            assert!(
                text.contains("/preserved"),
                "the text is the subtree's pretty print: {text}"
            );
            text.as_ptr()
        };
        assert_eq!(
            screen
                .over_limit_json_for(target(), 2, Language::En, &preserved)
                .as_ptr(),
            first,
            "an idle frame of the open header must reuse the serialized text"
        );

        // An edit advances the draft's generation: the next frame renders the
        // edited subtree.
        let edited = subtree("/edited");
        assert!(
            screen
                .over_limit_json_for(
                    Some((DraftTargetKind::Existing, id, 8)),
                    2,
                    Language::En,
                    &edited
                )
                .contains("/edited"),
            "a new edit generation must re-serialize the edited subtree"
        );

        // Another draft's subtree never reuses this one's text, and a call
        // with no draft identity to key on does not cache at all.
        assert!(
            screen
                .over_limit_json_for(
                    Some((DraftTargetKind::Add, "fedcba9876543210", 8)),
                    2,
                    Language::En,
                    &preserved
                )
                .contains("/preserved")
        );
        assert!(
            screen
                .over_limit_json_for(None, 2, Language::En, &preserved)
                .contains("/preserved")
        );
    }

    /// The over-limit branch renders its depth message and the preserved
    /// subtree's header, and pays nothing while that header is collapsed: the
    /// pretty print is serialized on demand, not as part of walking the
    /// configuration.
    #[test]
    fn the_over_limit_branch_renders_and_serializes_only_on_demand() {
        let depth = crate::model::stream::MAX_XHTTP_DOWNLOAD_DEPTH;
        let mut stream = StreamModel::default();
        {
            let mut current = &mut stream;
            for level in 0..=depth {
                current.network = Network::Xhttp;
                let settings = current
                    .xhttp_settings
                    .get_or_insert_with(XhttpSettings::default);
                current = settings
                    .download_settings
                    .get_or_insert_with(|| {
                        // A marker only this level's settings carry, so an
                        // ancestor's text can never satisfy the assertion.
                        Box::new(StreamModel {
                            network: Network::Xhttp,
                            xhttp_settings: Some(XhttpSettings {
                                path: format!("/level-{level}"),
                                ..Default::default()
                            }),
                            ..Default::default()
                        })
                    })
                    .as_mut();
            }
        }
        // The view descends one `downloadSettings` per level and keeps the one
        // past its limit: that leaf is what the header shows when expanded.
        let preserved = {
            let mut node = &stream;
            for _ in 0..=depth {
                node = node
                    .xhttp_settings
                    .as_ref()
                    .expect("every level carries xhttpSettings")
                    .download_settings
                    .as_deref()
                    .expect("every level carries downloadSettings");
            }
            serde_json::to_string_pretty(node).expect("the preserved subtree serializes")
        };
        assert!(preserved.contains("/level-"), "{preserved}");

        let mut harness = Harness::builder()
            .with_size(egui::vec2(900.0, 2400.0))
            .build_ui_state(
                |ui, screen: &mut ServersScreen| {
                    let _ = screen.transport_tab(
                        ui,
                        Language::En,
                        &mut stream,
                        0,
                        Some((DraftTargetKind::Existing, "0123456789abcdef", 1)),
                    );
                },
                ServersScreen::default(),
            );
        harness.run();
        assert!(
            harness
                .query_all_by_label_contains("preserved")
                .next()
                .is_some(),
            "the over-limit level must render its preserved-value header"
        );
        assert!(
            harness.state().over_limit_json.is_none(),
            "a collapsed header must not serialize the preserved subtree"
        );
    }

    #[test]
    fn transport_security_mux_and_advanced_tabs_are_render_idempotent() {
        for network in [
            Network::Raw,
            Network::Xhttp,
            Network::Kcp,
            Network::Grpc,
            Network::Ws,
            Network::Httpupgrade,
            Network::Hysteria,
        ] {
            let mut stream = StreamModel {
                network,
                ..Default::default()
            };
            let before = serde_json::to_value(&stream).unwrap();
            let mut screen = ServersScreen::default();
            let mut reported_changed = false;
            {
                let _harness = Harness::new_ui(|ui| {
                    reported_changed |=
                        screen.transport_tab(ui, Language::En, &mut stream, 0, None);
                });
            }
            assert!(!reported_changed, "{}", network.as_str());
            assert_eq!(serde_json::to_value(&stream).unwrap(), before);
        }

        for security in [Security::None, Security::Tls, Security::Reality] {
            let mut stream = StreamModel {
                security,
                ..Default::default()
            };
            let before = serde_json::to_value(&stream).unwrap();
            let mut screen = ServersScreen::default();
            let mut reported_changed = false;
            {
                let _harness = Harness::new_ui(|ui| {
                    reported_changed |=
                        screen.security_tab(ui, Language::En, None, &mut stream, None, &[]);
                });
            }
            assert!(!reported_changed, "{security:?}");
            assert_eq!(serde_json::to_value(&stream).unwrap(), before);
        }

        let mut profile = ServerProfile::new("advanced", OutboundModel::new(Protocol::Freedom));
        profile.outbound.stream.finalmask = Some(FinalmaskModel::default());
        profile.outbound.chain_via("dialer");
        let before = serde_json::to_value(&profile).unwrap();
        let mut screen = ServersScreen {
            tab: EditorTab::Advanced,
            ..Default::default()
        };
        let mut reported_changed = false;
        {
            let _harness = Harness::new_ui(|ui| {
                reported_changed |= ServersScreen::advanced_tab(
                    ui,
                    Language::En,
                    &mut profile,
                    &[],
                    AdvancedTabCtx {
                        set_key: (0, false, 0),
                        finalmask_errors: &[],
                        stream_sockopt_errors: &[],
                        dialer_proxy_options: &mut screen.dialer_proxy_options,
                        finalmask_raw: &mut screen.finalmask_raw,
                        pem_buffers: &mut screen.pem_buffers,
                    },
                );
            });
        }
        assert!(!reported_changed);
        assert_eq!(serde_json::to_value(&profile).unwrap(), before);

        let mut mux = Default::default();
        let before = serde_json::to_value(&mux).unwrap();
        let mut reported_changed = false;
        {
            let _harness = Harness::new_ui(|ui| {
                reported_changed |= mux_tab(ui, Language::En, &mut mux, None);
            });
        }
        assert!(!reported_changed);
        assert_eq!(serde_json::to_value(&mux).unwrap(), before);
    }

    #[test]
    fn reality_draft_fields_survive_tls_round_trip() {
        let reality = RealityModel {
            server_name: "reality-ui.example.com".into(),
            fingerprint: "firefox".into(),
            password: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            short_id: "0123456789abcdef".into(),
            spider_x: "/reality-ui-draft".into(),
            mldsa65_verify: "reality-ui-mldsa".into(),
            master_key_log: r"C:\reality-ui.keys".into(),
            ..Default::default()
        };
        let reality_snapshot = serde_json::to_value(&reality).unwrap();
        let stream = Rc::new(RefCell::new(StreamModel {
            security: Security::Reality,
            reality_settings: Some(reality),
            ..Default::default()
        }));
        let stream_for_ui = Rc::clone(&stream);
        let screen = Rc::new(RefCell::new(ServersScreen::default()));
        let screen_for_ui = Rc::clone(&screen);
        let mut harness = Harness::new_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().security_tab(
                ui,
                Language::En,
                None,
                &mut stream_for_ui.borrow_mut(),
                None,
                &[],
            );
        });

        harness.get_by_label("tls").click();
        harness.run();
        assert_eq!(stream.borrow().security, Security::Tls);

        harness.get_by_label("reality").click();
        harness.run();
        assert_eq!(stream.borrow().security, Security::Reality);
        assert_eq!(
            serde_json::to_value(stream.borrow().reality_settings.as_ref().unwrap()).unwrap(),
            reality_snapshot
        );

        let text_values = harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .filter_map(|node| node.value())
            .collect::<Vec<_>>();
        for expected in [
            "reality-ui.example.com",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "0123456789abcdef",
            "/reality-ui-draft",
            "reality-ui-mldsa",
            r"C:\reality-ui.keys",
        ] {
            assert!(
                text_values.iter().any(|value| value == expected),
                "{expected:?} was not restored in {text_values:?}"
            );
        }
    }
    #[test]
    fn probe_pin_panel_renders_rows_and_applies_on_click() {
        let leaf = "7f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";
        let stream = Rc::new(RefCell::new(StreamModel {
            security: Security::Tls,
            tls_settings: Some(TlsModel::default()),
            ..Default::default()
        }));
        let stream_for_ui = Rc::clone(&stream);
        let screen = Rc::new(RefCell::new(ServersScreen {
            tls_probe_leaf_pin: Some(leaf.to_owned()),
            tls_tool_output: Some(
                "TLS ping:  example.com:443\nPinging without SNI\nHandshake succeeded\n\
                 TLS Version:  TLS 1.3\nCert's leaf SHA256:\t7f9c2b3d4e5f60718293a4b5c6d7e8f9"
                    .to_owned(),
            ),
            tls_probe_ca_pins: vec![
                (
                    "DigiCert TLS RSA SHA256 2020 CA1".to_owned(),
                    "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_owned(),
                ),
                (
                    "DigiCert Global Root R11".to_owned(),
                    "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2".to_owned(),
                ),
            ],
            tls_probe_handshake_ok: true,
            tls_probe_profile: Some("profile-1".to_owned()),
            ..Default::default()
        }));
        let screen_for_ui = Rc::clone(&screen);
        // The TLS-arm informational hint rows push the probe
        // panel's lower buttons past the default 800x600 kittest viewport;
        // the real app scrolls, so the harness just gets a taller one.
        let mut harness = Harness::builder()
            .with_size(egui::vec2(800.0, 700.0))
            .build_ui(move |ui| {
                let _ = screen_for_ui.borrow_mut().security_tab(
                    ui,
                    Language::En,
                    Some((DraftTargetKind::Existing, "profile-1", 0)),
                    &mut stream_for_ui.borrow_mut(),
                    None,
                    &[],
                );
                screen_for_ui
                    .borrow_mut()
                    .probe_output_window(ui.ctx(), Language::En);
            });

        harness.get_by_label("Probe TLS certificate").click();
        harness.run();

        // Leaf + CA pin rows and the caution line render inline; the raw
        // output stays out of the tab until requested.
        harness.get_by_label("Leaf pin");
        // A multi-line monospace label is exposed as one exact label, so the
        // transcript must match as a whole.
        let raw_transcript = "TLS ping:  example.com:443\nPinging without SNI\n\
                              Handshake succeeded\nTLS Version:  TLS 1.3\n\
                              Cert's leaf SHA256:\t7f9c2b3d4e5f60718293a4b5c6d7e8f9";
        assert!(
            harness.query_by_label(raw_transcript).is_none(),
            "the raw transcript must not render inline in the tab"
        );
        harness.get_by_label("Show original output").click();
        harness.run();
        harness.get_by_label("TLS probe output");
        harness.get_by_label(raw_transcript);
        harness.get_by_label(leaf);
        harness.get_by_label("CA pins");
        // The QUIC capture button is present; it must not be clicked in the
        // harness (it spawns a network job).
        harness.get_by_label("Probe QUIC handshake");
        harness.get_by_label("DigiCert TLS RSA SHA256 2020 CA1");
        harness.get_by_label(t(Language::En, Key::SrvPinCaution));

        // Apply writes the leaf pin into the draft's tls_settings and shows
        // the success status; it never auto-applies on its own.
        harness.get_by_label("Apply to server").click();
        harness.run();
        let tls = stream.borrow().tls_settings.as_ref().unwrap().clone();
        assert_eq!(tls.pinned_peer_cert_sha256, leaf);
        let status = &screen.borrow().status;
        let status = status.as_ref().unwrap();
        assert_eq!(status.text, "Pin applied.");
        assert!(!status.is_error);
    }

    #[test]
    fn probe_pin_panel_reports_when_a_successful_handshake_has_no_pin() {
        let screen = Rc::new(RefCell::new(ServersScreen {
            tls_probe_handshake_ok: true,
            tls_probe_profile: Some("profile-1".to_owned()),
            ..Default::default()
        }));
        let screen_for_ui = Rc::clone(&screen);
        let mut stream = StreamModel {
            security: Security::Tls,
            tls_settings: Some(TlsModel::default()),
            ..Default::default()
        };
        let mut harness = Harness::new_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().security_tab(
                ui,
                Language::En,
                Some((DraftTargetKind::Existing, "profile-1", 0)),
                &mut stream,
                None,
                &[],
            );
        });
        harness.get_by_label("Probe TLS certificate").click();
        harness.run();
        harness.get_by_label(t(Language::En, Key::SrvProbeNoPin));
    }

    #[test]
    fn probe_pin_panel_hides_pins_for_another_profile() {
        let leaf = "7f9c2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9";
        let screen = Rc::new(RefCell::new(ServersScreen {
            tls_probe_leaf_pin: Some(leaf.to_owned()),
            tls_probe_handshake_ok: true,
            tls_probe_profile: Some("profile-1".to_owned()),
            ..Default::default()
        }));
        let screen_for_ui = Rc::clone(&screen);
        let stream = Rc::new(RefCell::new(StreamModel {
            security: Security::Tls,
            tls_settings: Some(TlsModel::default()),
            ..Default::default()
        }));
        let stream_for_ui = Rc::clone(&stream);
        let mut harness = Harness::new_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().security_tab(
                ui,
                Language::En,
                Some((DraftTargetKind::Existing, "profile-2", 0)),
                &mut stream_for_ui.borrow_mut(),
                None,
                &[],
            );
        });
        harness.get_by_label("Probe TLS certificate").click();
        harness.run();
        assert!(
            harness.query_by_label("Leaf pin").is_none(),
            "pins probed for profile-1 must not render while editing profile-2"
        );
        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "Apply to server")
                .is_none(),
            "Apply must be unreachable for a pin probed from another profile"
        );
    }

    #[test]
    fn probe_use_server_address_fills_domain_and_clears_stale_override() {
        let mut profile = ServerProfile::new("node", OutboundModel::new(Protocol::Vless));
        let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
            unreachable!("Vless is the default protocol");
        };
        settings.address = "1.2.3.4".into();
        settings.port = 8443;
        let address = profile
            .server_address()
            .expect("vless profile has an address");
        let stream = Rc::new(RefCell::new(StreamModel {
            security: Security::Tls,
            tls_settings: Some(TlsModel::default()),
            ..Default::default()
        }));
        let stream_for_ui = Rc::clone(&stream);
        let screen = Rc::new(RefCell::new(ServersScreen {
            // A stale override from an earlier probe must not survive the
            // fill: the next handshake would dial the old IP otherwise.
            tls_probe_ip: "9.9.9.9".into(),
            ..Default::default()
        }));
        let screen_for_ui = Rc::clone(&screen);
        let mut harness = Harness::new_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().security_tab(
                ui,
                Language::En,
                Some((DraftTargetKind::Existing, "profile-1", 0)),
                &mut stream_for_ui.borrow_mut(),
                Some(&address),
                &[],
            );
        });

        harness.get_by_label("Probe TLS certificate").click();
        harness.run();
        harness.get_by_label("Use server address:port").click();
        harness.run();

        assert_eq!(screen.borrow().tls_probe_domain, "1.2.3.4:8443");
        assert!(screen.borrow().tls_probe_ip.is_empty());
    }

    #[test]
    fn high_outbound_level_survives_basic_editor_render() {
        let mut profile = ServerProfile::new("http", OutboundModel::new(Protocol::Http));
        let ProtocolSettings::Http(settings) = &mut profile.outbound.settings else {
            unreachable!();
        };
        settings.address = "proxy.example".into();
        settings.port = 8080;
        settings.level = Some(u32::MAX);

        let mut screen = ServersScreen::default();
        {
            let _harness = Harness::new_ui(|ui| {
                let _ = screen.basic_tab_for_target(ui, Language::En, &mut profile, None, &[]);
            });
        }
        let ProtocolSettings::Http(settings) = &profile.outbound.settings else {
            unreachable!();
        };
        assert_eq!(settings.level, Some(u32::MAX));
    }

    #[test]
    fn freedom_mouse_created_states_are_immediately_valid() {
        let noises = Rc::new(RefCell::new(Vec::<Noise>::new()));
        let noises_for_ui = Rc::clone(&noises);
        let mut noise_harness = Harness::new_ui(move |ui| {
            let _ = noises_editor(ui, Language::En, &mut noises_for_ui.borrow_mut());
        });
        noise_harness.get_by_label("+ noise").click();
        noise_harness.run();
        drop(noise_harness);

        let rules = Rc::new(RefCell::new(Vec::<FreedomFinalRule>::new()));
        let rules_for_ui = Rc::clone(&rules);
        let mut rule_harness = Harness::new_ui(move |ui| {
            let _ = final_rules_editor(ui, Language::En, &mut rules_for_ui.borrow_mut());
        });
        rule_harness.get_by_label("+ final rule").click();
        rule_harness.run();
        drop(rule_harness);

        let profile = Rc::new(RefCell::new(ServerProfile::new(
            "direct",
            OutboundModel::new(Protocol::Freedom),
        )));
        let profile_for_ui = Rc::clone(&profile);
        let screen = Rc::new(RefCell::new(ServersScreen::default()));
        let screen_for_ui = Rc::clone(&screen);
        let mut fragment_harness = Harness::new_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().basic_tab_for_target(
                ui,
                Language::En,
                &mut profile_for_ui.borrow_mut(),
                None,
                &[],
            );
        });
        fragment_harness.get_by_label("TCP fragmentation").click();
        fragment_harness.run();
        drop(fragment_harness);

        {
            let mut profile = profile.borrow_mut();
            let ProtocolSettings::Freedom(settings) = &mut profile.outbound.settings else {
                unreachable!();
            };
            assert!(settings.fragment.is_some());
            settings.noises = noises.borrow().clone();
            settings.final_rules = rules.borrow().clone();
        }
        let findings = editor_validation_findings(&profile.borrow());
        assert!(findings.blocking.is_empty(), "{:#?}", findings.blocking);
        assert!(findings.advisory.is_empty(), "{:#?}", findings.advisory);
    }

    #[test]
    fn incomplete_imported_freedom_entries_are_rejected() {
        let mut profile = ServerProfile::new("direct", OutboundModel::new(Protocol::Freedom));
        let ProtocolSettings::Freedom(settings) = &mut profile.outbound.settings else {
            unreachable!();
        };
        settings.fragment = Some(Default::default());
        settings.noises.push(Default::default());
        settings.final_rules.push(Default::default());

        let blocking = editor_validation_findings(&profile).blocking;
        for code in [
            ValidationCode::FreedomFragmentInvalid,
            ValidationCode::FreedomNoiseInvalid,
            ValidationCode::FreedomFinalRuleInvalid,
        ] {
            assert!(
                blocking.iter().any(|issue| issue.code == code),
                "{code:?} must report: {blocking:#?}"
            );
        }
    }

    #[test]
    fn moved_editor_rules_still_report_through_the_editor_sweep() {
        // `sendThrough`, freedom final-rule actions, and DNS rule actions
        // moved into the model pass (validate_outbound); the editor's error
        // list must keep rendering their texts.
        let mut profile = ServerProfile::new("edge", OutboundModel::new(Protocol::Freedom));
        profile.outbound.send_through = Some("bogus".into());
        let ProtocolSettings::Freedom(settings) = &mut profile.outbound.settings else {
            unreachable!();
        };
        settings.final_rules.push(Default::default());
        let blocking = editor_validation_findings(&profile).blocking;
        assert!(
            blocking
                .iter()
                .any(|issue| issue.code == ValidationCode::SendThroughInvalid),
            "{blocking:#?}"
        );
        assert!(
            blocking
                .iter()
                .any(|issue| issue.code == ValidationCode::FreedomFinalRuleInvalid),
            "{blocking:#?}"
        );

        let mut profile = ServerProfile::new("dns", OutboundModel::new(Protocol::Dns));
        let ProtocolSettings::Dns(settings) = &mut profile.outbound.settings else {
            unreachable!();
        };
        settings.rules.push(Default::default());
        let blocking = editor_validation_findings(&profile).blocking;
        assert!(
            blocking
                .iter()
                .any(|issue| issue.code == ValidationCode::DnsRuleActionInvalid),
            "{blocking:#?}"
        );
    }

    #[test]
    fn shadowsocks_level_accepts_255_and_rejects_256() {
        let mut profile = ServerProfile::new("ss", OutboundModel::new(Protocol::Shadowsocks));
        let ProtocolSettings::Shadowsocks(settings) = &mut profile.outbound.settings else {
            unreachable!();
        };
        settings.address = "127.0.0.1".into();
        settings.port = 8388;
        settings.method = "aes-128-gcm".into();
        settings.password = "secret".into();
        settings.level = Some(255);
        assert!(
            !editor_validation_findings(&profile)
                .blocking
                .iter()
                .any(|issue| issue.code == ValidationCode::ShadowsocksLevelRange)
        );

        let ProtocolSettings::Shadowsocks(settings) = &mut profile.outbound.settings else {
            unreachable!();
        };
        settings.level = Some(256);
        assert!(
            editor_validation_findings(&profile)
                .blocking
                .iter()
                .any(|issue| issue.code == ValidationCode::ShadowsocksLevelRange)
        );
    }

    #[test]
    fn blackhole_custom_response_payload_field_and_inline_verdict_follow_the_type() {
        fn blackhole_profile(r#type: &str, data: &str) -> ServerProfile {
            let mut profile = ServerProfile::new("block", OutboundModel::new(Protocol::Blackhole));
            let ProtocolSettings::Blackhole(settings) = &mut profile.outbound.settings else {
                unreachable!()
            };
            settings.response = Some(BlackholeResponse {
                r#type: r#type.into(),
                custom_response_data: data.into(),
                ..Default::default()
            });
            profile
        }

        for (kind, data, shows_invalid) in [
            ("custom", "aGk=", false),
            ("custom", "not base64!", true),
            // The custom match is case-insensitive like the core's
            // (infra/conf/blackhole.go:24,31), so a case-variant spelling
            // still owns the payload field and its verdict.
            ("Custom", "not base64!", true),
            ("http", "not base64!", false),
            // A mixed-case spelling of a payload-less type must not surface
            // the field a second time.
            ("HTTP", "not base64!", false),
        ] {
            let mut profile = blackhole_profile(kind, data);
            let mut screen = ServersScreen::default();
            let mut harness = Harness::new_ui(|ui| {
                let _ = screen.basic_tab_for_target(ui, Language::En, &mut profile, None, &[]);
            });
            harness.run();
            assert_eq!(
                harness
                    .query_by_label(t(Language::En, Key::SrvCustomResponseData))
                    .is_some(),
                kind.eq_ignore_ascii_case("custom"),
                "{kind}: the payload field belongs to the custom type only"
            );
            assert_eq!(
                harness
                    .query_by_label(t(Language::En, Key::SrvBlackholeCustomDataInvalid))
                    .is_some(),
                shows_invalid,
                "{kind} with {data:?}: inline payload verdict"
            );
            drop(harness);
        }
    }

    #[test]
    fn blackhole_response_type_combo_shows_a_stored_mixed_case_value_and_keeps_it() {
        // Xray lowercases the stored value before matching its vocabulary
        // (infra/conf/blackhole.go:24), so a mixed-case spelling is a
        // working profile. Like the REALITY fingerprint combo with a name
        // outside its option set, the combo must display it, report no edit
        // for an untouched frame, and only rewrite the text when a canonical
        // option is deliberately selected.
        let profile = Rc::new(RefCell::new({
            let mut profile = ServerProfile::new("block", OutboundModel::new(Protocol::Blackhole));
            let ProtocolSettings::Blackhole(settings) = &mut profile.outbound.settings else {
                unreachable!()
            };
            settings.response = Some(BlackholeResponse {
                r#type: "HTTP".into(),
                custom_response_data: "not base64!".into(),
                ..Default::default()
            });
            profile
        }));
        let stored = serde_json::to_value(&profile.borrow().outbound).unwrap();

        let changed = Rc::new(RefCell::new(false));
        let (profile_for_ui, changed_for_ui) = (Rc::clone(&profile), Rc::clone(&changed));
        let mut screen = ServersScreen::default();
        let mut harness = Harness::new_ui(move |ui| {
            // `Harness::run` may step several frames; keep any edit a frame
            // reports instead of letting a later quiet frame clear it.
            *changed_for_ui.borrow_mut() |= screen.basic_tab_for_target(
                ui,
                Language::En,
                &mut profile_for_ui.borrow_mut(),
                None,
                &[],
            );
        });
        harness.run();
        assert!(
            harness
                .get_all_by_role(egui::accesskit::Role::ComboBox)
                .into_iter()
                .any(|node| node.value().as_deref() == Some("HTTP")),
            "the combo must display the stored spelling"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvBlackholeResponseInvalid))
                .is_none(),
            "a mixed-case spelling loads upstream and must not be flagged"
        );
        assert!(
            !*changed.borrow(),
            "an untouched frame must not report an edit"
        );
        assert_eq!(
            serde_json::to_value(&profile.borrow().outbound).unwrap(),
            stored,
            "a save-shaped frame must not rewrite the stored spelling"
        );

        // Selecting a canonical option still edits the field.
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .into_iter()
            .find(|node| node.value().as_deref() == Some("HTTP"))
            .expect("the response-type combo shows the stored spelling")
            .click();
        harness.run();
        harness
            .get_all_by_label("http")
            .next()
            .expect("the open popup offers the canonical http option")
            .click();
        harness.run();
        assert!(*changed.borrow(), "selecting a canonical option is an edit");
        drop(harness);
        let borrowed = profile.borrow();
        let ProtocolSettings::Blackhole(settings) = &borrowed.outbound.settings else {
            unreachable!()
        };
        assert_eq!(settings.response.as_ref().expect("response").r#type, "http");
    }

    #[test]
    fn blackhole_custom_response_base64_blocks_editor_commit_with_the_field_named() {
        let mut profile = ServerProfile::new("block", OutboundModel::new(Protocol::Blackhole));
        let ProtocolSettings::Blackhole(settings) = &mut profile.outbound.settings else {
            unreachable!()
        };
        // Unpadded base64: the padded standard alphabet is what Xray's
        // `base64.StdEncoding` decodes (infra/conf/blackhole.go:31).
        settings.response = Some(BlackholeResponse {
            r#type: "custom".into(),
            custom_response_data: "aGk".into(),
            ..Default::default()
        });
        let findings = editor_validation_findings(&profile);
        assert_eq!(
            finding(
                &findings.blocking,
                ValidationCode::BlackholeCustomResponseDataInvalid
            )
            .path
            .as_deref(),
            Some("settings.response.customResponseData"),
            "the blocking finding must name the payload field: {:#?}",
            findings.blocking
        );
        assert!(
            !findings
                .advisory
                .iter()
                .any(|issue| issue.code == ValidationCode::BlackholeCustomResponseDataInvalid),
            "the payload rule gates, it never advises: {:#?}",
            findings.advisory
        );

        let ProtocolSettings::Blackhole(settings) = &mut profile.outbound.settings else {
            unreachable!()
        };
        settings.response = Some(BlackholeResponse {
            r#type: "custom".into(),
            custom_response_data: "aGk=".into(),
            ..Default::default()
        });
        let blocking = editor_validation_findings(&profile).blocking;
        assert!(blocking.is_empty(), "{blocking:#?}");

        // The payload is only decoded for the custom type, so a stray value
        // under the other types must not block the commit.
        let ProtocolSettings::Blackhole(settings) = &mut profile.outbound.settings else {
            unreachable!()
        };
        settings.response = Some(BlackholeResponse {
            r#type: "http".into(),
            custom_response_data: "not base64!".into(),
            ..Default::default()
        });
        let blocking = editor_validation_findings(&profile).blocking;
        assert!(blocking.is_empty(), "{blocking:#?}");

        // The custom match is case-insensitive (infra/conf/blackhole.go:24,31):
        // a case-variant spelling still decodes the payload, so the same
        // unpadded value blocks the commit with the field named.
        let ProtocolSettings::Blackhole(settings) = &mut profile.outbound.settings else {
            unreachable!()
        };
        settings.response = Some(BlackholeResponse {
            r#type: "Custom".into(),
            custom_response_data: "aGk".into(),
            ..Default::default()
        });
        let blocking = editor_validation_findings(&profile).blocking;
        assert_eq!(
            finding(
                &blocking,
                ValidationCode::BlackholeCustomResponseDataInvalid
            )
            .path
            .as_deref(),
            Some("settings.response.customResponseData"),
            "the case-variant custom spelling must still gate on the payload: {blocking:#?}"
        );
    }

    #[test]
    fn over_limit_xhttp_download_nesting_blocks_editor_commit() {
        let mut profile = ServerProfile::new("direct", OutboundModel::new(Protocol::Freedom));
        let mut current = &mut profile.outbound.stream;
        for _ in 0..=crate::model::stream::MAX_XHTTP_DOWNLOAD_DEPTH {
            current.network = Network::Xhttp;
            let settings = current
                .xhttp_settings
                .get_or_insert_with(XhttpSettings::default);
            current = settings
                .download_settings
                .get_or_insert_with(|| Box::new(StreamModel::default()))
                .as_mut();
        }
        assert!(
            editor_validation_findings(&profile)
                .blocking
                .iter()
                .any(|issue| issue.code == ValidationCode::XhttpDepthExceeded)
        );
    }

    #[test]
    fn legacy_websocket_host_is_passive_render_idempotent() {
        let mut stream = StreamModel {
            network: Network::Ws,
            ws_settings: Some(WsSettings {
                headers: serde_json::Map::from_iter([("Host".into(), json!("legacy.example"))]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let before = serde_json::to_value(&stream).unwrap();
        let mut screen = ServersScreen::default();
        let mut reported_changed = false;
        {
            let _harness = Harness::new_ui(|ui| {
                reported_changed |= screen.transport_tab(ui, Language::En, &mut stream, 0, None);
            });
        }
        assert!(!reported_changed);
        assert_eq!(serde_json::to_value(stream).unwrap(), before);
    }

    #[test]
    fn import_parse_refuses_oversized_paste_before_any_worker() {
        let mut screen = ServersScreen {
            import_text: "x".repeat(links::MAX_BULK_LEN + 1),
            ..Default::default()
        };
        screen.start_import_parse(Language::En, egui::Context::default());
        assert!(
            !screen.import_parse_job.is_pending(),
            "an oversized paste must not spawn a worker"
        );
        let message = screen
            .import_parse_error
            .expect("oversized paste must produce a rejection message");
        assert!(
            message.contains("too large"),
            "message must name the cap: {message:?}"
        );
        assert!(
            !message.contains(&screen.import_text),
            "message must not echo the paste"
        );
        assert!(
            screen.import_parsed.is_empty(),
            "nothing may be parsed from an oversized paste"
        );
    }

    /// One headless frame of the whole Servers screen with the import dialog
    /// open, over a paste far larger than the dialog's viewport. Exercises the
    /// real paint path of the preview (virtualized rows, truncated labels) and
    /// checks the formatted rows survive into the next frame.
    fn render_servers_frame(screen: &mut ServersScreen, rig: &mut UiTestRig) {
        let _harness = Harness::new_ui(|ui| screen.show(ui, &mut rig.ctx()));
    }

    /// The import preview is formatted once per parse result, not per frame:
    /// the dialog paints it every frame while it is open, and the paste cap
    /// allows a subscription blob with tens of thousands of entries. A later
    /// frame reuses the formatted rows — the same text allocations — and an
    /// edit that invalidates the parsed snapshot drops them with it.
    #[test]
    fn import_dialog_paints_a_large_preview_and_reuses_its_rows() {
        const ROWS: usize = 300;
        let paste: String = (0..ROWS)
            .map(|index| {
                format!(
                    "vless://b831381d-6324-4d53-ad4f-8cda48b30811@h{index}.local:443?encryption=none#P{index}\n"
                )
            })
            .collect();
        let mut rig = UiTestRig::default();
        let mut screen = ServersScreen {
            import_open: true,
            import_text: paste.clone(),
            ..Default::default()
        };
        screen.import_parsed = links::parse_bulk(&paste);
        screen.import_parsed_source = Some(paste);

        render_servers_frame(&mut screen, &mut rig);
        let allocations: Vec<*const u8> = {
            let preview = screen
                .import_preview
                .as_ref()
                .expect("the open dialog builds the preview");
            assert_eq!(preview.rows.len(), ROWS);
            assert_eq!(preview.ok, ROWS);
            preview.rows.iter().map(|row| row.text.as_ptr()).collect()
        };

        render_servers_frame(&mut screen, &mut rig);
        let reused: Vec<*const u8> = screen
            .import_preview
            .as_ref()
            .unwrap()
            .rows
            .iter()
            .map(|row| row.text.as_ptr())
            .collect();
        assert_eq!(
            reused, allocations,
            "a later frame of the same dialog must reuse the formatted rows"
        );

        // Editing the paste invalidates the snapshot the preview was built
        // from, so the formatted rows go with it.
        screen.invalidate_import_preview();
        assert!(
            screen.import_preview.is_none(),
            "a text edit must drop the formatted preview"
        );
    }

    #[test]
    fn import_parse_worker_delivers_results_via_poll() {
        let mut screen = ServersScreen {
            import_text:
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.local:443?encryption=none#A\n\
             vless://b831381d-6324-4d53-ad4f-8cda48b30811@b.local:443?encryption=none#B\n"
                    .to_string(),
            ..Default::default()
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        screen.start_import_parse(Language::En, egui::Context::default());
        assert!(
            screen.import_parse_job.is_pending(),
            "a parse must run off the UI thread"
        );
        while screen.import_parse_job.is_pending() {
            assert!(
                std::time::Instant::now() < deadline,
                "worker did not deliver in time"
            );
            screen.poll_import_parse(Language::En);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(screen.import_parsed.len(), 2);
        assert!(screen.import_parsed.iter().all(|result| result.is_ok()));
        assert_eq!(
            screen.import_parsed_source.as_deref(),
            Some(screen.import_text.as_str())
        );
        assert!(screen.import_parse_error.is_none());
    }

    #[test]
    fn import_parse_discards_stale_result_after_edit() {
        let mut screen = ServersScreen {
            import_text:
                "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.local:443?encryption=none#A\n"
                    .to_string(),
            ..Default::default()
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        screen.start_import_parse(Language::En, egui::Context::default());
        // Edit the paste while the worker runs: the delivered result must be
        // discarded as stale, leaving the preview invalidated.
        screen.import_text =
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@c.local:443?encryption=none#C\n"
                .to_string();
        while screen.import_parse_job.is_pending() {
            assert!(
                std::time::Instant::now() < deadline,
                "worker did not deliver in time"
            );
            screen.poll_import_parse(Language::En);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(
            screen.import_parsed.is_empty(),
            "stale results must never reach the preview"
        );
        assert!(screen.import_parsed_source.is_none());
    }

    /// One full Advanced-tab frame through a kittest harness. The harness is
    /// dropped before returning so its borrows do not overlap later ones.
    fn render_advanced_tab(screen: &mut ServersScreen, profile: &mut ServerProfile) {
        let _harness = Harness::new_ui(|ui| {
            let _ = ServersScreen::advanced_tab(
                ui,
                Language::En,
                profile,
                &[],
                AdvancedTabCtx {
                    set_key: (0, false, 0),
                    finalmask_errors: &[],
                    stream_sockopt_errors: &[],
                    dialer_proxy_options: &mut screen.dialer_proxy_options,
                    finalmask_raw: &mut screen.finalmask_raw,
                    pem_buffers: &mut screen.pem_buffers,
                },
            );
        });
    }

    #[test]
    fn mask_lists_render_their_order_captions() {
        // Both mask lists carry an order caption. The UDP list names the
        // types the wrap pins to the last entry and the type it pins to the
        // first; the TCP list states that no type is pinned, because only the
        // UDP masks check their level while they wrap
        // (`transport/internet/finalmask/sudoku/config.go` and the other
        // per-type checks are UDP-only).
        let mut screen = ServersScreen::default();
        let mut profile =
            ServerProfile::new("caption-order", OutboundModel::new(Protocol::Freedom));
        profile.outbound.stream.finalmask = Some(FinalmaskModel::default());
        let mut harness = Harness::builder()
            .with_size(egui::vec2(1200.0, 2000.0))
            .build_ui(|ui| {
                let _ = ServersScreen::advanced_tab(
                    ui,
                    Language::En,
                    &mut profile,
                    &[],
                    AdvancedTabCtx {
                        set_key: (0, false, 0),
                        finalmask_errors: &[],
                        stream_sockopt_errors: &[],
                        dialer_proxy_options: &mut screen.dialer_proxy_options,
                        finalmask_raw: &mut screen.finalmask_raw,
                        pem_buffers: &mut screen.pem_buffers,
                    },
                );
            });
        harness.run();
        for key in [Key::SrvTcpMaskOrderCaption, Key::SrvUdpMaskOrderCaption] {
            let caption = t(Language::En, key);
            assert!(
                harness.query_by_label(caption).is_some(),
                "the mask lists must render {key:?}: {caption:?}"
            );
        }
        let udp = t(Language::En, Key::SrvUdpMaskOrderCaption);
        for name in ["udphop", "realm", "xicmp", "sudoku"] {
            assert!(udp.contains(name), "{udp:?} must name {name}");
        }
    }

    #[test]
    fn deleting_a_profile_evicts_only_its_raw_editor_buffers() {
        let mut screen = ServersScreen::default();
        let mut alpha = ServerProfile::new("alpha", OutboundModel::new(Protocol::Freedom));
        alpha.outbound.stream.finalmask = Some(FinalmaskModel {
            tcp: vec![FinalmaskTcpMask::Unknown(json!({"type": "future-alpha"}))],
            udp: Vec::new(),
            quic_params: None,
            extra: Default::default(),
        });
        let mut beta = ServerProfile::new("beta", OutboundModel::new(Protocol::Freedom));
        beta.outbound.stream.finalmask = Some(FinalmaskModel {
            tcp: vec![FinalmaskTcpMask::Unknown(json!({"type": "future-beta"}))],
            udp: Vec::new(),
            quic_params: None,
            extra: Default::default(),
        });
        let alpha_id = alpha.id.clone();
        let beta_id = beta.id.clone();

        // One render per profile creates one buffer each: the raw-editor
        // map carries one entry per rendered profile.
        render_advanced_tab(&mut screen, &mut alpha);
        render_advanced_tab(&mut screen, &mut beta);
        assert_eq!(screen.finalmask_raw.len(), 2);

        // Evicting a profile that never rendered is a no-op for the cache.
        screen.evict_raw_buffers("00000000000000000000000000000000");
        assert_eq!(screen.finalmask_raw.len(), 2);

        // Deleting alpha evicts exactly its buffer; beta's stays untouched.
        screen.evict_raw_buffers(&alpha_id);
        assert_eq!(
            screen.finalmask_raw.len(),
            1,
            "only the deleted profile's buffer may be evicted"
        );
        assert!(
            screen
                .finalmask_raw
                .values()
                .all(|buffer| buffer.profile == beta_id)
        );

        // Idle re-render of the surviving profile: its entry is reused, so
        // the map does not grow.
        render_advanced_tab(&mut screen, &mut beta);
        assert_eq!(screen.finalmask_raw.len(), 1);

        // Re-rendering the deleted profile recreates its buffer; the map
        // follows the live size.
        render_advanced_tab(&mut screen, &mut alpha);
        assert_eq!(screen.finalmask_raw.len(), 2);
    }

    #[test]
    fn renaming_a_profile_keeps_raw_editor_buffers_bounded() {
        let mut screen = ServersScreen::default();
        let mut profile =
            ServerProfile::new("original-name", OutboundModel::new(Protocol::Freedom));
        profile.outbound.stream.finalmask = Some(FinalmaskModel {
            tcp: vec![FinalmaskTcpMask::Unknown(json!({"type": "future-rename"}))],
            udp: Vec::new(),
            quic_params: None,
            extra: Default::default(),
        });
        let id = profile.id.clone();
        render_advanced_tab(&mut screen, &mut profile);
        assert_eq!(screen.finalmask_raw.len(), 1);
        let seeded_text = screen.finalmask_raw.values().next().unwrap().text.clone();

        // A rename changes only the display name — the profile id is
        // immutable, so the buffer keys stay valid: repeated renames must
        // not grow the cache or re-seed buffers.
        for rename in 0..5 {
            profile.name = format!("renamed-{rename}");
            render_advanced_tab(&mut screen, &mut profile);
        }
        assert_eq!(screen.finalmask_raw.len(), 1);
        let surviving = screen.finalmask_raw.values().next().unwrap();
        assert_eq!(surviving.profile, id);
        assert_eq!(
            surviving.text, seeded_text,
            "the buffer must survive renames"
        );
    }

    /// Editing the preserved-raw text into invalid JSON surfaces the parse
    /// error under the editor — the memoized `JsonBuf` error, not a
    /// per-frame re-parse — and the error keeps rendering across idle
    /// frames; a valid replacement clears it.
    #[test]
    fn invalid_raw_text_renders_the_parse_error_until_repaired() {
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        tokyo.outbound.stream.finalmask = Some(FinalmaskModel {
            tcp: vec![FinalmaskTcpMask::Unknown(json!({"type": "future-raw"}))],
            udp: Vec::new(),
            quic_params: None,
            extra: Default::default(),
        });
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.active = Some(tokyo.id.clone());
        let mut harness = wide_servers_harness(rig);
        harness.run();
        harness.get_by_label("Advanced").click();
        harness.run();

        // The seeded buffer parses clean: nothing reports under the editor.
        assert!(
            harness.query_by_label_contains("invalid JSON").is_none(),
            "the seeded raw config must parse clean"
        );

        harness
            .get_all_by_role(egui::accesskit::Role::MultilineTextInput)
            .next()
            .expect("the preserved-raw editor renders on the Advanced tab")
            .scroll_to_me();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::MultilineTextInput)
            .next()
            .expect("the editor stays in the tree")
            .click();
        harness.run();
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::MultilineTextInput)
            .find(|node| node.is_focused())
            .expect("the editor keeps focus after select-all")
            .type_text("{not json");
        harness.run();

        assert!(
            harness
                .state()
                .0
                .finalmask_raw
                .values()
                .any(|buffer| buffer.error.is_some()),
            "an invalid edit must leave its parse error on the buffer"
        );
        assert!(
            harness.query_by_label_contains("invalid JSON").is_some(),
            "the parse error must render under the editor"
        );

        // Idle frames keep rendering the memoized error; a valid replacement
        // clears it.
        harness.run_steps(4);
        assert!(
            harness.query_by_label_contains("invalid JSON").is_some(),
            "the parse error must persist across idle frames"
        );
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::MultilineTextInput)
            .find(|node| node.is_focused())
            .expect("the editor keeps focus")
            .type_text(r#"{"type":"custom","ok":true}"#);
        harness.run();
        assert!(
            harness.query_by_label_contains("invalid JSON").is_none(),
            "a valid replacement must clear the parse error"
        );
    }

    // ---------- unsaved-changes indicator ----------

    /// Full-servers-screen harness that also renders the leave modal every
    /// frame, mirroring the app-shell wiring.
    fn unsaved_harness(rig: UiTestRig) -> Harness<'static, (ServersScreen, UiTestRig)> {
        Harness::new_ui_state(
            |ui, state: &mut (ServersScreen, UiTestRig)| {
                state.0.show(ui, &mut state.1.ctx());
                state.0.show_leave_modal(ui.ctx(), &mut state.1.ctx());
            },
            (ServersScreen::default(), rig),
        )
    }

    /// Like [`unsaved_harness`] in a window tall enough that the Advanced
    /// tab's finalmask section (below the envelope section) is on screen for
    /// click-driven tests; the kittest default 800x600 would fold it under
    /// the editor's scroll viewport.
    fn wide_servers_harness(rig: UiTestRig) -> Harness<'static, (ServersScreen, UiTestRig)> {
        Harness::builder()
            .with_size(egui::vec2(1100.0, 700.0))
            .build_ui_state(
                |ui, state: &mut (ServersScreen, UiTestRig)| {
                    state.0.show(ui, &mut state.1.ctx());
                    state.0.show_leave_modal(ui.ctx(), &mut state.1.ctx());
                },
                (ServersScreen::default(), rig),
            )
    }

    /// Dirty the selected profile's editor draft the way an edit does:
    /// mutate the profile and bump the generation so the memoized
    /// validation recomputes on the next frame.
    fn edit_existing_draft(screen: &mut ServersScreen) {
        let draft = screen.existing_draft.as_mut().unwrap();
        draft.profile.name.push('-');
        draft.generation = draft.generation.wrapping_add(1);
    }

    #[test]
    fn editor_unsaved_dot_tracks_draft_edits_and_discard() {
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.active = Some(tokyo.id.clone());
        let mut harness = unsaved_harness(rig);
        harness.run();
        assert!(
            harness.query_by_label("●").is_none(),
            "a pristine draft must not show the unsaved dot"
        );
        edit_existing_draft(&mut harness.state_mut().0);
        harness.run();
        assert!(
            harness.query_by_label("●").is_some(),
            "an edited draft must show the unsaved dot"
        );
        // Discard reverts to the persisted profile: the dot disappears and
        // the editor stays open on a fresh clean draft.
        harness
            .get_by_label(t(Language::En, Key::SrvDiscardChanges))
            .click();
        harness.run();
        assert!(
            harness.query_by_label("●").is_none(),
            "the dot must disappear after Discard"
        );
        let state = harness.state();
        assert!(
            state.0.existing_draft.is_some(),
            "Discard must keep the editor open with a fresh draft"
        );
        assert_eq!(
            state.0.existing_draft.as_ref().unwrap().profile.name,
            tokyo.name,
            "the draft must revert to the persisted profile"
        );
    }

    #[test]
    fn select_guard_stages_modal_and_cancel_keeps_draft_and_selection() {
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        rig.servers.active = Some(tokyo.id.clone());
        let mut harness = unsaved_harness(rig);
        harness.run();
        edit_existing_draft(&mut harness.state_mut().0);
        harness.run();
        harness.get_by_label("Osaka").click();
        harness.run();
        let state = harness.state();
        assert_eq!(
            state.0.leave_pending,
            Some(LeaveAction::Select(osaka.id.clone())),
            "a selection switch with unsaved changes must stage the leave modal"
        );
        assert_eq!(
            state.0.selected.as_deref(),
            Some(tokyo.id.as_str()),
            "the selection must not switch while the modal is staged"
        );
        assert!(
            state.0.existing_draft.is_some(),
            "the draft must survive staging"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvUnsavedChanges))
                .is_some(),
            "the staged modal must render its heading"
        );
        // Cancel keeps the draft and the selection.
        harness.get_by_label(t(Language::En, Key::Cancel)).click();
        harness.run();
        let state = harness.state();
        assert!(
            state.0.leave_pending.is_none(),
            "Cancel must clear the staged action"
        );
        assert_eq!(
            state.0.selected.as_deref(),
            Some(tokyo.id.as_str()),
            "Cancel must not switch the selection"
        );
        assert!(
            state.0.existing_draft.is_some(),
            "Cancel must keep the draft"
        );
        assert!(
            harness.query_by_label("●").is_some(),
            "the draft must still be dirty after Cancel"
        );
    }

    #[test]
    fn select_guard_discard_drops_draft_and_switches_selection() {
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        rig.servers.active = Some(tokyo.id.clone());
        let mut harness = unsaved_harness(rig);
        harness.run();
        edit_existing_draft(&mut harness.state_mut().0);
        harness.run();
        harness.get_by_label("Osaka").click();
        harness.run();
        // The editor's own Discard button carries the same label, so take
        // the last match: the modal renders on top of the editor.
        harness
            .get_all_by_label(t(Language::En, Key::SrvDiscardChanges))
            .last()
            .expect("the leave modal must render its Discard button")
            .click();
        harness.run();
        let state = harness.state();
        assert!(
            state.0.leave_pending.is_none(),
            "Discard must clear the staged action"
        );
        assert_eq!(
            state.0.selected.as_deref(),
            Some(osaka.id.as_str()),
            "Discard must switch the selection"
        );
        assert_eq!(
            state.0.existing_draft.as_ref().unwrap().profile.id,
            osaka.id,
            "the editor must reopen on the newly selected profile"
        );
        assert!(
            harness.query_by_label("●").is_none(),
            "the discarded edits must not leave a dot behind"
        );
    }

    #[test]
    fn add_commit_clears_a_staged_select_when_the_switch_happens_immediately() {
        let mut screen = ServersScreen::default();
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        screen.selected = Some(tokyo.id.clone());
        // Only the add draft is dirty: the add window is a plain window, so
        // the list stays clickable behind it — a row click staged a Select
        // while the modal's Save must target the add draft.
        let added = ServerProfile::new("Added", OutboundModel::new(Protocol::Vless));
        screen.add_draft = Some(added.clone());
        screen.add_draft_validation_cache = Some(AddDraftValidationCache {
            generation: 0,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source: true,
        });
        screen.leave_pending = Some(LeaveAction::Select(osaka.id.clone()));
        let (tx, rx) = tokio::sync::oneshot::channel();
        screen.profile_validation_request = Request::reply(rx);
        screen.profile_validation_origin = Some(ProfileValidationOrigin::Draft);
        tx.send(Ok(ProfileValidationResult {
            origin: ProfileValidationOrigin::Draft,
            accepted: vec![added.clone()],
            rejected: Vec::new(),
            import_source: None,
            draft_target: Some(ToolTarget::AddDraft {
                profile_id: added.id.clone(),
                generation: 0,
            }),
        }))
        .unwrap();
        screen.poll_profile_validation(Language::En, &mut rig.ctx());
        assert!(
            screen.leave_pending.is_none(),
            "a staged Select must clear when the add commit switches immediately"
        );
        assert_eq!(
            screen.selected.as_deref(),
            Some(added.id.as_str()),
            "the add commit must select the new profile"
        );
        assert!(
            rig.servers.profiles.iter().any(|p| p.id == added.id),
            "the validated add must be committed"
        );
    }

    #[test]
    fn modal_save_is_inert_while_only_a_raw_buffer_is_dirty() {
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        rig.servers.active = Some(tokyo.id.clone());
        let mut harness = unsaved_harness(rig);
        harness.run();
        // A raw finalmask buffer holds text that never parsed into the
        // draft: the draft itself is unchanged, so Save must refuse — the
        // same gate as the editor's Validate-and-save button.
        harness.state_mut().0.finalmask_raw.insert(
            egui::Id::new("finalmask-test"),
            JsonBuf {
                key: Some(egui::Id::new("finalmask-test")),
                text: "{ invalid".into(),
                error: Some("parse failed".into()),
                dirty: true,
                profile: tokyo.id.clone(),
            },
        );
        harness.run();
        harness.get_by_label("Osaka").click();
        harness.run();
        assert_eq!(
            harness.state().0.leave_pending,
            Some(LeaveAction::Select(osaka.id.clone())),
            "buffer-only dirtiness must stage the leave modal"
        );
        harness
            .get_by_label(t(Language::En, Key::SrvUnsavedLeaveSave))
            .click();
        harness.run();
        let state = harness.state();
        assert_eq!(
            state.0.leave_pending,
            Some(LeaveAction::Select(osaka.id.clone())),
            "Save must stay inert while only the raw buffer is dirty"
        );
        assert!(
            !state.0.profile_validation_request.is_pending(),
            "no validation may start for a buffer-only dirty state"
        );
        assert_eq!(
            state.0.selected.as_deref(),
            Some(tokyo.id.as_str()),
            "the selection must not move"
        );
        // Discard remains the escape: it drops the draft, clears the
        // buffer, and completes the switch.
        harness
            .get_all_by_label(t(Language::En, Key::SrvDiscardChanges))
            .last()
            .expect("the leave modal must render its Discard button")
            .click();
        harness.run();
        let state = harness.state();
        assert!(
            state.0.leave_pending.is_none(),
            "Discard must clear the staged action"
        );
        assert_eq!(
            state.0.selected.as_deref(),
            Some(osaka.id.as_str()),
            "Discard must complete the switch"
        );
        assert!(
            state.0.finalmask_raw.is_empty(),
            "Discard must clear the raw buffers"
        );
    }

    #[test]
    fn add_draft_close_stages_close_leave_when_the_draft_is_dirty() {
        let mut screen = ServersScreen::default();
        let draft = ServerProfile::new("New Freedom server", OutboundModel::new(Protocol::Freedom));
        // The dialog has rendered, so the memoized cache carries the flag:
        // a fresh add draft is unsaved by definition (it has no committed
        // source).
        screen.add_draft_validation_cache = Some(AddDraftValidationCache {
            generation: 0,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source: true,
        });
        screen.close_add_draft(draft.clone());
        assert_eq!(
            screen.leave_pending,
            Some(LeaveAction::CloseAdd),
            "closing the add dialog with a dirty draft must stage CloseAdd"
        );
        assert_eq!(
            screen.add_draft.as_ref().map(|d| d.id.as_str()),
            Some(draft.id.as_str()),
            "the staged draft must stay in the dialog"
        );
    }

    #[test]
    fn add_draft_close_drops_a_pristine_draft_without_staging() {
        let mut screen = ServersScreen::default();
        let draft = ServerProfile {
            id: "draft-id".into(),
            ..ServerProfile::default()
        };
        screen.add_draft_validation_cache = Some(AddDraftValidationCache {
            generation: 0,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source: false,
        });
        screen.close_add_draft(draft);
        assert!(
            screen.leave_pending.is_none(),
            "a clean add draft must not stage the leave modal"
        );
        assert!(
            screen.add_draft.is_none(),
            "a clean add draft must be dropped on close"
        );
    }

    #[test]
    fn add_draft_close_clears_a_targeting_derive_dialog_and_keeps_the_guard() {
        let mut screen = ServersScreen::default();
        let draft = ServerProfile::new("New Freedom server", OutboundModel::new(Protocol::Freedom));
        // The dialog has rendered, so the memoized cache carries the flag:
        // a fresh add draft is unsaved by definition.
        screen.add_draft_validation_cache = Some(AddDraftValidationCache {
            generation: 0,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source: true,
        });
        screen.derive_dialog = Some(DeriveDialog {
            target: ToolTarget::AddDraft {
                profile_id: draft.id.clone(),
                generation: 0,
            },
            private_key: String::new(),
            error: None,
            pending: false,
        });
        screen.close_add_draft(draft.clone());
        assert!(
            screen.derive_dialog.is_none(),
            "a derive dialog cannot outlive the add draft it targets"
        );
        assert_eq!(
            screen.leave_pending,
            Some(LeaveAction::CloseAdd),
            "closing the add window with a dirty draft must stage CloseAdd"
        );
        assert_eq!(
            screen.add_draft.as_ref().map(|d| d.id.as_str()),
            Some(draft.id.as_str()),
            "the staged draft must stay in the dialog until the modal resolves"
        );
    }

    #[test]
    fn unsaved_changes_uses_the_memo_and_recomputes_only_when_stale() {
        let mut screen = ServersScreen::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let mut edited = tokyo.clone();
        edited.name = "Tokyo-2".into();
        screen.existing_draft = Some(ExistingProfileDraft {
            id: tokyo.id.clone(),
            tag: tokyo.tag(),
            profile: edited,
            source: serde_json::to_value(&tokyo).unwrap(),
            generation: 3,
        });
        assert!(
            !screen.unsaved_changes(),
            "an absent cache (fresh draft) is never dirty"
        );
        screen.editor_validation_cache = Some(EditorValidationCache {
            generation: 3,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source: false,
        });
        assert!(
            !screen.unsaved_changes(),
            "a fresh memo must be authoritative"
        );
        screen.existing_draft.as_mut().unwrap().generation = 4;
        assert!(
            screen.unsaved_changes(),
            "a stale memo must recompute the flag inline (same-frame accuracy)"
        );
        screen.editor_validation_cache = Some(EditorValidationCache {
            generation: 4,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source: false,
        });
        screen.finalmask_raw.insert(
            egui::Id::new("raw-field"),
            JsonBuf {
                key: None,
                text: "{".into(),
                error: Some("unterminated".into()),
                dirty: true,
                profile: tokyo.id.clone(),
            },
        );
        assert!(
            screen.unsaved_changes(),
            "a raw buffer holding uncommitted text must be dirty regardless of the memo"
        );
        // The add draft contributes independently.
        screen.finalmask_raw.clear();
        screen.add_draft = Some(ServerProfile::new(
            "New VLESS server",
            OutboundModel::new(Protocol::Vless),
        ));
        screen.add_draft_validation_cache = Some(AddDraftValidationCache {
            generation: 0,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source: true,
        });
        assert!(
            screen.unsaved_changes(),
            "a dirty add draft must count as unsaved"
        );
    }

    #[test]
    fn validation_failure_clears_the_staged_leave_action() {
        let mut screen = ServersScreen::default();
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        screen.existing_draft = Some(ExistingProfileDraft {
            id: tokyo.id.clone(),
            tag: tokyo.tag(),
            profile: tokyo.clone(),
            source: serde_json::to_value(&tokyo).unwrap(),
            generation: 7,
        });
        screen.leave_pending = Some(LeaveAction::Select("some-other-id".into()));
        let (tx, rx) = tokio::sync::oneshot::channel();
        screen.profile_validation_request = Request::reply(rx);
        screen.profile_validation_origin = Some(ProfileValidationOrigin::Draft);
        tx.send(Ok(ProfileValidationResult {
            origin: ProfileValidationOrigin::Draft,
            accepted: Vec::new(),
            rejected: vec![("Tokyo".into(), "xray said no".into())],
            import_source: None,
            draft_target: Some(ToolTarget::ExistingDraft {
                profile_id: tokyo.id.clone(),
                generation: 7,
            }),
        }))
        .unwrap();
        screen.poll_profile_validation(Language::En, &mut rig.ctx());
        assert!(
            screen.leave_pending.is_none(),
            "a rejected validation must cancel the staged leave action"
        );
        assert!(
            screen.existing_draft.is_some(),
            "the editor must stay open with the draft on rejection"
        );
        assert_eq!(
            screen.profile_validation_report.as_deref(),
            Some("Tokyo:\nxray said no"),
            "the rejection must render in the editor's error block"
        );
    }

    #[test]
    fn quit_stays_staged_until_every_dirty_draft_is_committed() {
        let mut screen = ServersScreen::default();
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        screen.selected = Some(tokyo.id.clone());
        let mut edited = tokyo.clone();
        edited.name = "Tokyo-2".into();
        screen.existing_draft = Some(ExistingProfileDraft {
            id: tokyo.id.clone(),
            tag: tokyo.tag(),
            profile: edited.clone(),
            source: serde_json::to_value(&tokyo).unwrap(),
            generation: 3,
        });
        screen.editor_validation_cache = Some(EditorValidationCache {
            generation: 3,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source: true,
        });
        // The add draft stays dirty after the existing draft commits: the
        // quit must remain staged for a second Save.
        let add = ServerProfile::new("New VLESS server", OutboundModel::new(Protocol::Vless));
        screen.add_draft = Some(add.clone());
        screen.add_draft_validation_cache = Some(AddDraftValidationCache {
            generation: 0,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source: true,
        });
        screen.leave_pending = Some(LeaveAction::Quit);
        let (tx, rx) = tokio::sync::oneshot::channel();
        screen.profile_validation_request = Request::reply(rx);
        screen.profile_validation_origin = Some(ProfileValidationOrigin::Draft);
        tx.send(Ok(ProfileValidationResult {
            origin: ProfileValidationOrigin::Draft,
            accepted: vec![edited.clone()],
            rejected: Vec::new(),
            import_source: None,
            draft_target: Some(ToolTarget::ExistingDraft {
                profile_id: tokyo.id.clone(),
                generation: 3,
            }),
        }))
        .unwrap();
        screen.poll_profile_validation(Language::En, &mut rig.ctx());
        assert_eq!(
            screen.leave_pending,
            Some(LeaveAction::Quit),
            "the quit must stay staged while the add draft is dirty"
        );
        assert!(!screen.take_quit_resume(), "the quit must not resume yet");
        assert!(
            screen.existing_draft.is_none(),
            "the existing draft must be committed"
        );
        // The add draft commits next: no dirty draft remains, so the quit
        // resumes and the new profile is selected.
        let (tx, rx) = tokio::sync::oneshot::channel();
        screen.profile_validation_request = Request::reply(rx);
        screen.profile_validation_origin = Some(ProfileValidationOrigin::Draft);
        tx.send(Ok(ProfileValidationResult {
            origin: ProfileValidationOrigin::Draft,
            accepted: vec![add.clone()],
            rejected: Vec::new(),
            import_source: None,
            draft_target: Some(ToolTarget::AddDraft {
                profile_id: add.id.clone(),
                generation: 0,
            }),
        }))
        .unwrap();
        screen.poll_profile_validation(Language::En, &mut rig.ctx());
        assert!(
            screen.leave_pending.is_none(),
            "the staged quit must clear on the final commit"
        );
        assert!(
            screen.take_quit_resume(),
            "the quit must resume once nothing is dirty"
        );
        assert!(
            !screen.take_quit_resume(),
            "the resume flag must be single-shot"
        );
        assert_eq!(
            screen.selected.as_deref(),
            Some(add.id.as_str()),
            "the add commit must select the new profile"
        );
    }

    #[test]
    fn quit_discard_drops_both_drafts_and_resumes_the_quit() {
        let mut screen = ServersScreen::default();
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        screen.existing_draft = Some(ExistingProfileDraft {
            id: tokyo.id.clone(),
            tag: tokyo.tag(),
            profile: tokyo.clone(),
            source: serde_json::to_value(&tokyo).unwrap(),
            generation: 0,
        });
        screen.editor_validation_cache = Some(EditorValidationCache {
            generation: 0,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source: true,
        });
        let add = ServerProfile::new("New VLESS server", OutboundModel::new(Protocol::Vless));
        screen.add_draft = Some(add.clone());
        screen.add_draft_validation_cache = Some(AddDraftValidationCache {
            generation: 0,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source: true,
        });
        screen.discard_leave_action(LeaveAction::Quit);
        assert!(
            screen.existing_draft.is_none(),
            "Quit discard must drop the existing draft"
        );
        assert!(
            screen.add_draft.is_none(),
            "Quit discard must drop the add draft"
        );
        assert!(
            screen.take_quit_resume(),
            "Quit discard must resume the quit"
        );
    }

    #[test]
    fn select_discard_drops_only_the_existing_draft() {
        let mut screen = ServersScreen::default();
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        screen.existing_draft = Some(ExistingProfileDraft {
            id: tokyo.id.clone(),
            tag: tokyo.tag(),
            profile: tokyo.clone(),
            source: serde_json::to_value(&tokyo).unwrap(),
            generation: 0,
        });
        screen.editor_validation_cache = Some(EditorValidationCache {
            generation: 0,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source: true,
        });
        // An open add dialog is independent of the selection switch: the
        // Select discard reverts the existing draft but keeps the add draft.
        let add = ServerProfile::new("New VLESS server", OutboundModel::new(Protocol::Vless));
        screen.add_draft = Some(add.clone());
        screen.discard_leave_action(LeaveAction::Select("osaka-target-id".into()));
        assert!(
            screen.existing_draft.is_none(),
            "Select discard must drop the existing draft"
        );
        assert_eq!(
            screen.add_draft.as_ref().map(|d| d.id.as_str()),
            Some(add.id.as_str()),
            "Select discard must keep the add draft"
        );
    }

    // ---------- servers-editor residuals ----------

    /// The exact inline verdict for one bad TCP item: locale template
    /// prefixed with the wire path (independent literal, not recomputed).
    const BAD_TCP_ITEM_MESSAGE: &str = "finalmask.tcp[0].settings.clients[0][0]: set \
        exactly one of packet, positive rand, reuse, or transform when capture is used";

    /// Freedom profile carrying one invalid TCP header-custom mask: a `clients`
    /// item that uses `capture` without packet/positive rand/reuse/transform.
    /// A mask list the sweep reports on: the header-custom TCP mask's client
    /// item sets `capture` without a payload, which Xray's fragment manager
    /// refuses.
    fn bad_finalmask_model() -> FinalmaskModel {
        FinalmaskModel {
            tcp: vec![FinalmaskTcpMask::HeaderCustom {
                settings: FinalmaskHeaderCustomTcp {
                    clients: vec![vec![FinalmaskTcpItem {
                        capture: "client".into(),
                        ..Default::default()
                    }]],
                    ..Default::default()
                },
                extra: Default::default(),
            }],
            udp: Vec::new(),
            quic_params: None,
            extra: Default::default(),
        }
    }

    fn profile_with_bad_finalmask() -> ServerProfile {
        let mut profile = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        profile.outbound.stream.finalmask = Some(bad_finalmask_model());
        profile
    }

    /// The gate's two compositions over every combination of its five facts:
    /// unsaved changes is the union of the draft's two dirty flags, and a
    /// commit needs a draft that differs from its source and that no
    /// error-severity finding blocks. The two facts that move without a draft
    /// edit (the validation job, the busy window) are the compositions' own
    /// business at the site — the action row's reading of them is pinned by
    /// `editor_action_row_renders_the_gate_fact_combinations`.
    #[test]
    fn draft_gate_compositions_read_every_fact() {
        for bits in 0..32u8 {
            let changed = bits & 1 != 0;
            let raw = bits & 2 != 0;
            let blocking = bits & 4 != 0;
            let gate = DraftGate {
                changed_from_source: changed,
                raw_buffers_dirty: raw,
                blocking,
                validating: bits & 8 != 0,
                busy: bits & 16 != 0,
            };
            assert_eq!(gate.dirty(), changed || raw, "unsaved changes: {bits:05b}");
            assert_eq!(
                gate.committable(),
                changed && !blocking,
                "a commit needs an edited draft that nothing blocks: {bits:05b}"
            );
        }
    }

    /// The editor action row's rendered enablement for the three fact
    /// combinations a user can reach: an edited draft that carries a blocking
    /// finding (nothing to save, something to discard), an edited draft that
    /// nothing blocks (both controls live), and a pristine draft (neither).
    #[test]
    fn editor_action_row_renders_the_gate_fact_combinations() {
        fn install(screen: &mut ServersScreen, profile: &ServerProfile, source: serde_json::Value) {
            let generation = screen
                .existing_draft
                .as_ref()
                .map_or(1, |draft| draft.generation.wrapping_add(1));
            screen.existing_draft = Some(ExistingProfileDraft {
                id: profile.id.clone(),
                tag: profile.tag(),
                profile: profile.clone(),
                source,
                generation,
            });
        }

        let clean = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(clean.clone());
        rig.servers.active = Some(clean.id.clone());
        let mut harness = wide_servers_harness(rig);
        harness.run();
        // The pristine draft: nothing to save and nothing to discard.
        assert_eq!(
            action_row_disabled(&harness),
            (true, true),
            "a draft that matches its source offers neither control"
        );

        // The same draft with an edit behind it: both controls are live.
        let mut edited = clean.clone();
        edited.name = "Tokyo edited".into();
        install(
            &mut harness.state_mut().0,
            &edited,
            serde_json::to_value(&clean).unwrap(),
        );
        harness.run();
        assert_eq!(
            action_row_disabled(&harness),
            (false, false),
            "an edited draft that nothing blocks must be saveable and discardable"
        );

        // The edit plus a blocking finding: Discard stays, Save goes dark.
        let mut blocked = edited.clone();
        blocked.outbound.stream.finalmask = Some(bad_finalmask_model());
        install(
            &mut harness.state_mut().0,
            &blocked,
            serde_json::to_value(&clean).unwrap(),
        );
        harness.run();
        assert!(
            !editor_blocking(&harness).is_empty(),
            "the fixture draft must carry a blocking finding"
        );
        assert_eq!(
            action_row_disabled(&harness),
            (true, false),
            "a blocking finding must take Save dark without touching Discard"
        );
    }

    /// The editor action row's two controls on the frame just rendered, as
    /// (Validate-and-save disabled, Discard disabled).
    fn action_row_disabled(harness: &Harness<'static, (ServersScreen, UiTestRig)>) -> (bool, bool) {
        let disabled = |label: &str| {
            harness
                .get_by_role_and_label(egui::accesskit::Role::Button, label)
                .accesskit_node()
                .is_disabled()
        };
        (
            disabled(t(Language::En, Key::SrvValidateAndSave)),
            disabled(t(Language::En, Key::SrvDiscardChanges)),
        )
    }

    /// The editor memo answers from the draft generation it was swept for: a
    /// refresh at the same generation keeps the findings it holds (a draft
    /// mutated behind its back must not be re-validated), a moved generation
    /// sweeps again, and the rendered strings are a function of the findings
    /// rather than of the profile — which is what makes a language change a
    /// re-render instead of a re-validation.
    #[test]
    fn editor_validation_memo_reuses_findings_until_the_generation_moves() {
        let mut profile = ServerProfile::new("vless", OutboundModel::new(Protocol::Vless));
        {
            let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
                unreachable!()
            };
            settings.address = "example.com".into();
            settings.port = 443;
            settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
            settings.encryption = "none".into();
        }
        let mut draft = ExistingProfileDraft {
            id: profile.id.clone(),
            tag: profile.tag(),
            source: serde_json::to_value(&profile).expect("the fixture serializes"),
            profile,
            generation: 1,
        };

        let mut cache = None;
        refresh_editor_validation(&mut cache, &draft, Language::En);
        let swept = cache.as_ref().expect("the first refresh sweeps the draft");
        assert_eq!(
            codes_of(&swept.findings.blocking),
            vec![ValidationCode::PublicVlessRequiresTlsOrEncryption],
            "{:#?}",
            swept.findings.blocking
        );
        let rendered = swept.rendered.blocking.clone();
        assert_eq!(rendered.len(), 1);

        // The same generation with a different profile behind it: the memo
        // keeps the sweep it made, and the strings it renders stay the ones
        // those findings produce (no re-validation, no re-render).
        draft.profile = ServerProfile::new("direct", OutboundModel::new(Protocol::Freedom));
        refresh_editor_validation(&mut cache, &draft, Language::En);
        let reused = cache.as_ref().expect("the memo stays populated");
        assert_eq!(
            codes_of(&reused.findings.blocking),
            vec![ValidationCode::PublicVlessRequiresTlsOrEncryption],
            "a same-generation refresh must not re-sweep: {:#?}",
            reused.findings.blocking
        );
        assert_eq!(
            reused.rendered.blocking, rendered,
            "the strings come from the findings, not from the profile"
        );

        // A moved generation sweeps the profile as it is now and renders it.
        draft.source = serde_json::to_value(&draft.profile).expect("the fixture serializes");
        draft.generation = 2;
        refresh_editor_validation(&mut cache, &draft, Language::En);
        let reswept = cache.as_ref().expect("the memo stays populated");
        assert!(
            reswept.findings.blocking.is_empty(),
            "{:#?}",
            reswept.findings.blocking
        );
        assert!(reswept.rendered.blocking.is_empty());
        assert!(
            reswept.rendered.advisory.is_empty(),
            "{:#?}",
            reswept.rendered.advisory
        );
    }

    /// The Advanced tab renders the draft's finalmask verdicts inline, in
    /// model order, and follows a draft edit that adds one — the verdicts
    /// come from the sweep the draft's generation was validated with.
    #[test]
    fn advanced_tab_finalmask_verdicts_render_inline_and_track_edits() {
        let mut rig = UiTestRig::default();
        let tokyo = profile_with_bad_finalmask();
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.active = Some(tokyo.id.clone());
        let mut harness = unsaved_harness(rig);
        harness.run();
        harness.get_by_label("Advanced").click();
        harness.run();
        assert!(
            harness.query_by_label(BAD_TCP_ITEM_MESSAGE).is_some(),
            "the finalmask verdict must render inline on the Advanced tab"
        );
        assert_eq!(
            harness
                .state()
                .0
                .editor_validation_cache
                .as_ref()
                .expect("the draft-open frame seeds the finalmask verdicts")
                .findings
                .finalmask
                .iter()
                .map(|issue| issue.path.clone())
                .collect::<Vec<_>>(),
            vec![Some("finalmask.tcp[0].settings.clients[0][0]".into())],
        );
        harness.run();
        assert!(
            harness.query_by_label(BAD_TCP_ITEM_MESSAGE).is_some(),
            "the verdict must keep rendering on idle frames"
        );
        // One edit that adds a second invalid item: the next sweep carries
        // both verdicts in model order, and the second renders inline.
        let state = harness.state_mut();
        let draft = state.0.existing_draft.as_mut().unwrap();
        let FinalmaskTcpMask::HeaderCustom { settings, .. } = &mut draft
            .profile
            .outbound
            .stream
            .finalmask
            .as_mut()
            .expect("the fixture profile carries a finalmask")
            .tcp[0]
        else {
            panic!("the fixture mask is a header-custom TCP mask");
        };
        settings.clients[0].push(FinalmaskTcpItem {
            capture: "client2".into(),
            ..Default::default()
        });
        draft.generation = draft.generation.wrapping_add(1);
        harness.run();
        let generation = harness
            .state()
            .0
            .existing_draft
            .as_ref()
            .expect("the editor keeps the edited draft")
            .generation;
        let cache = harness
            .state()
            .0
            .editor_validation_cache
            .as_ref()
            .expect("the edited draft must be covered by a fresh sweep");
        assert_eq!(
            cache.generation, generation,
            "the findings must describe the draft's current generation"
        );
        let second_message = "finalmask.tcp[0].settings.clients[0][1]: set exactly one of \
            packet, positive rand, reuse, or transform when capture is used";
        assert_eq!(
            cache.rendered.finalmask,
            vec![BAD_TCP_ITEM_MESSAGE.to_string(), second_message.to_string()],
            "the sweep must carry both verdicts in model order"
        );
        assert!(
            harness.query_by_label(second_message).is_some(),
            "the edited verdict must render inline"
        );
    }

    /// A rig whose active profile carries the retired `proxySettings` key in
    /// the shape a stored file would hold, with a second profile to chain to.
    fn retired_key_rig() -> (UiTestRig, ServerProfile, ServerProfile) {
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        tokyo.outbound.retired_proxy_settings = Some(json!({"tag": "srv-exit"}));
        let osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        rig.servers.active = Some(tokyo.id.clone());
        (rig, tokyo, osaka)
    }

    /// The draft's blocking findings, as the editor's own sweep produced them.
    fn editor_blocking(
        harness: &Harness<'static, (ServersScreen, UiTestRig)>,
    ) -> Vec<ValidationIssue> {
        harness
            .state()
            .0
            .editor_validation_cache
            .as_ref()
            .expect("the editor validates the draft")
            .findings
            .blocking
            .clone()
    }

    #[test]
    fn retired_proxy_settings_finding_lists_the_chain_fix_and_clears_on_a_chain_decision() {
        // A stored profile from a build that still wrote `proxySettings`:
        // the editor opens on it (the load does not fail), the blocking list
        // names the replacement, and the Advanced tab carries exactly one
        // control for the chain target — the sockopt picker.
        let (rig, tokyo, osaka) = retired_key_rig();
        let mut harness = unsaved_harness(rig);
        harness.run();
        assert!(
            harness.state().0.existing_draft.is_some(),
            "a profile with the retired key must stay editable"
        );
        assert!(
            editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::OutboundProxySettingsRemoved),
            "{:#?}",
            editor_blocking(&harness)
        );

        harness.get_by_label("Advanced").click();
        harness.run();
        assert_eq!(
            harness.get_all_by_label("dialerProxy").count(),
            1,
            "exactly one editor control edits the chain target"
        );
        assert!(
            harness
                .query_by_label("proxySettings.tag (chain via)")
                .is_none(),
            "the retired chain combo must be gone"
        );

        // An unrelated edit (the name) must leave the gate in place: only a
        // chain decision resolves the retired key.
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.value().as_deref() == Some("Tokyo"))
            .expect("the name field")
            .click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.is_focused())
            .expect("the name field keeps focus")
            .type_text("-2");
        harness.run();
        let state = harness.state();
        assert!(
            state
                .0
                .existing_draft
                .as_ref()
                .expect("the editor stays open")
                .profile
                .outbound
                .retired_proxy_settings
                .is_some(),
            "a rename must not dismiss the retired key"
        );
        assert!(
            editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::OutboundProxySettingsRemoved),
            "the finding must survive an unrelated edit"
        );

        // Setting the target with the chain picker is the decision: the key
        // is dropped from the draft, the finding leaves the blocking list,
        // and the profile serializes without the key. The picker starts on
        // the empty meaning ("(none)") and sits at the bottom of the tab, so
        // scroll it into view first.
        let empty_label = t(Language::En, Key::NoneSelected);
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .find(|node| node.value().as_deref() == Some(empty_label))
            .expect("the chain-target picker starts empty")
            .scroll_to_me();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .find(|node| node.value().as_deref() == Some(empty_label))
            .expect("the chain-target picker starts empty")
            .click();
        harness.run();
        // The open popup offers every other profile's tag in list order,
        // then the built-in targets — and never the edited profile's own tag
        // (a chain to itself could only produce a cycle). The popup's option
        // rows are the only buttons carrying a tag label in this frame
        // (the editor's other buttons are icon or action labels).
        use egui_kittest::kittest::NodeT as _;
        let button_labels: Vec<String> = harness
            .root()
            .children_recursive()
            .filter(|node| node.accesskit_node().role() == egui::accesskit::Role::Button)
            .filter_map(|node| node.accesskit_node().label())
            .collect();
        let listed: Vec<&str> = button_labels
            .iter()
            .map(String::as_str)
            .filter(|label| label.starts_with("srv-") || matches!(*label, "direct" | "block"))
            .collect();
        assert_eq!(
            listed,
            [osaka.tag().as_str(), "direct", "block"],
            "the picker offers the other profiles' tags, then direct and block"
        );
        assert!(
            !button_labels.iter().any(|label| label == &tokyo.tag()),
            "the edited profile's own tag must not be a chain option"
        );
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, &osaka.tag())
            .click();
        harness.run();
        let state = harness.state();
        let draft = state
            .0
            .existing_draft
            .as_ref()
            .expect("the editor stays open");
        assert_eq!(
            draft
                .profile
                .outbound
                .stream
                .sockopt
                .as_ref()
                .map(|sockopt| sockopt.dialer_proxy.as_str()),
            Some(osaka.tag().as_str()),
            "the picker must edit the chain target"
        );
        assert!(
            draft.profile.outbound.retired_proxy_settings.is_none(),
            "the chain decision clears the retired key"
        );
        let persisted = serde_json::to_value(&draft.profile).expect("the draft serializes");
        assert!(
            persisted["outbound"].get("proxySettings").is_none(),
            "the resolved profile must serialize without the key: {persisted}"
        );
        assert!(
            !editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::OutboundProxySettingsRemoved),
            "{:#?}",
            editor_blocking(&harness)
        );
    }

    #[test]
    fn dialer_proxy_picker_clears_the_chain_and_keeps_a_stored_unknown_tag() {
        // A stored target naming no profile must keep displaying and stay
        // untouched until the user picks another option: validation — not
        // the editor — reports the dangling reference, so the picker must
        // never silently rewrite it into a resolvable tag.
        let stored = "srv-stale";
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        tokyo.outbound.stream.sockopt = Some(SockoptModel {
            dialer_proxy: stored.into(),
            ..Default::default()
        });
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(ServerProfile::new(
            "Osaka",
            OutboundModel::new(Protocol::Freedom),
        ));
        rig.servers.active = Some(tokyo.id.clone());
        let mut harness = unsaved_harness(rig);
        harness.run();
        harness.get_by_label("Advanced").click();
        harness.run();

        // The raw value is the picker's selection even though no option
        // matches it, and idle frames keep it verbatim (the draft's own
        // value and what it serializes to).
        assert!(
            harness
                .get_all_by_role(egui::accesskit::Role::ComboBox)
                .any(|node| node.value().as_deref() == Some(stored)),
            "the picker must display the stored chain target"
        );
        harness.run();
        let draft = harness
            .state()
            .0
            .existing_draft
            .as_ref()
            .expect("the editor stays open")
            .profile
            .clone();
        assert_eq!(
            draft
                .outbound
                .stream
                .sockopt
                .as_ref()
                .map(|sockopt| sockopt.dialer_proxy.as_str()),
            Some(stored),
            "an idle frame must not rewrite the stored chain target"
        );
        assert_eq!(
            serde_json::to_value(&draft).expect("the draft serializes")["outbound"]["streamSettings"]
                ["sockopt"]["dialerProxy"],
            json!(stored),
            "the stored spelling must round-trip unchanged"
        );

        // The empty entry clears the chain. The picker sits at the bottom of
        // the tab, so scroll it into view before opening it.
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .find(|node| node.value().as_deref() == Some(stored))
            .expect("the picker shows the stored tag")
            .scroll_to_me();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .find(|node| node.value().as_deref() == Some(stored))
            .expect("the picker shows the stored tag")
            .click();
        harness.run();
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::NoneSelected),
            )
            .click();
        harness.run();
        assert_eq!(
            harness
                .state()
                .0
                .existing_draft
                .as_ref()
                .expect("the editor stays open")
                .profile
                .outbound
                .stream
                .sockopt
                .as_ref()
                .map(|sockopt| sockopt.dialer_proxy.as_str()),
            Some(""),
            "the empty entry must clear the chain"
        );
    }

    #[test]
    fn advanced_chain_target_options_rebuild_once_per_set_change_and_never_on_idle_frames() {
        let mut rig = UiTestRig::default();
        let alpha = ServerProfile::new("alpha", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(alpha.clone());
        rig.servers.profiles.push(ServerProfile::new(
            "beta",
            OutboundModel::new(Protocol::Freedom),
        ));
        rig.servers.active = Some(alpha.id.clone());
        let mut harness = unsaved_harness(rig);
        harness.run();
        harness.get_by_label("Advanced").click();
        harness.run();
        // The options list's allocation identity is the memo, and its
        // generation is the profile-set signal it was built for.
        let built_for = harness
            .state()
            .0
            .dialer_proxy_options
            .as_ref()
            .expect("the first Advanced frame builds the chain-target options once")
            .generation;
        assert_eq!(
            built_for.2, 2,
            "the options must be built for the rendered profile set"
        );
        let options = harness
            .state()
            .0
            .dialer_proxy_options
            .as_ref()
            .expect("the options memo stays warm")
            .options
            .as_ptr();
        harness.run();
        harness.run();
        assert_eq!(
            harness
                .state()
                .0
                .dialer_proxy_options
                .as_ref()
                .expect("the options memo stays warm")
                .options
                .as_ptr(),
            options,
            "idle frames must not rebuild the chain-target options"
        );
        // A profile-set change rebuilds exactly once; idle frames after it
        // stay quiet.
        let gamma = ServerProfile::new("gamma", OutboundModel::new(Protocol::Freedom));
        let gamma_tag = gamma.tag();
        harness.state_mut().1.servers.profiles.push(gamma);
        harness.run();
        let rebuilt = harness
            .state()
            .0
            .dialer_proxy_options
            .as_ref()
            .expect("the set change must rebuild the chain-target options exactly once");
        assert_ne!(
            rebuilt.generation, built_for,
            "the rebuilt options must carry the advanced profile-set signal"
        );
        assert!(
            rebuilt.options.iter().any(|option| option == &gamma_tag),
            "the rebuilt options must offer the profile the set gained"
        );
        let rebuilt_options = rebuilt.options.as_ptr();
        harness.run();
        harness.run();
        assert_eq!(
            harness
                .state()
                .0
                .dialer_proxy_options
                .as_ref()
                .expect("the options memo stays warm")
                .options
                .as_ptr(),
            rebuilt_options,
            "idle frames after the set change must not rebuild"
        );
    }

    #[test]
    fn retired_proxy_settings_dismissal_drops_the_key_without_a_chain() {
        // A user who wants no chain resolves the finding with the dismissal
        // control on the finding row: the key is dropped, no field changes,
        // and the profile serializes without it.
        let (rig, _tokyo, _osaka) = retired_key_rig();
        let mut harness = unsaved_harness(rig);
        harness.run();
        let before = harness
            .state()
            .0
            .existing_draft
            .as_ref()
            .expect("the draft opens")
            .profile
            .clone();
        assert!(
            harness
                .query_by_label("The app removes the retired key. The server dials directly.")
                .is_some(),
            "the note must state the dropped chain when none is set"
        );

        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                "Remove the proxySettings key",
            )
            .click();
        harness.run();
        harness.run();
        let state = harness.state();
        let draft = state
            .0
            .existing_draft
            .as_ref()
            .expect("the editor stays open");
        assert!(
            draft.profile.outbound.retired_proxy_settings.is_none(),
            "the dismissal must clear the retired key"
        );
        assert_eq!(
            draft.profile.chain_target(),
            None,
            "the dismissal must not invent a chain"
        );
        assert_eq!(
            draft.profile.name, before.name,
            "the dismissal must not touch other fields"
        );
        assert_eq!(
            draft.profile.outbound.settings.protocol(),
            before.outbound.settings.protocol()
        );
        let persisted = serde_json::to_value(&draft.profile).expect("the draft serializes");
        assert!(
            persisted["outbound"].get("proxySettings").is_none(),
            "the dismissed profile must serialize without the key: {persisted}"
        );
        assert!(
            !editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::OutboundProxySettingsRemoved),
            "{:#?}",
            editor_blocking(&harness)
        );
    }

    #[test]
    fn retired_proxy_settings_dismissal_note_follows_the_chain_state() {
        // A profile that still dials through another server keeps its chain
        // when the key is dismissed, so the "dials directly" note stays off
        // and the dismissal only drops the key.
        let (mut rig, tokyo, osaka) = retired_key_rig();
        let osaka_tag = osaka.tag();
        rig.servers
            .profiles
            .iter_mut()
            .find(|profile| profile.id == tokyo.id)
            .expect("the fixture profile")
            .outbound
            .chain_via(&osaka_tag);
        let mut harness = unsaved_harness(rig);
        harness.run();
        assert!(
            harness
                .query_by_label("The app removes the retired key. The server dials directly.")
                .is_none(),
            "the note must not claim a dropped chain while one is set"
        );
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                "Remove the proxySettings key",
            )
            .click();
        harness.run();
        harness.run();
        let state = harness.state();
        let draft = state
            .0
            .existing_draft
            .as_ref()
            .expect("the editor stays open");
        assert!(
            draft.profile.outbound.retired_proxy_settings.is_none(),
            "the dismissal must clear the retired key"
        );
        assert_eq!(
            draft.profile.chain_target(),
            Some(osaka_tag.as_str()),
            "the dismissal must keep an existing chain"
        );
    }

    /// A rig whose active profile carries the retired `quicParams.udpHop`
    /// key in the shape a stored file would hold.
    fn retired_hop_rig() -> UiTestRig {
        let mut profile = ServerProfile::new("Hy", OutboundModel::new(Protocol::Freedom));
        profile.outbound.stream.finalmask = Some(FinalmaskModel {
            quic_params: Some(FinalmaskQuicParams {
                retired_udp_hop: Some(json!({"ports": "443,10000-10010", "interval": "5-10"})),
                ..Default::default()
            }),
            ..Default::default()
        });
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(profile.clone());
        rig.servers.active = Some(profile.id.clone());
        rig
    }

    /// The draft's `quicParams` as the editor holds it.
    fn draft_quic_params(
        harness: &Harness<'static, (ServersScreen, UiTestRig)>,
    ) -> FinalmaskQuicParams {
        harness
            .state()
            .0
            .existing_draft
            .as_ref()
            .expect("the editor stays open")
            .profile
            .outbound
            .stream
            .finalmask
            .as_ref()
            .and_then(|finalmask| finalmask.quic_params.clone())
            .expect("the fixture carries quicParams")
    }

    /// The draft's first `udphop` mask mode, as the editor holds it.
    fn draft_udphop_mode(harness: &Harness<'static, (ServersScreen, UiTestRig)>) -> String {
        let draft = &harness
            .state()
            .0
            .existing_draft
            .as_ref()
            .expect("the editor stays open")
            .profile;
        draft
            .outbound
            .stream
            .finalmask
            .as_ref()
            .and_then(|finalmask| {
                finalmask.udp.iter().find_map(|mask| match mask {
                    FinalmaskUdpMask::Udphop { settings, .. } => Some(settings.mode.clone()),
                    _ => None,
                })
            })
            .expect("the fixture carries a udphop mask")
    }

    #[test]
    fn retired_udp_hop_finding_lists_the_mask_fix_and_clears_on_a_rebuild() {
        // A stored profile from a build that still wrote the hop under the
        // QUIC parameters: the editor opens on it, the blocking list names
        // the mask and the equivalence, and only building the mask resolves
        // the key.
        let mut harness = wide_servers_harness(retired_hop_rig());
        harness.run();
        assert!(
            harness.state().0.existing_draft.is_some(),
            "a profile with the retired key must stay editable"
        );
        let blocking = editor_blocking(&harness);
        let hop = finding(&blocking, ValidationCode::FinalmaskQuicHopMoved);
        let message = validation_issue_message(&hop, Language::En);
        assert!(
            message.contains("intervalLocal") && message.contains("intervalRemote"),
            "the fix-it text must state the equivalence: {message:?}"
        );

        harness.get_by_label("Advanced").click();
        harness.run();
        assert!(
            harness.query_by_label("udpHop").is_none(),
            "the retired QUIC-location control must be gone"
        );

        // An unrelated edit (the name) must leave the gate in place.
        edit_existing_draft(&mut harness.state_mut().0);
        harness.run();
        let renamed = harness
            .state()
            .0
            .existing_draft
            .as_ref()
            .unwrap()
            .profile
            .name
            .clone();
        assert!(
            draft_quic_params(&harness).retired_udp_hop.is_some(),
            "a rename must not dismiss the retired key"
        );

        // Rebuilding the hop as a UDP mask is the decision: the new mask
        // replaces the retired key in the same edit.
        harness.get_by_label("+ UDP mask").click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .into_iter()
            .find(|node| node.value().as_deref() == Some("header-custom"))
            .expect("the added mask's type combo")
            .click();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "udphop")
            .click();
        harness.run();
        harness.run();
        assert!(
            draft_quic_params(&harness).retired_udp_hop.is_none(),
            "rebuilding the hop as the mask must clear the retired key"
        );
        assert!(
            !editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::FinalmaskQuicHopMoved),
            "{:#?}",
            editor_blocking(&harness)
        );
        let draft = &harness.state().0.existing_draft.as_ref().unwrap().profile;
        assert_eq!(
            draft.outbound.stream.finalmask.as_ref().unwrap().udp.len(),
            1,
            "the rebuilt hop must stay in the mask list"
        );
        assert_eq!(
            draft.name, renamed,
            "the rebuild must not touch other fields"
        );
        let persisted = serde_json::to_value(draft).expect("the draft serializes");
        assert!(
            persisted["outbound"]["streamSettings"]["finalmask"]["quicParams"]
                .get("udpHop")
                .is_none(),
            "the resolved profile must serialize without the key: {persisted}"
        );
    }

    #[test]
    fn retired_udp_hop_dismissal_drops_the_key_without_a_mask() {
        // A user who wants no hop resolves the finding with the dismissal
        // control on the finding row: the key is dropped, no field changes,
        // and the profile serializes without it.
        let mut harness = wide_servers_harness(retired_hop_rig());
        harness.run();
        let before = harness
            .state()
            .0
            .existing_draft
            .as_ref()
            .expect("the draft opens")
            .profile
            .clone();
        assert!(
            harness
                .query_by_label("The app removes the retired key. The hop stops working.")
                .is_some(),
            "the note must state what the dismissed hop costs"
        );
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "Remove the udpHop key")
            .click();
        harness.run();
        harness.run();
        assert!(
            draft_quic_params(&harness).retired_udp_hop.is_none(),
            "the dismissal must clear the retired key"
        );
        let draft = &harness.state().0.existing_draft.as_ref().unwrap().profile;
        assert_eq!(
            draft.name, before.name,
            "the dismissal must not touch other fields"
        );
        assert!(
            draft
                .outbound
                .stream
                .finalmask
                .as_ref()
                .is_none_or(|finalmask| finalmask.udp.is_empty()),
            "the dismissal must not invent a mask"
        );
        let persisted = serde_json::to_value(draft).expect("the draft serializes");
        assert!(
            persisted["outbound"]["streamSettings"]["finalmask"]["quicParams"]
                .get("udpHop")
                .is_none(),
            "the dismissed profile must serialize without the key: {persisted}"
        );
        assert!(
            !editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::FinalmaskQuicHopMoved),
            "{:#?}",
            editor_blocking(&harness)
        );
    }

    /// The combo control an `opt_bool` row renders: the switch label and its
    /// combo sit in one horizontal row, and the combo carries no accessible
    /// name of its own, so it is found as the single combo in the label's
    /// row — the nearest ancestor whose subtree holds exactly one.
    fn quic_switch_combo<'a>(
        harness: &'a Harness<'static, (ServersScreen, UiTestRig)>,
        label: &str,
    ) -> egui_kittest::Node<'a> {
        use egui_kittest::kittest::NodeT as _;
        let label_node = harness
            .root()
            .children_recursive()
            .find(|node| {
                // egui text labels carry their text as the accesskit value,
                // not as the node label.
                let node = node.accesskit_node();
                node.label().as_deref() == Some(label)
                    || (node.role() == egui::accesskit::Role::Label
                        && node.value().as_deref() == Some(label))
            })
            .unwrap_or_else(|| panic!("the {label} switch must render: {:?}", harness.root()));
        let mut ancestor = label_node.parent();
        while let Some(row) = ancestor {
            let mut combos = row
                .children_recursive()
                .filter(|node| node.accesskit_node().role() == egui::accesskit::Role::ComboBox);
            if let Some(combo) = combos.next()
                && combos.next().is_none()
            {
                return combo;
            }
            ancestor = row.parent();
        }
        panic!("no row pairs the {label} switch label with exactly one combo");
    }

    #[test]
    fn quic_switch_rows_edit_and_round_trip_through_the_settings_file() {
        // The client-side switches upstream added to `quicParams`
        // (`infra/conf/transport_finalmask.go:993-1011`): each row is an
        // "(unset)/true/false" control, an unset switch never reaches the
        // generated configuration, and a set one survives a save/load cycle
        // under its upstream key. `disableStatelessReset` is listener-only
        // upstream, so it gets no row — the model keeps it for round-trip
        // and the raw override.
        const SWITCH_KEYS: [&str; 3] = [
            "brutalDisableLossCompensation",
            "disableChromeParrot",
            "disableGSO",
        ];
        let mut profile = ServerProfile::new("Hy", OutboundModel::new(Protocol::Hysteria));
        profile.outbound.settings = ProtocolSettings::Hysteria(crate::model::HysteriaSettings {
            address: "hy.example.com".into(),
            port: 443,
            ..Default::default()
        });
        profile.outbound.stream.finalmask = Some(FinalmaskModel {
            quic_params: Some(FinalmaskQuicParams::default()),
            ..Default::default()
        });
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(profile.clone());
        rig.servers.active = Some(profile.id.clone());
        let mut harness = wide_servers_harness(rig);
        harness.run();
        harness.get_by_label("Advanced").click();
        harness.run();

        // The listener-only switch stays out of the editor.
        {
            use egui_kittest::kittest::NodeT as _;
            assert!(
                harness.root().children_recursive().all(|node| {
                    let node = node.accesskit_node();
                    node.label().as_deref() != Some("disableStatelessReset")
                        && node.value().as_deref() != Some("disableStatelessReset")
                }),
                "the listener-only switch must not render an editor row"
            );
        }

        // Untouched, none of the switches is emitted.
        let unset = harness
            .state()
            .0
            .existing_draft
            .as_ref()
            .expect("the editor stays open")
            .profile
            .outbound
            .to_wire("srv-01234567");
        let unset_quic = &unset["streamSettings"]["finalmask"]["quicParams"];
        for key in SWITCH_KEYS {
            assert!(
                unset_quic.get(key).is_none(),
                "an unset {key} must not reach the wire: {unset_quic}"
            );
        }

        // Set them all through their editor rows.
        for key in SWITCH_KEYS {
            quic_switch_combo(&harness, key).scroll_to_me();
            harness.run();
            quic_switch_combo(&harness, key).click();
            harness.run();
            harness
                .get_by_role_and_label(egui::accesskit::Role::Button, "true")
                .click();
            harness.run();
        }
        let edited = draft_quic_params(&harness);
        assert_eq!(edited.brutal_disable_loss_compensation, Some(true));
        assert_eq!(edited.disable_chrome_parrot, Some(true));
        assert_eq!(edited.disable_gso, Some(true));
        assert_eq!(
            edited.disable_stateless_reset, None,
            "the row-less switch must stay unset"
        );

        // The settings file keeps every set switch, and the reloaded profile
        // still holds it.
        let draft = harness
            .state()
            .0
            .existing_draft
            .as_ref()
            .expect("the editor stays open")
            .profile
            .clone();
        let persisted = serde_json::to_value(&draft).expect("the draft serializes");
        let persisted_quic = &persisted["outbound"]["streamSettings"]["finalmask"]["quicParams"];
        for key in SWITCH_KEYS {
            assert_eq!(
                persisted_quic[key],
                json!(true),
                "{key} must survive the save: {persisted_quic}"
            );
        }
        let reloaded: ServerProfile =
            serde_json::from_value(persisted).expect("the saved profile loads");
        let reloaded_quic = reloaded
            .outbound
            .stream
            .finalmask
            .as_ref()
            .and_then(|finalmask| finalmask.quic_params.clone())
            .expect("the reloaded profile keeps quicParams");
        assert_eq!(reloaded_quic.brutal_disable_loss_compensation, Some(true));
        assert_eq!(reloaded_quic.disable_chrome_parrot, Some(true));
        assert_eq!(reloaded_quic.disable_gso, Some(true));

        // And the generated configuration (what the preview shows) carries
        // them under the same keys.
        let wire = draft.outbound.to_wire("srv-01234567");
        let wire_quic = &wire["streamSettings"]["finalmask"]["quicParams"];
        for key in SWITCH_KEYS {
            assert_eq!(wire_quic[key], json!(true), "{wire_quic}");
        }
    }

    #[test]
    fn udphop_mask_editor_edits_the_combinable_mode_set_and_the_settings() {
        // The mode is one comma-separated set: the three checkboxes rewrite
        // the known tokens in canonical order, and a stored token outside the
        // three names stays in the value, so the validation finding keeps
        // naming it instead of a checkbox edit dropping the user's text.
        let mut profile = ServerProfile::new("Hy", OutboundModel::new(Protocol::Hysteria));
        profile.outbound.stream.finalmask = Some(FinalmaskModel {
            udp: vec![
                serde_json::from_value(json!({
                    "type": "udphop",
                    "settings": {
                        "mode": "perConnRemote,banana",
                        "interval": "5-10",
                        "remotePorts": "443",
                        "remoteIPs": ["203.0.113.10"]
                    }
                }))
                .expect("the udphop envelope loads"),
            ],
            ..Default::default()
        });
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(profile.clone());
        rig.servers.active = Some(profile.id.clone());
        let mut harness = wide_servers_harness(rig);
        harness.run();
        harness.get_by_label("Advanced").click();
        harness.run();

        // Every setting of the mask is on screen.
        for mode in ["intervalLocal", "intervalRemote", "perConnRemote"] {
            assert!(
                harness
                    .query_by_role_and_label(egui::accesskit::Role::CheckBox, mode)
                    .is_some(),
                "the {mode} mode checkbox must render"
            );
        }
        assert!(harness.query_by_label("interval (s)").is_some());
        assert!(harness.query_by_label("remotePorts").is_some());
        assert!(harness.query_by_label("remoteIPs").is_some());
        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::CheckBox, "sockopt")
                .is_some(),
            "the per-mask socket options must render"
        );

        // intervalLocal joins the set; the stored unknown token rides along.
        harness
            .get_by_role_and_label(egui::accesskit::Role::CheckBox, "intervalLocal")
            .click();
        harness.run();
        assert_eq!(
            draft_udphop_mode(&harness),
            "intervalLocal,perConnRemote,banana"
        );
        // Adding intervalRemote and dropping perConnRemote leaves the old
        // hop's equivalent pair; the unknown token still rides along.
        harness
            .get_by_role_and_label(egui::accesskit::Role::CheckBox, "intervalRemote")
            .click();
        harness.run();
        assert_eq!(
            draft_udphop_mode(&harness),
            "intervalLocal,intervalRemote,perConnRemote,banana"
        );
        harness
            .get_by_role_and_label(egui::accesskit::Role::CheckBox, "perConnRemote")
            .click();
        harness.run();
        assert_eq!(
            draft_udphop_mode(&harness),
            "intervalLocal,intervalRemote,banana"
        );
    }

    /// The add dialog's memo mirrors the editor's: a refresh at the same
    /// generation keeps the findings it holds, a moved generation sweeps
    /// again, and its strings follow the findings it swept.
    #[test]
    fn add_draft_memo_reuses_findings_until_the_generation_moves() {
        let draft = profile_with_bad_finalmask();
        let mut cache = None;
        refresh_add_draft_validation(&mut cache, 0, &draft, Language::En);
        let swept = cache
            .as_ref()
            .expect("the first refresh sweeps the add draft");
        let verdicts = codes_of(&swept.findings.finalmask);
        assert_eq!(verdicts.len(), 1, "{:#?}", swept.findings.finalmask);
        let rendered = swept.rendered.finalmask.clone();

        // The same generation with a different draft behind it: the memo
        // answers with the sweep it made (the dialog bumps the generation on
        // every content edit, so this is the idle-frame path).
        let mut edited = draft.clone();
        edited.name = "edited".into();
        refresh_add_draft_validation(&mut cache, 0, &edited, Language::En);
        let reused = cache.as_ref().expect("the memo stays populated");
        assert_eq!(
            codes_of(&reused.findings.finalmask),
            verdicts,
            "a same-generation refresh must not re-sweep: {:#?}",
            reused.findings.finalmask
        );
        assert_eq!(reused.rendered.finalmask, rendered);

        // A moved generation sweeps the clean draft it is handed.
        let clean = ServerProfile::new("direct", OutboundModel::new(Protocol::Freedom));
        refresh_add_draft_validation(&mut cache, 1, &clean, Language::En);
        let reswept = cache.as_ref().expect("the memo stays populated");
        assert!(reswept.findings.finalmask.is_empty());
        assert!(reswept.rendered.finalmask.is_empty());
    }

    #[test]
    fn finalmask_type_combo_switches_to_known_types_and_leaves_unknowns_alone() {
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        tokyo.outbound.stream.finalmask = Some(FinalmaskModel {
            tcp: vec![FinalmaskTcpMask::Unknown(json!({"type": "future-x"}))],
            udp: Vec::new(),
            quic_params: None,
            extra: Default::default(),
        });
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.active = Some(tokyo.id.clone());
        let mut harness = wide_servers_harness(rig);
        harness.run();
        harness.get_by_label("Advanced").click();
        harness.run();
        // The unknown envelope's combo shows the translated placeholder with
        // the retained discriminator.
        let unknown_combo = "Unknown (future-x)";
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .find(|node| node.value().as_deref() == Some(unknown_combo))
            .expect("the unknown mask's type combo shows its placeholder")
            .click();
        harness.run();
        // Picking a known type replaces the unknown envelope; the edit
        // re-validates exactly once.
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "header-custom")
            .click();
        harness.run();
        assert_eq!(
            harness
                .state()
                .0
                .existing_draft
                .as_ref()
                .unwrap()
                .profile
                .outbound
                .stream
                .finalmask
                .as_ref()
                .unwrap()
                .tcp[0]
                .known_type(),
            Some("header-custom"),
            "picking a known type must convert the unknown mask"
        );
        assert_eq!(
            harness
                .state()
                .0
                .editor_validation_cache
                .as_ref()
                .expect("the conversion edit must re-validate exactly once")
                .generation,
            harness
                .state()
                .0
                .existing_draft
                .as_ref()
                .expect("the editor keeps the converted draft")
                .generation,
            "the conversion edit must re-validate exactly once"
        );
        // Re-picking the current type of a known mask is a no-op: the draft
        // generation — the key every edit bumps and the memo sweeps on —
        // must not move.
        let generation = harness
            .state()
            .0
            .existing_draft
            .as_ref()
            .expect("the editor keeps the converted draft")
            .generation;
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .find(|node| node.value().as_deref() == Some("header-custom"))
            .expect("the converted mask's combo shows its known type")
            .click();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, "header-custom")
            .click();
        harness.run();
        assert_eq!(
            harness
                .state()
                .0
                .existing_draft
                .as_ref()
                .expect("the editor keeps the converted draft")
                .generation,
            generation,
            "re-picking the current type must not count as an edit"
        );
        assert_eq!(
            harness
                .state()
                .0
                .existing_draft
                .as_ref()
                .unwrap()
                .profile
                .outbound
                .stream
                .finalmask
                .as_ref()
                .unwrap()
                .tcp[0]
                .known_type(),
            Some("header-custom"),
            "the mask must keep its type after a same-type pick"
        );
    }

    /// The rows the virtualized list actually laid out: the consumer-visible
    /// band, counted from the rendered `Server {i:02}` row buttons of a
    /// [`seeded_rig`] list.
    fn laid_out_list_rows(harness: &Harness<'static, (ServersScreen, UiTestRig)>) -> u64 {
        (0..harness.state().1.servers.profiles.len())
            .filter(|index| {
                harness
                    .query_by_role_and_label(
                        egui::accesskit::Role::Button,
                        &format!("Server {index:02}"),
                    )
                    .is_some()
            })
            .count() as u64
    }

    /// Seed a rig with `count` freedom profiles named `Server {i:02}`.
    fn seeded_rig(count: usize) -> (UiTestRig, Vec<String>) {
        let mut rig = UiTestRig::default();
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let profile = ServerProfile::new(
                format!("Server {i:02}"),
                OutboundModel::new(Protocol::Freedom),
            );
            ids.push(profile.id.clone());
            rig.servers.profiles.push(profile);
        }
        (rig, ids)
    }

    #[test]
    fn server_list_lays_out_only_the_visible_band_and_idle_frames_keep_the_same_band() {
        // The profile list must lay out only the visible
        // index band. A 64-row list in the 1100x700 harness (list viewport
        // ~500 px, row pitch 18 + 3 = 21 px) shows ~25 of 64 rows; the
        // rendered rows must be the band, never the profile total, and idle
        // frames (same band) must lay out the same rows again.
        let (rig, _) = seeded_rig(64);
        let mut harness = wide_servers_harness(rig);
        harness.run();

        let band = laid_out_list_rows(&harness);
        // Even a full 700 px viewport fits ceil(700/21) + 2 fringe rows =
        // 36 rows at the very most; the real band is ~26, so anything above
        // the visible rows means the loop regressed to laying out the list.
        assert!(
            (15..=37).contains(&band),
            "the laid-out band must be the visible rows (~26), not all 64 (got {band})"
        );
        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "Server 63")
                .is_none(),
            "a row far below the fold must not be laid out before any scroll"
        );
        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "Server 00")
                .is_some(),
            "the first row must be laid out at the top of the list"
        );

        // Idle frames lay out the same band again: the rendered rows are the
        // ones the first frame showed.
        harness.run();
        harness.run_steps(2);
        assert_eq!(
            laid_out_list_rows(&harness),
            band,
            "idle frames must lay out the same band"
        );
    }

    #[test]
    fn server_list_rows_stay_interactive_after_scrolling_into_the_virtualized_band() {
        // After scrolling deep into the virtualized band, a
        // row must still select, probe, and stage a delete exactly like in
        // the full list — the band renders the same widgets at the same
        // geometry as the un-virtualized rows did.
        let (rig, ids) = seeded_rig(64);
        let mut harness = wide_servers_harness(rig);
        harness.run();
        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "Server 63")
                .is_none(),
            "the last row must not exist (be laid out) until the list is scrolled"
        );

        // Wheel-scroll to the bottom (content is 64 x 21 px ~= 1 344 px
        // tall). The pointer must hover the list for the wheel to reach it;
        // egui smooths wheel deltas over frames, so the trailing steps let
        // the scroll settle on the clamped bottom position.
        harness
            .input_mut()
            .events
            .push(egui::Event::PointerMoved(egui::pos2(100.0, 300.0)));
        for _ in 0..80 {
            harness.input_mut().events.push(egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, -100.0),
                phase: egui::TouchPhase::Move,
                modifiers: egui::Modifiers::NONE,
            });
            harness.step();
        }
        harness.run_steps(40);

        let row_rect = harness
            .query_by_role_and_label(egui::accesskit::Role::Button, "Server 63")
            .expect("the last row must be laid out once the list is scrolled to the bottom")
            .rect();
        let row_center = row_rect.center();
        assert!(
            row_center.x < 300.0 && row_center.y > 400.0,
            "the scrolled-to row must be painted inside the list's lower half (x={x}, y={y})",
            x = row_center.x,
            y = row_center.y
        );
        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::Button, "Server 00")
                .is_none(),
            "the first row must not be laid out once the list is scrolled to the bottom"
        );
        let row_y = row_center.y;
        assert!(
            (15..=37).contains(&laid_out_list_rows(&harness)),
            "the bottom band must still be the visible rows, not all 64"
        );

        // Clicking the name selects that profile: the band must map rows to
        // the right profiles after scrolling.
        harness
            .query_by_role_and_label(egui::accesskit::Role::Button, "Server 63")
            .expect("the last row is laid out")
            .click();
        harness.run_steps(2);
        assert_eq!(
            harness.state().0.selected.as_deref(),
            Some(ids[63].as_str()),
            "clicking a scrolled-to row must select that profile"
        );

        // The per-row probe button in the same band row sends exactly that
        // profile (y-centered on the row the name click used).
        harness
            .get_all_by_label("⚡")
            .find(|node| (node.rect().center().y - row_y).abs() < 8.0)
            .expect("the scrolled-to row must render its probe button")
            .click();
        harness.run_steps(2);
        let cmd = harness
            .state_mut()
            .1
            ._cmd_rx
            .try_recv()
            .expect("a row probe must send a command");
        match cmd {
            CoreCmd::ProbeLatency { profiles, .. } => {
                assert_eq!(profiles.len(), 1, "a row probe must send one profile");
                assert_eq!(
                    profiles[0].id, ids[63],
                    "the probe must carry the row whose button was clicked"
                );
            }
            other => panic!("expected ProbeLatency, got {other:?}"),
        }
        assert_eq!(
            harness.state().0.pending_latency_probe,
            Some(true),
            "the row probe must mark the pending slot"
        );

        // The per-row delete button in the same band row stages the
        // confirmation dialog for that profile. The button's right edge
        // runs under the ScrollArea's overlay scrollbar track (~x190+), so
        // press the visible left part like a real pointer would; kittest's
        // node-center click would land on the track.
        let del_rect = harness
            .get_all_by_label("🗑")
            .find(|node| (node.rect().center().y - row_y).abs() < 8.0)
            .expect("the scrolled-to row must render its delete button")
            .rect();
        let press = egui::pos2(del_rect.left() + 4.0, del_rect.center().y);
        harness
            .input_mut()
            .events
            .push(egui::Event::PointerMoved(press));
        harness.step();
        harness.input_mut().events.push(egui::Event::PointerButton {
            pos: press,
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        });
        harness.step();
        harness.input_mut().events.push(egui::Event::PointerButton {
            pos: press,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        });
        harness.run_steps(2);
        assert_eq!(
            harness
                .state()
                .0
                .delete_pending
                .as_ref()
                .map(|dialog| dialog.name.as_str()),
            Some("Server 63"),
            "the delete dialog must target the row whose button was clicked"
        );
        assert!(
            harness.query_by_label("Delete server").is_some(),
            "the delete confirmation dialog must open"
        );

        // Cancel leaves the list untouched.
        harness.get_by_label("Cancel").click();
        harness.run_steps(2);
        assert!(harness.state().0.delete_pending.is_none());
        assert_eq!(
            harness.state().1.servers.profiles.len(),
            64,
            "cancelling the delete must not remove the profile"
        );
        assert_eq!(
            harness.state().0.selected.as_deref(),
            Some(ids[63].as_str()),
            "cancelling the delete must keep the selection"
        );
    }

    /// A bare WireGuard profile whose in-network DNS list carries `entries`.
    fn wireguard_rig(entries: &[&str]) -> UiTestRig {
        let mut profile = ServerProfile::new("wg", OutboundModel::new(Protocol::Wireguard));
        if let ProtocolSettings::Wireguard(settings) = &mut profile.outbound.settings {
            settings.remote_dns = entries.iter().map(|entry| (*entry).to_owned()).collect();
        }
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(profile.clone());
        rig.servers.active = Some(profile.id.clone());
        rig
    }

    /// The editor's `remoteDNS` row currently showing `value`.
    fn remote_dns_row<'a>(
        harness: &'a Harness<'static, (ServersScreen, UiTestRig)>,
        value: &str,
    ) -> egui_kittest::Node<'a> {
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.value().as_deref() == Some(value))
            .unwrap_or_else(|| panic!("the remoteDNS row showing {value:?} must render"))
    }

    #[test]
    fn wireguard_remote_dns_row_edits_and_reports_a_bad_entry_only_while_it_stands() {
        // The list renders as editable rows, and a value the pinned core
        // cannot build (it parses each entry with `netip.MustParseAddr`)
        // reports inline and in the blocking list at edit time; repairing the
        // entry clears both.
        let mut harness = wide_servers_harness(wireguard_rig(&["1.1.1.1"]));
        harness.run();
        remote_dns_row(&harness, "1.1.1.1").scroll_to_me();
        harness.run();
        remote_dns_row(&harness, "1.1.1.1").click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.is_focused())
            .expect("the remoteDNS row takes focus")
            .type_text("x");
        harness.run();

        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsEntryInvalid))
                .is_some(),
            "the bad entry must report inline under its row"
        );
        assert!(
            editor_blocking(&harness).iter().any(|issue| {
                issue.code == ValidationCode::WireguardRemoteDnsInvalid
                    && issue.path.as_deref() == Some("settings.remoteDNS")
            }),
            "{:#?}",
            editor_blocking(&harness)
        );

        // Repair in place: the inline verdict and the gate both clear.
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.is_focused())
            .expect("the remoteDNS row keeps focus")
            .type_text("8.8.8.8");
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsEntryInvalid))
                .is_none(),
            "the repaired entry must not report"
        );
        assert!(
            !editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::WireguardRemoteDnsInvalid),
            "{:#?}",
            editor_blocking(&harness)
        );
        let draft = harness
            .state()
            .0
            .existing_draft
            .as_ref()
            .expect("the editor stays open");
        let ProtocolSettings::Wireguard(settings) = &draft.profile.outbound.settings else {
            panic!("the draft stays a WireGuard profile");
        };
        assert_eq!(settings.remote_dns, vec!["8.8.8.8".to_owned()]);
    }

    /// The in-network DNS list's own "+ Add" button: the one directly under
    /// the list's rows (the local-address list above carries its own, and the
    /// peer fields only render once a peer exists).
    fn remote_dns_add_button<'a>(
        harness: &'a Harness<'static, (ServersScreen, UiTestRig)>,
        below_y: f32,
    ) -> egui_kittest::Node<'a> {
        harness
            .get_all_by_label(t(Language::En, Key::AddRow))
            .filter(|node| node.rect().center().y > below_y)
            .min_by(|a, b| {
                a.rect()
                    .center()
                    .y
                    .partial_cmp(&b.rect().center().y)
                    .expect("finite rects")
            })
            .expect("the in-network DNS list renders its + Add button under its rows")
    }

    #[test]
    fn wireguard_remote_dns_sentinel_renders_alone_and_reports_a_mixed_list() {
        // The sentinel reads as the list's only entry. Alone it is valid and
        // silent; next to an address the core would parse the word as an
        // address and crash, so that entry alone carries the verdict.
        let mut harness = wide_servers_harness(wireguard_rig(&["local"]));
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsNote))
                .is_some(),
            "the sentinel semantics note must render under the list"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsLocalOnly))
                .is_none(),
            "the sentinel alone must not report"
        );
        assert!(
            !editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::WireguardRemoteDnsInvalid),
            "{:#?}",
            editor_blocking(&harness)
        );

        // Adding a row makes the sentinel invalid, although its own text
        // never changed: the verdict must follow the list length, not sit
        // frozen on the frame it was first computed.
        remote_dns_row(&harness, "local").scroll_to_me();
        harness.run();
        let sentinel_y = remote_dns_row(&harness, "local").rect().center().y;
        remote_dns_add_button(&harness, sentinel_y).click();
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsLocalOnly))
                .is_some(),
            "the sentinel row must gain its verdict when another row joins the list"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsEntryInvalid))
                .is_some(),
            "the empty new row must report its own verdict"
        );
        assert!(
            editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::WireguardRemoteDnsInvalid),
            "{:#?}",
            editor_blocking(&harness)
        );
        drop(harness);

        // The seeded mixed list reports on the sentinel row, and removing the
        // address row clears it.
        let mut harness = wide_servers_harness(wireguard_rig(&["local", "1.1.1.1"]));
        harness.run();
        remote_dns_row(&harness, "local").scroll_to_me();
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsLocalOnly))
                .is_some(),
            "the mixed list must report on the sentinel row"
        );
        assert!(
            editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::WireguardRemoteDnsInvalid),
            "{:#?}",
            editor_blocking(&harness)
        );

        // Removing the address row leaves the sentinel alone in the list. The
        // surviving row's text never changed, so its verdict must key on the
        // list length too — a verdict frozen from the longer list would keep
        // reporting here (and keep the profile gated) forever.
        let row_y = remote_dns_row(&harness, "1.1.1.1").rect().center().y;
        harness
            .get_all_by_label(t(Language::En, Key::DeleteRow))
            .find(|node| (node.rect().center().y - row_y).abs() < 8.0)
            .expect("the address row renders its delete button")
            .click();
        harness.run_steps(2);
        let draft = harness
            .state()
            .0
            .existing_draft
            .as_ref()
            .expect("the editor stays open");
        let ProtocolSettings::Wireguard(settings) = &draft.profile.outbound.settings else {
            panic!("the draft stays a WireGuard profile");
        };
        assert_eq!(
            settings.remote_dns,
            vec!["local".to_owned()],
            "the deleted row must leave the model"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsLocalOnly))
                .is_none(),
            "the surviving sentinel row's verdict must clear with the list"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsEntryInvalid))
                .is_none(),
            "no row may keep a verdict from the longer list"
        );
        assert!(
            !editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::WireguardRemoteDnsInvalid),
            "{:#?}",
            editor_blocking(&harness)
        );
    }

    #[test]
    fn realm_mask_editor_writes_ip_mode_and_port_mapping_through() {
        fn realm(mask: &FinalmaskUdpMask) -> &FinalmaskRealm {
            match mask {
                FinalmaskUdpMask::Realm { settings, .. } => settings,
                other => panic!("the harness renders a realm mask, got {other:?}"),
            }
        }

        let mask = Rc::new(RefCell::new(FinalmaskUdpMask::Realm {
            settings: Box::new(FinalmaskRealm {
                url: "realm://token@realm.example/id".into(),
                stun_servers: vec!["stun.example.com:3478".into()],
                ..Default::default()
            }),
            extra: Default::default(),
        }));
        let mask_for_ui = Rc::clone(&mask);
        let buffers = Rc::new(RefCell::new(RawBuffers::default()));
        let buffers_for_ui = Rc::clone(&buffers);
        let pem_buffers = Rc::new(RefCell::new(std::collections::HashMap::new()));
        let pem_buffers_for_ui = Rc::clone(&pem_buffers);
        let mut harness = Harness::new_ui(move |ui| {
            let _ = finalmask_udp_settings_editor(
                ui,
                Language::En,
                &mut mask_for_ui.borrow_mut(),
                RawField {
                    id: FieldKey {
                        key: egui::Id::new("realm-editor-test"),
                        profile: "profile-test",
                    },
                    buffers: &mut buffers_for_ui.borrow_mut(),
                },
                &mut pem_buffers_for_ui.borrow_mut(),
            );
        });
        harness.run();

        // An untouched frame emits neither key, so a profile that never set
        // them keeps its exact wire shape.
        assert_eq!(
            serde_json::to_value(&*mask.borrow()).unwrap()["settings"],
            json!({
                "url": "realm://token@realm.example/id",
                "stunServers": ["stun.example.com:3478"]
            })
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvRealmIpModeNote))
                .is_some(),
            "the ipMode note must render"
        );

        // The combo shows the core default and offers the three wire values.
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .into_iter()
            .find(|node| node.value().as_deref() == Some(t(Language::En, Key::SrvDefault)))
            .expect("the ipMode combo shows the default")
            .click();
        harness.run();
        harness.get_by_label("v4").click();
        harness.run();
        assert_eq!(realm(&mask.borrow()).ip_mode, "v4");

        // `portMapping` materializes the object; `enabled` and the two
        // seconds fields then write into it.
        harness.get_by_label("portMapping").click();
        harness.run();
        assert!(
            realm(&mask.borrow()).port_mapping.is_some(),
            "the portMapping toggle must add the object"
        );
        harness.get_by_label("enabled").click();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvTimeoutS))
            .click();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvLifetimeS))
            .click();
        harness.run();
        let emitted = serde_json::to_value(&*mask.borrow()).unwrap();
        assert_eq!(
            emitted["settings"]["portMapping"],
            json!({"enabled": true, "timeout": 0, "lifetime": 0}),
            "{emitted}"
        );
    }

    #[test]
    fn hysteria_masquerade_editor_toggles_x_forwarded() {
        let stream = Rc::new(RefCell::new(StreamModel {
            network: Network::Hysteria,
            hysteria_settings: Some(HysteriaTransport {
                auth: "hy2password".into(),
                masquerade: Some(MasqueradeCfg {
                    r#type: "proxy".into(),
                    url: "https://masq.example.com".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }));
        let stream_for_ui = Rc::clone(&stream);
        let screen = Rc::new(RefCell::new(ServersScreen::default()));
        let screen_for_ui = Rc::clone(&screen);
        let mut harness = Harness::new_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().transport_tab(
                ui,
                Language::En,
                &mut stream_for_ui.borrow_mut(),
                0,
                None,
            );
        });
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvXForwardedNote))
                .is_some(),
            "the xForwarded switch must render its note"
        );
        // Unset emits nothing; the switch writes the camelCase key.
        assert_eq!(
            serde_json::to_value(stream.borrow().hysteria_settings.as_ref().unwrap()).unwrap()["masquerade"],
            json!({"type": "proxy", "url": "https://masq.example.com"})
        );
        harness
            .get_by_label(t(Language::En, Key::SrvXForwarded))
            .click();
        harness.run();
        let emitted =
            serde_json::to_value(stream.borrow().hysteria_settings.as_ref().unwrap()).unwrap();
        assert_eq!(
            emitted["masquerade"]["xForwarded"],
            json!(true),
            "{emitted}"
        );
    }
}
