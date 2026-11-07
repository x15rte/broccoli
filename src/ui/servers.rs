//! Servers screen: one full-width, virtualized table of profiles under a
//! toolbar, with the tabbed full-coverage outbound editor in a pop-up window.
//! Covers all 12 protocols, all 7 transports, TLS/REALITY, mux, and the
//! advanced envelope (sendThrough / targetStrategy / finalmask / sockopt).

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::i18n::{Key, t, t_fmt, validation_issue_message, validation_message};
use crate::links;
use crate::model::go_std_base64_decodes;
use crate::model::outbound::{
    BlackholeResponse, DnsOutRule, Fragment, FreedomFinalRule, GeneratedSecret, MuxModel, Noise,
    VlessReverse, WireguardPeer, blackhole_response_is_custom, blackhole_response_type_supported,
};
use crate::model::settings::{ColumnWidths, Language, SortColumn, ViewSort};
use crate::model::stream::{
    MAX_XHTTP_DOWNLOAD_DEPTH, MasqueWarp, MasqueradeCfg, XDRIVE_DEFAULT_CONCURRENCY,
    XDRIVE_DEFAULT_EAGER_WINDOW_MS, XDRIVE_DEFAULT_FLUSH_INTERVAL_MS,
    XDRIVE_DEFAULT_HOLE_TIMEOUT_MS, XDRIVE_DEFAULT_MAX_POLL_INTERVAL_MS,
    XDRIVE_DEFAULT_POLL_INTERVAL_MS, XDRIVE_DEFAULT_SEGMENT_BYTES,
    XDRIVE_DEFAULT_SESSION_TTL_SECONDS, XDRIVE_MAX_CONCURRENCY, XDRIVE_MAX_SEGMENT_BYTES,
    XDRIVE_SERVICE_DRIVE, XDRIVE_SERVICE_LOCAL, XDRIVE_SERVICE_S3, XDRIVE_SERVICE_TEMPLATE,
    XDRIVE_SERVICES, XDRIVE_TEMPLATE_AUTH_TYPES, XDRIVE_TEMPLATE_DEFAULT_CONCURRENCY,
    XDRIVE_TEMPLATE_MAX_CONCURRENCY, XdriveOperation, XdriveTemplate, XdriveTemplateAuth,
    XdriveTemplateOp, xdrive_folder_required,
};
use crate::model::validation::{
    self, DNS_OUT_ACTIONS, ValidationCode, ValidationIssue, Verdict, XUDP_PROXY_UDP443_MODES,
    dns_out_action_supported, freedom_final_rule_supported, masque_warp_address_list_verdict,
    mux_conflicts_with_vision_flow, pinned_peer_cert_sha256_valid, reality_mldsa65_verify_valid,
    reality_public_key_valid, send_through_supported, server_name_implausible,
    validate_outbound_with_blocks,
};
use crate::model::{
    CustomSockopt, FinalmaskTcpMask, FinalmaskUdpMask, HappyEyeballs, HttpCamouflageRequest,
    HttpCamouflageResponse, Int32Range, Network, OutboundModel, ProbeOutcome, ProbeSource,
    ProbeVerdict, Protocol, ProtocolSettings, RawHeader, Security, ServerProfile, ServersFile,
    Settings, Sniffing, SockoptModel, StreamModel, WsSettings,
};
use crate::rt::{
    CoreCmd, LatencyProbeResult, ProfileValidationOrigin, ProfileValidationReply,
    ProfileValidationRequest, ToolTarget,
};
use crate::tls_ping::{ca_pins_from_probe_output, leaf_pin_from_probe_output};
use crate::ui::gate::{Rung, verdict};
use crate::ui::inbounds::sniffing_editor;
use crate::ui::popup;
use crate::ui::request::{Request, Terminal};
use crate::ui::status::{StatusColors, status_colors_of};
use crate::ui::widgets;
use crate::ui::{
    FeedbackLevel, ServersCtx, format_latency_probe_feedback, format_single_latency_probe_feedback,
};
use egui::{Color32, RichText, Stroke, StrokeKind};

pub(crate) mod finalmask_editors;
mod keygen;
mod raw_editor;
mod tls_editor;
mod validators;
mod xmux;
mod xray_tool;

use finalmask_editors::{
    finalmask_move_buttons, finalmask_quic_editor, finalmask_tcp_settings_editor,
    finalmask_udp_settings_editor,
};
use keygen::{PRIV_PREFIXES, PUB_PREFIXES, gen_short_id, keygen_value};
use raw_editor::{FieldKey, RawField, SeededBuffers};
use validators::{
    v_masque_remote_dns_entry, v_masque_warp_address_entry, v_masque_warp_private_key,
    v_masque_warp_public_key, v_optional_wg_key, v_required, v_uuid, v_uuid_required,
    v_vless_encryption, v_vless_encryption_required, v_wg_public_key, v_wg_remote_dns_entry,
    v_wg_secret_key,
};
use xmux::xmux_section;
use xray_tool::XrayToolKind;

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

/// The uplink placement options the combos off `packet-up` offer: the model's
/// own subset for those forms, so the combo and the rule that refuses the
/// rest cannot drift.
const UPLINK_STREAM_PLACEMENTS: [&str; 3] = validation::UPLINK_STREAM_PLACEMENT_OPTIONS;

// ---------- delete-confirmation reference scan ----------

/// Every model site referencing `profile_id`'s outbound tag, as wire paths —
/// the delete confirmation renders them verbatim. The scan itself belongs to
/// the dial graph, which answers "who references this tag" for the profile
/// half and the settings half alike.
fn server_reference_paths(
    servers: &ServersFile,
    settings: &Settings,
    profile_id: &str,
) -> Vec<String> {
    crate::model::dial::DialGraph::for_settings(servers, settings).references(settings, profile_id)
}

// ---------- editor validation sweep ----------

fn runnable_fragment() -> Fragment {
    Fragment {
        length: Some(Int32Range::single(100)),
        interval: Some(Int32Range::single(10)),
        ..Default::default()
    }
}

fn runnable_noise() -> Noise {
    Noise {
        r#type: "str".into(),
        packet: "padding".into(),
        ..Default::default()
    }
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

/// One full editor validation sweep, as findings: the model's
/// `validate_outbound_with_blocks` verdict — protocol settings, stream
/// security and the transport's own blocks — plus the stream blocks that same
/// pass returns (finalmask, sockopt, ECH sockopt). The sweep mints no rule of
/// its own: every finding the editor gates on has a model code and a wire
/// path, so the Save gate, generation and the importer answer one verdict, and
/// an inline block row is never a second validation of the block. Nothing
/// here is rendered; [`EditorValidationFindings::render`] turns a sweep into
/// the strings the lists and the inline verdicts show, once per (draft
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
    finalmask: Verdict,
    /// The Advanced tab's inline `stream.sockopt` verdict.
    stream_sockopt: Verdict,
    /// The Security tab's inline verdict for the TLS settings' ECH DNS-query
    /// socket options (`stream.tlsSettings.echSockopt`).
    ech_sockopt: Verdict,
}

/// The rendered form of one sweep: one `path: message` string per finding, in
/// the sweep's order, and the two list halves already composed with their
/// bullet. Rebuilt when the draft generation or the language moves, so no
/// paint path renders or formats a finding.
#[derive(Default)]
struct EditorValidationRender {
    /// The blocked-save list's lines: the bullet composed with each blocking
    /// finding's message here, once per (draft generation, language), so the
    /// list paints stored strings instead of formatting per frame.
    blocking: Vec<String>,
    /// The warnings list's lines, bulleted like `blocking`.
    advisory: Vec<String>,
    finalmask: Vec<String>,
    stream_sockopt: Vec<String>,
    ech_sockopt: Vec<String>,
    /// The Basic tab's inline outbound verdicts: the blocking findings whose
    /// code the tab renders itself — the public-endpoint transport-security
    /// rules and the freedom fragment and noise blocks. Inline text stays
    /// bare: the tab renders the message itself, without the list's bullet.
    basic_inline: Vec<String>,
}

/// Render one finding list as the editor's list lines: the shared bullet
/// composed with the finding's message, once per (draft generation,
/// language).
fn render_bulleted<'a>(
    findings: impl Iterator<Item = &'a ValidationIssue>,
    lang: Language,
) -> Vec<String> {
    findings
        .map(|issue| {
            let message = validation_issue_message(issue, lang);
            t_fmt(lang, Key::ErrorBullet, &[&message])
        })
        .collect()
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

/// True for the rules the Basic tab renders inline under the protocol fields —
/// the public-endpoint transport-security findings and the freedom fragment
/// and noise blocks the tab's own editors fill in. These are the same findings
/// the error list carries, filtered by code where they render instead of
/// re-derived.
fn basic_tab_inline_verdict(code: &ValidationCode) -> bool {
    matches!(
        code,
        ValidationCode::VisionRequiresTlsOrReality
            | ValidationCode::PublicVlessRequiresTlsOrEncryption
            | ValidationCode::PublicTrojanRequiresTlsOrReality
            | ValidationCode::FreedomFragmentInvalid
            | ValidationCode::FreedomNoiseInvalid
    )
}

impl EditorValidationFindings {
    /// The strings the editor shows for this sweep, in its own order.
    fn render(&self, lang: Language) -> EditorValidationRender {
        EditorValidationRender {
            blocking: render_bulleted(self.blocking.iter(), lang),
            advisory: render_bulleted(self.advisory.iter(), lang),
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

/// The editor's one model sweep for a draft: the aggregated verdict (the
/// error and warning lists) plus the stream blocks the tabs render inline.
/// Both come from the same `validate_outbound_with_blocks` pass, so a block's
/// inline rows are the sweep's own findings — never a second validation of
/// the same block, and never a verdict that can drift from the error list.
fn editor_validation_findings(profile: &ServerProfile) -> EditorValidationFindings {
    let (model, blocks) = validate_outbound_with_blocks(&profile.outbound);
    // The two list halves are the aggregate verdict consumed, not cloned: the
    // lists own exactly the findings the sweep produced, in pass order.
    let (blocking, advisory) = model.into_tiers();
    EditorValidationFindings {
        blocking,
        advisory,
        finalmask: blocks.finalmask,
        stream_sockopt: blocks.sockopt,
        ech_sockopt: blocks.ech_sockopt,
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

/// Which socket-options block an editor is rendering: the stream's own block
/// or the TLS settings' ECH DNS-query block. They share `SockoptModel` but
/// not every field's semantics, so the editor asks which one it paints
/// instead of guessing from the wire path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SockoptUsage {
    Stream,
    EchDnsQuery,
}

/// Outbound-role socket options (the stream block and the ECH DNS-query
/// block). Options the Windows outbound path never reads render no widget
/// here: the Linux-only knobs (`mark`, `tproxy`, `tcpCongestion`,
/// `tcpWindowClamp`, `tcpMaxSeg`, `tcpUserTimeout`), `tcpMptcp` (Go's dialer
/// consumes it on Linux only), and the listener-only values (`v6only`,
/// `acceptProxyProtocol`, `trustedXForwardedFor`, which only listeners
/// consume). The model keeps them so a hand-edited profile round-trips
/// unchanged. Every widget below has a reader in the core this app runs.
fn sockopt_editor(
    ui: &mut egui::Ui,
    lang: Language,
    sockopt: &mut SockoptModel,
    usage: SockoptUsage,
    // The stream block is the chain surface: its `dialerProxy` renders as a
    // picker over the caller's chain-target options. The ECH DNS-query block
    // embeds the same struct but sits in an editor with no profile list, so
    // it keeps the free-text field (`None`).
    dialer_proxy_options: Option<&[String]>,
    // The block's memoized verdicts from the enclosing draft's validation
    // sweep (their wire path in the message), rendered under the fields.
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
        None => widgets::text_field(
            ui,
            "dialerProxy",
            &mut sockopt.dialer_proxy,
            t(lang, Key::SrvDialerProxyHint),
        ),
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
                changed |= widgets::text_field(
                    ui,
                    "level",
                    &mut custom.level,
                    t(lang, Key::SrvCustomLevelHint),
                );
                changed |= widgets::combo_str_labeled(
                    ui,
                    "type",
                    &mut custom.r#type,
                    &["", "int", "str"],
                    t(lang, Key::SrvDefault),
                    false,
                );
                changed |=
                    widgets::text_field(ui, "opt", &mut custom.opt, t(lang, Key::SrvCustomOptHint));
                changed |= widgets::text_field(ui, "value", &mut custom.value, "");
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
        .on_hover_text(t(lang, Key::SrvEchSockoptNote))
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
            changed |= sockopt_editor(ui, lang, sockopt, SockoptUsage::EchDnsQuery, None, errors);
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
/// Returns (value_changed, button_clicked). While `masked` is set the value
/// renders as the masked stand-in; the keygen button stays live, because it
/// produces a value instead of reading one.
fn keygen_field(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    validate: impl Fn(&str) -> Option<String>,
    button: &KeygenButton<'_>,
    masked: bool,
) -> (bool, bool) {
    let error = validate(value);
    let mut clicked = false;
    let (changed, _rect) = ui
        .horizontal(|ui| {
            ui.label(label);
            let btn_w = 72.0 + ui.spacing().item_spacing.x;
            let w = (ui.available_width() - btn_w).max(100.0);
            let r = if masked {
                widgets::masked_stand_in(ui, !value.is_empty(), hint)
            } else {
                ui.add(
                    egui::TextEdit::singleline(value)
                        .hint_text(hint)
                        .desired_width(w),
                )
            };
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
/// `scratch` is the screen's pair of reuse buffers: the key column's (a map
/// key is not a `&mut String` of its own) and a non-string value's formatted
/// text. Both are seeded before a widget and read back only when that widget
/// reports an edit, so an owned buffer per row never allocates on a repaint.
///
/// The row layout is [`widgets::kv_row`], shared with the plain
/// `Vec<(String, String)>` tables, so the two-column rule lives in one place.
fn json_map_kv(
    ui: &mut egui::Ui,
    lang: Language,
    map: &mut serde_json::Map<String, serde_json::Value>,
    key_hint: &str,
    val_hint: &str,
    scratch: &mut KvScratch,
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
                let key_text = scratch.key.edit(k);
                // A JSON string is edited in place — the widget writes the
                // model's own text only on a real edit. Every other value
                // round-trips through the scratch and becomes a string only
                // when it is edited; `&*v` seeds without moving the row.
                let mut formatted_value = false;
                let value_text = match &mut *v {
                    serde_json::Value::String(text) => text,
                    other => {
                        formatted_value = true;
                        scratch.value.edit(&*other)
                    }
                };
                let edit = widgets::kv_row(
                    ui,
                    key_text,
                    key_hint,
                    value_text,
                    val_hint,
                    t(lang, Key::DeleteRow),
                );
                if edit.key {
                    // A key must be non-empty and different to be a rename.
                    scratch.key.commit_if(
                        |text| !text.is_empty() && text != k.as_str(),
                        |text| rename = Some((k.clone(), text.to_owned())),
                    );
                }
                if edit.value {
                    if formatted_value {
                        *v = serde_json::Value::String(scratch.value.text().to_owned());
                    }
                    changed = true;
                }
                if edit.removed {
                    remove = Some(k.clone());
                }
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

/// The two reuse buffers of one JSON key→value table (see [`json_map_kv`]):
/// the key column's and a non-string value's. One per screen table group, so
/// the buffers keep their capacity across frames.
#[derive(Default)]
struct KvScratch {
    key: widgets::Scratch,
    value: widgets::Scratch,
}

/// One xdrive numeric scalar: zero keeps the core's own default
/// (transport/internet/xdrive/params.go:28-50), so the field spans `0..=max`
/// and names the default it falls back to. `max` is the runtime's cap where
/// it has one, and `u32::MAX` otherwise.
fn xdrive_scalar(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    value: &mut u32,
    max: u32,
    default: u32,
) -> bool {
    ui.horizontal(|ui| {
        let mut changed = false;
        ui.label(label);
        changed |= ui
            .add(egui::DragValue::new(value).range(0..=max).speed(1.0))
            .changed();
        ui.weak(t_fmt(
            lang,
            Key::SrvXdriveCoreDefault,
            &[&default.to_string()],
        ));
        changed
    })
    .inner
}

/// The template retry status list: one status code per row, with a row
/// remove button and an add button. Sent as Go `[]int`, so the rows are
/// numbers rather than text.
fn xdrive_status_list(ui: &mut egui::Ui, lang: Language, statuses: &mut Vec<i64>) -> bool {
    let mut changed = false;
    let mut remove = None;
    for (index, status) in statuses.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button(t(lang, Key::DeleteRow)).clicked() {
                    remove = Some(index);
                }
                changed |= ui
                    .add(egui::DragValue::new(status).range(100..=599))
                    .changed();
            });
        });
    }
    if let Some(index) = remove {
        statuses.remove(index);
        changed = true;
    }
    if ui.button(t(lang, Key::AddRow)).clicked() {
        statuses.push(429);
        changed = true;
    }
    changed
}

fn transport_headers(
    ui: &mut egui::Ui,
    lang: Language,
    map: &mut serde_json::Map<String, serde_json::Value>,
    scratch: &mut KvScratch,
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
    scratch: &mut KvScratch,
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
    /// click path (keygen/tool requests, derive dialog, validation start)
    /// instead of per frame: the editors pass a borrowed draft identity and
    /// the owned value is built where it is used.
    fn draft(kind: DraftKind, profile_id: &str, generation: u64) -> Self {
        match kind {
            DraftKind::Existing => ToolTarget::ExistingDraft {
                profile_id: profile_id.to_owned(),
                generation,
            },
            DraftKind::Add => ToolTarget::AddDraft {
                profile_id: profile_id.to_owned(),
                generation,
            },
        }
    }

    /// The draft slot this target names.
    fn draft_kind(&self) -> DraftKind {
        match self {
            ToolTarget::ExistingDraft { .. } => DraftKind::Existing,
            ToolTarget::AddDraft { .. } => DraftKind::Add,
        }
    }

    /// The profile id the target names.
    fn profile_id(&self) -> &str {
        match self {
            ToolTarget::ExistingDraft { profile_id, .. }
            | ToolTarget::AddDraft { profile_id, .. } => profile_id,
        }
    }

    /// The draft generation the request was staged from. A verdict for any
    /// other generation is stale: every content edit bumps it.
    fn generation(&self) -> u64 {
        match self {
            ToolTarget::ExistingDraft { generation, .. }
            | ToolTarget::AddDraft { generation, .. } => *generation,
        }
    }

    /// True when this target names the same slot, profile id and generation
    /// as the borrowed identity an editor holds: the memo keys hold the owned
    /// form and compare it against the frame's draft in place.
    fn matches(&self, target: DraftTarget<'_>) -> bool {
        self.draft_kind() == target.kind
            && self.profile_id() == target.profile_id
            && self.generation() == target.generation
    }
}

/// Which of the screen's two draft slots a draft or a request names: the
/// selected profile's editor draft, or the in-progress add-server draft. Both
/// hold one [`ProfileDraft`]; this is the only thing that distinguishes their
/// slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum DraftKind {
    Existing,
    Add,
}

/// The borrowed form of a draft identity: the slot, the profile id the draft
/// mirrors, and the generation a verdict must still match to be applied. The
/// editor entry points take this one named value instead of a positional
/// `(kind, id, generation)` triple spelled out at every call site.
///
/// The tab closures build it field-wise from the draft they hold: a
/// constructor borrowing the whole draft would collide with the `&mut
/// draft.profile` the same call passes. The owned [`ToolTarget`] is built from
/// it only where a request is staged, so an idle repaint never allocates the
/// profile id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DraftTarget<'a> {
    kind: DraftKind,
    profile_id: &'a str,
    generation: u64,
}

impl DraftTarget<'_> {
    /// The owned request target for this identity, cloning the profile id
    /// only on the click path.
    fn owned(self) -> ToolTarget {
        ToolTarget::draft(self.kind, self.profile_id, self.generation)
    }
}

/// The snapshot one draft is compared against, precomputed once at creation:
/// the persisted profile the draft was loaded from (or the empty profile of
/// an add draft), serialized with the same serializer the comparison uses,
/// plus the two source facts the retired-key gates read out of it. Deriving
/// both here keeps an edit's changed-from-source question to one
/// serialization of the live profile — no JSON tree is built to diff, and no
/// snapshot document is re-read.
///
/// The derived default — empty bytes and no source facts — is what a snapshot
/// that cannot serialize leaves: no profile serializes to it, so the draft
/// stays "changed", the answer a failed serialization always gives.
#[derive(Default)]
struct DraftBaseline {
    /// `serde_json::to_vec` of the snapshot. The comparison side serializes
    /// the live profile the same way, so equal profiles produce equal bytes
    /// and a value the editor reverted by hand compares unchanged.
    json: Vec<u8>,
    /// The snapshot's chain target (`streamSettings.sockopt.dialerProxy`).
    /// Empty and absent are both "no chain", exactly as
    /// `ServerProfile::chain_target` reads the live draft.
    chain_target: Option<String>,
    /// The snapshot's `udphop` UDP masks, serialized as the settings file
    /// writes them.
    udphop_masks: Vec<serde_json::Value>,
}

impl DraftBaseline {
    /// The baseline of `source`: its serialized bytes and the two source
    /// facts the retired-key gates compare the draft against.
    fn of(source: &ServerProfile) -> Result<Self, serde_json::Error> {
        Ok(Self {
            json: serde_json::to_vec(source)?,
            chain_target: source.chain_target().map(str::to_owned),
            udphop_masks: udphop_masks(source),
        })
    }
}

/// One open editor draft, in either slot. The existing-profile editor and the
/// add-server dialog differ in where the draft commits to and what "changed"
/// is measured against — which is what `kind` and the baseline spell — so one
/// type holds both. The tab closures pass a borrowed [`DraftTarget`] and the
/// owned [`ToolTarget`] is built only on the click path, so repaints never
/// allocate the 36-char profile id.
struct ProfileDraft {
    kind: DraftKind,
    /// The profile id, mirrored from `profile.id`. Profile ids are immutable
    /// (a rename changes only the display name), so this never drifts. The
    /// copy lets the tab closures borrow the id (for tool targets and the
    /// tag list) without either cloning `self.selected` per repaint or
    /// overlapping `&mut draft.profile`.
    id: String,
    /// The outbound tag of the profile this draft carries, derived from
    /// the profile and formatted once at creation so the editor header
    /// row stays allocation-free on idle repaints. It is the tag the profile
    /// keeps once the draft commits; only the editor paints it.
    tag: String,
    profile: ServerProfile,
    /// The snapshot this draft is compared against: the persisted profile the
    /// draft was loaded from, or — for an add draft, which has no committed
    /// source — the empty profile carrying the draft's id, taken once at
    /// creation.
    baseline: DraftBaseline,
    /// The draft generation, bumped by every content edit. It keys the
    /// memoized validation and stamps the request target a tool or validation
    /// is staged with, so a verdict that arrives after an edit is dropped.
    generation: u64,
    /// Memoized validation for this draft (see [`EditorValidationCache`]),
    /// `None` until the draft's editor has rendered once.
    validation: Option<EditorValidationCache>,
}

impl ProfileDraft {
    /// The draft for an already-persisted profile: what it is compared
    /// against is the snapshot the file holds, so an unedited draft is never
    /// "changed".
    fn existing(persisted: &ServerProfile) -> Result<Self, serde_json::Error> {
        Ok(Self {
            kind: DraftKind::Existing,
            id: persisted.id.clone(),
            tag: persisted.tag(),
            profile: persisted.clone(),
            baseline: DraftBaseline::of(persisted)?,
            generation: 0,
            validation: None,
        })
    }

    /// The draft for a profile being added: it has no committed source, so
    /// what it is compared against is the empty profile carrying its id — an
    /// add draft is unsaved by definition until it commits.
    fn add(profile: ServerProfile) -> Self {
        let baseline = DraftBaseline::of(&ServerProfile {
            id: profile.id.clone(),
            ..ServerProfile::default()
        })
        .unwrap_or_default();
        Self {
            kind: DraftKind::Add,
            id: profile.id.clone(),
            tag: profile.tag(),
            profile,
            baseline,
            generation: 0,
            validation: None,
        }
    }

    /// The owned request target for this draft: the identity a tool or
    /// validation request is staged with, and the generation a verdict must
    /// still match to be applied.
    fn target(&self) -> ToolTarget {
        self.draft_target().owned()
    }

    /// This draft's borrowed identity — the form the tab closures take and
    /// the one [`ToolTarget::matches`] compares a staged request against, so
    /// "is this verdict still for the open draft" has one definition.
    fn draft_target(&self) -> DraftTarget<'_> {
        DraftTarget {
            kind: self.kind,
            profile_id: &self.id,
            generation: self.generation,
        }
    }

    /// A content edit, a tool application or a dismissal landed in this draft:
    /// its generation moves, so the memoized validation stops covering it and a
    /// verdict that arrives for the older generation is dropped. Every edit path
    /// runs this before the frame's [`Self::refresh`], which is what keeps a
    /// stale verdict from being rendered for a generation.
    ///
    /// The screen's reported validation output is not touched here: the add
    /// dialog keeps its report until the next attempt, because that output is
    /// why its window is still open, while the selected profile's editor drops
    /// it with the edit (see `ServersScreen::draft_edited`).
    fn edited(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    /// Bring this draft's memoized validation up to date: sweep the profile only
    /// when the memo does not cover the draft's generation, render the findings
    /// it holds only when the generation or the language moved. A language
    /// change therefore re-renders without re-validating, and an idle frame does
    /// neither. The changed-from-source baseline is the draft's own baseline
    /// (the persisted snapshot, or the empty template of an add draft), compared
    /// once per sweep.
    fn refresh(&mut self, lang: Language) {
        let covered = self
            .validation
            .as_ref()
            .is_some_and(|cached| cached.generation == self.generation);
        if !covered {
            let findings = editor_validation_findings(&self.profile);
            let rendered = findings.render(lang);
            self.validation = Some(EditorValidationCache {
                generation: self.generation,
                findings,
                rendered_language: lang,
                rendered,
                changed_from_source: profile_differs_from_baseline(&self.profile, &self.baseline),
            });
            return;
        }
        if let Some(cached) = self.validation.as_mut()
            && cached.rendered_language != lang
        {
            let rendered = cached.findings.render(lang);
            cached.rendered = rendered;
            cached.rendered_language = lang;
        }
    }

    /// Whether this draft differs from the baseline it is compared against: the
    /// memoized answer while the memo covers the draft's generation, a fresh
    /// comparison when it is stale (a tool-applied edit can land after the
    /// refresh, and the topbar chip reads this before the editor renders), and
    /// "unchanged" while there is no memo — a draft whose editor has not swept
    /// once, exactly as the pre-sweep state always has: every render path sweeps
    /// before it reads this.
    fn changed_from_source(&self) -> bool {
        match self.validation.as_ref() {
            Some(cached) if cached.generation == self.generation => cached.changed_from_source,
            Some(_) => profile_differs_from_baseline(&self.profile, &self.baseline),
            None => false,
        }
    }

    /// The facts every control of this draft reads this frame: the draft's own
    /// facts as the validation refresh left them, plus the seeded-buffer scan
    /// and the frame's validation/busy facts.
    fn gate(&self, buffers: &SeededBuffers, validating: bool, busy: bool) -> DraftGate {
        DraftGate {
            changed_from_source: self.changed_from_source(),
            raw_buffers_dirty: buffers.holds_uncommitted(&self.id),
            blocking: self
                .validation
                .as_ref()
                .is_some_and(|cached| !cached.findings.blocking.is_empty()),
            validating,
            busy,
        }
    }
}

/// Memoized editor validation for one draft: the findings (swept once per
/// draft generation, bumped on every edit and tool application) and the
/// strings they render to (rebuilt when the generation or the language
/// moves, so a language change re-renders instead of re-validating). Both
/// live here so a draft's editor never serializes or validates the whole
/// profile on a repaint.
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
    /// The draft differs from its baseline (see
    /// [`ProfileDraft::changed_from_source`]). For an
    /// existing draft that is the persisted profile; for an add draft, which
    /// has no committed source, the empty template it was created against.
    changed_from_source: bool,
}

struct XrayToolJob {
    target: ToolTarget,
    kind: XrayToolKind,
    request: Request<Result<String, String>>,
}

/// The facts every draft control reads, built by [`ProfileDraft::gate`] where the
/// draft's findings are. The two memoized facts — whether the draft differs
/// from its baseline, and whether an error-severity finding blocks it — come
/// from the validation memo the sweep produced, so a generation bump updates
/// the verdicts and those facts together. The three facts that move without a
/// draft edit (a seeded buffer's uncommitted text, the profile validation
/// job, and the busy window) are read where the control renders.
#[derive(Clone, Copy, Default)]
struct DraftGate {
    /// The draft differs from its baseline: the persisted profile for an
    /// existing draft, the empty template for an add draft.
    changed_from_source: bool,
    /// A raw-JSON buffer of this draft holds text that never reached the
    /// draft (a PEM buffer never does — see [`SeededBuffers`]).
    raw_buffers_dirty: bool,
    /// An error-severity finding exists.
    blocking: bool,
    /// The profile validation job is in flight.
    validating: bool,
    /// An exclusive job holds the busy window.
    busy: bool,
}

impl DraftGate {
    /// The draft holds unsaved changes: it differs from its baseline, or a
    /// raw-JSON buffer holds text that never reached it. The "Unsaved
    /// changes" dot, the Discard button, and the leave guard read this.
    fn dirty(self) -> bool {
        self.changed_from_source || self.raw_buffers_dirty
    }

    /// The draft may commit: it differs from its baseline and no
    /// error-severity finding blocks it. Validate-and-save and the leave
    /// modal's Save read this. A buffer-only dirty state is deliberately not
    /// committable — the raw text never parsed, so committing would be a
    /// no-op that leaves the unsaved indicator on.
    fn committable(self) -> bool {
        self.changed_from_source && !self.blocking
    }
}

/// The chain-target (`dialerProxy`) picker's options for one editor: every
/// other profile's tag in server-list order, then the built-in
/// `direct`/`block` targets validation accepts. Memoized per editor — a
/// rebuild costs one tag format per profile — so it reruns only when the
/// model generation moves (the profile set or a rename) or the rendered
/// profile advances; idle repaint frames reuse the snapshot.
struct DialerProxyOptions {
    generation: (u64, usize),
    /// The profile whose own tag the options exclude — a chain to itself
    /// could only produce a cycle.
    own_id: String,
    options: Vec<String>,
}

/// The TLS probe's state for one editor: what the user asked to probe, what
/// the probe produced, and whether its output window is open. All of it
/// describes the draft the probe was started from, so it lives with that
/// draft's slot — a pin is only meaningful for the profile it came from
/// (`profile`), and the window that shows it belongs to that profile's dialog.
#[derive(Default)]
struct TlsProbe {
    /// The host the user typed to probe.
    domain: String,
    /// The address the probe is pointed at, prefilled from the draft's
    /// endpoint and editable.
    ip: String,
    /// The probe's raw output, shown in its own window.
    output: Option<String>,
    /// What the last probe (or the request that could not be staged) reported.
    error: Option<String>,
    /// Leaf SHA256 pin parsed from the last successful probe output.
    leaf_pin: Option<String>,
    /// CA (name, pin) rows parsed from the last successful probe output.
    ca_pins: Vec<(String, String)>,
    /// Whether the last probe completed a handshake; gates the pin panel.
    /// Cleared when a new probe starts or fails; pins render only for the
    /// profile that produced them (see `profile`).
    handshake_ok: bool,
    /// Profile id whose probe produced `leaf_pin`; the pin panel renders and
    /// Apply is reachable only while the editor targets that same profile, so
    /// a pin can never be applied to a different node.
    profile: Option<String>,
    /// Whether the raw probe output window is open (drawn in `show_dialogs`).
    show_output: bool,
}

impl TlsProbe {
    /// Drop what the probe produced — its output, the pins parsed from it and
    /// the window showing them — keeping the address the user typed. The pins
    /// describe the profile that produced them, so they never outlive its
    /// draft; the address is a starting point for the next probe.
    fn discard_result(&mut self) {
        self.output = None;
        self.error = None;
        self.leaf_pin = None;
        self.ca_pins.clear();
        self.handshake_ok = false;
        self.profile = None;
        self.show_output = false;
    }
}

/// One editor slot: the draft it holds and the state that describes that draft
/// alone — the chain-target picker's option memo and the TLS probe's output.
/// The screen holds one slot per editor (the selected profile's editor and the
/// add-server dialog), so a draft's keep-alive state has one owner and dies
/// with the draft instead of outliving it on the screen.
///
/// The seeded raw-JSON/PEM buffer store is deliberately not here: it is keyed
/// by field identity and records its owner's profile id, and the tab functions
/// that render its editors (including the nested-settings recursion) reach it
/// through the screen, so it stays one store for the screen: closing a slot
/// evicts the buffers of its own draft, while reverting clears every buffer
/// (no editor may keep showing text of a draft that reverted).
///
/// A draft is taken out for the frame that renders it ([`Self::take`] and
/// [`Self::hold`]), because the render body mutates the screen around the draft
/// (the tabs' context, the seeded buffers, the validation request) while it
/// edits the profile.
#[derive(Default)]
struct DraftSlot {
    draft: Option<ProfileDraft>,
    /// The chain-target picker's option memo for this slot's editor (see
    /// [`DialerProxyOptions`]).
    chain_options: Option<DialerProxyOptions>,
    /// The TLS probe state for this slot's draft.
    probe: TlsProbe,
}

impl DraftSlot {
    /// The draft this slot holds, if any.
    fn draft(&self) -> Option<&ProfileDraft> {
        self.draft.as_ref()
    }

    /// The draft this slot holds, mutably, if any.
    fn draft_mut(&mut self) -> Option<&mut ProfileDraft> {
        self.draft.as_mut()
    }

    /// Take the draft out for the frame that renders it; [`Self::hold`] puts it
    /// back when the render returns, including the paths that gave up early.
    fn take(&mut self) -> Option<ProfileDraft> {
        self.draft.take()
    }

    /// Put a taken draft back into this slot.
    fn hold(&mut self, draft: ProfileDraft) {
        self.draft = Some(draft);
    }

    /// Close this slot's draft without committing: the draft goes away and the
    /// buffers seeded for it are dead weight. Click-time only.
    fn close(&mut self, buffers: &mut SeededBuffers) {
        if let Some(draft) = self.draft.take() {
            buffers.evict_owned(&draft.id);
        }
    }

    /// Revert this slot's draft: the screen shows the persisted profile again,
    /// so the draft, the probe result that described it and every seeded buffer
    /// go together — otherwise an editor would keep showing the discarded
    /// draft's text. Click-time only.
    fn revert(&mut self, buffers: &mut SeededBuffers) {
        self.draft = None;
        self.probe.discard_result();
        buffers.clear();
    }
}

/// Refresh `slot` when its signal moved and hand back the options it holds.
/// The cached slot's generation is the rebuild key — idle frames reuse the
/// options it holds.
fn refresh_dialer_proxy_options<'a>(
    slot: &'a mut Option<DialerProxyOptions>,
    set_key: (u64, usize),
    own_id: &str,
    profiles: &[ServerProfile],
) -> &'a [String] {
    let unchanged = slot
        .as_ref()
        .is_some_and(|cached| cached.generation == set_key && cached.own_id.as_str() == own_id);
    if !unchanged {
        let options =
            crate::model::dial::DialGraph::for_profiles(profiles).chain_target_options(own_id);
        *slot = Some(DialerProxyOptions {
            generation: set_key,
            own_id: own_id.to_owned(),
            options,
        });
    }
    slot.as_ref()
        .map_or(&[], |cached| cached.options.as_slice())
}

/// Trailing context for [`ServersScreen::transport_tab`]: the draft identity
/// its requests are staged against, whether the reveal control masks its
/// credentials, the outbound protocol that decides which transports are
/// offered, and the outbound's mux block an xdrive selection seeds. All
/// belong to the editor frame that renders the tab, and bundling them keeps
/// the tab under clippy's argument-count ceiling without a lint suppression
/// (zero-suppression repo contract).
struct TransportTabCtx<'a> {
    target: Option<DraftTarget<'a>>,
    masked: bool,
    protocol: Protocol,
    /// `Some` only for the top-level outbound stream: mux is an outbound
    /// field, and selecting xdrive enables it there. A nested XHTTP
    /// `downloadSettings` stream has no mux of its own.
    mux: Option<&'a mut MuxModel>,
}

/// Trailing context for [`ServersScreen::advanced_tab`]:
/// the model generation and profile count the chain-target options memoize
/// on, the memoized
/// finalmask verdicts, the memoized `stream.sockopt` verdict, and the seeded
/// text buffers the tab's raw-JSON and PEM fields edit through. Bundled so
/// the tab stays under clippy's argument-count ceiling without a lint
/// suppression (zero-suppression repo contract).
struct AdvancedTabCtx<'a> {
    set_key: (u64, usize),
    finalmask_errors: &'a [String],
    stream_sockopt_errors: &'a [String],
    /// The chain-target picker's memo slot for the editor rendering this
    /// tab (see [`DialerProxyOptions`]).
    dialer_proxy_options: &'a mut Option<DialerProxyOptions>,
    buffers: &'a mut SeededBuffers,
    /// Whether the tab's credentials (the finalmask passwords) render masked
    /// (the reveal control).
    masked: bool,
}

/// What one finalmask list needs that the other does not: its wording and
/// the identity its rows' raw-editor buffers are keyed by. The two lists
/// otherwise render the same rows.
struct MaskListSpec<'a> {
    /// The list's `push_id` salt (`finalmask-tcp` / `finalmask-udp`).
    group: &'static str,
    /// The kind's wire name — the field id's middle element.
    tag: &'static str,
    /// The profile id the raw-editor buffers belong to.
    profile: &'a str,
    heading: Key,
    note: Key,
    /// The "mask N" row label.
    ordinal: Key,
    add_label: Key,
    /// Whether the rows' credentials render masked (the reveal control).
    masked: bool,
    /// The draft generation the settings editors' verdicts memoize on.
    revision: u64,
}

/// One finalmask list's per-kind vocabulary and editor: the TCP and UDP
/// lists render the same chrome — type combo, reorder controls, then the
/// kind's settings — and differ only here.
///
/// Plain function pointers to the model's own methods, not a trait: the two
/// lists are one layout and the mask type is what varies, so the variation is
/// a value the list takes.
struct MaskKind<M> {
    /// The `type` string the mask serializes as, when it is a known one.
    known_type: fn(&M) -> Option<&'static str>,
    /// The envelope's `type` string, known or not: what a row displays when
    /// its type is one this build does not know.
    discriminator: fn(&M) -> Option<&str>,
    /// The mask of this kind `kind` names (the loader folds the spelling).
    from_known_type: fn(&str) -> Option<M>,
    /// The types the outbound editor offers, in the model's table order. The
    /// model returns an opaque iterator, so the box allocates once per frame
    /// the type menu is open and never on a closed-menu frame.
    outbound_types: fn() -> Box<dyn Iterator<Item = &'static str>>,
    /// The kind's settings rows, below the type combo.
    edit_settings: fn(&mut egui::Ui, Language, &mut M, RawField<'_>, bool, u64) -> bool,
}

/// The TCP mask list's vocabulary (no revision input: every TCP field's
/// verdict reads the draft generation the row is rendered at).
fn tcp_mask_kind() -> MaskKind<FinalmaskTcpMask> {
    MaskKind {
        known_type: FinalmaskTcpMask::known_type,
        discriminator: FinalmaskTcpMask::discriminator,
        from_known_type: FinalmaskTcpMask::from_known_type,
        outbound_types: || Box::new(FinalmaskTcpMask::outbound_types()),
        edit_settings: |ui, lang, mask, field, masked, _revision| {
            finalmask_tcp_settings_editor(ui, lang, mask, field, masked)
        },
    }
}

/// The UDP mask list's vocabulary; its editors' verdicts memoize on the
/// draft generation, so the revision reaches them.
fn udp_mask_kind() -> MaskKind<FinalmaskUdpMask> {
    MaskKind {
        known_type: FinalmaskUdpMask::known_type,
        discriminator: FinalmaskUdpMask::discriminator,
        from_known_type: FinalmaskUdpMask::from_known_type,
        outbound_types: || Box::new(FinalmaskUdpMask::outbound_types()),
        edit_settings: |ui, lang, mask, field, masked, revision| {
            finalmask_udp_settings_editor(ui, lang, mask, field, masked, revision)
        },
    }
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

/// True when `profile` differs from the baseline snapshot it is compared
/// against. Both sides are written by the same serializer, so the comparison
/// is one `to_vec` of the live profile against the bytes taken at creation
/// (serde_json's value order is deterministic, so a profile the user reverted
/// by hand compares unchanged). A profile that cannot serialize counts as
/// changed, so a draft whose serialization fails can never commit silently.
fn profile_differs_from_baseline(profile: &ServerProfile, baseline: &DraftBaseline) -> bool {
    serde_json::to_vec(profile)
        .map(|current| current != baseline.json)
        .unwrap_or(true)
}

struct QrDialog {
    name: String,
    link: String,
    tex: Option<egui::TextureHandle>,
}

/// State captured once when the delete-confirmation dialog opens. The dialog
/// is modal: its inputs (the profile set, routing rules, balancers) cannot
/// change while it is open, so the names and the reference scan are computed a
/// single time instead of on every repaint.
struct DeleteDialog {
    /// Every profile the one confirmation deletes, in the selection's display
    /// order.
    ids: Vec<String>,
    /// The dialog's subject: the row's name for a single delete, or the
    /// selected count for a batch.
    name: String,
    references: Vec<String>,
}

/// The Copy to group dialog: the subscription rows the copies are made of,
/// captured in the selection's display order, and the manual group they land
/// in. The target starts at the reserved `Manual` group.
struct CopyDialog {
    ids: Vec<String>,
    target: String,
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
    /// A plain click: focus and select one row, collapsing the selection.
    Select(String),
    /// A Ctrl-click: add or remove the row from the selection.
    ToggleSelection(String),
    /// A Shift-click: select the visible range from the anchor to the row.
    ExtendSelection(String),
    /// Ctrl+A: select every row the current tab shows.
    SelectAllVisible,
    /// A click on empty space: drop the selection.
    ClearSelection,
    SetActive(String),
    /// Flip the profile's switch. The active profile and a chain-only hop are
    /// locked; the handler re-checks both.
    ToggleEnabled(String),
    /// Set the switch on every selected row, skipping locked rows.
    SetSelectionEnabled(bool),
    /// Open the editor window on one profile.
    Edit(String),
    /// Append a copy of one profile beside it, in the same group.
    Duplicate(String),
    /// Share every selected row (one link per row on the clipboard).
    ExportSelection,
    /// Open the manual-group picker that copies every selected subscription
    /// row into it.
    CopySelection,
    /// Delete every selected row behind one confirmation.
    DeleteSelection,
    ProbeLatency(String),
    /// Probe the selection, or the whole current tab when nothing is
    /// selected.
    ProbeLatencySelection,
    /// Move the dragged profile (its index in the list as drawn) to a sibling
    /// inside its own group: `before` names the row it lands ahead of, or its
    /// block's tail. A cross-block drop never reaches this action.
    MoveInGroup {
        from: usize,
        before: Option<usize>,
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
    /// Open the editor window on one profile after resolution.
    OpenEditor(String),
    /// Close the editor window after resolution.
    CloseExisting,
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

/// What one import-preview row reports: a clean link, a link whose
/// compatibility parameters were dropped, or a failed link. The kind only
/// decides the row's color and tooltip.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ImportPreviewKind {
    Ok,
    Warn,
    Err,
}

/// One formatted import-preview row: the text the list paints and its kind.
struct ImportPreviewRow {
    text: String,
    kind: ImportPreviewKind,
}

/// Memoized pretty print of one preserved over-limit `downloadSettings`
/// subtree: its header body re-runs on every frame it stays open, and the
/// subtree is as large as the configuration behind it. The key is the draft
/// the text belongs to — the owned request target, whose generation every
/// editor change advances — plus the nesting depth the subtree sits at and the
/// language the frame renders under, so the text is rebuilt exactly when the
/// subtree it describes can have moved.
struct OverLimitJson {
    /// `None` for a render-only caller with no draft identity to key on: the
    /// text is refilled on every such call and never reused.
    key: Option<(ToolTarget, u32, Language)>,
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

/// What the server table shows: one of the three default views or one group.
/// Transient — opening the screen starts on `Emitted`, and nothing stores it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum ServerTab {
    #[default]
    Emitted,
    /// The built-in `Manual` group; its tab is a default, its group is not.
    Manual,
    All,
    Group(String),
}

/// The label on one tab: a default tab's static translation, or a group
/// tab's stored title borrowed from the model (falling back to the reserved
/// `Manual` title when the record is gone). Never allocates.
fn tab_label<'a>(
    tab: &ServerTab,
    servers: &'a crate::model::ServersFile,
    lang: Language,
) -> &'a str {
    match tab {
        ServerTab::Emitted => t(lang, Key::SrvTabEmitted),
        ServerTab::Manual => t(lang, Key::SrvTabManual),
        ServerTab::All => t(lang, Key::SrvTabAll),
        ServerTab::Group(id) => servers
            .group_title_of(id)
            .unwrap_or(crate::model::servers::MANUAL_GROUP_TITLE),
    }
}

/// The tabs the bar renders, in display order: the three default tabs, then
/// the pinned groups in stored order, then the unpinned ones. The `Manual`
/// group owns the default `Manual` tab, so it is not repeated here.
fn tab_order(servers: &crate::model::ServersFile) -> Vec<ServerTab> {
    let mut tabs = Vec::with_capacity(servers.groups.len() + 3);
    tabs.push(ServerTab::Emitted);
    tabs.push(ServerTab::Manual);
    tabs.push(ServerTab::All);
    for pinned in [true, false] {
        for group in &servers.groups {
            if !group.is_manual() && group.pinned == pinned {
                tabs.push(ServerTab::Group(group.id.clone()));
            }
        }
    }
    tabs
}

/// The sort a header click asks for: a new column starts ascending, the same
/// column toggles.
fn next_view_sort(current: Option<ViewSort>, column: SortColumn) -> ViewSort {
    match current {
        Some(sort) if sort.column == column => ViewSort {
            column,
            ascending: !sort.ascending,
        },
        _ => ViewSort {
            column,
            ascending: true,
        },
    }
}

/// The row list of one tab, rebuilt only when the model, the tab, the search
/// or the view sort moves.
struct TabRowsCache {
    generation: u64,
    tab: ServerTab,
    search: String,
    sort: Option<ViewSort>,
    rows: std::rc::Rc<[usize]>,
    /// The display rows a drag may lift or land on: the hops are not drag
    /// places, so they are left out here rather than filtered per frame.
    seeds: std::rc::Rc<[usize]>,
    /// `seeds_before[i]`: how many seed rows precede display index `i`.
    seeds_before: std::rc::Rc<[usize]>,
}

/// The tab bar's entries for one model generation. The list moves only when
/// the groups — their records, order or pins — do; a label is borrowed from
/// the model (or a static translation) and formatted per frame.
struct TabBarCache {
    generation: u64,
    tabs: std::rc::Rc<[ServerTab]>,
}

/// The subscription card's formatted lines: a feed's quota, expiry and update
/// hint are formatted once per group, model generation, language and traffic
/// unit, not per painted frame. The expiry line carries whether the feed is
/// past its date, because that line paints in the error color, and the day it
/// was formatted on — the remaining days change at midnight even when the
/// model does not.
struct SubscriptionCard {
    group: String,
    generation: u64,
    lang: Language,
    unit: crate::model::settings::TrafficUnit,
    /// The UTC day the expiry line was formatted on (`unix seconds /
    /// 86_400`); `None` when the feed reports no expiry.
    day: Option<u64>,
    quota: Option<String>,
    expiry: Option<(String, bool)>,
    update: Option<String>,
}

impl SubscriptionCard {
    /// Format `subscription`'s lines once, stamped with the inputs the text
    /// depends on.
    fn new(
        group: &str,
        generation: u64,
        lang: Language,
        unit: crate::model::settings::TrafficUnit,
        subscription: &crate::model::servers::Subscription,
    ) -> Self {
        let mut quota = None;
        let mut expiry = None;
        let mut update = None;
        let mut day = None;
        if let Some(metadata) = subscription.metadata.as_ref() {
            let used = metadata.upload.saturating_add(metadata.download);
            let has_quota = metadata.total > 0 || metadata.upload > 0 || metadata.download > 0;
            if has_quota && metadata.total > 0 {
                let percent = used
                    .saturating_mul(100)
                    .checked_div(metadata.total)
                    .unwrap_or_default();
                quota = Some(t_fmt(
                    lang,
                    Key::SrvQuotaUsed,
                    &[
                        &crate::ui::dashboard::format_bytes(used, unit),
                        &crate::ui::dashboard::format_bytes(metadata.total, unit),
                        &percent,
                    ],
                ));
            } else if has_quota {
                quota = Some(t_fmt(
                    lang,
                    Key::SrvQuotaUnlimited,
                    &[&crate::ui::dashboard::format_bytes(used, unit)],
                ));
            }
            if metadata.expire > 0 {
                let now = unix_now();
                day = Some(now / 86_400);
                expiry = Some(if now >= metadata.expire {
                    (t(lang, Key::SrvSubscriptionExpired).to_owned(), true)
                } else {
                    let days = (metadata.expire - now).div_ceil(86_400);
                    (
                        t_fmt(
                            lang,
                            Key::SrvSubscriptionExpiresIn,
                            &[&days, &unix_date(metadata.expire)],
                        ),
                        false,
                    )
                });
            }
            if metadata.update_interval > 0 {
                update = Some(t_fmt(
                    lang,
                    Key::SrvSubscriptionUpdateHint,
                    &[&metadata.update_interval],
                ));
            }
        }
        Self {
            group: group.to_owned(),
            generation,
            lang,
            unit,
            day,
            quota,
            expiry,
            update,
        }
    }
}

#[derive(Default)]
pub struct ServersScreen {
    selected: Option<String>,
    /// The rows selected in the current tab, by profile id. Scoped to the tab
    /// and to what the search shows: a row that leaves the visible set leaves
    /// the selection, and a tab switch clears it.
    selection: std::collections::BTreeSet<String>,
    /// The row a Shift-click extends from. `None` until a plain or Ctrl click
    /// names one.
    selection_anchor: Option<String>,
    /// Whether the opening focus was filled in. The screen focuses the active
    /// server (or the first row) once; switching tabs clears the focus and
    /// does not bring it back.
    selection_initialized: bool,
    /// The active tab. Opening the screen starts on `Emitted`.
    view: ServerTab,
    /// The screen's view sort, persisted with the UI preferences: it
    /// survives a tab switch and a restart, and never reorders stored rows.
    view_sort: Option<ViewSort>,
    /// Whether the persisted view sort was read into this screen. The sort
    /// ships in the settings, so the screen loads it on its first frame.
    sort_initialized: bool,
    /// The list's search text; it filters the current tab only.
    search: String,
    tab_rows_cache: Option<TabRowsCache>,
    /// The tab bar's entry list, rebuilt only when the model generation
    /// moves (see [`TabBarCache`]).
    tab_bar_cache: Option<TabBarCache>,
    /// The subscription card's formatted text, rebuilt only when its group,
    /// the model generation, the language or the traffic unit moves (see
    /// [`SubscriptionCard`]).
    subscription_card: Option<SubscriptionCard>,
    /// The model generation the selection was last pruned against: a stale
    /// selection id can only come from a model change.
    selection_generation: Option<u64>,
    /// Per-profile table cells (the protocol-and-security column and the
    /// `address:port` column), rebuilt only when the model generation moves.
    row_details: Option<(
        u64,
        std::rc::Rc<std::collections::HashMap<usize, RowDetail>>,
    )>,
    /// The column widths fitted to the header and the cell text, rebuilt when
    /// the model generation or the language moves. The table reads the
    /// widths the user dragged from the settings and falls back to these.
    adaptive_widths: Option<(u64, Language, ColumnWidths)>,
    /// The toolbar's "Fit columns" command, consumed by the table on the
    /// frame that set it.
    fit_columns: bool,
    /// The widths a divider drag works from, with the divider the pointer
    /// grabbed. Held across frames so each frame lays the column out from the
    /// press, not from the previous frame's stored widths.
    column_drag: Option<ColumnDrag>,
    /// The emitted set memoized for one model generation: the row switches
    /// and their lock hints read it, and it is rebuilt only when the model
    /// moves, never per repaint.
    emitted_cache: Option<(u64, std::rc::Rc<crate::model::servers::EmittedSet>)>,
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
    /// The two editor slots: the selected profile's editor and the in-progress
    /// add-server dialog. Each holds its own draft, chain-target memo and probe
    /// state, so neither can read the other's verdicts, options or pins while
    /// both render in one frame.
    existing: DraftSlot,
    add: DraftSlot,
    /// The selected profile editor's reveal control: `true` while the user
    /// asked to see the credentials this screen hides. Transient — leaving the
    /// screen or selecting another profile hides them again.
    revealed_existing: bool,
    /// The add-draft dialog's reveal control. It opens revealed and keeps that
    /// state for the dialog's lifetime: an empty form hides no credential, and
    /// the user opened it to type one — masking it on a screen round-trip
    /// would demand a click mid-entry. It is not the editor's reveal, which
    /// dies with the screen.
    revealed_add: bool,
    /// The list's reveal control: `true` while the user asked to see the
    /// server information this screen hides. Transient — leaving the screen
    /// hides it again. It is not the editor's reveal: the list shows no
    /// credentials.
    revealed_list: bool,
    import_open: bool,
    import_text: String,
    /// The group a paste or converted batch lands in: the group the tab that
    /// opened the import dialog owns.
    import_group: Option<String>,
    group_dialog: Option<GroupDraft>,
    /// The one in-flight refresh; the group it targets travels with the
    /// result.
    subscription_fetch: Request<SubscriptionFetchResult>,
    /// The group the in-flight fetch targets, so deleting another group does
    /// not cancel it.
    subscription_fetch_group: Option<String>,
    /// A group awaiting delete confirmation.
    group_delete_pending: Option<String>,
    import_parsed: Vec<Result<links::ParsedLink, String>>,
    import_parsed_source: Option<String>,
    import_refusals: Vec<(String, String)>,
    import_ignored: usize,
    import_ignored_names: Vec<String>,
    /// The report window on screen: its title and one refresh report.
    report_view: Option<(String, crate::model::servers::RefreshReport)>,
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
    /// The Copy to group picker; `Some` while it is on screen.
    copy_dialog: Option<CopyDialog>,
    delete_pending: Option<DeleteDialog>,
    derive_dialog: Option<DeriveDialog>,
    /// Staged leave action awaiting the unsaved-changes modal (see
    /// [`LeaveAction`]): the modal renders while this is `Some`, and the
    /// commit handlers clear it once the staged action resolves.
    leave_pending: Option<LeaveAction>,
    status: Option<StatusLine>,
    /// When the current status toast was set; the toast auto-clears once
    /// [`STATUS_TOAST_AUTO_CLEAR`] has elapsed (see `show_status_toast`).
    status_set_at: Option<Instant>,
    tool_job: Option<XrayToolJob>,
    /// The seeded text buffers the raw-JSON and PEM editors render from,
    /// keyed by the field's egui `Id` (per-field buffer identity, stable
    /// across frames, no per-frame key allocation); evicted with their owning
    /// profile.
    seeded_buffers: SeededBuffers,
    /// Reused edit buffers for the header key/value tables (`json_map_kv`):
    /// the key column and the non-string value rows each need a `&mut String`
    /// for the frame, and one owned buffer per row would allocate on every
    /// repaint. Seeded from the row's own text before each widget and read
    /// back only when that widget reports an edit.
    json_scratch: KvScratch,
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
    parsed: Vec<Result<links::ParsedLink, String>>,
    /// Refused items with their raw text, for the report.
    refused: Vec<(String, String)>,
    ignored: usize,
    /// The ignored sections/parameters, named for the report rows.
    ignored_names: Vec<String>,
}

/// The New group dialog's fields: a kind choice, then the fields that kind
/// asks for. Editing an existing group keeps its kind — the dialog shows the
/// kind but never offers the other one.
#[derive(Default)]
struct GroupDraft {
    /// The group being edited; `None` creates a new group.
    editing: Option<String>,
    kind: crate::model::servers::GroupKind,
    title: String,
    url: String,
    custom_user_agent: bool,
    user_agent: String,
}

impl GroupDraft {
    /// The dialog for `group`: its kind is fixed and its fields are the
    /// stored ones.
    fn editing(group: &crate::model::servers::Group) -> Self {
        let subscription = group.subscription.as_ref();
        Self {
            editing: Some(group.id.clone()),
            kind: group.kind(),
            title: group.title.clone(),
            url: subscription
                .map(|subscription| subscription.url.clone())
                .unwrap_or_default(),
            custom_user_agent: subscription
                .is_some_and(|subscription| subscription.user_agent_custom),
            user_agent: subscription
                .map(|subscription| subscription.user_agent.clone())
                .unwrap_or_default(),
        }
    }
}

/// The kind names the New group dialog offers.
fn group_kind_label(kind: crate::model::servers::GroupKind, lang: Language) -> &'static str {
    match kind {
        crate::model::servers::GroupKind::Manual => t(lang, Key::SrvGroupKindManual),
        crate::model::servers::GroupKind::Subscription => t(lang, Key::SrvGroupKindSubscription),
    }
}

/// The add draft's group picker: every group by title, writing the chosen
/// group's id and cached title into the draft. A draft pointing at a vanished
/// group shows `Manual`, which is where its row would land. Returns whether the
/// user chose another group.
fn group_picker(
    ui: &mut egui::Ui,
    servers: &crate::model::ServersFile,
    profile: &mut crate::model::servers::ServerProfile,
) -> bool {
    let selected = servers
        .group_title_of(profile.group_id())
        .unwrap_or(crate::model::servers::MANUAL_GROUP_TITLE);
    let mut changed = false;
    egui::ComboBox::from_id_salt("servers.add-draft.group")
        .selected_text(selected)
        .show_ui(ui, |ui| {
            for group in &servers.groups {
                let current = profile.group_id() == group.id.as_str();
                if ui.selectable_label(current, &group.title).clicked() && !current {
                    profile.group = group.id.clone();
                    profile.group_title = group.title.clone();
                    changed = true;
                }
            }
        });
    changed
}

/// One fetch worker's terminal result.
struct SubscriptionFetchResult {
    group_id: String,
    outcome: Result<crate::sys::subscription::FetchOutcome, crate::sys::subscription::FetchError>,
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
                Ok(parsed) => {
                    ok += 1;
                    let protocol = parsed.outbound.protocol.as_str();
                    if parsed.ignored.is_empty() {
                        ImportPreviewRow {
                            text: t_fmt(lang, Key::SrvImportOkMark, &[&parsed.name, &protocol]),
                            kind: ImportPreviewKind::Ok,
                        }
                    } else {
                        ImportPreviewRow {
                            text: t_fmt(
                                lang,
                                Key::SrvImportIgnoredMark,
                                &[&parsed.name, &protocol, &parsed.ignored.join(", ")],
                            ),
                            kind: ImportPreviewKind::Warn,
                        }
                    }
                }
                Err(error) => ImportPreviewRow {
                    text: t_fmt(lang, Key::SrvImportErrMark, &[error]),
                    kind: ImportPreviewKind::Err,
                },
            })
            .collect();
        self.import_preview = Some(ImportPreview { lang, ok, rows });
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
            let mut body = links::parse_body_cancellable(&text, stop);
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                return None;
            }
            let refused: Vec<(String, String)> = body
                .refused
                .iter()
                .map(|refusal| (refusal.raw.clone(), refusal.error.clone()))
                .collect();
            let ignored = body.ignored.len();
            let ignored_names: Vec<String> = body
                .ignored
                .iter()
                .map(|section| section.name.clone())
                .collect();
            let mut parsed: Vec<Result<links::ParsedLink, String>> =
                std::mem::take(&mut body.entries)
                    .into_iter()
                    .map(|entry| {
                        Ok(links::ParsedLink {
                            profile: entry.profile,
                            ignored: entry.ignored,
                        })
                    })
                    .collect();
            parsed.extend(body.refused.into_iter().map(|refusal| Err(refusal.error)));
            Some(ImportParseResult {
                source: text,
                parsed,
                refused,
                ignored,
                ignored_names,
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
        self.import_refusals = result.refused;
        self.import_ignored = result.ignored;
        self.import_ignored_names = result.ignored_names;
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

    /// Start one subscription refresh. The group's stored User-Agent wins
    /// when set; otherwise the global one is sent (an empty global value
    /// omits the header).
    fn start_subscription_fetch(
        &mut self,
        lang: Language,
        repaint: egui::Context,
        uictx: &mut ServersCtx<'_>,
        group_id: String,
    ) {
        let Some(group) = uictx
            .servers
            .groups
            .iter()
            .find(|group| group.id == group_id)
        else {
            return;
        };
        let Some(subscription) = group.subscription.as_ref() else {
            return;
        };
        let url = subscription.url.clone();
        let user_agent = subscription.effective_user_agent(&uictx.settings.subscription_user_agent);
        let bind = match subscription_bind_address(lang, uictx.settings, uictx.core_running) {
            Ok(bind) => bind,
            Err(error) => {
                self.set_status(StatusLine::err(error));
                return;
            }
        };
        self.subscription_fetch_group = Some(group_id.clone());
        match Request::worker("broccoli-subscription-fetch", &repaint, move |stop| {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                return None;
            }
            let outcome = crate::sys::subscription::fetch(&url, &user_agent, bind);
            Some(SubscriptionFetchResult { group_id, outcome })
        }) {
            Ok(job) => self.subscription_fetch = job,
            Err(error) => self.set_status(StatusLine::err(t_fmt(
                lang,
                Key::SrvSubscriptionFetchFailed,
                &[&error.to_string()],
            ))),
        }
    }

    /// Drain one finished fetch: reconcile the group, store the metadata and
    /// the report, or keep the previous servers and record the error.
    fn poll_subscription_fetch(&mut self, lang: Language, uictx: &mut ServersCtx<'_>) {
        let Some(terminal) = self.subscription_fetch.poll() else {
            return;
        };
        self.subscription_fetch_group = None;
        let result = match terminal {
            Terminal::Answered(result) => result,
            Terminal::Exited => {
                self.set_status(StatusLine::err(t(lang, Key::WorkerExitedWithoutResult)));
                return;
            }
        };
        let Some(index) = uictx
            .servers
            .groups
            .iter()
            .position(|group| group.id == result.group_id)
        else {
            return;
        };
        let at = unix_now();
        match result.outcome {
            Err(error) => {
                if let Some(subscription) = uictx.servers.groups[index].subscription.as_mut() {
                    subscription.last_fetch = Some(crate::model::servers::FetchResult {
                        at,
                        ok: false,
                        error: error.to_string(),
                        ..Default::default()
                    });
                }
                let message = t_fmt(lang, Key::SrvSubscriptionFetchFailed, &[&error.to_string()]);
                let mut report = crate::model::servers::RefreshReport {
                    at,
                    refused: 1,
                    ..Default::default()
                };
                crate::model::servers::push_report_row(
                    &mut report.rows,
                    crate::model::servers::ReportRow {
                        kind: crate::model::servers::ReportKind::Refused,
                        name: error.to_string(),
                        raw: error.to_string(),
                    },
                );
                let title = uictx.servers.groups[index].title.clone();
                if let Some(subscription) = uictx.servers.groups[index].subscription.as_mut() {
                    subscription.report = Some(report.clone());
                }
                self.report_view = Some((title, report));
                self.set_status(StatusLine::err(message));
                uictx.hooks.mark_dirty();
            }
            Ok(outcome) => {
                let parsed = links::parse_body(&outcome.body);
                if parsed.entries.is_empty() {
                    let mut report = crate::model::servers::RefreshReport {
                        at,
                        refused: parsed.refused.len().max(1),
                        ignored: parsed.ignored.len(),
                        ..Default::default()
                    };
                    let mut rows = Vec::new();
                    for refusal in &parsed.refused {
                        crate::model::servers::push_report_row(
                            &mut rows,
                            crate::model::servers::ReportRow {
                                kind: crate::model::servers::ReportKind::Refused,
                                name: refusal.error.clone(),
                                raw: refusal.raw.clone(),
                            },
                        );
                    }
                    for ignored in &parsed.ignored {
                        crate::model::servers::push_report_row(
                            &mut rows,
                            crate::model::servers::ReportRow {
                                kind: crate::model::servers::ReportKind::Ignored,
                                name: ignored.name.clone(),
                                raw: String::new(),
                            },
                        );
                    }
                    if parsed.refused.is_empty() {
                        crate::model::servers::push_report_row(
                            &mut rows,
                            crate::model::servers::ReportRow {
                                kind: crate::model::servers::ReportKind::Refused,
                                name: t(lang, Key::SrvSubscriptionEmpty).to_owned(),
                                raw: String::new(),
                            },
                        );
                    }
                    report.rows = rows;
                    let title = uictx.servers.groups[index].title.clone();
                    if let Some(subscription) = uictx.servers.groups[index].subscription.as_mut() {
                        subscription.last_fetch = Some(crate::model::servers::FetchResult {
                            at,
                            ok: false,
                            error: t(lang, Key::SrvSubscriptionEmpty).into(),
                            ..Default::default()
                        });
                        subscription.report = Some(report.clone());
                    }
                    self.report_view = Some((title, report));
                    self.set_status(StatusLine::err(t(lang, Key::SrvSubscriptionEmpty)));
                    uictx.hooks.mark_dirty();
                    return;
                }
                let entries: Vec<crate::model::servers::SubscriptionEntry> = parsed
                    .entries
                    .iter()
                    .map(|entry| crate::model::servers::SubscriptionEntry {
                        profile: entry.profile.clone(),
                        content_key: links::body::content_key(&entry.profile),
                        identity_key: links::body::identity_key(&entry.profile),
                    })
                    .collect();
                let mut report = uictx.servers.refresh_subscription_group(
                    uictx.settings,
                    &result.group_id,
                    entries,
                );
                report.refused = parsed.refused.len();
                report.ignored = parsed.ignored.len();
                for refusal in &parsed.refused {
                    crate::model::servers::push_report_row(
                        &mut report.rows,
                        crate::model::servers::ReportRow {
                            kind: crate::model::servers::ReportKind::Refused,
                            name: refusal.error.clone(),
                            raw: refusal.raw.clone(),
                        },
                    );
                }
                for ignored in &parsed.ignored {
                    crate::model::servers::push_report_row(
                        &mut report.rows,
                        crate::model::servers::ReportRow {
                            kind: crate::model::servers::ReportKind::Ignored,
                            name: ignored.name.clone(),
                            raw: String::new(),
                        },
                    );
                }
                let pick = |header: &str, key: &str| -> String {
                    if header.trim().is_empty() {
                        parsed.comments.get(key).cloned().unwrap_or_default()
                    } else {
                        header.to_owned()
                    }
                };
                let metadata = crate::model::servers::SubscriptionMetadata::from_provider(
                    &pick(
                        &outcome.headers.subscription_userinfo,
                        "subscription-userinfo",
                    ),
                    &pick(
                        &outcome.headers.profile_update_interval,
                        "profile-update-interval",
                    ),
                    &pick(&outcome.headers.profile_title, "profile-title"),
                    &pick(
                        &outcome.headers.profile_web_page_url,
                        "profile-web-page-url",
                    ),
                    &pick(&outcome.headers.support_url, "support-url"),
                    &pick(&outcome.headers.announce, "announce"),
                );
                // A provider title pre-fills a group the user left unnamed.
                if let Some(title) = metadata
                    .as_ref()
                    .map(|metadata| metadata.title.clone())
                    .filter(|title| !title.is_empty())
                    && uictx.servers.groups[index]
                        .subscription
                        .as_ref()
                        .is_some_and(|subscription| {
                            subscription.report.is_none() && subscription.title_auto
                        })
                {
                    crate::model::servers::rename_group(
                        uictx.servers,
                        uictx.settings,
                        &result.group_id,
                        &title,
                    );
                    if let Some(subscription) = uictx.servers.groups[index].subscription.as_mut() {
                        subscription.title_auto = false;
                    }
                }
                let report_view = report.clone();
                let report_title = uictx.servers.groups[index].title.clone();
                if let Some(subscription) = uictx.servers.groups[index].subscription.as_mut() {
                    subscription.last_fetch = Some(crate::model::servers::FetchResult {
                        at,
                        ok: true,
                        error: String::new(),
                        ..Default::default()
                    });
                    subscription.metadata = metadata;
                    subscription.report = Some(report);
                }
                self.report_view = Some((report_title, report_view));
                uictx.hooks.mark_dirty();
            }
        }
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
        ctx: &mut ServersCtx<'_>,
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
        if !ctx.hooks.send(CoreCmd::ValidateProfiles {
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
            // The runtime's command channel is gone: no terminal can arrive,
            // so nothing may stay pending. The refusal names why — the send
            // verb logged the closed channel, and the user's message carries
            // the same fact.
            self.profile_validation_origin = None;
            self.profile_validation_count = 0;
            return Err(t_fmt(
                lang,
                Key::SrvStartValidationFailed,
                &[&t(lang, Key::CoreRuntimeUnavailable)],
            ));
        }
        self.profile_validation_request = Request::reply(rx);
        Ok(())
    }

    fn poll_profile_validation(&mut self, lang: Language, uictx: &mut ServersCtx) {
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
                if self.current_draft(target).is_none() {
                    // The draft this verdict belongs to has been edited,
                    // replaced or closed since the request went out: the
                    // generation check is what makes a stale verdict safe.
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
                match target.draft_kind() {
                    DraftKind::Add => {
                        let id = profile.id.clone();
                        self.add.draft = None;
                        uictx.servers.adopt_profile(profile);
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
                        uictx.hooks.mark_dirty();
                        // The leave modal's Save committed the add draft:
                        // resume the staged action (see
                        // [`Self::resume_leave_after_commit`]). A Select
                        // staged by the guard above stays staged until the
                        // existing draft's question resolves it.
                        self.resume_leave_after_commit(DraftKind::Add, uictx);
                    }
                    DraftKind::Existing => {
                        let exists = uictx
                            .servers
                            .profiles
                            .iter()
                            .any(|persisted| persisted.id == target.profile_id());
                        if !exists {
                            self.profile_validation_report =
                                Some(t(lang, Key::SrvServerDeletedWhileValidating).into());
                            return;
                        }
                        uictx.servers.replace_profile(uictx.settings, profile);
                        self.existing.draft = None;
                        self.profile_validation_report = None;
                        self.set_status(StatusLine::ok(t(lang, Key::SrvServerValidatedAndSaved)));
                        uictx.hooks.mark_dirty();
                        // The leave modal's Save committed the existing
                        // draft: resume the staged action (see
                        // [`Self::resume_leave_after_commit`]). A CloseAdd
                        // stays staged for the add draft's own Save.
                        self.resume_leave_after_commit(DraftKind::Existing, uictx);
                    }
                }
            }
            ProfileValidationOrigin::Import => {
                let accepted_count = result.accepted.len();
                let mut added_names = Vec::new();
                if accepted_count > 0 {
                    let first_id = result.accepted[0].id.clone();
                    // The tab that opened the import owns the batch: the
                    // dialog captured its group, so a tab switch while the
                    // paste validated cannot retarget it.
                    let target_group = self
                        .import_group
                        .clone()
                        .unwrap_or_else(|| self.target_group(uictx.servers));
                    for profile in result.accepted {
                        if uictx
                            .servers
                            .profiles
                            .iter()
                            .any(|existing| existing.id == profile.id)
                        {
                            uictx.servers.replace_profile(uictx.settings, profile);
                        } else {
                            added_names.push(profile.name.clone());
                            uictx.servers.adopt_profile_in(profile, &target_group);
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
                    uictx.hooks.mark_dirty();
                }
                let refusals = std::mem::take(&mut self.import_refusals);
                let ignored = std::mem::take(&mut self.import_ignored);
                let ignored_names = std::mem::take(&mut self.import_ignored_names);
                if !added_names.is_empty() || !refusals.is_empty() || !ignored_names.is_empty() {
                    let mut report = crate::model::servers::RefreshReport {
                        at: unix_now(),
                        added: added_names.len(),
                        refused: refusals.len(),
                        ignored,
                        ..Default::default()
                    };
                    for name in added_names {
                        crate::model::servers::push_report_row(
                            &mut report.rows,
                            crate::model::servers::ReportRow {
                                kind: crate::model::servers::ReportKind::Added,
                                name,
                                raw: String::new(),
                            },
                        );
                    }
                    for (raw, error) in refusals {
                        crate::model::servers::push_report_row(
                            &mut report.rows,
                            crate::model::servers::ReportRow {
                                kind: crate::model::servers::ReportKind::Refused,
                                name: error,
                                raw,
                            },
                        );
                    }
                    for name in ignored_names {
                        crate::model::servers::push_report_row(
                            &mut report.rows,
                            crate::model::servers::ReportRow {
                                kind: crate::model::servers::ReportKind::Ignored,
                                name,
                                raw: String::new(),
                            },
                        );
                    }
                    self.report_view = Some((t(lang, Key::SrvReportTitle).to_string(), report));
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
        // The cooperative stop flag ends a cancelled run: the verb's adapter
        // abandons its work on the same flag, and a verdict for a cancelled
        // request is dropped here instead of delivered, so the screen's
        // stale-target check never sees it.
        let request = Request::worker("broccoli-xray-tool", &repaint, move |stop| {
            if stop.load(Ordering::Acquire) {
                return None;
            }
            let result = xray_tool::run(kind, lang, &args, stop);
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

    /// The editor slot `kind` names.
    fn slot(&self, kind: DraftKind) -> &DraftSlot {
        match kind {
            DraftKind::Existing => &self.existing,
            DraftKind::Add => &self.add,
        }
    }

    /// The editor slot `kind` names, mutably.
    fn slot_mut(&mut self, kind: DraftKind) -> &mut DraftSlot {
        match kind {
            DraftKind::Existing => &mut self.existing,
            DraftKind::Add => &mut self.add,
        }
    }

    /// Switch the draft's protocol and surface the transport reset xdrive
    /// forces when the profile leaves VLESS. The status carries the note;
    /// the switch reports whether anything changed.
    fn switch_draft_protocol(
        &mut self,
        profile: &mut ServerProfile,
        protocol: Protocol,
        lang: Language,
    ) -> bool {
        if profile.outbound.protocol == protocol {
            return false;
        }
        let switched = profile.outbound.select_protocol(protocol);
        if switched == crate::model::outbound::ProtocolSwitch::XdriveReset {
            self.set_status(StatusLine::ok(t(lang, Key::SrvXdriveResetToRaw)));
        }
        true
    }

    /// The open draft in `kind`'s slot, if any.
    fn draft(&self, kind: DraftKind) -> Option<&ProfileDraft> {
        self.slot(kind).draft()
    }

    /// The open draft in `kind`'s slot, mutably, if any.
    fn draft_mut(&mut self, kind: DraftKind) -> Option<&mut ProfileDraft> {
        self.slot_mut(kind).draft_mut()
    }

    /// The TLS probe state the Security tab renders for `target`: the slot that
    /// target names, or the editor slot's when the stream carries no draft
    /// identity of its own (a nested or read-only settings block shows the
    /// editor's panel, and its own probe request is refused for want of an
    /// identity).
    fn probe_for_target(&mut self, target: Option<DraftTarget<'_>>) -> &mut TlsProbe {
        match target {
            Some(target) => &mut self.slot_mut(target.kind).probe,
            None => &mut self.existing.probe,
        }
    }

    /// The draft `target` names, when it is still the open one at the same
    /// generation: a tool or validation verdict for a draft that has been
    /// edited, replaced or closed since the request went out is dropped here.
    fn current_draft(&self, target: &ToolTarget) -> Option<&ProfileDraft> {
        self.draft(target.draft_kind())
            .filter(|draft| target.matches(draft.draft_target()))
    }

    /// The gate of the open draft in `kind`'s slot as this frame sees it;
    /// `None` while that slot is empty. `busy` is the frame's own fact — a
    /// caller with no frame (the topbar chip's per-frame check) passes
    /// `false` and reads only a composition that ignores it.
    fn gate(&self, kind: DraftKind, busy: bool) -> Option<DraftGate> {
        self.draft(kind).map(|draft| {
            draft.gate(
                &self.seeded_buffers,
                self.profile_validation_in_progress(ProfileValidationOrigin::Draft),
                busy,
            )
        })
    }

    /// The change protocol for the selected profile's draft: an edit, a tool
    /// application or a dismissal landed, so the draft's memoized validation no
    /// longer covers it and the reported validation output — which described the
    /// content before the edit — is dropped with it. Nothing then renders a
    /// stale verdict or a stale log beside the edited profile; Validate-and-save
    /// recomputes both. The add dialog keeps its report until its next attempt,
    /// because that output is why its window is still open (see
    /// [`ProfileDraft::edited`]).
    fn draft_edited(&mut self, draft: &mut ProfileDraft) {
        draft.edited();
        self.profile_validation_report = None;
    }

    /// The profile a tool verdict writes into: the draft `target` names, at
    /// any generation (the verdict's currency was checked before it was
    /// applied).
    fn profile_for_target_mut(&mut self, target: &ToolTarget) -> Option<&mut ServerProfile> {
        self.draft_mut(target.draft_kind())
            .filter(|draft| draft.id == target.profile_id())
            .map(|draft| &mut draft.profile)
    }

    /// A tool verdict landed in the draft `target` names, so the draft's change
    /// protocol runs: the memoized validation sweeps the mutated profile on the
    /// next refresh and any in-flight request for the older generation is
    /// dropped. The screen's validation report is left alone — it belongs to the
    /// last Validate, not to a tool.
    fn advance_target_generation(&mut self, target: &ToolTarget) {
        if let Some(draft) = self.draft_mut(target.draft_kind())
            && draft.id == target.profile_id()
        {
            draft.edited();
        }
    }

    /// Report a tool's failure where its own control renders: the probe's panel
    /// for the TLS probe kinds, the derive dialog for the REALITY key, and the
    /// status line otherwise.
    fn report_tool_error(&mut self, target: &ToolTarget, kind: XrayToolKind, error: String) {
        match kind {
            XrayToolKind::TlsPin => {
                self.slot_mut(target.draft_kind()).probe.error = Some(error);
            }
            XrayToolKind::TlsPing | XrayToolKind::TlsPingQuic => {
                let probe = &mut self.slot_mut(target.draft_kind()).probe;
                probe.error = Some(error);
                // A failed probe leaves no current handshake to pin.
                probe.handshake_ok = false;
                probe.profile = None;
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
                    if profile
                        .outbound
                        .settings
                        .write_generated_secret(GeneratedSecret::Id, value)
                        .is_ok()
                    {
                        applied = true;
                        Ok(t(lang, Key::SrvUuidGenerated).to_string())
                    } else {
                        Err(t(lang, Key::SrvUuidTargetNoId).into())
                    }
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
                        if profile
                            .outbound
                            .settings
                            .write_generated_secret(GeneratedSecret::VlessEncryption, &value)
                            .is_ok()
                        {
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
                Some(value) if v_wg_secret_key(lang, &value).is_none() => {
                    if let Some(profile) = self.profile_for_target_mut(target) {
                        if profile
                            .outbound
                            .settings
                            .write_generated_secret(GeneratedSecret::WireguardSecretKey, &value)
                            .is_ok()
                        {
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
                            let probe = &mut self.slot_mut(target.draft_kind()).probe;
                            probe.output = Some(t_fmt(lang, Key::SrvTlsPinComputedLeaf, &[&value]));
                            probe.error = None;
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
                    let probe = &mut self.slot_mut(target.draft_kind()).probe;
                    probe.leaf_pin = leaf_pin_from_probe_output(&output);
                    probe.ca_pins = ca_pins_from_probe_output(&output);
                    probe.profile = Some(target.profile_id().to_owned());
                    probe.handshake_ok = true;
                    probe.output = Some(output);
                    probe.error = None;
                    Ok(t(lang, Key::SrvTlsHandshakeSucceeded).to_string())
                } else {
                    self.slot_mut(target.draft_kind()).probe.handshake_ok = false;
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
            Err(error) => self.report_tool_error(target, kind, error),
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
        if self.current_draft(&job.target).is_none() {
            return;
        }
        match terminal {
            Terminal::Answered(Ok(output)) => {
                self.apply_tool_output(lang, &job.target, job.kind, output)
            }
            Terminal::Answered(Err(error)) => self.report_tool_error(&job.target, job.kind, error),
            Terminal::Exited => self.report_tool_error(
                &job.target,
                job.kind,
                t(lang, Key::SrvToolStoppedWithoutResult).into(),
            ),
        }
    }

    /// Hide the editor's values again. The shell calls this when the user
    /// leaves the screen, so a reveal never outlives the visit. The add-server
    /// dialog's reveal is not the editor's: it belongs to the dialog's own
    /// lifetime, which starts revealed (see `revealed_add`).
    pub(crate) fn mask_secrets(&mut self) {
        self.revealed_existing = false;
        self.revealed_list = false;
        // The memoized row details hold the masked or revealed endpoint; a
        // reset must not survive in the cache after the screen is left.
        self.row_details = None;
    }

    pub fn show(&mut self, ui: &mut egui::Ui, ctx: &mut ServersCtx) {
        let lang = ctx.settings.language;
        self.poll_profile_validation(lang, ctx);
        self.poll_import_parse(lang);
        self.poll_subscription_fetch(lang, ctx);
        self.poll_xray_tool(lang);
        self.consume_latency_probe_result(ctx);
        // Keep the focus, the multi-selection and the open editor pointing at
        // real profiles. A stale selection id can only come from a model
        // change, so the selection sweep runs when the generation moves,
        // never on every repaint.
        if let Some(id) = &self.selected
            && !ctx.servers.profiles.iter().any(|profile| &profile.id == id)
        {
            self.selected = None;
        }
        let generation = ctx.hooks.model_generation();
        if self.selection_generation != Some(generation) {
            self.selection_generation = Some(generation);
            self.retain_existing_selection(ctx.servers);
        }
        if self.existing.draft().is_some_and(|draft| {
            !ctx.servers
                .profiles
                .iter()
                .any(|profile| profile.id == draft.id)
        }) {
            // The edited profile was deleted under the window: drop the draft
            // and the buffers seeded for it.
            self.existing.close(&mut self.seeded_buffers);
        }
        if ctx.servers.active_route_repaired {
            ctx.servers.active_route_repaired = false;
            self.set_status(StatusLine::err(t(lang, Key::SrvActiveRouteReset)));
        }
        if !self.selection_initialized {
            self.selection_initialized = true;
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
        }
        // The view sort is a UI preference: the screen reads it once, from
        // the settings, so the table opens in the order the user left it.
        if !self.sort_initialized {
            self.sort_initialized = true;
            self.view_sort = ctx.settings.server_table_sort;
        }
        // A group deleted under its tab falls back to the default view; the
        // selection belongs to the tab that just went away.
        let stale_view = matches!(&self.view, ServerTab::Group(id)
            if !ctx.servers.groups.iter().any(|group| &group.id == id));
        if stale_view {
            self.select_tab(ServerTab::Emitted);
        }

        egui::CentralPanel::default().show(ui, |ui| self.show_table(ui, ctx));
        self.show_dialogs(ui.ctx(), ctx);
    }

    // ---------- tab bar ----------

    /// Switch tabs. The selection belongs to the tab that was showing, so it
    /// is dropped here; the view sort is the screen's and stays, and the
    /// stored order never moves.
    fn select_tab(&mut self, tab: ServerTab) {
        if self.view == tab {
            return;
        }
        self.view = tab;
        self.selected = None;
        self.selection.clear();
        self.selection_anchor = None;
        self.tab_rows_cache = None;
    }

    /// The group a new row lands in: the current tab's group, or `Manual` when
    /// the tab is a view over the profile list. A group that disappeared falls
    /// back to `Manual` with it.
    fn target_group(&self, servers: &crate::model::ServersFile) -> String {
        match &self.view {
            ServerTab::Group(id) if servers.group_title_of(id).is_some() => id.clone(),
            _ => crate::model::servers::MANUAL_GROUP_ID.to_owned(),
        }
    }

    /// Point an add draft at the group the current tab owns, so the picker
    /// opens on that group and the row lands there.
    fn target_profile_group(
        &self,
        servers: &crate::model::ServersFile,
        profile: &mut crate::model::servers::ServerProfile,
    ) {
        let group = self.target_group(servers);
        profile.group_title = servers
            .group_title_of(&group)
            .unwrap_or(crate::model::servers::MANUAL_GROUP_TITLE)
            .to_owned();
        profile.group = group;
    }

    /// The tab bar above the table. The three default tabs stay first and
    /// undeletable; every group tab follows in its band, can be dragged inside
    /// that band, and pins or unpins from its context menu.
    fn show_tab_bar(&mut self, ui: &mut egui::Ui, ctx: &mut ServersCtx, lang: Language) {
        // The tab list is a function of the groups alone, so it is rebuilt
        // with the model and borrowed every other frame: the labels come from
        // the model (or the static translations) rather than from a
        // per-frame String per tab.
        let generation = ctx.hooks.model_generation();
        if self.tab_bar_cache.as_ref().map(|cache| cache.generation) != Some(generation) {
            self.tab_bar_cache = Some(TabBarCache {
                generation,
                tabs: std::rc::Rc::from(tab_order(ctx.servers).into_boxed_slice()),
            });
        }
        let tabs = std::rc::Rc::clone(
            &self
                .tab_bar_cache
                .as_ref()
                .expect("the tab list was cached above")
                .tabs,
        );
        let mut select: Option<ServerTab> = None;
        let mut pin: Option<(String, bool)> = None;
        let mut rename: Option<String> = None;
        let mut delete: Option<String> = None;
        // One rect per tab, by tab index: the drop half looks the target up
        // in the cached list instead of cloning tabs into a second vector.
        let mut tab_rects: Vec<egui::Rect> = Vec::with_capacity(tabs.len());
        ui.horizontal_wrapped(|ui| {
            for tab in tabs.iter() {
                let selected = self.view == *tab;
                let mut text = egui::RichText::new(tab_label(tab, ctx.servers, lang));
                text = if selected {
                    text.strong().color(ui.visuals().text_color())
                } else {
                    text.weak()
                };
                let response = ui.add(egui::Button::new(text).frame(false));
                tab_rects.push(response.rect);
                if selected {
                    // A tab reads as a tab through its rule, not a filled
                    // pill: the strip under the labels is the selection.
                    ui.painter().rect_filled(
                        egui::Rect::from_min_size(
                            egui::pos2(response.rect.left(), response.rect.bottom() + 1.0),
                            egui::vec2(response.rect.width(), 2.0),
                        ),
                        1.0,
                        ui.visuals().selection.bg_fill,
                    );
                }
                if response.clicked() {
                    select = Some(tab.clone());
                }
                let ServerTab::Group(id) = tab else {
                    continue;
                };
                if response
                    .interact(egui::Sense::click_and_drag())
                    .drag_started_by(egui::PointerButton::Primary)
                {
                    egui::DragAndDrop::set_payload(ui.ctx(), DragTab(tab.clone()));
                }
                let pinned = ctx
                    .servers
                    .groups
                    .iter()
                    .find(|group| &group.id == id)
                    .is_some_and(|group| group.pinned);
                response.context_menu(|ui| {
                    let (key, value) = if pinned {
                        (Key::SrvUnpinTab, false)
                    } else {
                        (Key::SrvPinTab, true)
                    };
                    if ui.button(t(lang, key)).clicked() {
                        pin = Some((id.clone(), value));
                        ui.close();
                    }
                    ui.separator();
                    if ui.button(t(lang, Key::SrvRenameGroup)).clicked() {
                        rename = Some(id.clone());
                        ui.close();
                    }
                    if ui.button(t(lang, Key::SrvDeleteGroup)).clicked() {
                        delete = Some(id.clone());
                        ui.close();
                    }
                });
            }
        });
        if let Some((id, pinned)) = pin
            && let Some(group) = ctx.servers.groups.iter_mut().find(|group| group.id == id)
        {
            group.pinned = pinned;
            ctx.hooks.mark_dirty();
        }
        // Only a group tab opens these: the three default tabs carry no group
        // record, so they can be neither renamed nor deleted.
        if let Some(id) = rename
            && let Some(group) = ctx.servers.groups.iter().find(|group| group.id == id)
        {
            self.group_dialog = Some(GroupDraft::editing(group));
        }
        if let Some(id) = delete {
            self.group_delete_pending = Some(id);
        }
        if let Some(tab) = select {
            self.select_tab(tab);
        }
        // A release over another group tab of the same band lands the drag at
        // that tab's gap. The other band and the defaults never accept a drop.
        if ui.input(|input| input.pointer.button_released(egui::PointerButton::Primary))
            && egui::DragAndDrop::payload::<DragTab>(ui.ctx()).is_some()
            && let Some(lifted) = egui::DragAndDrop::take_payload::<DragTab>(ui.ctx())
            && let ServerTab::Group(id) = &lifted.0
        {
            let Some(position) = ui.input(|input| input.pointer.interact_pos()) else {
                return;
            };
            let Some(target_at) = tab_rects.iter().position(|rect| rect.contains(position)) else {
                return;
            };
            let ServerTab::Group(target_id) = &tabs[target_at] else {
                return;
            };
            let Some(dragged) = ctx.servers.groups.iter().find(|group| group.id == *id) else {
                return;
            };
            // The band is the model's own definition of a tab row — the
            // groups `reorder_group_in_band` moves — read in stored order.
            let band: Vec<&str> = ctx
                .servers
                .groups
                .iter()
                .filter(|group| group.in_band(dragged.pinned))
                .map(|group| group.id.as_str())
                .collect();
            let Some(from) = band.iter().position(|candidate| *candidate == id.as_str()) else {
                return;
            };
            let Some(target_gap) = band
                .iter()
                .position(|candidate| *candidate == target_id.as_str())
            else {
                return;
            };
            let gap = target_gap + usize::from(position.x > tab_rects[target_at].center().x);
            let to = reorder_target(from, gap);
            if to != from {
                ctx.servers.reorder_group_in_band(id, to);
                ctx.hooks.mark_dirty();
            }
        }
    }

    /// The subscription card between the tab bar and the table: the feed's
    /// title, quota, expiry and update hint with its refresh, report and
    /// delete actions. Only a subscription group's tab owns a feed, so the
    /// three views and a manual group render nothing here.
    ///
    /// The quota and expiry lines allocate to format, and the card paints
    /// every frame its tab is open, so they are memoized for one group, model
    /// generation, language and traffic unit ([`SubscriptionCard`]); the
    /// report and the edit draft are cloned only when their button is
    /// clicked.
    fn show_subscription_card(&mut self, ui: &mut egui::Ui, ctx: &mut ServersCtx, lang: Language) {
        let ServerTab::Group(view) = &self.view else {
            return;
        };
        let Some(group) = ctx.servers.groups.iter().find(|group| &group.id == view) else {
            return;
        };
        let Some(subscription) = group.subscription.as_ref() else {
            return;
        };
        let generation = ctx.hooks.model_generation();
        let unit = ctx.settings.traffic_unit;
        let stale = self.subscription_card.as_ref().is_none_or(|card| {
            card.generation != generation
                || card.group != group.id
                || card.lang != lang
                || card.unit != unit
                // The remaining-days line changes at midnight, so a card that
                // carries one is rebuilt when the day moves.
                || card.day.is_some_and(|day| day != unix_now() / 86_400)
        });
        if stale {
            self.subscription_card = Some(SubscriptionCard::new(
                &group.id,
                generation,
                lang,
                unit,
                subscription,
            ));
        }
        let card = self
            .subscription_card
            .as_ref()
            .expect("the card was formatted above");
        let title = group.title.as_str();
        let has_report = subscription.report.is_some();
        let mut refresh = false;
        let mut show_report = false;
        let mut delete = false;
        let mut edit = false;
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui
                    .button(RichText::new(title).strong())
                    .on_hover_text(t(lang, Key::SrvEditSubscription))
                    .clicked()
                {
                    edit = true;
                }
                if let Some(quota) = &card.quota {
                    ui.weak(quota.as_str());
                }
                match &card.expiry {
                    Some((text, true)) => {
                        ui.colored_label(status_colors_of(ui).err, text.as_str());
                    }
                    Some((text, false)) => {
                        ui.weak(text.as_str());
                    }
                    None => {}
                }
                if let Some(update) = &card.update {
                    ui.weak(update.as_str());
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button(t(lang, Key::SrvDeleteGroup)).clicked() {
                        delete = true;
                    }
                    let report_button = if has_report {
                        ui.small_button(t(lang, Key::SrvShowReport))
                    } else {
                        ui.add_enabled(
                            false,
                            egui::Button::new(t(lang, Key::SrvShowReport)).small(),
                        )
                    };
                    if report_button.clicked() {
                        show_report = true;
                    }
                    if ui
                        .small_button(t(lang, Key::SrvRefreshSubscription))
                        .clicked()
                    {
                        refresh = true;
                    }
                });
            });
        });
        if delete {
            self.group_delete_pending = Some(group.id.clone());
        }
        if edit {
            self.group_dialog = Some(GroupDraft::editing(group));
        }
        if show_report && let Some(report) = &subscription.report {
            self.report_view = Some((group.title.clone(), report.clone()));
        }
        if refresh {
            let repaint = ui.ctx().clone();
            let id = group.id.clone();
            self.start_subscription_fetch(lang, repaint, ctx, id);
        }
    }

    // ---------- the table ----------

    fn show_table(&mut self, ui: &mut egui::Ui, ctx: &mut ServersCtx) {
        let lang = ctx.settings.language;
        ui.add_space(4.0);
        let mut reveal_changed = false;
        ui.horizontal(|ui| {
            ui.heading(t(lang, Key::ScreenServers));
            // The reveal sits in front of the list, beside its title: while
            // Hide server information masks the endpoints, the list offers
            // the same control the editor does, so reading an address does
            // not require opening a profile.
            if ctx.settings.hide_server_info {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let before = self.revealed_list;
                    widgets::reveal_toggle(ui, lang, &mut self.revealed_list);
                    reveal_changed = before != self.revealed_list;
                });
            }
        });
        if reveal_changed {
            // The row details memo runs on the model generation; the reveal
            // is not part of the model, so drop the memo to repaint them.
            self.row_details = None;
        }
        // The route is part of the screen's state: a server row, a balancer,
        // or one of the built-in Direct/Block routes.
        let route = if let Some(tag) = ctx.settings.routing.active_balancer_tag() {
            tag.to_owned()
        } else if let Some(tag) = ctx.servers.active_route_builtin() {
            if tag == crate::model::inbound::DIRECT_OUTBOUND_TAG {
                t(lang, Key::RouteDirect).to_owned()
            } else {
                t(lang, Key::RouteBlock).to_owned()
            }
        } else {
            ctx.servers
                .active_profile()
                .map_or_else(|| t(lang, Key::NoneSelected).to_owned(), |p| p.name.clone())
        };
        ui.label(t_fmt(lang, Key::SrvActiveRoute, &[&route]));
        self.show_tab_bar(ui, ctx, lang);
        // The selected tab's underline is painted three points below its
        // label, inside the gap, so the constant is added rather than consumed:
        // the toolbar clears the underline by twelve points, not nine.
        ui.add_space(TAB_STRIP_TO_TOOLBAR_GAP);
        self.show_subscription_card(ui, ctx, lang);

        // One-probe-at-a-time gate for the toolbar command. The probe dials
        // through its own isolated core, so no phase rung refuses it; its own
        // request is the window's occupant while it runs, so the window is
        // read for other jobs only — that is what keeps the "already
        // running" rung ahead of the busy rung the probe's own job would
        // otherwise state.
        let probe_pending = self.pending_latency_probe.is_some();
        let probe_verdict = verdict(true, ctx.busy.is_held() && !probe_pending, probe_pending);
        let probe_gate = match probe_verdict.rung {
            Rung::Ready => (true, ""),
            Rung::Pending => (false, t(lang, Key::SrvLatencyTestAlreadyRunning)),
            // The not-running rung cannot arise: the probe dials its own
            // core, so the verdict above states no phase fact.
            Rung::NotRunning | Rung::Busy => (false, t(lang, Key::SrvAnotherOperationWorking)),
        };
        let mut action: Option<ListAction> = None;
        // The toolbar's commands, with search at the end of the row so
        // filtering sits beside the actions it filters.
        let mut add_proto: Option<Protocol> = None;
        if probe_pending {
            // The test owns the toolbar: progress replaces the commands so
            // the set under test cannot change, while Cancel stays reachable.
            ui.horizontal(|ui| {
                ui.spinner();
                if ctx.probe_progress.total == 0 {
                    ui.label(t(lang, Key::SrvTesting));
                } else {
                    ui.label(t_fmt(
                        lang,
                        Key::SrvTestingProgress,
                        &[&ctx.probe_progress.done, &ctx.probe_progress.total],
                    ));
                }
                if ui.button(t(lang, Key::Cancel)).clicked() {
                    ctx.hooks.send(CoreCmd::CancelLatencyProbe);
                }
            });
        } else {
            ui.horizontal(|ui| {
                ui.add_enabled_ui(self.add.draft.is_none(), |ui| {
                    ui.menu_button(t(lang, Key::SrvAddServer), |ui| {
                        for protocol in Protocol::ALL {
                            if ui.button(protocol.as_str()).clicked() {
                                add_proto = Some(protocol);
                                ui.close();
                            }
                        }
                    });
                });
                if ui.button(t(lang, Key::SrvImportLinks)).clicked() {
                    self.import_open = true;
                    self.import_group = Some(self.target_group(ctx.servers));
                    self.profile_validation_report = None;
                }
                if ui.button(t(lang, Key::SrvNewGroup)).clicked() {
                    self.group_dialog = Some(GroupDraft::default());
                }
                ui.separator();
                // The latency command is gated like the table's own probe
                // paths, plus the no-profiles case.
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
                    action = Some(ListAction::ProbeLatencySelection);
                }
                // The columns fit their content until a divider is dragged; this
                // command gives the dragged widths back to the fit. It sits with
                // the view commands because that is what it changes.
                if ui
                    .button(t(lang, Key::SrvFitColumns))
                    .on_hover_text(t(lang, Key::SrvFitColumnsHint))
                    .clicked()
                {
                    self.fit_columns = true;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text(t(lang, Key::SrvSearch))
                            .desired_width(220.0),
                    );
                    if !self.search.is_empty() && ui.small_button("✕").clicked() {
                        self.search.clear();
                    }
                });
            });
        }
        if let Some(protocol) = add_proto {
            self.draft_tab = EditorTab::Basic;
            let mut profile = ServerProfile::new(
                t_fmt(lang, Key::SrvNewDraftName, &[&protocol.as_str()]),
                OutboundModel::new(protocol),
            );
            self.target_profile_group(ctx.servers, &mut profile);
            self.add.draft = Some(ProfileDraft::add(profile));
            // A fresh draft starts with no memoized verdicts, so this is a
            // fresh validation subject whatever the previous draft left.
            self.profile_validation_report = None;
            // An empty form hides no credential, and the user opened it to
            // type one.
            self.revealed_add = true;
        }
        if let Some((level, message)) = &self.latency_probe_feedback {
            let color = match level {
                FeedbackLevel::Ok => status_colors_of(ui).ok,
                FeedbackLevel::Warn => status_colors_of(ui).warn,
                FeedbackLevel::Err => status_colors_of(ui).err,
            };
            ui.colored_label(color, message);
        }
        // One flat table per tab, on the same widths as every row. The
        // sortable header exists only where sorting is a view: every tab but
        // `Emitted`, whose order is the outbound order.
        ui.add_space(4.0);
        let sortable = self.view != ServerTab::Emitted && !probe_pending;
        let shape = TableShape {
            order: self.view == ServerTab::Emitted,
            group: self.view == ServerTab::All,
        };
        let generation = ctx.hooks.model_generation();
        // The toolbar's fit command takes effect on the frame that asked for
        // it, before the columns are laid out.
        if std::mem::take(&mut self.fit_columns) && ctx.settings.server_table_columns.is_some() {
            ctx.settings.server_table_columns = None;
            ctx.hooks.mark_dirty();
        }
        if self
            .adaptive_widths
            .as_ref()
            .map(|(cached, language, _)| (*cached, *language))
            != Some((generation, lang))
        {
            self.adaptive_widths = Some((generation, lang, adaptive_widths(ui, lang, ctx.servers)));
        }
        let fitted = self
            .adaptive_widths
            .as_ref()
            .map_or(TABLE_DEFAULT_WIDTHS, |(_, _, widths)| *widths);
        let manual = ctx.settings.server_table_columns.map(sanitized_widths);
        let widths = manual.unwrap_or(fitted);
        // The adaptive fit puts every column at its measured width: the tag
        // keeps its own width and the spare band stays to the right of the
        // table instead of being absorbed by the tag.
        let columns = table_columns(shape, widths);
        // The header's band is reserved here and painted after the rows: the
        // rows own the horizontal scroll bar, and the header is translated by
        // the offset they report on this same frame, so the two can never
        // disagree while the bar is dragged.
        let (header_rect, _) = ui.allocate_exact_size(
            egui::vec2(ui.available_width(), TABLE_ROW_HEIGHT),
            egui::Sense::hover(),
        );

        // Virtualized profile list: only the visible index
        // band is laid out, hit-tested, and painted per frame; egui clipping
        // is not layout. Rows are uniform single-line rows at `TABLE_ROW_HEIGHT`,
        // the height every cell reserves, so `show_rows` and the rows agree on
        // one height. `show_rows` adds `item_spacing.y` between rows,
        // reproducing the old sequential layout row-for-row (only the
        // trailing row spacing is trimmed from the content height, the
        // standard `show_rows` convention), and keeps the same scroll-state
        // id (same `id_salt` as the empty-state `show` below), so the scroll
        // offset is preserved across the switch.
        let row_height = TABLE_ROW_HEIGHT;
        let profiles = &ctx.servers.profiles;
        if self.emitted_cache.as_ref().map(|(cached, _)| *cached) != Some(generation) {
            self.emitted_cache = Some((generation, std::rc::Rc::new(ctx.servers.emitted_set())));
        }
        let emitted = std::rc::Rc::clone(
            &self
                .emitted_cache
                .as_ref()
                .expect("the emitted set was cached above")
                .1,
        );
        let stale_rows = self.tab_rows_cache.as_ref().is_none_or(|cache| {
            cache.generation != generation
                || cache.tab != self.view
                || cache.search != self.search
                || cache.sort != self.view_sort
        });
        if stale_rows {
            let rows: Box<[usize]> =
                tab_rows(ctx.servers, &self.view, &self.search, self.view_sort).into_boxed_slice();
            // The rows a drag may lift or land on: this tab's display rows
            // without the chain hops, and for every display index the count
            // of seed rows before it. Both are derived with the row list so a
            // drag reads them in O(1) instead of filtering and scanning every
            // row on each frame of the gesture.
            let mut seeds = Vec::with_capacity(rows.len());
            let mut seeds_before = Vec::with_capacity(rows.len() + 1);
            for &index in &rows {
                seeds_before.push(seeds.len());
                if !emitted.chain_only.contains(&index) {
                    seeds.push(index);
                }
            }
            seeds_before.push(seeds.len());
            self.tab_rows_cache = Some(TabRowsCache {
                generation,
                tab: self.view.clone(),
                search: self.search.clone(),
                sort: self.view_sort,
                rows: std::rc::Rc::from(rows),
                seeds: std::rc::Rc::from(seeds.into_boxed_slice()),
                seeds_before: std::rc::Rc::from(seeds_before.into_boxed_slice()),
            });
        }
        let display_rows = std::rc::Rc::clone(
            &self
                .tab_rows_cache
                .as_ref()
                .expect("the tab rows were cached above")
                .rows,
        );
        let seed_rows = std::rc::Rc::clone(
            &self
                .tab_rows_cache
                .as_ref()
                .expect("the tab rows were cached above")
                .seeds,
        );
        let seeds_before = std::rc::Rc::clone(
            &self
                .tab_rows_cache
                .as_ref()
                .expect("the tab rows were cached above")
                .seeds_before,
        );
        // A row the tab no longer shows — filtered out, or gone with its
        // group — leaves the selection before any command reads it. Only the
        // row list's own rebuild can change which rows are visible, so the
        // sweep rides on it instead of running selection × rows every frame.
        if stale_rows {
            self.retain_visible_selection(&display_rows, profiles);
        }
        // One clone per frame instead of a lookup per row: the menu's switch
        // label asks which selected rows are locked, and the route is one of
        // the two locks.
        let active_id = ctx.servers.active.clone();
        if self.row_details.as_ref().map(|(cached, _)| *cached) != Some(generation) {
            let hide = ctx.settings.hide_server_info && !self.revealed_list;
            let details: std::collections::HashMap<usize, RowDetail> = profiles
                .iter()
                .enumerate()
                .map(|(index, profile)| (index, row_detail(profile, hide)))
                .collect();
            self.row_details = Some((generation, std::rc::Rc::new(details)));
        }
        let row_details = std::rc::Rc::clone(
            &self
                .row_details
                .as_ref()
                .expect("the row details were cached above")
                .1,
        );
        // Whether a row took the pointer's primary click this frame: a click
        // the rows did not take falls to the empty space below them and
        // clears the selection.
        let mut row_hit = false;
        // Solid scroll bars allocate their own strip, so the horizontal bar
        // cannot float over the last row's cells.
        let scroll_x = ui
            .scope(|ui| {
                ui.spacing_mut().scroll = egui::style::ScrollStyle::solid();
                if display_rows.is_empty() {
                    let rows = egui::ScrollArea::both()
                        .id_salt(ui.auto_id_with("servers.list.scroll"))
                        .max_height(ui.available_height().max(80.0))
                        .show(ui, |ui| {
                            let message = if self.search.trim().is_empty() {
                                t(lang, Key::NoServersYet)
                            } else {
                                t(lang, Key::SrvNoMatches)
                            };
                            ui.label(RichText::new(message).weak());
                        });
                    // No rows means nothing to scroll to; the header returns to the
                    // table's start with them.
                    rows.state.clamped_offset().x
                } else {
                    let rows = egui::ScrollArea::both()
                        .id_salt(ui.auto_id_with("servers.list.scroll"))
                        .max_height(ui.available_height().max(80.0))
                        .show_rows(ui, row_height, display_rows.len(), |ui, rows| {
                            // egui's floating (overlay) scroll bar paints and
                            // hit-tests over the band's right edge: a vertical
                            // ScrollArea shrinks horizontally to its content and the
                            // bar hugs that edge, reserving no space of its own
                            // (`ScrollStyle::allocated_width` is the floating
                            // allocation, zero by default). A row fills the band, so
                            // its trailing delete button would sit under the track
                            // and a press on its right part would grab the bar
                            // instead. Reserve the bar's overlap — computed once per
                            // frame from the style, since every row shares the band —
                            // and report the full band width again at the end so the
                            // bar stays pinned to the edge the rows stop short of.
                            let band_right = ui.max_rect().right();
                            ui.set_max_width(columns.total());
                            let colors = status_colors_of(ui);
                            // One frame of drag-reorder state: the pointer (only
                            // while a row is lifted and the pointer is inside the
                            // list viewport), the proposed drop — its gap index and
                            // the y its insertion line paints at. egui owns the
                            // gesture ([`egui::DragAndDrop`]): a row's payload is what
                            // says a lift is in flight, and recomputing the gap from
                            // the laid-out band every frame keeps a scrolled
                            // virtualized list dropping at real row boundaries.
                            let viewport = ui.clip_rect();
                            let spacing = ui.spacing().item_spacing.y;
                            let lifted = egui::DragAndDrop::payload::<DragRow>(ui.ctx())
                                .map(|payload| payload.0);
                            let drag_pos = lifted
                                .is_some()
                                .then(|| ui.input(|i| i.pointer.interact_pos()))
                                .flatten()
                                .filter(|pos| viewport.contains(*pos));
                            // The generated order pins the active server first, so its
                            // row is a block of its own and accepts no drop.
                            let active_index = ctx.servers.active.as_deref().and_then(|id| {
                                profiles.iter().position(|profile| profile.id == id)
                            });
                            // A hop row is a consequence of the chain, not a place in
                            // its group, so it neither lifts nor receives a drop: the
                            // block algorithm reads the seed rows alone, and both the
                            // seed list and the per-display seed count were derived
                            // with the row cache, so a drag frame reads them instead
                            // of filtering and scanning every row.
                            let drag_rows: Option<&[usize]> = lifted.map(|_| seed_rows.as_ref());
                            let seed_position = |display: usize| {
                                seeds_before
                                    .get(display)
                                    .copied()
                                    .unwrap_or(seeds_before.len())
                            };
                            let map_drop = |from: usize, gap: usize| {
                                let rows = drag_rows?;
                                block_drop(
                                    rows,
                                    profiles,
                                    active_index,
                                    seed_position(from),
                                    seed_position(gap),
                                )
                            };
                            // Only a gap inside the lifted row's own block proposes a
                            // drop: another group's block would silently rewrite the
                            // wrong group's row order.
                            let droppable = |gap: usize| {
                                lifted.is_some_and(|from| map_drop(from, gap).is_some())
                            };
                            let mut drop_mark: Option<(usize, f32)> = None;
                            // Whether the row under the pointer already named the
                            // gap: a refused gap proposes nothing, and no later
                            // block's gap may claim a drop the pointer never aimed at.
                            let mut gap_decided = false;
                            let mut last_row_bottom: Option<f32> = None;
                            for display in rows {
                                let index = display_rows[display];
                                let p = &profiles[index];
                                let is_sel = self.selection.contains(p.id.as_str());
                                // The neighbours decide where the selection band
                                // opens and closes: the outline omits an edge shared
                                // with another selected row.
                                let selected_at = |position: usize| {
                                    display_rows.get(position).is_some_and(|&other| {
                                        self.selection.contains(profiles[other].id.as_str())
                                    })
                                };
                                let joined_above = display > 0 && selected_at(display - 1);
                                let joined_below = selected_at(display + 1);
                                let is_active =
                                    ctx.servers.active.as_deref() == Some(p.id.as_str());
                                // Latency badge text is memoized per profile:
                                // formatting runs only when the row's latency,
                                // the language, or the theme palette moved — a
                                // near-constant input, so idle rows pay a hash
                                // lookup plus a value compare, never a `t_fmt`.
                                if !self.latency_badges.get(p.id.as_str()).is_some_and(|badge| {
                                    badge.matches(
                                        p.verdict.as_ref().map(|verdict| verdict.outcome),
                                        lang,
                                        colors,
                                    )
                                }) {
                                    self.latency_badges.insert(
                                        p.id.clone(),
                                        LatencyBadge::new(p.verdict.as_ref(), lang, colors),
                                    );
                                }
                                let badge = self
                                    .latency_badges
                                    .get(p.id.as_str())
                                    .expect("badge inserted above");
                                // The lifted row dims in place; the insertion line
                                // carries the drop position. The opacity round-trips
                                // through this ui's painter, so the rows around it
                                // paint untouched.
                                let previous_opacity = ui.opacity();
                                if lifted == Some(display) {
                                    ui.multiply_opacity(DRAGGED_ROW_OPACITY);
                                }
                                let detail = row_details.get(&index);
                                let clicks = server_list_row(
                                    ui,
                                    lang,
                                    columns,
                                    RowCells {
                                        name: &p.name,
                                        detail: detail.unwrap_or(&EMPTY_ROW_DETAIL),
                                        verdict: p.verdict.as_ref(),
                                        extras: RowExtras {
                                            order: shape.order.then_some(display + 1),
                                            group: shape.group.then_some(p.group_title.as_str()),
                                        },
                                    },
                                    RowState {
                                        selected: is_sel,
                                        joined_above,
                                        joined_below,
                                        active: is_active,
                                        hop: emitted.chain_only.contains(&index),
                                        dialers: if emitted.chain_only.contains(&index) {
                                            emitted
                                                .dialers
                                                .get(&index)
                                                .map(Vec::as_slice)
                                                .unwrap_or(&[])
                                        } else {
                                            // An enabled server that others dial through
                                            // is a seed, not a hop: the note belongs to
                                            // the row that exists only for the chain.
                                            &[]
                                        },
                                        frozen: probe_pending,
                                        switch: RowSwitch {
                                            // The active server and a chain-only hop
                                            // are in the generated document whatever
                                            // their own switch says, so both render
                                            // checked and locked.
                                            checked: is_active
                                                || p.enabled
                                                || emitted.chain_only.contains(&index),
                                            locked_hint: if is_active {
                                                Some(t(lang, Key::SrvActiveAlwaysEmitted))
                                            } else if emitted.chain_only.contains(&index) {
                                                Some(t(lang, Key::SrvChainOnlyHint))
                                            } else {
                                                None
                                            },
                                        },
                                    },
                                    badge,
                                );
                                ui.set_opacity(previous_opacity);
                                // A primary press that grows past egui's click
                                // threshold lifts this row: the row's own drag sense
                                // hands egui the payload, whose index the drop half
                                // reads. The active server is pinned first by the
                                // generated order, so its row never lifts, and a chain
                                // hop's slot is a consequence of another row's chain,
                                // so it never lifts either. A press held with a
                                // selection modifier is a select gesture, never a
                                // drag. Egui clears the payload on release or Escape,
                                // so the gesture ends even when the window loses focus
                                // mid-drag.
                                let modifiers = ui.input(|i| i.modifiers);
                                let modified =
                                    modifiers.command || modifiers.ctrl || modifiers.shift;
                                if clicks.row.drag_started_by(egui::PointerButton::Primary)
                                    && !probe_pending
                                    && !modified
                                    && self.view == ServerTab::Emitted
                                    && !is_active
                                    && !emitted.chain_only.contains(&index)
                                {
                                    egui::DragAndDrop::set_payload(ui.ctx(), DragRow(display));
                                }
                                if !probe_pending {
                                    if clicks.toggle {
                                        action = Some(ListAction::ToggleEnabled(p.id.clone()));
                                    } else if clicks.double_clicked() {
                                        action = Some(ListAction::Edit(p.id.clone()));
                                    } else if clicks.name.clicked() || clicks.row.clicked() {
                                        row_hit = true;
                                        action = Some(if modifiers.command || modifiers.ctrl {
                                            ListAction::ToggleSelection(p.id.clone())
                                        } else if modifiers.shift {
                                            ListAction::ExtendSelection(p.id.clone())
                                        } else {
                                            ListAction::Select(p.id.clone())
                                        });
                                    }
                                }
                                // The row under the pointer proposes the gap: above
                                // its midline inserts before it, below inserts after
                                // it. Comparing midlines (not rects) leaves no dead
                                // band in the rows' spacing. Only the lifted row's own
                                // block proposes one, so a cross-block drop paints no
                                // insertion line and cannot move a row.
                                if let Some(pos) = drag_pos
                                    && !gap_decided
                                    && pos.y <= clicks.row.rect.center().y
                                {
                                    gap_decided = true;
                                    if droppable(display) {
                                        drop_mark =
                                            Some((display, clicks.row.rect.top() - spacing * 0.5));
                                    }
                                }
                                last_row_bottom = Some(clicks.row.rect.bottom());
                                // The menu clones the id only when an action is
                                // actually clicked, so borrow the row's id instead of
                                // cloning the 36-char String on every repaint. The
                                // batch commands read the screen's selection, which the
                                // menu replaces with this row when it opens on a row
                                // outside it.
                                let id = &p.id;
                                let mut menu = |ui: &mut egui::Ui| {
                                    if !self.selection.contains(id.as_str()) {
                                        self.selection.clear();
                                        self.selection.insert(id.clone());
                                        self.selection_anchor = Some(id.clone());
                                    }
                                    if ui.button(t(lang, Key::SrvEdit)).clicked() {
                                        action = Some(ListAction::Edit(id.clone()));
                                        ui.close();
                                    }
                                    let set_active = ui.add_enabled(
                                        self.is_single_selection(id),
                                        egui::Button::new(t(lang, Key::SrvSetActive)),
                                    );
                                    if set_active.clicked() {
                                        action = Some(ListAction::SetActive(id.clone()));
                                        ui.close();
                                    }
                                    if ui.button(t(lang, Key::SrvDuplicate)).clicked() {
                                        action = Some(ListAction::Duplicate(id.clone()));
                                        ui.close();
                                    }
                                    if ui.button(t(lang, Key::TestLatency)).clicked() {
                                        action = Some(ListAction::ProbeLatency(id.clone()));
                                        ui.close();
                                    }
                                    // A copy is made of subscription rows only; a
                                    // manual row has nothing a refresh could take
                                    // away.
                                    let copyable = self.selection.iter().any(|selected| {
                                        profiles.iter().any(|profile| {
                                            profile.id == *selected && profile.origin.is_some()
                                        })
                                    });
                                    if ui
                                        .add_enabled(
                                            copyable,
                                            egui::Button::new(t(lang, Key::SrvCopyToGroup)),
                                        )
                                        .clicked()
                                    {
                                        action = Some(ListAction::CopySelection);
                                        ui.close();
                                    }
                                    // One control for one state: the item offers the
                                    // switch the selection does not have yet. Locked
                                    // rows (the route and chain hops) are skipped by
                                    // the command, so they decide neither the label
                                    // nor whether the item can act.
                                    let mut has_unlocked = false;
                                    let mut any_unlocked_off = false;
                                    for (index, profile) in profiles.iter().enumerate() {
                                        if !self.selection.contains(&profile.id) {
                                            continue;
                                        }
                                        let locked = active_id.as_deref()
                                            == Some(profile.id.as_str())
                                            || emitted.chain_only.contains(&index);
                                        if locked {
                                            continue;
                                        }
                                        has_unlocked = true;
                                        any_unlocked_off |= !profile.enabled;
                                    }
                                    let (enable_key, enable) = if any_unlocked_off {
                                        (Key::SrvEnableSelected, true)
                                    } else {
                                        (Key::SrvDisableSelected, false)
                                    };
                                    if ui
                                        .add_enabled(
                                            has_unlocked,
                                            egui::Button::new(t(lang, enable_key)),
                                        )
                                        .clicked()
                                    {
                                        action = Some(ListAction::SetSelectionEnabled(enable));
                                        ui.close();
                                    }
                                    if ui.button(t(lang, Key::SrvShare)).clicked() {
                                        action = Some(ListAction::ExportSelection);
                                        ui.close();
                                    }
                                    if ui.button(t(lang, Key::SrvDeleteEllipsis)).clicked() {
                                        action = Some(ListAction::DeleteSelection);
                                        ui.close();
                                    }
                                };
                                // The name button fills its cell, so both it and the
                                // row background open the context menu.
                                if !probe_pending {
                                    clicks.row.context_menu(|ui| menu(ui));
                                    clicks.name.context_menu(|ui| menu(ui));
                                }
                            }
                            // Below every laid-out row's midline the drop lands at
                            // the band's end: the visible tail of a scrolled list, or
                            // the empty space under a short one — only while the
                            // lifted row's block owns that tail, and only when no row
                            // already named the gap.
                            if drag_pos.is_some()
                                && !gap_decided
                                && let Some(bottom) = last_row_bottom
                                && droppable(display_rows.len())
                            {
                                drop_mark = Some((display_rows.len(), bottom + spacing * 0.5));
                            }
                            // The release ends the gesture: egui hands back the
                            // lifted row's display index, and the drop lands it at the
                            // proposed gap inside its own block. A release off the
                            // rows proposed none, so it cancels — and so does a gap
                            // another group's block owns, because the proposal half
                            // already refused it. Escape aborts the payload before any
                            // release is seen. The rows are a view of the stored list
                            // — emitted and filtered — so the gap maps back through
                            // the seed rows, never a raw profile or display index.
                            if !probe_pending
                                && let Some((gap, _)) = drop_mark
                                && ui.input(|i| {
                                    i.pointer.button_released(egui::PointerButton::Primary)
                                })
                                && let Some(lifted) =
                                    egui::DragAndDrop::take_payload::<DragRow>(ui.ctx())
                                && let Some(drop) = map_drop(lifted.0, gap)
                            {
                                action = Some(ListAction::MoveInGroup {
                                    from: drop.from,
                                    before: drop.before,
                                });
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
                                let delta = drag_scroll_delta(
                                    viewport,
                                    pos,
                                    ui.input(|i| i.stable_dt).min(0.1),
                                );
                                if delta != 0.0 {
                                    ui.scroll_with_delta(egui::vec2(0.0, delta));
                                    ui.ctx().request_repaint();
                                }
                            }
                            // The rows stopped short of the band's right edge; report
                            // the full width so the overlay bar stays there instead of
                            // following the shrunken content onto the controls.
                            ui.expand_to_include_x(band_right);
                        });
                    // The rows own the horizontal scroll; the header is painted below
                    // from this frame's offset, so no repaint is needed to sync them.
                    rows.state.clamped_offset().x
                }
            })
            .inner;

        // The header, translated by the offset the rows just reported. The
        // clip is the band, so a column scrolled out of view is neither drawn
        // nor hit-tested over the rest of the screen.
        let mut header_ui = ui.new_child(
            egui::UiBuilder::new()
                .id_salt("servers.header")
                .max_rect(header_rect.translate(egui::vec2(-scroll_x, 0.0)))
                .layout(egui::Layout::top_down(egui::Align::Min)),
        );
        header_ui.set_max_width(columns.total());
        header_ui.set_clip_rect(header_rect.intersect(ui.clip_rect()));
        let outcome = table_header(
            &mut header_ui,
            lang,
            columns,
            widths,
            sortable,
            self.view_sort,
            &mut self.column_drag,
        );
        if outcome.fit && ctx.settings.server_table_columns.is_some() {
            ctx.settings.server_table_columns = None;
            ctx.hooks.mark_dirty();
        } else if let Some(resized) = outcome.resized {
            ctx.settings.server_table_columns = Some(resized);
            ctx.hooks.mark_dirty();
        }
        if let Some(column) = outcome.sort {
            self.view_sort = Some(next_view_sort(self.view_sort, column));
            // The sort is a display preference: it saves with the other UI
            // settings and never reaches the configuration pipeline.
            ctx.settings.server_table_sort = self.view_sort;
            ctx.hooks.mark_ui_dirty();
        }

        // A click in the empty band below a short list clears the selection.
        if !probe_pending && !row_hit && self.delete_pending.is_none() {
            let blank = ui.allocate_response(
                egui::vec2(ui.available_width(), ui.available_height().max(0.0)),
                egui::Sense::click(),
            );
            if blank.clicked() {
                action = Some(ListAction::ClearSelection);
            }
        }
        // The table owns Ctrl+A and Enter only while no text field holds
        // focus (the search box's own select-all stays its own) and no dialog
        // is asking a question.
        let typing = ui.memory(|memory| memory.focused().is_some());
        let overlay_open = self.delete_pending.is_some()
            || self.group_delete_pending.is_some()
            || self.copy_dialog.is_some()
            || self.leave_pending.is_some()
            || self.qr_dialog.is_some()
            || self.derive_dialog.is_some();
        if !probe_pending && !typing && !overlay_open {
            if ui
                .input(|i| (i.modifiers.command || i.modifiers.ctrl) && i.key_pressed(egui::Key::A))
            {
                action = Some(ListAction::SelectAllVisible);
            }
            if ui.input(|i| i.key_pressed(egui::Key::Enter))
                && self.selection.len() == 1
                && let Some(id) = self.selection.iter().next()
            {
                action = Some(ListAction::SetActive(id.clone()));
            }
        }
        // apply deferred list actions (needs &mut profiles)
        match action {
            Some(ListAction::Select(id)) => {
                // A dirty draft guards the switch: the leave modal stages
                // and its resolution performs the selection.
                self.guard_select(id);
            }
            Some(ListAction::ToggleSelection(id)) => self.toggle_selection(&id),
            Some(ListAction::ExtendSelection(id)) => {
                self.extend_selection(&id, &display_rows, profiles);
            }
            Some(ListAction::SelectAllVisible) => {
                self.select_all_visible(&display_rows, profiles);
            }
            Some(ListAction::ClearSelection) => {
                self.selection.clear();
                self.selection_anchor = None;
                self.selected = None;
            }
            Some(ListAction::ProbeLatency(id)) => {
                // A menu opened on a row outside the selection replaced the
                // selection with that row first; a menu click inside a
                // multi-selection probes the whole selection.
                let ids = if self.selection.len() > 1 {
                    self.selected_ids(&display_rows, profiles)
                } else {
                    vec![id]
                };
                self.probe_rows(ctx, &ids, ids.len() == 1);
            }
            Some(ListAction::ProbeLatencySelection) => {
                // The toolbar command targets the selection, or the whole
                // current tab when nothing is selected. Its feedback always
                // names the target count, even when the target is one row.
                let selected = self.selected_ids(&display_rows, profiles);
                let ids = if selected.is_empty() {
                    display_rows
                        .iter()
                        .map(|&index| profiles[index].id.clone())
                        .collect()
                } else {
                    selected
                };
                self.probe_rows(ctx, &ids, false);
            }
            Some(ListAction::SetSelectionEnabled(enabled)) => {
                let ids = self.selected_ids(&display_rows, profiles);
                self.set_selected_enabled(ctx, &ids, enabled);
            }
            Some(ListAction::ExportSelection) => {
                let ids = self.selected_ids(&display_rows, profiles);
                self.export_rows(ui, ctx, lang, &ids);
            }
            Some(ListAction::CopySelection) => {
                let ids = self.selected_ids(&display_rows, profiles);
                self.open_copy_dialog(&ids, ctx.servers);
            }
            Some(ListAction::DeleteSelection) => {
                let ids = self.selected_ids(&display_rows, profiles);
                self.open_delete_dialog(ctx.servers, ctx.settings, lang, ids);
            }
            Some(ListAction::Duplicate(id)) => {
                if let Some(index) = ctx.servers.profiles.iter().position(|p| p.id == id) {
                    let mut copy = ctx.servers.profiles[index].clone();
                    copy.id = uuid::Uuid::new_v4().simple().to_string();
                    copy.name = t_fmt(lang, Key::SrvCopySuffix, &[&copy.name]);
                    copy.name = ctx
                        .servers
                        .unique_profile_name(copy.group_id(), &copy.name, None);
                    ctx.servers.profiles.insert(index + 1, copy.clone());
                    // The switch to the copy is guarded like any other
                    // selection change (the copy is already inserted; the
                    // guard only defers the selection).
                    self.guard_select(copy.id);
                    ctx.hooks.mark_dirty();
                }
            }
            Some(ListAction::SetActive(id)) => {
                // The active profile is the list's first row (the config's
                // default route), so choosing it moves it there — and an
                // explicitly chosen server takes the default route back from
                // an active balancer.
                ctx.settings.routing.active_balancer.clear();
                ctx.servers.activate(&id);
                ctx.hooks.mark_dirty();
            }
            Some(ListAction::Edit(id)) => self.open_editor(ctx.servers, lang, &id),
            Some(ListAction::ToggleEnabled(id)) => {
                let enabled = ctx
                    .servers
                    .profiles
                    .iter()
                    .find(|profile| profile.id == id)
                    .is_some_and(|profile| !profile.enabled);
                self.set_enabled_rows(ctx, std::slice::from_ref(&id), enabled);
            }
            Some(ListAction::MoveInGroup { from, before }) => {
                // The payload index was read off this frame's list; a list
                // that shrank under the gesture (a probe that removed a
                // profile) simply drops the move. The model refuses a
                // destination another group owns and reports whether the
                // stored order actually changed.
                let moved = ctx.servers.move_profile_in_group(from, before);
                if moved {
                    ctx.hooks.mark_dirty();
                }
            }
            None => {}
        }
    }
    fn consume_latency_probe_result(&mut self, ctx: &mut ServersCtx) {
        let Some(single) = self.pending_latency_probe else {
            return;
        };
        let Some(result) = self.latency_probe.take_parked(ctx.probe_feedback) else {
            return;
        };
        self.pending_latency_probe = None;
        let cancelled = matches!(
            &result.result,
            Err(failure) if failure.headline.key() == Key::ProbeCancelledByUser
        );
        let progress = result.progress;
        self.latency_probe_feedback = Some(if cancelled {
            (
                FeedbackLevel::Warn,
                t_fmt(
                    ctx.settings.language,
                    Key::SrvLatencyCancelled,
                    &[&progress.done, &progress.total],
                ),
            )
        } else if single {
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

    /// True when the existing-draft (selected server) or the add-draft
    /// holds uncommitted changes. Cheap: reads the memoized validation
    /// verdicts; if a draft's memo generation is stale relative to the draft
    /// generation, recompute the changed flag inline (one serialize). Must
    /// be same-frame accurate for the topbar chip (called before/after the
    /// Servers screen renders this frame).
    pub fn unsaved_changes(&self) -> bool {
        // The dirty composition reads only the draft's own facts, and this
        // per-frame chip check runs without a frame: nothing read below
        // consults the busy window. The add draft's raw-buffer half is not
        // part of its unsaved state — the dialog's own controls treat an
        // add draft as unsaved from the moment it exists.
        self.draft_unsaved(DraftKind::Existing, false) || self.draft_unsaved(DraftKind::Add, false)
    }

    /// Focus one row and make it the sole selection: the plain-click,
    /// editor-open and resolved leave-action path.
    fn focus_row(&mut self, id: &str) {
        self.selected = Some(id.to_owned());
        self.selection.clear();
        self.selection.insert(id.to_owned());
        self.selection_anchor = Some(id.to_owned());
    }

    /// Drop every selected id no profile backs any more, so a deleted profile
    /// cannot be acted on through a stale selection.
    fn retain_existing_selection(&mut self, servers: &ServersFile) {
        self.selection
            .retain(|id| servers.profiles.iter().any(|profile| &profile.id == id));
        if self
            .selection_anchor
            .as_deref()
            .is_some_and(|anchor| !self.selection.contains(anchor))
        {
            self.selection_anchor = None;
        }
    }

    /// Keep the selection inside the rows the current tab shows: a search that
    /// filters a row out also removes it from the selection.
    fn retain_visible_selection(&mut self, rows: &[usize], profiles: &[ServerProfile]) {
        self.selection.retain(|id| {
            rows.iter()
                .any(|&index| profiles[index].id.as_str() == id.as_str())
        });
        if self
            .selection_anchor
            .as_deref()
            .is_some_and(|anchor| !self.selection.contains(anchor))
        {
            self.selection_anchor = None;
        }
    }

    /// The selection in display order, the order every batch command applies.
    /// Built only by the commands that read it, so a repaint that clicks
    /// nothing never clones the selected ids.
    fn selected_ids(&self, rows: &[usize], profiles: &[ServerProfile]) -> Vec<String> {
        rows.iter()
            .map(|&index| &profiles[index])
            .filter(|profile| self.selection.contains(profile.id.as_str()))
            .map(|profile| profile.id.clone())
            .collect()
    }

    /// Ctrl-click: add the row to the selection, or remove it.
    fn toggle_selection(&mut self, id: &str) {
        if self.selection.remove(id) {
            if self.selection_anchor.as_deref() == Some(id) {
                self.selection_anchor = None;
            }
            if self.selected.as_deref() == Some(id) {
                self.selected = self.selection.iter().next().cloned();
            }
        } else {
            self.selection.insert(id.to_owned());
            self.selected = Some(id.to_owned());
            self.selection_anchor = Some(id.to_owned());
        }
    }

    /// Shift-click: select every visible row between the anchor and `id`.
    /// Without a usable anchor the row becomes the whole selection.
    fn extend_selection(&mut self, id: &str, rows: &[usize], profiles: &[ServerProfile]) {
        let Some(target) = rows
            .iter()
            .position(|&index| profiles[index].id.as_str() == id)
        else {
            return;
        };
        let anchor = self
            .selection_anchor
            .as_deref()
            .and_then(|anchor| {
                rows.iter()
                    .position(|&index| profiles[index].id.as_str() == anchor)
            })
            .unwrap_or(target);
        let (start, end) = if anchor <= target {
            (anchor, target)
        } else {
            (target, anchor)
        };
        self.selection.clear();
        for index in &rows[start..=end] {
            self.selection.insert(profiles[*index].id.clone());
        }
        self.selection_anchor = Some(profiles[rows[anchor]].id.clone());
        self.selected = Some(id.to_owned());
    }

    /// Ctrl+A: select every row the current tab shows.
    fn select_all_visible(&mut self, rows: &[usize], profiles: &[ServerProfile]) {
        self.selection.clear();
        let mut first = None;
        for &index in rows {
            let id = &profiles[index].id;
            self.selection.insert(id.clone());
            first.get_or_insert_with(|| id.clone());
        }
        self.selection_anchor = first.clone();
        if first.is_some() {
            self.selected = first;
        }
    }

    /// True when this "id" is the only selected row.
    fn is_single_selection(&self, id: &str) -> bool {
        self.selection.len() == 1 && self.selection.contains(id)
    }

    /// Guard a selection switch to `id`: when a draft holds uncommitted
    /// changes, stage the leave modal instead of switching (the modal's
    /// Save/Discard resolution performs the switch); otherwise switch
    /// immediately. Returns true when the selection was switched now.
    /// The delete-confirmation dialog is its own gate, so while it is open
    /// the guard never stages. A click on the already-focused profile
    /// changes nothing there, but still collapses a multi-selection to it.
    fn guard_select(&mut self, id: String) -> bool {
        if self.delete_pending.is_some() {
            self.focus_row(&id);
            return true;
        }
        if self.selected.as_deref() == Some(id.as_str()) {
            self.focus_row(&id);
            return true;
        }
        if self.unsaved_changes() {
            self.stage_leave(LeaveAction::Select(id));
            false
        } else {
            self.focus_row(&id);
            true
        }
    }

    /// Apply one switch state to `ids` through the same lock rules a row's
    /// own switch follows: the active server and a chain-only hop stay put.
    /// Returns (changed, skipped).
    fn set_enabled_rows(
        &mut self,
        ctx: &mut ServersCtx,
        ids: &[String],
        enabled: bool,
    ) -> (usize, usize) {
        if ids.is_empty() {
            return (0, 0);
        }
        let wanted: std::collections::HashSet<&str> = ids.iter().map(String::as_str).collect();
        let emitted = ctx.servers.emitted_set();
        let active = ctx.servers.active.clone();
        let mut changed = 0;
        let mut skipped = 0;
        for (index, profile) in ctx.servers.profiles.iter_mut().enumerate() {
            if !wanted.contains(profile.id.as_str()) {
                continue;
            }
            let locked = active.as_deref() == Some(profile.id.as_str())
                || emitted.chain_only.contains(&index);
            if locked {
                skipped += 1;
                continue;
            }
            if profile.enabled != enabled {
                profile.enabled = enabled;
                changed += 1;
            }
        }
        if changed > 0 {
            ctx.hooks.mark_dirty();
        }
        (changed, skipped)
    }

    /// The batch Enable/Disable command: one loop over the selection, one
    /// status line that reports the skipped locked rows.
    fn set_selected_enabled(&mut self, ctx: &mut ServersCtx, ids: &[String], enabled: bool) {
        if ids.is_empty() {
            return;
        }
        let (changed, skipped) = self.set_enabled_rows(ctx, ids, enabled);
        let lang = ctx.settings.language;
        self.set_status(StatusLine::ok(t_fmt(
            lang,
            if enabled {
                Key::SrvBatchEnabled
            } else {
                Key::SrvBatchDisabled
            },
            &[&changed, &skipped],
        )));
    }

    /// Probe `ids` with one isolated child: the batch path behind both the
    /// toolbar command and a row menu opened inside a selection. `single`
    /// selects the one-row feedback wording.
    fn probe_rows(&mut self, ctx: &mut ServersCtx, ids: &[String], single: bool) {
        let profiles: Vec<ServerProfile> = ids
            .iter()
            .filter_map(|id| {
                ctx.servers
                    .profiles
                    .iter()
                    .find(|profile| &profile.id == id)
                    .cloned()
            })
            .collect();
        if profiles.is_empty() {
            self.latency_probe_feedback = Some((
                FeedbackLevel::Err,
                t(ctx.settings.language, Key::LatencyRequiresProfile).to_owned(),
            ));
            return;
        }
        let single = single && profiles.len() == 1;
        self.latency_probe_feedback = None;
        match ctx.request_latency_probe_for_profiles(profiles) {
            Ok(()) => {
                self.pending_latency_probe = Some(single);
                self.latency_probe = Request::park_in_shell();
                // A new test starts from zero: the previous run's count must
                // not stand in for this one until its first arrival lands.
                *ctx.probe_progress = crate::rt::ProbeProgress { done: 0, total: 0 };
            }
            Err(error) => self.latency_probe_feedback = Some((FeedbackLevel::Err, error)),
        }
    }

    /// Copy the selected rows' links in display order: one row keeps the
    /// existing link-and-QR sharing, a multi-row selection puts one link per
    /// line on the clipboard and reports how many were copied.
    fn export_rows(&mut self, ui: &egui::Ui, ctx: &ServersCtx, lang: Language, ids: &[String]) {
        let mut shared = Vec::with_capacity(ids.len());
        let mut name = None;
        let mut failed = 0usize;
        let mut first_error = None;
        for id in ids {
            let Some(profile) = ctx.servers.profiles.iter().find(|p| &p.id == id) else {
                continue;
            };
            match links::to_link(profile) {
                Ok(link) => {
                    name.get_or_insert_with(|| profile.name.clone());
                    shared.push(link);
                }
                Err(error) => {
                    failed += 1;
                    first_error.get_or_insert(error);
                }
            }
        }
        let total = shared.len() + failed;
        if shared.is_empty() {
            if let Some(error) = first_error {
                self.set_status(StatusLine::err(t_fmt(
                    lang,
                    Key::SrvExportFailed,
                    &[&error.text(lang)],
                )));
            }
            return;
        }
        if total == 1 {
            let link = shared.pop().expect("one shared link");
            ui.ctx().copy_text(link.clone());
            self.qr_dialog = Some(QrDialog {
                name: name.unwrap_or_default(),
                link,
                tex: None,
            });
            self.set_status(StatusLine::ok(t(lang, Key::SrvLinkCopiedToClipboard)));
            return;
        }
        let copied = shared.len();
        ui.ctx().copy_text(shared.join("\n"));
        if first_error.is_some() {
            self.set_status(StatusLine::err(t_fmt(
                lang,
                Key::SrvLinksCopiedPartial,
                &[&copied, &total],
            )));
        } else {
            self.set_status(StatusLine::ok(t_fmt(
                lang,
                Key::SrvLinksCopiedToClipboard,
                &[&copied],
            )));
        }
    }

    /// Open the one delete confirmation for `ids`, snapshotting its names and
    /// references now: the dialog is modal, so its inputs cannot change while
    /// it is open, and the linear reference scan must not repeat per repaint.
    fn open_delete_dialog(
        &mut self,
        servers: &ServersFile,
        settings: &Settings,
        lang: Language,
        ids: Vec<String>,
    ) {
        if ids.is_empty() || self.delete_pending.is_some() {
            return;
        }
        let mut references = Vec::new();
        let mut name = None;
        for id in &ids {
            let Some(profile) = servers.profiles.iter().find(|p| &p.id == id) else {
                continue;
            };
            if ids.len() == 1 {
                name = Some(profile.name.clone());
            }
            for reference in server_reference_paths(servers, settings, id) {
                if !references.contains(&reference) {
                    references.push(reference);
                }
            }
        }
        let name = name.unwrap_or_else(|| t_fmt(lang, Key::SrvSelectedServers, &[&ids.len()]));
        self.delete_pending = Some(DeleteDialog {
            ids,
            name,
            references,
        });
    }

    /// Open the Copy to group picker for the selection's subscription rows,
    /// in display order. The dialog is exclusive like the delete
    /// confirmation; rows with no origin keys are not copies the feed could
    /// later compete with and are skipped.
    fn open_copy_dialog(&mut self, ids: &[String], servers: &ServersFile) {
        if self.copy_dialog.is_some() {
            return;
        }
        let ids: Vec<String> = ids
            .iter()
            .filter(|id| {
                servers
                    .profiles
                    .iter()
                    .any(|profile| &profile.id == *id && profile.origin.is_some())
            })
            .cloned()
            .collect();
        if ids.is_empty() {
            return;
        }
        self.copy_dialog = Some(CopyDialog {
            ids,
            target: crate::model::servers::MANUAL_GROUP_ID.to_owned(),
        });
    }

    /// Open the editor window on `id`: a double click, the Edit command, or a
    /// resolved leave action. A dirty draft guards the switch — its question
    /// stages `OpenEditor` and the resolution performs the open — while a
    /// clean state loads the profile's draft straight away.
    fn open_editor(&mut self, servers: &ServersFile, lang: Language, id: &str) {
        if self
            .existing
            .draft()
            .is_some_and(|draft| draft.id.as_str() == id)
        {
            self.focus_row(id);
            return;
        }
        if self.unsaved_changes() {
            self.stage_leave(LeaveAction::OpenEditor(id.to_owned()));
        } else {
            self.load_existing_draft(servers, lang, id);
        }
    }

    /// Load `id`'s persisted profile into the editor slot, replacing whatever
    /// the window held: the previous draft's seeded buffers and probe result
    /// go with it, because both describe the draft that is leaving.
    fn load_existing_draft(&mut self, servers: &ServersFile, lang: Language, id: &str) {
        let Some(persisted) = servers.profiles.iter().find(|profile| profile.id == id) else {
            return;
        };
        match ProfileDraft::existing(persisted) {
            Ok(draft) => {
                self.existing.close(&mut self.seeded_buffers);
                self.existing.probe.discard_result();
                self.existing.hold(draft);
                self.focus_row(id);
                self.derive_dialog = None;
                self.profile_validation_report = None;
                self.revealed_existing = false;
            }
            Err(error) => self.set_status(StatusLine::err(t_fmt(
                lang,
                Key::SrvPrepareDraftFailed,
                &[&error],
            ))),
        }
    }

    /// The editor window was closed or cancelled without commit. A derive
    /// dialog targeting this draft cannot outlive it, so it is cleared first.
    /// The draft then takes the shared close guard: stage the leave question
    /// when it holds uncommitted changes, otherwise drop it and evict its
    /// seeded buffers.
    fn close_existing_editor(&mut self, draft: ProfileDraft, busy: bool) {
        if self.derive_dialog.as_ref().is_some_and(|dialog| {
            matches!(
                &dialog.target,
                ToolTarget::ExistingDraft { profile_id, .. } if profile_id == &draft.id
            )
        }) {
            self.derive_dialog = None;
        }
        self.existing.hold(draft);
        if self.delete_pending.is_none() && self.draft_unsaved(DraftKind::Existing, busy) {
            self.stage_leave(LeaveAction::CloseExisting);
        } else {
            self.close_existing_draft();
        }
    }

    /// The Add-server dialog was closed or cancelled without commit. A derive
    /// dialog targeting this draft cannot outlive it (its apply would
    /// reference a draft that no longer exists), so it is cleared first. The
    /// draft then takes the shared close guard: stage the leave modal when it
    /// differs from its baseline, otherwise drop it and evict its seeded
    /// editor buffers (dead weight).
    fn close_add_draft(&mut self, draft: ProfileDraft) {
        if self.derive_dialog.as_ref().is_some_and(|dialog| {
            matches!(
                &dialog.target,
                ToolTarget::AddDraft { profile_id, .. } if profile_id == &draft.id
            )
        }) {
            self.derive_dialog = None;
        }
        self.add.hold(draft);
        if self.delete_pending.is_none() && self.draft_unsaved(DraftKind::Add, false) {
            self.stage_leave(LeaveAction::CloseAdd);
        } else {
            self.add.close(&mut self.seeded_buffers);
        }
    }

    /// Revert the existing editor draft to its persisted profile: the draft, the
    /// probe result tied to it and the seeded raw-JSON/PEM editor buffers all go
    /// together (the cleanup the editor's Discard button performs), so nothing
    /// keeps showing the discarded draft. The derive dialog goes with it — its
    /// apply would reference a draft that no longer exists.
    fn discard_existing_draft(&mut self) {
        self.existing.revert(&mut self.seeded_buffers);
        self.derive_dialog = None;
        self.profile_validation_report = None;
    }

    /// Drop the editor's draft with the seeded buffers and probe result that
    /// belong to it: the window closes and nothing keeps showing the draft.
    fn close_existing_draft(&mut self) {
        self.existing.close(&mut self.seeded_buffers);
        self.existing.probe.discard_result();
    }

    /// Whether `kind`'s draft is unsaved. The existing editor's raw panes can
    /// hold text that never reached its draft, so that slot counts the raw
    /// buffers; an add draft has no committed source, so its changed flag is
    /// its whole unsaved state.
    fn draft_unsaved(&self, kind: DraftKind, busy: bool) -> bool {
        match kind {
            DraftKind::Existing => self.gate(kind, busy).is_some_and(DraftGate::dirty),
            DraftKind::Add => self.draft_saveable(kind, busy),
        }
    }

    /// Whether `kind`'s draft has changes its Save would commit.
    fn draft_saveable(&self, kind: DraftKind, busy: bool) -> bool {
        self.gate(kind, busy)
            .is_some_and(|gate| gate.changed_from_source)
    }

    /// Perform a leave action whose drafts are already resolved. A selection
    /// switch only moves the selection: the editor keeps the profile it
    /// holds, because only Edit, a double click or Add change it. OpenEditor
    /// loads the profile the user asked for; the Close actions drop their
    /// windows; Quit resumes the app quit.
    fn apply_leave_action(&mut self, action: LeaveAction, uictx: &mut ServersCtx) {
        match action {
            LeaveAction::Select(id) => self.focus_row(&id),
            LeaveAction::OpenEditor(id) => {
                let lang = uictx.settings.language;
                self.load_existing_draft(uictx.servers, lang, &id);
            }
            LeaveAction::CloseExisting => self.close_existing_draft(),
            LeaveAction::CloseAdd => self.add.close(&mut self.seeded_buffers),
            LeaveAction::Quit => uictx.hooks.request_quit_resume(),
        }
    }

    /// Resume the staged leave action after `committed`'s draft was saved and
    /// closed. An action the commit does not resolve stays staged for the
    /// other draft's Save, or for the question the user still has to answer;
    /// a resolved one is performed here.
    fn resume_leave_after_commit(&mut self, committed: DraftKind, uictx: &mut ServersCtx) {
        let Some(action) = self.leave_pending.clone() else {
            return;
        };
        let other = match committed {
            DraftKind::Existing => DraftKind::Add,
            DraftKind::Add => DraftKind::Existing,
        };
        let resolved = match &action {
            // A plain click or the editor's close is answered by the existing
            // draft's Save; the add commit only resolves it when the guard
            // switched immediately (which clears it before this point).
            LeaveAction::Select(_) | LeaveAction::CloseExisting => committed == DraftKind::Existing,
            LeaveAction::OpenEditor(_) => true,
            LeaveAction::CloseAdd => committed == DraftKind::Add,
            LeaveAction::Quit => !self.draft_unsaved(other, uictx.busy.is_held()),
        };
        if !resolved {
            return;
        }
        self.leave_pending = None;
        self.apply_leave_action(action, uictx);
    }

    /// Discard resolution of the leave modal: revert the existing draft in
    /// place (revert + buffer clear; the actions that close the window then
    /// drop it), drop the add draft Quit abandons, then perform the action.
    fn discard_leave_action(&mut self, action: LeaveAction, uictx: &mut ServersCtx) {
        match &action {
            LeaveAction::CloseAdd => self.add.close(&mut self.seeded_buffers),
            LeaveAction::Quit => {
                self.discard_existing_draft();
                self.add.close(&mut self.seeded_buffers);
            }
            LeaveAction::Select(_) => {
                // A plain click only moves the selection, so Discard reverts
                // the editor's draft in place: the window keeps the profile
                // it holds instead of retargeting to the clicked row.
                let editing = self.existing.draft.as_ref().map(|draft| draft.id.clone());
                self.discard_existing_draft();
                if let Some(editing) = editing {
                    let lang = uictx.settings.language;
                    self.load_existing_draft(uictx.servers, lang, &editing);
                }
            }
            LeaveAction::OpenEditor(_) | LeaveAction::CloseExisting => {
                self.discard_existing_draft();
            }
        }
        self.leave_pending = None;
        self.apply_leave_action(action, uictx);
    }

    /// Save resolution of the leave modal: start the existing validation
    /// pipeline for the dirty draft (the existing draft first, then the add
    /// draft) and keep the action staged — the commit handler resumes it on
    /// success or clears it on rejection. Failure to start clears the
    /// staged action and shows the status error.
    fn save_leave_action(&mut self, action: LeaveAction, lang: Language, uictx: &mut ServersCtx) {
        let busy = uictx.busy.is_held();
        let mut staged = None;
        for kind in [DraftKind::Existing, DraftKind::Add] {
            let Some(draft) = self.draft(kind) else {
                continue;
            };
            if self.draft_saveable(kind, busy) {
                staged = Some((draft.target(), draft.profile.clone()));
                break;
            }
        }
        let Some((target, profile)) = staged else {
            // Every dirty draft was already committed while the modal was
            // staged; the deferred action is safe to perform now.
            self.leave_pending = None;
            self.apply_leave_action(action, uictx);
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

    /// Render the leave confirmation if an action is staged; no-op otherwise.
    /// Safe to call every frame from `App::ui`: the question renders in the
    /// main window, which it dims and blocks, like the safety-ack confirmation.
    /// Dismissing it — a click on the dimmed window, Escape — is Cancel: the
    /// staged action is cleared without performing it.
    ///
    /// A staged action that came from a window — closing either editor — is
    /// that window's own: while `servers_screen_rendered` says the servers
    /// screen drew its windows this frame, the editor renders the question
    /// inside itself, and this call renders nothing, so the user answers the
    /// window they just closed instead of a question floating over the main
    /// window. Off the servers screen the editor is gone with its window, and
    /// the question falls back to the main window so it stays answerable.
    pub fn show_leave_modal(
        &mut self,
        egui_ctx: &egui::Context,
        uictx: &mut ServersCtx,
        servers_screen_rendered: bool,
    ) {
        if self.leave_pending.is_none() {
            return;
        }
        if servers_screen_rendered && self.close_is_staged_in_window() {
            return;
        }
        let lang = uictx.settings.language;
        let mut decision: Option<LeaveDecision> = None;
        let declined = popup::modal(
            egui_ctx,
            "servers.leave",
            t(lang, Key::SrvUnsavedChanges),
            520.0,
            |ui| {
                decision = self.leave_confirmation(ui, uictx, None);
            },
        );
        if decision.is_none() && declined {
            // The confirmation's own dismissal — a click on the dimmed main
            // window, Escape — is Cancel: the staged action is cleared without
            // performing it.
            decision = Some(LeaveDecision::Cancel);
        }
        if let Some(decision) = decision {
            self.resolve_leave(decision, uictx);
        }
    }

    /// Whether closing one of the editor windows is the staged leave action
    /// and that window is still on screen. The window's own question is the
    /// one about the draft it holds, so it renders that question inside
    /// itself and the main window's home leaves it alone; a staged action is
    /// exclusive, so at most one home asks it.
    fn close_is_staged_in_window(&self) -> bool {
        match self.leave_pending {
            Some(LeaveAction::CloseExisting) => self.existing.draft.is_some(),
            Some(LeaveAction::CloseAdd) => self.add.draft.is_some(),
            _ => false,
        }
    }

    /// Whether closing the add-server editor is the staged leave action.
    fn add_close_is_staged(&self) -> bool {
        matches!(self.leave_pending, Some(LeaveAction::CloseAdd))
    }

    /// The leave confirmation's content: what the staged action would do to the
    /// dirty draft, and the three answers. Returns this frame's answer, which
    /// the caller resolves through [`Self::resolve_leave`].
    ///
    /// Both homes of the question render this: the main window, through
    /// [`Self::show_leave_modal`], and the add-server editor inside itself.
    /// That editor passes its draft's gate — it holds the draft out of its
    /// slot until the end of the frame, so the slot alone cannot answer for
    /// it.
    fn leave_confirmation(
        &mut self,
        ui: &mut egui::Ui,
        uictx: &mut ServersCtx,
        add_gate: Option<DraftGate>,
    ) -> Option<LeaveDecision> {
        let lang = uictx.settings.language;
        let validating = self.profile_validation_in_progress(ProfileValidationOrigin::Draft);
        // Each draft's Save reads the same gate as its editor's own commit
        // control: `committable` refuses a raw-buffer-only dirty state, whose
        // commit would be a no-op that leaves the unsaved indicator on.
        let busy = uictx.busy.is_held();
        let existing_saveable = self
            .gate(DraftKind::Existing, busy)
            .is_some_and(DraftGate::committable);
        let add_saveable = match add_gate {
            Some(gate) => gate.committable(),
            None => self
                .gate(DraftKind::Add, busy)
                .is_some_and(DraftGate::committable),
        };
        let saveable = existing_saveable || add_saveable;
        let mut decision = None;
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
        decision
    }

    /// Resolve the staged action with the answer the question got. The action
    /// resolves only through the question's buttons; a dismissal reaches this
    /// as Cancel, which clears it without performing it.
    fn resolve_leave(&mut self, decision: LeaveDecision, uictx: &mut ServersCtx) {
        let lang = uictx.settings.language;
        // The question renders only while an action is staged, so the take
        // never comes up empty here.
        let action = self.leave_pending.take();
        match decision {
            LeaveDecision::Save => {
                if let Some(action) = action {
                    self.save_leave_action(action, lang, uictx);
                }
            }
            LeaveDecision::Discard => {
                if let Some(action) = action {
                    self.discard_leave_action(action, uictx);
                }
            }
            // Cancel: change nothing beyond clearing the staged action.
            LeaveDecision::Cancel => {}
        }
    }
}

/// One memoized latency badge: the badge text and color are
/// formatted once per input change — the outcome, language, status
/// palette — and reused by every painted row whose inputs still match.
/// The measurement time is deliberately not part of the key: monitoring
/// refreshes it every tick, and the cell's text would not change.
/// [`ServersScreen::latency_badges`] holds one per listed profile.
struct LatencyBadge {
    outcome: Option<ProbeOutcome>,
    lang: Language,
    colors: StatusColors,
    text: String,
    color: Color32,
}

impl LatencyBadge {
    fn new(verdict: Option<&ProbeVerdict>, lang: Language, colors: StatusColors) -> Self {
        let outcome = verdict.map(|verdict| verdict.outcome);
        let (text, color) = match outcome {
            // Never measured: an empty cell reads as "no result yet" without
            // repeating the header in every row.
            None => (String::new(), Color32::GRAY),
            Some(ProbeOutcome::Dead) => (t(lang, Key::LatencyTimeout).into(), colors.err),
            Some(ProbeOutcome::Delay(v)) if v < 300 => {
                (t_fmt(lang, Key::LatencyMs, &[&v]), colors.ok)
            }
            Some(ProbeOutcome::Delay(v)) if v < 1000 => {
                (t_fmt(lang, Key::LatencyMs, &[&v]), colors.warn)
            }
            Some(ProbeOutcome::Delay(v)) => (t_fmt(lang, Key::LatencyMs, &[&v]), colors.err),
        };
        Self {
            outcome,
            lang,
            colors,
            text,
            color,
        }
    }

    /// The memo still covers a row whose visible inputs are the outcome,
    /// `lang` and `colors` — an allocation-free per-row compare.
    fn matches(&self, outcome: Option<ProbeOutcome>, lang: Language, colors: StatusColors) -> bool {
        self.outcome == outcome && self.lang == lang && self.colors == colors
    }
}

/// The latency cell's hover: what measured it, how old the measurement is,
/// and — for a dead verdict — the error the core reported.
fn verdict_hover(lang: Language, verdict: &ProbeVerdict) -> String {
    let source = match verdict.source {
        ProbeSource::LatencyTest => t(lang, Key::SrvVerdictSourceTest),
        ProbeSource::Monitoring => t(lang, Key::SrvVerdictSourceMonitoring),
    };
    let age = std::time::SystemTime::now()
        .duration_since(verdict.measured_at)
        .unwrap_or_default();
    let mut text = if age < Duration::from_secs(1) {
        t_fmt(lang, Key::SrvVerdictJustNow, &[&source])
    } else {
        t_fmt(lang, Key::SrvVerdictAgo, &[&age_phrase(lang, age), &source])
    };
    if let Some(error) = &verdict.error {
        text.push('\n');
        text.push_str(&t_fmt(lang, Key::SrvVerdictError, &[error]));
    }
    text
}

/// A duration as the largest whole unit that has passed, singular or plural.
fn age_phrase(lang: Language, age: Duration) -> String {
    let seconds = age.as_secs();
    if seconds >= 86_400 {
        let days = seconds / 86_400;
        return if days == 1 {
            t(lang, Key::SrvAgeDay).to_owned()
        } else {
            t_fmt(lang, Key::SrvAgeDays, &[&days])
        };
    }
    if seconds >= 3_600 {
        let hours = seconds / 3_600;
        return if hours == 1 {
            t(lang, Key::SrvAgeHour).to_owned()
        } else {
            t_fmt(lang, Key::SrvAgeHours, &[&hours])
        };
    }
    if seconds >= 60 {
        let minutes = seconds / 60;
        return if minutes == 1 {
            t(lang, Key::SrvAgeMinute).to_owned()
        } else {
            t_fmt(lang, Key::SrvAgeMinutes, &[&minutes])
        };
    }
    if seconds <= 1 {
        t(lang, Key::SrvAgeSecond).to_owned()
    } else {
        t_fmt(lang, Key::SrvAgeSeconds, &[&seconds])
    }
}

/// The row's selection and emission state, grouped so the row builder keeps a
/// readable argument list.
struct RowState<'a> {
    selected: bool,
    /// The adjacent displayed row is selected too. A run of selected rows
    /// draws its outline as one band: no shared edge, no rule between them.
    joined_above: bool,
    joined_below: bool,
    active: bool,
    /// The row is a chain hop: another outbound dials through it, so the row
    /// exists because of that reference. The paint marks it with a blue bar.
    hop: bool,
    /// The labels of the emitted servers that dial through this row, in
    /// emitted order. The latency hover names them; empty for a seed nothing
    /// dials through.
    dialers: &'a [String],
    /// The latency test owns the list: row clicks, drags, the menu and the
    /// switch are inert while it runs.
    frozen: bool,
    switch: RowSwitch<'a>,
}

/// The row's enable switch: its current state, and — for the active server or
/// a chain-only hop — why the switch is locked.
struct RowSwitch<'a> {
    checked: bool,
    locked_hint: Option<&'a str>,
}

/// What a rendered table row reported: the row's own response (click,
/// right-click and drag anywhere on the row), the name button's response, and
/// whether the enable switch was clicked.
struct RowClicks {
    row: egui::Response,
    name: egui::Response,
    toggle: bool,
}

impl RowClicks {
    /// Whether this frame opened an editor on the row: a double click
    /// anywhere on the row or on its name button. Checked before the plain
    /// click so the second press of the gesture opens the editor instead of
    /// only selecting the row again.
    fn double_clicked(&self) -> bool {
        self.row.double_clicked() || self.name.double_clicked()
    }
}

/// One row's two formatted table cells: the protocol-and-security column and
/// the `address:port` column. Formatted once per model generation, because
/// both are functions of the profile alone.
#[derive(Clone)]
struct RowDetail {
    protocol: String,
    endpoint: String,
    /// Whether the Privacy setting hid the endpoint, as opposed to the
    /// profile carrying none.
    endpoint_hidden: bool,
}

/// The cell text a row renders when the memo has no entry for it (the
/// impossible index-after-rebuild case): both columns empty.
const EMPTY_ROW_DETAIL: RowDetail = RowDetail {
    protocol: String::new(),
    endpoint: String::new(),
    endpoint_hidden: false,
};

/// The widths a table starts from before the fit has run: the wide address
/// column and the room a checkbox and a latency badge need. The fit lets the
/// tag take the rest of the band, so the header and every row place the
/// data columns at the same x every frame.
const TABLE_DEFAULT_WIDTHS: ColumnWidths = ColumnWidths {
    order: 56.0,
    switch: 64.0,
    name: 0.0,
    latency: 84.0,
    protocol: 128.0,
    address: 240.0,
    group: 160.0,
};
/// The smallest width the tag column keeps; a fit or a drag may not go under
/// it. The table scrolls sideways past the viewport, so the floor protects the
/// header from collapsing, not the window from overflowing.
const TABLE_MIN_NAME_WIDTH: f32 = 160.0;
/// The height one row keeps. Dense enough that a hundred servers read as a
/// list, not a form.
const TABLE_ROW_HEIGHT: f32 = 26.0;
/// The inset every cell keeps from its column edge. Without it the header
/// words run together into one line and the table reads as prose.
const TABLE_CELL_INSET: f32 = 8.0;
/// The room a sort arrow needs beside its column's label.
const TABLE_SORT_ARROW_ROOM: f32 = 18.0;
/// The clear space between the tab strip's underline and the toolbar's first
/// control. The selected tab paints its rule three points below its label, so
/// the toolbar sits fifteen points under the label and twelve under the rule.
const TAB_STRIP_TO_TOOLBAR_GAP: f32 = 12.0;
/// How wide the pointer's grab band on a column divider is.
const TABLE_DIVIDER_HIT_WIDTH: f32 = 6.0;

/// One column of the servers table, in draw order: the tag and the value
/// read beside it come before the detail columns. Every column stores its
/// width; the fit lets the tag take the slack when the table is narrower than
/// the viewport.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Column {
    Order,
    Switch,
    Name,
    Latency,
    Protocol,
    Address,
    Group,
}

/// The narrowest each resizable column gets. There is no maximum: a column
/// holds whatever its content measures or the user drags, and a table wider
/// than the viewport scrolls instead of truncating. The tag column keeps its
/// floor, because a tag narrower than that reads as a rule, not a column.
fn column_bounds(column: Column) -> (f32, f32) {
    match column {
        Column::Order => (40.0, 96.0),
        Column::Switch => (48.0, 96.0),
        Column::Name => (TABLE_MIN_NAME_WIDTH, f32::INFINITY),
        Column::Latency => (64.0, f32::INFINITY),
        Column::Protocol => (80.0, f32::INFINITY),
        Column::Address => (120.0, f32::INFINITY),
        Column::Group => (80.0, f32::INFINITY),
    }
}

/// The stored width of `column`, or `None` for the flexible name column.
fn stored_width(widths: ColumnWidths, column: Column) -> Option<f32> {
    match column {
        Column::Order => Some(widths.order),
        Column::Switch => Some(widths.switch),
        Column::Name => Some(widths.name),
        Column::Protocol => Some(widths.protocol),
        Column::Address => Some(widths.address),
        Column::Latency => Some(widths.latency),
        Column::Group => Some(widths.group),
    }
}

fn set_stored_width(widths: &mut ColumnWidths, column: Column, width: f32) {
    match column {
        Column::Order => widths.order = width,
        Column::Switch => widths.switch = width,
        Column::Name => widths.name = width,
        Column::Protocol => widths.protocol = width,
        Column::Address => widths.address = width,
        Column::Latency => widths.latency = width,
        Column::Group => widths.group = width,
    }
}

/// The widths the table can use: a hand-edited settings file may carry a
/// negative, a zero from a partial object or a NaN, and each lands on the
/// adaptive default rather than drawing a column nothing can read.
fn sanitized_widths(widths: ColumnWidths) -> ColumnWidths {
    let mut out = TABLE_DEFAULT_WIDTHS;
    for column in [
        Column::Order,
        Column::Switch,
        Column::Name,
        Column::Latency,
        Column::Protocol,
        Column::Address,
        Column::Group,
    ] {
        let (low, high) = column_bounds(column);
        let fallback = stored_width(TABLE_DEFAULT_WIDTHS, column).unwrap_or(low);
        let value = stored_width(widths, column).unwrap_or(fallback);
        let value = if value.is_finite() && value > 0.0 {
            value
        } else {
            fallback
        };
        set_stored_width(&mut out, column, value.clamp(low, high));
    }
    out
}

/// Which optional columns a tab carries: `Emitted` numbers its rows in
/// outbound order, and `All` names each row's group.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct TableShape {
    order: bool,
    group: bool,
}

/// The extra cells one row paints beyond the six shared columns.
#[derive(Clone, Copy, Default)]
struct RowExtras<'a> {
    /// The outbound order number, shown only on `Emitted`.
    order: Option<usize>,
    /// The row's group title, shown only on `All`.
    group: Option<&'a str>,
}

/// What one row shows: the name, the formatted protocol and endpoint cells,
/// and the tab's extra columns.
#[derive(Clone, Copy)]
struct RowCells<'a> {
    name: &'a str,
    detail: &'a RowDetail,
    /// The live verdict behind the latency cell; the hover reads its time and
    /// error, which the memoized badge does not keep.
    verdict: Option<&'a ProbeVerdict>,
    extras: RowExtras<'a>,
}

/// The six shared column widths plus the tab's optional columns, laid out in
/// `available` points.
#[derive(Clone, Copy)]
struct TableColumns {
    order: Option<f32>,
    switch: f32,
    name: f32,
    latency: f32,
    protocol: f32,
    address: f32,
    group: Option<f32>,
}

fn table_columns(shape: TableShape, widths: ColumnWidths) -> TableColumns {
    let order = shape.order.then_some(widths.order);
    let group = shape.group.then_some(widths.group);
    TableColumns {
        order,
        switch: widths.switch,
        name: widths.name.max(TABLE_MIN_NAME_WIDTH),
        latency: widths.latency,
        protocol: widths.protocol,
        address: widths.address,
        group,
    }
}

/// Fit each column to the wider of its header and its widest cell, so the
/// fitted layout never clips a value it could hold: the widths are the
/// measurements themselves, floored at each column's minimum and capped at
/// nothing. The tag column is measured like any other; the table gives it
/// the slack when the fit is narrower than the viewport. Measured from the
/// same strings the rows paint, once per model generation rather than per
/// frame.
fn adaptive_widths(ui: &egui::Ui, lang: Language, servers: &ServersFile) -> ColumnWidths {
    let body = egui::TextStyle::Body.resolve(ui.style());
    let mono = egui::TextStyle::Monospace.resolve(ui.style());
    let button = egui::TextStyle::Button.resolve(ui.style());
    let measure = |text: &str, font: &egui::FontId| {
        ui.painter()
            .layout_no_wrap(text.to_owned(), font.clone(), egui::Color32::WHITE)
            .size()
            .x
    };
    let cell = |text: &str, font: &egui::FontId| measure(text, font) + 2.0 * TABLE_CELL_INSET;
    let header = |text: &str, sortable: bool| {
        cell(text, &body) + if sortable { TABLE_SORT_ARROW_ROOM } else { 0.0 }
    };

    let mut widths = ColumnWidths {
        order: header(t(lang, Key::SrvColOrder), false),
        switch: header(t(lang, Key::SrvColEnabled), false),
        name: header(t(lang, Key::SrvColName), true),
        latency: header(t(lang, Key::SrvColLatency), true),
        protocol: header(t(lang, Key::SrvColProtocol), true),
        address: header(t(lang, Key::SrvColAddress), false),
        group: header(t(lang, Key::SrvColGroup), false),
    };
    // The latency column shows a result, a timeout or nothing: its widest
    // value is one of the two words, never a row's own number.
    let latency_text = [
        t_fmt(lang, Key::LatencyMs, &[&9999i64]),
        t(lang, Key::LatencyTimeout).to_owned(),
    ];
    for text in &latency_text {
        widths.latency = widths.latency.max(cell(text, &body));
    }
    for (index, profile) in servers.profiles.iter().enumerate() {
        widths.order = widths.order.max(cell(&(index + 1).to_string(), &body));
        // The tag cell paints the unnamed fallback for an empty name, and its
        // button's own text style is what the column must hold.
        let name = if profile.name.is_empty() {
            t(lang, Key::SrvUnnamed)
        } else {
            profile.name.as_str()
        };
        widths.name = widths.name.max(cell(name, &button));
        widths.protocol = widths
            .protocol
            .max(cell(&row_detail(profile, false).protocol, &body));
        widths.address = widths
            .address
            .max(cell(&profile.server_address().unwrap_or_default(), &mono));
        widths.group = widths.group.max(cell(&profile.group_title, &body));
    }
    for group in &servers.groups {
        widths.group = widths.group.max(cell(&group.title, &body));
    }
    sanitized_widths(widths)
}

/// One step of a divider drag: the column on the left of the divider takes
/// the pointer's movement since the press, and nothing else moves. The
/// table's total changes with it, its neighbour keeps its width, and only
/// the dragged column's own minimum stops the drag.
fn drag_divider(widths: ColumnWidths, column: Column, dx: f32) -> ColumnWidths {
    let Some(current) = stored_width(widths, column) else {
        return widths;
    };
    let (low, high) = column_bounds(column);
    let next = (current + dx).clamp(low, high);
    let mut next_widths = widths;
    set_stored_width(&mut next_widths, column, next);
    next_widths
}

/// The widths a divider drag starts from: every stored width as it stood at
/// the press, with the tag column frozen at the width it had on screen. The
/// fit lets the tag take the slack, so a drag that starts from the fit must
/// capture that width before the first stored layout replaces it.
fn frozen_widths(widths: ColumnWidths, columns: TableColumns) -> ColumnWidths {
    let mut frozen = widths;
    frozen.name = columns.name;
    frozen
}

impl TableColumns {
    /// The width of the whole table. The header and every row draw on this
    /// one number, so a column's edges cannot drift between the names and the
    /// data below them.
    fn total(self) -> f32 {
        self.order.unwrap_or(0.0)
            + self.switch
            + self.name
            + self.latency
            + self.protocol
            + self.address
            + self.group.unwrap_or(0.0)
    }
}

/// One table cell: exactly `width` points wide and one control row tall,
/// clipped so a long value truncates inside its own column instead of
/// painting over the next one.
///
/// The cell reserves its whole column width before drawing anything. A cell
/// that sized itself to its content — a checkbox, a short endpoint — would
/// shift every column after it by however much that content fell short, per
/// row and per frame: the header and the rows would disagree on where each
/// column starts.
fn table_cell(ui: &mut egui::Ui, width: f32, add: impl FnOnce(&mut egui::Ui)) -> egui::Response {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(width, TABLE_ROW_HEIGHT), egui::Sense::hover());
    let inset = TABLE_CELL_INSET.min(width / 2.0);
    let content = rect.shrink2(egui::vec2(inset, 0.0));
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(content)
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
    );
    child.set_clip_rect(rect.intersect(ui.clip_rect()));
    add(&mut child);
    response
}

/// What the table header reported this frame: a sort command, the widths
/// after a divider drag, or a request to fit the columns again.
#[derive(Default)]
struct HeaderOutcome {
    sort: Option<SortColumn>,
    resized: Option<ColumnWidths>,
    fit: bool,
}

/// The widths one divider drag works from: the divider the pointer grabbed
/// and the widths the press found. The drag applies the pointer's movement
/// since the press to this anchor, so every frame lays out the same width
/// plus one total movement instead of compounding the last frame's stored
/// result.
#[derive(Clone, Copy)]
struct ColumnDrag {
    divider: usize,
    widths: ColumnWidths,
}

/// The table's header row: the tab's columns, and — where the tab is a view —
/// name, latency and protocol as sort controls. `Emitted`'s order is the
/// outbound order, so its header never offers a sort.
///
/// The dividers between columns are drag handles: a drag resizes the column
/// on its left and lets the table's total change, and a double click asks
/// for the fitted widths back. `drag` carries the anchor across frames.
fn table_header(
    ui: &mut egui::Ui,
    lang: Language,
    columns: TableColumns,
    widths: ColumnWidths,
    sortable: bool,
    sort: Option<ViewSort>,
    drag: &mut Option<ColumnDrag>,
) -> HeaderOutcome {
    let weak = |ui: &mut egui::Ui, text: &str| {
        ui.add(egui::Label::new(RichText::new(text).weak()).truncate());
    };
    let mut outcome = HeaderOutcome::default();
    // The header is a line of column names over their own columns, closed by
    // one rule. A filled band with column separators reads as a title bar and
    // separates the names from the data they name.
    let band = egui::Rect::from_min_size(
        ui.cursor().min,
        egui::vec2(columns.total(), TABLE_ROW_HEIGHT),
    );
    let mut column_header =
        |ui: &mut egui::Ui, text: &str, column: Option<SortColumn>, width: f32, right: bool| {
            table_cell(ui, width, |ui| {
                let mut draw = |ui: &mut egui::Ui| {
                    let Some(column) = column.filter(|_| sortable) else {
                        weak(ui, text);
                        return;
                    };
                    ui.scope(|ui| {
                        // A frame-less button keeps its padding, which would
                        // push the label off the data column below; the cell's
                        // inset is the only gutter this table uses.
                        ui.spacing_mut().button_padding = egui::vec2(0.0, 0.0);
                        if ui
                            .add(egui::Button::new(RichText::new(text).weak()).frame(false))
                            .clicked()
                        {
                            outcome.sort = Some(column);
                        }
                    });
                    if let Some(current) = sort.filter(|current| current.column == column) {
                        ui.add_space(4.0);
                        ui.label(RichText::new(if current.ascending { "▲" } else { "▼" }).weak());
                    }
                };
                if right {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), draw);
                } else {
                    draw(ui);
                }
            });
        };
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        if let Some(width) = columns.order {
            column_header(ui, t(lang, Key::SrvColOrder), None, width, true);
        }
        column_header(ui, t(lang, Key::SrvColEnabled), None, columns.switch, false);
        column_header(
            ui,
            t(lang, Key::SrvColName),
            Some(SortColumn::Name),
            columns.name,
            false,
        );
        column_header(
            ui,
            t(lang, Key::SrvColLatency),
            Some(SortColumn::Latency),
            columns.latency,
            true,
        );
        column_header(
            ui,
            t(lang, Key::SrvColProtocol),
            Some(SortColumn::Protocol),
            columns.protocol,
            false,
        );
        column_header(
            ui,
            t(lang, Key::SrvColAddress),
            None,
            columns.address,
            false,
        );
        if let Some(width) = columns.group {
            column_header(ui, t(lang, Key::SrvColGroup), None, width, false);
        }
    });
    ui.painter().hline(
        band.x_range(),
        band.max.y - 0.5,
        egui::Stroke::new(1.0, ui.visuals().widgets.inactive.bg_stroke.color),
    );

    let mut spans = [(Column::Switch, 0.0); 7];
    let mut count = 0;
    for (column, width) in [
        (Column::Order, columns.order),
        (Column::Switch, Some(columns.switch)),
        (Column::Name, Some(columns.name)),
        (Column::Latency, Some(columns.latency)),
        (Column::Protocol, Some(columns.protocol)),
        (Column::Address, Some(columns.address)),
        (Column::Group, columns.group),
    ] {
        if let Some(width) = width {
            spans[count] = (column, width);
            count += 1;
        }
    }
    let mut x = band.left();
    for (index, &(left, width)) in spans[..count.saturating_sub(1)].iter().enumerate() {
        x += width;
        let hit = egui::Rect::from_min_max(
            egui::pos2(x - TABLE_DIVIDER_HIT_WIDTH / 2.0, band.top()),
            egui::pos2(x + TABLE_DIVIDER_HIT_WIDTH / 2.0, band.max.y),
        );
        let response = ui.interact(
            hit,
            ui.auto_id_with(("servers.column-divider", index)),
            egui::Sense::click_and_drag(),
        );
        let hot = response.hovered() || response.dragged();
        // Every column edge is visible, faintly: a target that only appears
        // on hover is invisible on an empty stretch of header, which is
        // exactly where a wide tag leaves its divider.
        ui.painter().vline(
            x,
            band.y_range(),
            egui::Stroke::new(
                1.0,
                if hot {
                    ui.visuals().widgets.inactive.bg_stroke.color
                } else {
                    ui.visuals().widgets.noninteractive.bg_stroke.color
                },
            ),
        );
        if hot {
            ui.ctx().set_cursor_icon(egui::CursorIcon::ResizeHorizontal);
        }
        if response.double_clicked() {
            outcome.fit = true;
        }
        if response.drag_started() {
            *drag = Some(ColumnDrag {
                divider: index,
                widths: frozen_widths(widths, columns),
            });
        }
        if response.dragged()
            && let Some(anchor) = (*drag).filter(|anchor| anchor.divider == index)
        {
            // The movement since the press, applied once to the widths the
            // press found — never the per-frame step applied to last frame's
            // stored widths, which drifts as soon as a frame is skipped.
            let dx = response.total_drag_delta().map_or(0.0, |total| total.x);
            outcome.resized = Some(drag_divider(anchor.widths, left, dx));
        }
        if response.drag_stopped() {
            *drag = None;
        }
    }
    outcome
}

/// The drag payload of one server-list row: the row's index in the list as
/// drawn. An index and not the profile id, because a cloned id would allocate
/// per row; the release reads the payload in the same frame that laid the
/// list out, so the index still names that row. Only the `Emitted` tab lifts
/// rows, and only a row that is neither the active server nor a chain hop:
/// the active row is pinned first by the generated order, and a hop's slot is
/// a consequence of another row's chain, while the drag rewrites that row's
/// own group order — the only order the list stores. The drop half reads the
/// display list with the hop rows left out, so the payload index maps to its
/// seed position before the block algorithm sees it.
///
/// The row's own response is the drag source — it hands egui the payload
/// through [`egui::DragAndDrop::set_payload`] — instead of
/// [`egui::Ui::dnd_drag_source`]: that helper's drag-sensing rect covers the
/// row's buttons and name button, and a press on any of them would be taken
/// as the row's drag, so the button would never see its click. The drop half
/// is still egui's: the payload survives until the release (or Escape) that
/// ends it, and the release frame takes it back through
/// [`egui::DragAndDrop::take_payload`].
#[derive(Clone, Copy)]
struct DragRow(usize);

/// The drag payload of one group tab: the tab itself. Only group tabs are
/// draggable, and only inside their pinned or unpinned band.
#[derive(Clone)]
struct DragTab(ServerTab);

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

/// The stored move one `Emitted` drop asks for: the dragged profile and the
/// sibling inside the same group it lands ahead of. `before: None` lands it at
/// its block's tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockDrop {
    from: usize,
    before: Option<usize>,
}

/// Map a drop on the `Emitted` list to a move inside the dragged row's own
/// group block. `rows` is the list as drawn with the hop rows left out — a
/// hop is a consequence of the chain, not a place in its group — as profile
/// indices, `from` and `gap` index that list the way [`reorder_target`] reads
/// them, and `active` is the profile the generated order pins first — that
/// row is a block of its own and accepts no drop.
///
/// A gap whose neighbours are both another group's rows yields `None`, so a
/// drop outside the row's block neither paints an insertion line nor changes
/// the stored order. At a block boundary the gap belongs to the block on the
/// other side; when the lifted row's block owns that side, the row goes to the
/// block's tail, because the next row belongs to the following block.
/// [`move_profile_in_group`](crate::model::ServersFile::move_profile_in_group)
/// is what then refuses a destination the view alone could not spot.
fn block_drop(
    rows: &[usize],
    profiles: &[ServerProfile],
    active: Option<usize>,
    from: usize,
    gap: usize,
) -> Option<BlockDrop> {
    let &from_profile = rows.get(from)?;
    if Some(from_profile) == active || gap == from || gap == from + 1 {
        return None;
    }
    let group = profiles.get(from_profile)?.group_id();
    // The lifted row is not a place to land; the gaps beside it are no-ops.
    let in_block = |display: usize| {
        rows.get(display).is_some_and(|&index| {
            index != from_profile
                && Some(index) != active
                && profiles
                    .get(index)
                    .is_some_and(|profile| profile.group_id() == group)
        })
    };
    let previous = gap.checked_sub(1);
    let next = (gap < rows.len()).then_some(gap);
    if !previous.is_some_and(in_block) && !next.is_some_and(in_block) {
        return None;
    }
    let before = next
        .filter(|&display| in_block(display))
        .map(|display| rows[display]);
    Some(BlockDrop {
        from: from_profile,
        before,
    })
}

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

/// One row's two formatted table cells. The protocol column pairs the
/// protocol with its transport security when the security is not plain; the
/// endpoint column is empty while the user hid server information, because
/// the address is exactly what that setting hides.
fn row_detail(profile: &crate::model::ServerProfile, hide_server_info: bool) -> RowDetail {
    let protocol = profile.outbound.protocol.as_str();
    let security = profile.outbound.stream.security.as_str();
    let protocol = if security == "none" {
        protocol.to_owned()
    } else {
        format!("{protocol} · {security}")
    };
    let endpoint = if hide_server_info {
        String::new()
    } else {
        profile.server_address().unwrap_or_default()
    };
    RowDetail {
        protocol,
        endpoint,
        endpoint_hidden: hide_server_info,
    }
}

/// One tab's rows as profile indices, in view order: the emitted set in
/// generated order, one group's rows in stored order, or every row in grouped
/// order for `All`. `search` filters by name or address, case-insensitively,
/// and only inside this tab. `sort` is a view over the rows — except on
/// `Emitted`, whose order is the outbound order and is never sorted here.
fn tab_rows(
    servers: &crate::model::ServersFile,
    tab: &ServerTab,
    search: &str,
    sort: Option<ViewSort>,
) -> Vec<usize> {
    let needle = search.trim().to_lowercase();
    let group_members = |group_id: &str| -> Vec<usize> {
        servers
            .profiles
            .iter()
            .enumerate()
            .filter(|(_, profile)| profile.group_id() == group_id)
            .map(|(index, _)| index)
            .collect()
    };
    let mut rows: Vec<usize> = match tab {
        ServerTab::Emitted => servers.emitted_set().order,
        ServerTab::All => servers.grouped_order(),
        ServerTab::Manual => group_members(crate::model::servers::MANUAL_GROUP_ID),
        ServerTab::Group(id) => group_members(id),
    };
    rows.retain(|&index| {
        if needle.is_empty() {
            return true;
        }
        let profile = &servers.profiles[index];
        profile.name.to_lowercase().contains(&needle)
            || profile
                .server_address()
                .is_some_and(|address| address.to_lowercase().contains(&needle))
    });
    if *tab != ServerTab::Emitted
        && let Some(sort) = sort
    {
        sort_view_rows(&mut rows, &servers.profiles, sort);
    }
    rows
}

/// Sort a tab's row indices by one column, ascending or descending. The
/// stored order is untouched; only the view's row list moves.
fn sort_view_rows(rows: &mut [usize], profiles: &[crate::model::ServerProfile], sort: ViewSort) {
    match sort.column {
        SortColumn::Name => rows.sort_by_cached_key(|&index| profiles[index].name.to_lowercase()),
        SortColumn::Protocol => {
            rows.sort_by_cached_key(|&index| profiles[index].outbound.protocol.as_str().to_owned());
        }
        SortColumn::Latency => {
            rows.sort_by_cached_key(|&index| {
                match profiles[index]
                    .verdict
                    .as_ref()
                    .and_then(ProbeVerdict::delay_ms)
                {
                    Some(value) => (0u8, value),
                    None => (1u8, i64::MAX),
                }
            });
        }
    }
    if !sort.ascending {
        rows.reverse();
    }
}

/// The current Unix time in seconds: the one clock read the screen's time
/// stamps share.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

/// A Unix time as `YYYY-MM-DD` (UTC), for an expiry caption. No calendar
/// dependency: days since the epoch → civil date (proleptic Gregorian).
fn unix_date(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// The source address a direct subscription fetch binds: the uplink adapter
/// the latency probe resolves, reduced to its first IPv4 (else IPv6) address,
/// because the HTTP client binds an address rather than an adapter.
fn subscription_bind_address(
    lang: Language,
    settings: &crate::model::Settings,
    core_running: bool,
) -> Result<Option<std::net::IpAddr>, String> {
    if !settings.subscription_direct_fetch {
        return Ok(None);
    }
    let interfaces = crate::sys::netif::list_all();
    let tun_name = settings.tun.effective_name();
    let tun_index = interfaces
        .iter()
        .find(|interface| interface.name == tun_name)
        .map(|interface| interface.index);
    let tun_active = settings.mode == crate::model::Mode::Tun && core_running;
    match crate::sys::netif::resolve_probe_uplink(
        Some(&settings.tun.auto_outbounds_interface),
        tun_active,
        tun_index,
        &interfaces,
    ) {
        crate::sys::netif::ProbeUplink::Unbound => Ok(None),
        crate::sys::netif::ProbeUplink::Interface(name) => {
            let address = interfaces
                .iter()
                .find(|interface| interface.name == name)
                .and_then(|interface| {
                    interface
                        .ips
                        .iter()
                        .filter_map(|ip| ip.parse::<std::net::IpAddr>().ok())
                        .min_by_key(|address| !address.is_ipv4())
                });
            address
                .map(Some)
                .ok_or_else(|| t_fmt(lang, Key::SrvSubscriptionNoUplinkAddress, &[&name]))
        }
        crate::sys::netif::ProbeUplink::TunSelf { name } => {
            Err(t_fmt(lang, Key::ProbeInterfaceTunSelf, &[&name]))
        }
        crate::sys::netif::ProbeUplink::Down { name } => {
            Err(t_fmt(lang, Key::ProbeInterfaceDown, &[&name]))
        }
        crate::sys::netif::ProbeUplink::Missing { name } => {
            Err(t_fmt(lang, Key::ProbeInterfaceMissing, &[&name]))
        }
    }
}

/// One row of the servers table: the order number (on `Emitted`), the active
/// marker, the switch, the name, the latency column, the
/// protocol-and-security column, the `address:port` column and the tab's
/// group column, in that order. Returns the
/// row [`egui::Response`] (click, right-click and drag anywhere on the row),
/// the name button's response (it must be treated as a select target too), and
/// whether the switch was clicked.
///
/// The name is a truncated selectable button inside its own cell, so an
/// over-long name ends in "…" at the column boundary instead of painting over
/// the latency or address column. The row's interaction is registered by the
/// surrounding `ui.horizontal` after the cells, so the switch's own click
/// wins; every other click, double-click, right-click and drag lands on the
/// row.
fn server_list_row(
    ui: &mut egui::Ui,
    lang: Language,
    columns: TableColumns,
    cells: RowCells<'_>,
    row: RowState<'_>,
    latency: &LatencyBadge,
) -> RowClicks {
    let RowCells {
        name,
        detail,
        verdict,
        extras,
    } = cells;
    // A row reads as a row when its band is visible: the pointer's row lifts,
    // a selected row is outlined, and the route or a server another outbound
    // dials through is marked at the row's edge. The fill is issued before the
    // horizontal layout allocates the cells, so it stays underneath them.
    let band = egui::Rect::from_min_size(
        ui.cursor().min,
        egui::vec2(columns.total(), TABLE_ROW_HEIGHT),
    );
    let colors = status_colors_of(ui);
    if ui.rect_contains_pointer(band) {
        ui.painter()
            .rect_filled(band, 0.0, ui.visuals().widgets.hovered.weak_bg_fill);
    }
    // Selection is an outline rather than a fill: the values keep their own
    // colour, and a run of selected rows draws one band — the shared edges
    // and the rule between two selected rows are omitted, so Ctrl+A reads as
    // one rectangle instead of a stack of boxes.
    let outline = row.selected.then_some(colors.selected);
    let marker = if row.active {
        // The active route is a bar at the row's edge, not a whole column
        // spent on one dot.
        Some(colors.ok)
    } else if row.hop {
        // A hop is in the list because another outbound dials through it. The
        // blue bar takes the active row's place and shape, so one mark answers
        // "why is this row here"; a route that is also a hop keeps green.
        Some(colors.hop)
    } else {
        None
    };
    if let Some(color) = marker {
        let bar = egui::Rect::from_min_size(
            egui::pos2(band.left(), band.top() + 5.0),
            egui::vec2(3.0, band.height() - 10.0),
        );
        ui.painter().rect_filled(bar, 1.0, color);
    }
    let inner = ui.horizontal(|ui| {
        // Cells abut: the gutter is each cell's own inset, so the header and
        // every row lay their columns out on the same x.
        ui.spacing_mut().item_spacing.x = 0.0;
        if let (Some(width), Some(order)) = (columns.order, extras.order) {
            table_cell(ui, width, |ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(order.to_string()).weak()).selectable(false),
                    );
                });
            });
        }
        let mut checked = row.switch.checked;
        table_cell(ui, columns.switch, |ui| {
            let response = ui.add_enabled(
                !row.frozen && row.switch.locked_hint.is_none(),
                egui::Checkbox::without_text(&mut checked),
            );
            match row.switch.locked_hint {
                Some(hint) => {
                    response.on_disabled_hover_text(hint);
                }
                None => {
                    response.on_hover_text(t(lang, Key::Enabled));
                }
            }
        });
        let toggled = checked != row.switch.checked;
        let name_resp = table_cell_button(ui, columns.name, lang, name, row.frozen);
        let latency_cell = table_cell(ui, columns.latency, |ui| {
            // The badge text/color come from the row's memoized
            // [`LatencyBadge`] — borrowed, never re-formatted per painted row.
            // Not selectable: `interaction.selectable_labels` defaults to
            // true, and a click-sensing label would sit on top of the row's
            // click target, making the latency area unclickable. Values align
            // right so the digits read as a column; an unmeasured row paints
            // nothing, which is why the badge text is empty then.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add(
                    egui::Label::new(RichText::new(latency.text.as_str()).color(latency.color))
                        .selectable(false),
                );
            });
        });
        // The hover belongs to the whole cell, not the text: a hop with no
        // measurement paints an empty badge and must still explain itself.
        // Both lines are composed when the tooltip opens, so an idle frame
        // allocates nothing.
        if verdict.is_some() || !row.dialers.is_empty() {
            latency_cell.on_hover_ui(|ui| {
                if let Some(verdict) = verdict {
                    ui.label(verdict_hover(lang, verdict));
                }
                if !row.dialers.is_empty() {
                    ui.label(t_fmt(lang, Key::SrvDialedBy, &[&row.dialers.join(", ")]));
                }
            });
        }
        table_cell(ui, columns.protocol, |ui| {
            ui.add(egui::Label::new(RichText::new(&detail.protocol).weak()).truncate());
        });
        table_cell(ui, columns.address, |ui| {
            if detail.endpoint_hidden {
                // Masked like the editor's fields: the column reads as a
                // deliberate redaction, not as a server with no address.
                widgets::masked_stand_in(ui, true, "");
            } else {
                // The endpoint is data: the monospace face lines the ports up
                // column-wise, and an absent address paints nothing rather than
                // a dash that only repeats the header. A host name too long for
                // the column truncates, and its full value stays on hover.
                let response = ui.add(
                    egui::Label::new(RichText::new(detail.endpoint.as_str()).monospace().weak())
                        .truncate(),
                );
                if !detail.endpoint.is_empty() {
                    response.on_hover_text(detail.endpoint.as_str());
                }
            }
        });
        if let (Some(width), Some(group)) = (columns.group, extras.group) {
            table_cell(ui, width, |ui| {
                ui.add(egui::Label::new(RichText::new(group).weak()).truncate());
            });
        }
        (toggled, name_resp)
    });
    let (toggled, name_resp) = inner.inner;
    // The rule closes the row's band: with no striping it is what keeps a long
    // list from reading as one field of text. Inside a selection run it is
    // omitted — the outline carries the edge, and two selected rows must not
    // be split by a line.
    if !(row.selected || row.joined_below) {
        ui.painter().hline(
            band.x_range(),
            band.max.y - 0.5,
            egui::Stroke::new(1.0, ui.visuals().widgets.noninteractive.bg_stroke.color),
        );
    }
    if let Some(color) = outline {
        draw_selection_edges(
            ui.painter(),
            band,
            color,
            row.joined_above,
            row.joined_below,
        );
    }
    let resp = if row.frozen {
        inner.response.interact(egui::Sense::hover())
    } else {
        inner.response.interact(egui::Sense::click_and_drag())
    };
    RowClicks {
        row: resp,
        name: name_resp,
        toggle: toggled,
    }
}

/// The selection outline: a 1-point rectangle drawn edge by edge, so a run of
/// selected rows omits the edge it shares with its neighbour and reads as one
/// band. The bottom edge takes the row rule's place; the verticals run the
/// full band so two adjacent selected rows join without a seam.
fn draw_selection_edges(
    painter: &egui::Painter,
    band: egui::Rect,
    color: egui::Color32,
    joined_above: bool,
    joined_below: bool,
) {
    let stroke = egui::Stroke::new(1.0, color);
    painter.vline(band.left() + 0.5, band.y_range(), stroke);
    painter.vline(band.right() - 0.5, band.y_range(), stroke);
    if !joined_above {
        painter.hline(band.x_range(), band.top() + 0.5, stroke);
    }
    if !joined_below {
        painter.hline(band.x_range(), band.max.y - 0.5, stroke);
    }
}

/// The name cell: a frame-less button truncated at the column boundary. The
/// click target stays for opening the editor and starting a drag, but the
/// cell paints no highlight of its own — the row's outline carries selection,
/// and an accent-filled name inside it would say the same thing twice.
fn table_cell_button(
    ui: &mut egui::Ui,
    width: f32,
    lang: Language,
    name: &str,
    frozen: bool,
) -> egui::Response {
    let mut response = None;
    table_cell(ui, width, |ui| {
        let text = if name.is_empty() {
            t(lang, Key::SrvUnnamed).to_owned()
        } else {
            name.to_owned()
        };
        response = Some(
            ui.scope(|ui| {
                // The button's own padding would indent the name past the
                // header above it; the cell inset is the table's only gutter.
                ui.spacing_mut().button_padding = egui::vec2(0.0, 0.0);
                ui.add_enabled(!frozen, egui::Button::new(text).frame(false).truncate())
                    .on_hover_text(t(lang, Key::SrvDragToReorder))
            })
            .inner,
        );
    });
    response.expect("the name cell always adds its button")
}

/// What the editor window's body asked for this frame. The work happens after
/// the draft is put back (or closed), because the window's body only draws.
#[derive(Default)]
struct EditorWindowOutcome {
    validate: bool,
    discard: bool,
    close: bool,
}

impl ServersScreen {
    // ---------- editor window ----------

    /// The profile editor's pop-up window. Opened by a double click on a row,
    /// by the row's Edit command, or as the target of a resolved leave
    /// question; it renders exactly while the slot holds a draft.
    fn show_editor_window(&mut self, ctx: &egui::Context, uictx: &mut ServersCtx) {
        let Some(mut draft) = self.existing.take() else {
            return;
        };
        let lang = uictx.settings.language;
        let validating = self.profile_validation_in_progress(ProfileValidationOrigin::Draft);
        let busy = uictx.busy.is_held();
        let mut outcome = EditorWindowOutcome::default();
        let mut leave_decision: Option<LeaveDecision> = None;
        // The question about this window's own draft is this window's: the
        // user closed it, so it renders here, dimming the draft it asks
        // about, instead of in a second window on top of it. A backend with
        // no windows to give renders both in one context, where the modal
        // already covers the window it dims.
        let backdrop_dismissed = matches!(self.leave_pending, Some(LeaveAction::CloseExisting))
            && !ctx.embed_viewports()
            && popup::backdrop(ctx, "servers.leave.edit-draft");
        let close_requested = popup::show(
            ctx,
            "servers.edit-draft",
            t(lang, Key::SrvEditServerWindow),
            [680.0, 600.0],
            true,
            |ui| {
                self.show_editor_body(ui, uictx, &mut draft, &mut outcome);
                if matches!(self.leave_pending, Some(LeaveAction::CloseExisting)) {
                    let gate = draft.gate(&self.seeded_buffers, validating, busy);
                    let dismissed = popup::modal(
                        ui.ctx(),
                        "servers.leave.edit-draft",
                        t(lang, Key::SrvUnsavedChanges),
                        520.0,
                        |ui| {
                            leave_decision = self.leave_confirmation(ui, uictx, Some(gate));
                        },
                    );
                    if leave_decision.is_none() && (dismissed || backdrop_dismissed) {
                        // A dismissal of the question — a click on the dimmed
                        // draft, Escape, or a click on the dimmed main window —
                        // is Cancel, as it is in the main window; a button's
                        // answer wins the frame it lands in.
                        leave_decision = Some(LeaveDecision::Cancel);
                    }
                }
            },
        );

        // Only the leave question's Discard drops the draft with the window it
        // closed; every other answer — Save holding it for the verdict it
        // starts, Cancel leaving the editor as it was — is what the gate below
        // does with an untouched window.
        let discarded = matches!(leave_decision, Some(LeaveDecision::Discard));
        if !discarded {
            if outcome.discard {
                // Discard reverts the editor in place: the window stays open
                // on a fresh draft of the same profile.
                let id = draft.id.clone();
                self.existing.hold(draft);
                self.discard_existing_draft();
                self.load_existing_draft(uictx.servers, lang, &id);
            } else if outcome.validate {
                match self.start_profile_validation(
                    lang,
                    ProfileValidationOrigin::Draft,
                    vec![draft.profile.clone()],
                    Some(draft.target()),
                    uictx,
                ) {
                    Ok(()) => self.existing.hold(draft),
                    Err(error) => {
                        self.profile_validation_report = Some(error.clone());
                        self.set_status(StatusLine::err(error));
                        self.existing.hold(draft);
                    }
                }
            } else if validating || (!close_requested && !outcome.close) {
                // A validation in flight holds the window: the platform's
                // close on it is refused until the verdict lands, because the
                // draft and the report it will render are what the window is
                // open for.
                self.existing.hold(draft);
            } else {
                // The window was closed without commit: the close guard stages
                // the leave question when the draft is dirty, and otherwise
                // drops the draft with its seeded raw buffers.
                self.close_existing_editor(draft, busy);
            }
        }

        // The answer resolves last, with the draft back in its slot: Save's
        // validation reads the slot the same way the window's own commit does,
        // and Discard closes the draft the gate above held back.
        if let Some(decision) = leave_decision {
            self.resolve_leave(decision, uictx);
        }
    }

    /// One frame of the editor window's content. The caller owns the draft out
    /// of its slot for the frame (the tabs mutate the screen around it) and
    /// puts it back or closes it afterwards; `outcome` carries what the
    /// action row asked for to that owner.
    fn show_editor_body(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &mut ServersCtx,
        draft: &mut ProfileDraft,
        outcome: &mut EditorWindowOutcome,
    ) {
        let lang = ctx.settings.language;
        // The validation blocks below — the dot, the Advanced tab's inline
        // finalmask verdict, the error list, the Validate gate — render from
        // the draft's memoized verdicts, so a draft whose generation or
        // language moved outside this frame's content edits (fresh open, tool
        // application, language switch) must carry a current memo before
        // anything renders. Content edits bump the generation after the tab
        // content and refresh again below; idle frames hit only the cheap
        // freshness check here and there.
        draft.refresh(lang);
        // The two gate facts that move without a draft edit: the profile
        // validation job (read here so the dot, the tabs' gates and the
        // action row all see one value) and the busy window.
        let validating = self.profile_validation_in_progress(ProfileValidationOrigin::Draft);
        let busy = ctx.busy.is_held();
        let mut changed = false;
        ui.horizontal(|ui| {
            let name_label = ui.label(t(lang, Key::SrvName));
            changed |= ui
                .add(egui::TextEdit::singleline(&mut draft.profile.name).desired_width(220.0))
                .labelled_by(name_label.id)
                .changed();
            ui.separator();
            ui.monospace(draft.tag.as_str());
            // Unsaved-changes dot: the draft differs from its baseline or a
            // raw-JSON buffer holds uncommitted text (the same condition that
            // enables Discard). Only the existing draft gets the dot — an add
            // draft is unsaved by definition.
            if draft.gate(&self.seeded_buffers, validating, busy).dirty() {
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
                            changed |=
                                self.switch_draft_protocol(&mut draft.profile, protocol, lang);
                        }
                    }
                });
        });
        ui.separator();
        ui.horizontal(|ui| {
            for &tab in TABS {
                ui.selectable_value(&mut self.tab, tab, tab.label(lang));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                widgets::reveal_toggle(ui, lang, &mut self.revealed_existing);
            });
        });
        // What the tabs below mask: the credentials, and the server
        // information only while the setting asks for it. One value for the
        // whole screen, derived after the control ran, so a click applies the
        // same frame.
        let mask = widgets::Mask {
            secrets: !self.revealed_existing,
            server_info: !self.revealed_existing && ctx.settings.hide_server_info,
        };
        ui.separator();
        // The action row below (validation block + Validate/Discard buttons)
        // is laid out after the tab content; reserve its worst-case height
        // (errors capped in their own scroll below) so the buttons stay
        // visible and clickable at any window size, and the tab content
        // scrolls inside the remainder instead of expanding past the panel
        // edge (mirrors the servers.list reserve above and the add-draft
        // dialog's fixed cap).
        let tab_height = (ui.available_height() - 240.0).max(160.0);
        // The borrowed identity the three tabs below take, built once per
        // frame from the draft's own fields (see [`DraftTarget`]): it carries
        // the generation the sweep above covers, so a request staged from it
        // is dropped only once an edit moves the draft on.
        let target = DraftTarget {
            kind: DraftKind::Existing,
            profile_id: draft.id.as_str(),
            generation: draft.generation,
        };
        egui::ScrollArea::vertical()
            .id_salt("servers.editor.scroll")
            .max_height(tab_height)
            .show(ui, |ui| {
                changed |= match self.tab {
                    EditorTab::Basic => {
                        let inline_errors: &[String] = draft
                            .validation
                            .as_ref()
                            .map(|cached| cached.rendered.basic_inline.as_slice())
                            .unwrap_or(&[]);
                        self.basic_tab_for_target(
                            ui,
                            lang,
                            &mut draft.profile,
                            Some(target),
                            inline_errors,
                            mask,
                        )
                    }
                    EditorTab::Transport => {
                        let OutboundModel {
                            protocol,
                            stream,
                            mux,
                            ..
                        } = &mut draft.profile.outbound;
                        self.transport_tab(
                            ui,
                            lang,
                            stream,
                            0,
                            TransportTabCtx {
                                target: Some(target),
                                masked: mask.secrets,
                                protocol: *protocol,
                                mux: Some(mux),
                            },
                        )
                    }
                    EditorTab::Security => {
                        let address = draft.profile.server_address();
                        let ech_sockopt_errors: &[String] = draft
                            .validation
                            .as_ref()
                            .map(|cached| cached.rendered.ech_sockopt.as_slice())
                            .unwrap_or(&[]);
                        self.security_tab_for_target(
                            ui,
                            lang,
                            Some(target),
                            &mut draft.profile.outbound.stream,
                            address.as_deref(),
                            ech_sockopt_errors,
                        )
                    }
                    EditorTab::Mux => {
                        let flow = vless_flow(&draft.profile.outbound.settings);
                        mux_tab(ui, lang, &mut draft.profile.outbound.mux, flow)
                    }
                    EditorTab::Advanced => {
                        // The inline finalmask and sockopt verdicts ride the
                        // draft's memoized validation (refreshed above
                        // whenever the draft generation or language moved):
                        // identical messages, zero re-validation on idle
                        // frames.
                        let finalmask_errors: &[String] = draft
                            .validation
                            .as_ref()
                            .map(|cached| cached.rendered.finalmask.as_slice())
                            .unwrap_or(&[]);
                        let stream_sockopt_errors: &[String] = draft
                            .validation
                            .as_ref()
                            .map(|cached| cached.rendered.stream_sockopt.as_slice())
                            .unwrap_or(&[]);
                        ServersScreen::advanced_tab(
                            ui,
                            lang,
                            &mut draft.profile,
                            &ctx.servers.profiles,
                            AdvancedTabCtx {
                                set_key: (ctx.hooks.model_generation(), ctx.servers.profiles.len()),
                                finalmask_errors,
                                stream_sockopt_errors,
                                dialer_proxy_options: &mut self.existing.chain_options,
                                buffers: &mut self.seeded_buffers,
                                masked: mask.secrets,
                            },
                        )
                    }
                };
            });
        if changed {
            // The retired `proxySettings` key needs a chain decision, not any
            // edit: the profile stops gating when its chain target differs
            // from the loaded baseline's, or when the user dismisses the key
            // on the finding row. An unrelated edit (a rename, a port) leaves
            // the gate in place, so a save can never drop a chain the user
            // never looked at.
            if draft.profile.chain_target() != draft.baseline.chain_target.as_deref() {
                draft.profile.outbound.retired_proxy_settings = None;
            }
            // The retired `quicParams.udpHop` key clears the same way: the
            // user rebuilds the hop as a `udphop` UDP mask (the mask list
            // moved away from the loaded baseline's), or dismisses the key on
            // the finding row. Editing an unrelated mask leaves the gate.
            if udphop_masks(&draft.profile) != draft.baseline.udphop_masks
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
            self.draft_edited(draft);
        }
        // Content edits ran the change protocol above; refresh the draft's
        // memoized verdicts (validation errors, finalmask issues,
        // changed-from-source) once for the new generation. Idle frames hit
        // the cheap freshness check only.
        draft.refresh(lang);
        let Some(cached) = draft.validation.as_ref() else {
            // The refresh above leaves a memo for the generation it was
            // handed; an impossible miss renders nothing further, and the
            // caller keeps the draft so the editor's state cannot be lost.
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
                        ui.colored_label(status_colors_of(ui).err, error);
                    }
                });
            // The retired `proxySettings` finding's other way out: a user who
            // wants no chain at all drops the key here instead of setting a
            // target; the control is the finding row's own and never appears
            // for any other rule.
            if draft.profile.outbound.retired_proxy_settings.is_some() {
                ui.horizontal(|ui| {
                    if ui.button(t(lang, Key::SrvRemoveProxySettingsKey)).clicked() {
                        dismissed_retired_key = true;
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
                        ui.colored_label(status_colors_of(ui).warn, warning);
                    }
                });
        }
        // The retired `quicParams.udpHop` advisory's other way out: a user who
        // wants no hop at all drops the key here instead of building the mask.
        // The key applies normally, so the control renders whenever it is
        // present, whatever else the profile's verdict says.
        if retired_udp_hop_present(&draft.profile) {
            ui.horizontal(|ui| {
                if ui.button(t(lang, Key::SrvRemoveUdpHopKey)).clicked() {
                    dismissed_retired_hop = true;
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
        let gate = draft.gate(&self.seeded_buffers, validating, busy);
        ui.horizontal(|ui| {
            outcome.validate = ui
                .add_enabled(
                    gate.committable() && !gate.validating && !gate.busy,
                    egui::Button::new(t(lang, Key::SrvValidateAndSave)),
                )
                .on_hover_text(t(lang, Key::SrvValidateAndSaveHint))
                .clicked();
            outcome.discard = ui
                .add_enabled(
                    gate.dirty() && !gate.validating,
                    egui::Button::new(t(lang, Key::SrvDiscardChanges)),
                )
                .clicked();
            if validating {
                ui.spinner();
                ui.weak(t(lang, Key::SrvValidatingXrayTest));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                outcome.close = ui.button(t(lang, Key::Close)).clicked();
            });
        });
        // Dismissing the retired key changes the draft without touching any
        // field: the next frame's sweep drops the finding, and the next save
        // writes the profile without the key.
        if dismissed_retired_key {
            draft.profile.outbound.retired_proxy_settings = None;
            self.draft_edited(draft);
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
            self.draft_edited(draft);
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
        target: Option<DraftTarget<'_>>,
        // The Basic tab's memoized inline outbound verdicts (the
        // public-endpoint TLS rules and the freedom blocks), rendered under
        // the protocol fields.
        inline_errors: &[String],
        // What the fields below mask: the credentials, and the server
        // information only while the settings ask for it.
        mask: widgets::Mask,
    ) -> bool {
        let mut changed = false;
        match &mut profile.outbound.settings {
            ProtocolSettings::Vless(settings) => {
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port, mask);
                let (field_changed, generate) = keygen_field(
                    ui,
                    t(lang, Key::SrvIdUuid),
                    &mut settings.id,
                    "",
                    |v| v_uuid_required(lang, v),
                    &KeygenButton {
                        label: t(lang, Key::Generate),
                        hover: t(lang, Key::SrvGenerateUuidHint),
                    },
                    mask.secrets,
                );
                changed |= field_changed;
                if generate {
                    self.request_tool(ui, lang, target, XrayToolKind::Uuid, vec!["uuid".into()]);
                }
                changed |= widgets::noted(ui, t(lang, Key::SrvVisionUdp443Note), |ui| {
                    widgets::combo_str_labeled(
                        ui,
                        "flow",
                        &mut settings.flow,
                        &VLESS_FLOW,
                        t(lang, Key::SrvDefault),
                        false,
                    )
                });
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
                let (field_changed, generate) = keygen_field(
                    ui,
                    "encryption",
                    &mut settings.encryption,
                    t(lang, Key::SrvVlessEncryptionHint),
                    |v| v_vless_encryption_required(lang, v),
                    &KeygenButton {
                        label: t(lang, Key::Generate),
                        hover: t(lang, Key::SrvGenerateVlessencHint),
                    },
                    // The generated encryption string configures the protocol
                    // variant; it is no credential.
                    false,
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
                        t(lang, Key::SrvVlessReverseTagHint),
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
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port, mask);
                let (field_changed, generate) = keygen_field(
                    ui,
                    t(lang, Key::SrvIdUuid),
                    &mut settings.id,
                    "",
                    |v| v_uuid_required(lang, v),
                    &KeygenButton {
                        label: t(lang, Key::Generate),
                        hover: t(lang, Key::SrvGenerateUuidHint),
                    },
                    mask.secrets,
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
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port, mask);
                changed |= widgets::masked_validated_field(
                    ui,
                    "password",
                    &mut settings.password,
                    "",
                    |v| v_required(lang, v),
                    mask.secrets,
                );
                changed |= widgets::opt_num(ui, "level", &mut settings.level, 0..=u32::MAX);
            }
            ProtocolSettings::Shadowsocks(settings) => {
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port, mask);
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
                changed |= widgets::masked_validated_field(
                    ui,
                    "password",
                    &mut settings.password,
                    t(lang, Key::SrvShadowsocksPasswordHint),
                    |v| v_required(lang, v),
                    mask.secrets,
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
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port, mask);
                changed |=
                    widgets::masked_text_field(ui, "user", &mut settings.user, "", mask.secrets);
                changed |=
                    widgets::masked_text_field(ui, "pass", &mut settings.pass, "", mask.secrets);
                changed |= widgets::opt_num(ui, "level", &mut settings.level, 0..=u32::MAX);
            }
            ProtocolSettings::Http(settings) => {
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port, mask);
                changed |=
                    widgets::masked_text_field(ui, "user", &mut settings.user, "", mask.secrets);
                changed |=
                    widgets::masked_text_field(ui, "pass", &mut settings.pass, "", mask.secrets);
                changed |= json_map_kv(
                    ui,
                    lang,
                    &mut settings.headers,
                    t(lang, Key::HeaderHint),
                    t(lang, Key::ValueHint),
                    &mut self.json_scratch,
                );
                changed |= widgets::opt_num(ui, "level", &mut settings.level, 0..=u32::MAX);
            }
            ProtocolSettings::Wireguard(settings) => {
                let (field_changed, generate) = keygen_field(
                    ui,
                    t(lang, Key::SrvSecretKey),
                    &mut settings.secret_key,
                    t(lang, Key::SrvSecretKeyHint),
                    |v| v_wg_secret_key(lang, v),
                    &KeygenButton {
                        label: t(lang, Key::Generate),
                        hover: t(lang, Key::SrvGenerateWgHint),
                    },
                    mask.secrets,
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
                // Every entry is validated as an address literal; the retired
                // `local` sentinel is refused like any other non-address entry.
                changed |= widgets::noted(ui, t(lang, Key::SrvWgRemoteDnsNote), |ui| {
                    widgets::validated_string_list(
                        ui,
                        lang,
                        t(lang, Key::SrvWgRemoteDns),
                        &mut settings.remote_dns,
                        t(lang, Key::SrvWgRemoteDnsHint),
                        |entry, _list_len| v_wg_remote_dns_entry(lang, entry),
                    )
                });
                let mut mtu = (settings.mtu != 0).then_some(settings.mtu);
                if widgets::opt_num(ui, "mtu", &mut mtu, 576..=1500) {
                    settings.mtu = mtu.unwrap_or_default();
                    changed = true;
                }
                // The retired `domainStrategy` key has no authoring control:
                // the pinned core deleted the field, so a stored value draws
                // the advisory here and a control that drops it on the next
                // commit. The advisory names the replacement (the stream
                // sockopt strategy).
                if !settings.domain_strategy.is_empty() {
                    ui.colored_label(
                        status_colors_of(ui).warn,
                        validation_message(&ValidationCode::WireguardDomainStrategyRetired, lang),
                    );
                    if ui
                        .button(t(lang, Key::SrvRemoveWgDomainStrategyKey))
                        .clicked()
                    {
                        settings.domain_strategy.clear();
                        changed = true;
                    }
                }
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
                                t(lang, Key::SrvWgPeerPublicKeyHint),
                                |v| v_wg_public_key(lang, v),
                            );
                            ui.small(t(lang, Key::SrvWgPeerPublicKeyNote));
                            changed |= widgets::masked_validated_field(
                                ui,
                                "endpoint",
                                &mut peer.endpoint,
                                "host:51820",
                                |v| v_required(lang, v),
                                mask.server_info,
                            );
                            changed |= widgets::masked_validated_field(
                                ui,
                                t(lang, Key::SrvPreSharedKey),
                                &mut peer.pre_shared_key,
                                "(optional)",
                                |v| v_optional_wg_key(lang, v),
                                mask.secrets,
                            );
                            changed |= widgets::string_list(
                                ui,
                                lang,
                                t(lang, Key::SrvWgAllowedIps),
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
                        t(lang, Key::SrvPacketsHint),
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
                            t(lang, Key::SrvBlackholeDataHint),
                            |value| {
                                if go_std_base64_decodes(value) {
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
                            changed |= widgets::text_field(
                                ui,
                                "qType",
                                &mut rule.q_type,
                                t(lang, Key::SrvDnsRuleQTypeHint),
                            );
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
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port, mask);
            }
            ProtocolSettings::Masque(settings) => {
                changed |= addr_port(ui, lang, &mut settings.address, &mut settings.port, mask);
                // Every entry is an address literal; a bad one refuses the
                // config at load (the model's `MasqueRemoteDnsInvalid`).
                changed |= widgets::validated_string_list(
                    ui,
                    lang,
                    t(lang, Key::SrvMasqueRemoteDns),
                    &mut settings.remote_dns,
                    "1.1.1.1",
                    |entry, _list_len| v_masque_remote_dns_entry(lang, entry),
                );
            }
        }
        // The Basic tab's inline rules render from the memoized validation
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
        target: Option<DraftTarget<'_>>,
        kind: XrayToolKind,
        args: Vec<String>,
    ) {
        let Some(target) = target else {
            self.set_status(StatusLine::err(t(lang, Key::SrvKeygenDraftOnly)));
            return;
        };
        if let Err(error) = self.queue_xray_tool(lang, ui.ctx().clone(), target.owned(), kind, args)
        {
            self.set_status(StatusLine::err(error));
        }
    }

    fn security_tab_for_target(
        &mut self,
        ui: &mut egui::Ui,
        lang: Language,
        target: Option<DraftTarget<'_>>,
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
        target: Option<DraftTarget<'_>>,
        depth: u32,
        lang: Language,
        download: &StreamModel,
    ) -> &str {
        // The cached key is compared in place — nothing is allocated on a
        // hit, and the header body runs every frame it stays open.
        let unchanged = match (target, self.over_limit_json.as_ref()) {
            (Some(target), Some(cached)) => {
                cached
                    .key
                    .as_ref()
                    .is_some_and(|(cached, cached_depth, _)| {
                        cached.matches(target) && *cached_depth == depth
                    })
            }
            _ => false,
        };
        if !unchanged {
            let text = serde_json::to_string_pretty(download)
                .unwrap_or_else(|error| t_fmt(lang, Key::SrvSerializationError, &[&error]));
            self.over_limit_json = Some(OverLimitJson {
                key: target.map(|target| (target.owned(), depth, lang)),
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
        ctx: TransportTabCtx<'_>,
    ) -> bool {
        let TransportTabCtx {
            target,
            masked,
            protocol,
            mut mux,
        } = ctx;
        let mut changed = false;
        ui.horizontal(|ui| {
            ui.label(t(lang, Key::SrvNetwork));
            // The selector's list is the model's own fact: a MASQUE outbound
            // offers only its handler's transport, VLESS every other
            // transport, and every other protocol the general set.
            for &n in Network::selectable_networks(protocol) {
                let allowed = st.can_select_network(n).is_ok();
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
                let response = match n {
                    Network::Grpc => response
                        .on_hover_text(t(lang, Key::SrvGrpcMuxNote))
                        .on_hover_text(t(lang, Key::SrvGrpcDeprecated)),
                    Network::Ws => response.on_hover_text(t(lang, Key::SrvWsDeprecated)),
                    Network::Httpupgrade => {
                        response.on_hover_text(t(lang, Key::SrvHttpupgradeDeprecated))
                    }
                    _ => response,
                };
                if response.clicked() && st.network != n && st.select_network(n).is_ok() {
                    // MASQUE runs only over TLS, so choosing its transport
                    // selects that security mode too rather than leaving a
                    // pair the model would refuse.
                    if n == Network::Masque {
                        let _ = st.select_security(Security::Tls);
                    }
                    // xdrive needs one mux connection; seeding the switch
                    // leaves the rest of the mux knobs editable.
                    if n == Network::Xdrive
                        && let Some(mux) = mux.as_deref_mut()
                    {
                        mux.enabled = true;
                    }
                    changed = true;
                }
            }
        });
        ui.separator();
        // The transport-security pair notice: one model verdict
        // (`transport_security_notice`), the same refusal the security
        // selector disables options with, so the two tabs cannot disagree.
        // Hysteria and MASQUE are repaired by selecting TLS, so their notice
        // carries the switch button; REALITY's conflict is with the transport
        // itself and keeps its label-only notice.
        if let Some(code) = st.transport_security_notice() {
            ui.horizontal(|ui| {
                ui.colored_label(status_colors_of(ui).err, validation_message(&code, lang));
                if code != ValidationCode::RealityRequiresTransport
                    && ui.small_button(t(lang, Key::SrvSwitchToTls)).clicked()
                    && st.select_security(Security::Tls).is_ok()
                {
                    changed = true;
                }
            });
        }
        match st.network {
            Network::Raw => {
                changed |= st.edit_raw(|s| {
                    let mut changed = false;
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
                                &mut self.json_scratch,
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
                                &mut self.json_scratch,
                            );
                        }
                    }
                    changed
                });
            }
            Network::Xhttp => {
                changed |= st.edit_xhttp(|s| {
                    let mut changed = false;
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
                            transport_headers(ui, lang, &mut s.headers, &mut self.json_scratch);
                    });
                    widgets::section(ui, t(lang, Key::SrvPadding), |ui| {
                        changed |= widgets::opt_range(
                            ui,
                            "xPaddingBytes",
                            &mut s.x_padding_bytes,
                            1..=4096,
                        );
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
                        changed |=
                            widgets::text_field(ui, "uplinkDataKey", &mut s.uplink_data_key, "");
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
                        changed |=
                            widgets::text_field(ui, "sessionIDKey", &mut s.session_id_key, "");
                        changed |=
                            widgets::text_field(ui, "sessionIDTable", &mut s.session_id_table, "");
                        changed |= widgets::opt_range(
                            ui,
                            "sessionIDLength",
                            &mut s.session_id_length,
                            1..=64,
                        );
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
                    changed |= xmux_section(ui, lang, &mut s.xmux);
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
                                        changed |= self.transport_tab(
                                            ui,
                                            lang,
                                            download,
                                            depth + 1,
                                            TransportTabCtx {
                                                target,
                                                masked,
                                                protocol,
                                                mux: None,
                                            },
                                        );
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
                    changed
                });
            }
            Network::Kcp => {
                changed |= st.edit_kcp(|s| {
                    let mut changed = false;
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
                    changed
                });
            }
            Network::Grpc => {
                changed |= st.edit_grpc(|s| {
                    let mut changed = false;
                    changed |= widgets::text_field(ui, "serviceName", &mut s.service_name, "grpc");
                    changed |=
                        widgets::text_field(ui, "authority", &mut s.authority, "example.com");
                    changed |= widgets::noted(ui, t(lang, Key::SrvGrpcMultiModeNote), |ui| {
                        widgets::opt_bool(
                            ui,
                            "multiMode",
                            &mut s.multi_mode,
                            t(lang, Key::SrvUnset),
                        )
                    });
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
                    changed
                });
            }
            Network::Ws => {
                changed |= st.edit_ws(|s| {
                    let mut changed = false;
                    changed |= widgets::text_field(ui, "host", &mut s.host, "example.com");
                    changed |= widgets::text_field(ui, "path", &mut s.path, "/?ed=2048");
                    changed |= websocket_transport_headers(ui, lang, s, &mut self.json_scratch);
                    changed |= widgets::opt_num(
                        ui,
                        t(lang, Key::SrvHeartbeatPeriodS),
                        &mut s.heartbeat_period,
                        0..=600,
                    );
                    changed
                });
            }
            Network::Httpupgrade => {
                changed |= st.edit_httpupgrade(|s| {
                    let mut changed = false;
                    changed |= widgets::text_field(ui, "host", &mut s.host, "example.com");
                    changed |= widgets::text_field(ui, "path", &mut s.path, "/?ed=2048");
                    changed |= transport_headers(ui, lang, &mut s.headers, &mut self.json_scratch);
                    changed
                });
            }
            Network::Hysteria => {
                changed |= st.edit_hysteria(|s| {
                    let mut changed = false;
                    if s.version != 2 {
                        ui.horizontal(|ui| {
                            ui.colored_label(
                                status_colors_of(ui).err,
                                t(lang, Key::SrvOnlyHysteria2),
                            );
                            if ui.small_button(t(lang, Key::SrvUseVersion2)).clicked() {
                                s.version = 2;
                                changed = true;
                            }
                        });
                    }
                    changed |= widgets::masked_text_field(
                        ui,
                        t(lang, Key::SrvAuthPassword),
                        &mut s.auth,
                        "",
                        masked,
                    );
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
                                changed |= widgets::text_field(
                                    ui,
                                    "url",
                                    &mut m.url,
                                    "https://example.com",
                                );
                                changed |= ui
                                    .checkbox(&mut m.rewrite_host, t(lang, Key::SrvRewriteHost))
                                    .changed();
                                changed |= ui
                                    .checkbox(&mut m.x_forwarded, t(lang, Key::SrvXForwarded))
                                    .changed();
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
                                    &mut self.json_scratch,
                                );
                                let mut sc = m.status_code;
                                if widgets::opt_num(
                                    ui,
                                    t(lang, Key::SrvStatusCode),
                                    &mut sc,
                                    100..=599,
                                ) {
                                    m.status_code = sc;
                                    changed = true;
                                }
                            }
                            _ => {}
                        }
                    }
                    changed
                });
            }
            Network::Masque => {
                changed |= st.edit_masque(|s| {
                    let mut changed = false;
                    // WARP changes both defaults the core applies: it replaces the
                    // host with `cloudflareaccess.com` and the path with `/`. The
                    // hints show the values the wire will carry, and the model's
                    // wire pass fills them in.
                    let default_host = if s.warp.is_some() {
                        crate::model::stream::MASQUE_WARP_HOST
                    } else {
                        "example.com"
                    };
                    let default_path = if s.warp.is_some() {
                        crate::model::stream::MASQUE_WARP_PATH
                    } else {
                        crate::model::stream::MASQUE_DEFAULT_PATH
                    };
                    changed |= widgets::text_field(ui, "host", &mut s.host, default_host);
                    // An unset path leaves the core's own default; the field hint
                    // shows that value, and only the two placeholders survive the
                    // model's `MasquePathInvalid` rule.
                    changed |= widgets::text_field(ui, "path", &mut s.path, default_path);
                    changed |= widgets::masked_text_field(ui, "user", &mut s.user, "", masked);
                    changed |= widgets::masked_text_field(ui, "pass", &mut s.pass, "", masked);
                    changed |= transport_headers(ui, lang, &mut s.headers, &mut self.json_scratch);
                    changed |= xmux_section(ui, lang, &mut s.xmux);
                    let mut has_warp = s.warp.is_some();
                    if ui
                        .checkbox(&mut has_warp, t(lang, Key::SrvMasqueWarp))
                        .changed()
                    {
                        s.warp = has_warp.then(MasqueWarp::default);
                        changed = true;
                    }
                    let credentials = !s.user.is_empty() || !s.pass.is_empty();
                    if let Some(warp) = s.warp.as_mut() {
                        if credentials {
                            ui.colored_label(
                                status_colors_of(ui).err,
                                validation_message(
                                    &ValidationCode::MasqueWarpCredentialsConflict,
                                    lang,
                                ),
                            );
                        }
                        changed |= widgets::masked_validated_multiline(
                            ui,
                            t(lang, Key::SrvMasqueWarpPrivateKey),
                            &mut warp.private_key,
                            "",
                            4,
                            |value| v_masque_warp_private_key(lang, value),
                            masked,
                        );
                        changed |= widgets::masked_validated_multiline(
                            ui,
                            t(lang, Key::SrvMasqueWarpPublicKey),
                            &mut warp.public_key,
                            "",
                            4,
                            |value| v_masque_warp_public_key(lang, value),
                            masked,
                        );
                        // One entry can be IPv4 or IPv6; a second must be the
                        // other family. The row rule judges one entry, and the
                        // list rule — the same one the model pass reads — reports
                        // the count and family rule under the list.
                        changed |= widgets::validated_string_list(
                            ui,
                            lang,
                            t(lang, Key::SrvMasqueWarpAddresses),
                            &mut warp.address,
                            "172.16.0.2",
                            |entry, _list_len| v_masque_warp_address_entry(lang, entry),
                        );
                        if let Some(code) = masque_warp_address_list_verdict(&warp.address) {
                            ui.colored_label(
                                status_colors_of(ui).err,
                                validation_message(&code, lang),
                            );
                        }
                    }
                    changed
                });
            }
            Network::Xdrive => {
                changed |= st.edit_xdrive(|s| {
                    let mut changed = false;
                    changed |= widgets::combo_str_labeled(
                        ui,
                        t(lang, Key::SrvXdriveService),
                        &mut s.service,
                        XDRIVE_SERVICES,
                        t(lang, Key::SrvXdriveServiceUnset),
                        false,
                    );
                    // The service decides what the folder names, so the hint
                    // follows the choice and the field is required exactly where
                    // the core refuses an empty one at start.
                    let folder_hint = match s.service.as_str() {
                        XDRIVE_SERVICE_LOCAL => t(lang, Key::SrvXdriveFolderLocalHint),
                        XDRIVE_SERVICE_DRIVE => t(lang, Key::SrvXdriveFolderDriveHint),
                        XDRIVE_SERVICE_TEMPLATE => t(lang, Key::SrvXdriveFolderTemplateHint),
                        XDRIVE_SERVICE_S3 => t(lang, Key::SrvXdriveFolderS3Hint),
                        _ => "",
                    };
                    let folder_required = xdrive_folder_required(&s.service);
                    let folder_validate = |folder: &str| {
                        (folder_required && folder.is_empty()).then(|| {
                            validation_message(&ValidationCode::XdriveRemoteFolderRequired, lang)
                        })
                    };
                    // The local service is the one that names a directory on this
                    // machine — the one folder whose format the user cannot guess
                    // — so it gets the picker. The Drive folder id and the
                    // template token are opaque to the outside, and the button
                    // comes and goes with the service chosen above.
                    let mut pick_folder = |ui: &mut egui::Ui| -> Option<String> {
                        if !ui.small_button(t(lang, Key::SrvBrowse)).clicked() {
                            return None;
                        }
                        rfd::FileDialog::new()
                            .pick_folder()
                            .map(|folder| folder.to_string_lossy().into_owned())
                    };
                    let folder_picker: Option<widgets::Trailing<'_>> =
                        (s.service == XDRIVE_SERVICE_LOCAL).then_some(&mut pick_folder);
                    changed |= widgets::validated_field_with_trailing(
                        ui,
                        t(lang, Key::SrvXdriveRemoteFolder),
                        &mut s.remote_folder,
                        folder_hint,
                        folder_validate,
                        folder_picker,
                    );
                    changed |= widgets::masked_string_list(
                        ui,
                        lang,
                        t(lang, Key::SrvXdriveSecrets),
                        &mut s.secrets,
                        "",
                        masked,
                    );
                    match s.service.as_str() {
                        XDRIVE_SERVICE_DRIVE => {
                            ui.weak(t(lang, Key::SrvXdriveSecretsOrder));
                            // The core's conf build refuses any count but
                            // three, so the editor says so where the rows are.
                            if s.secrets.len() != 3 {
                                ui.colored_label(
                                    status_colors_of(ui).err,
                                    validation_message(
                                        &ValidationCode::XdriveDriveSecretsInvalid,
                                        lang,
                                    ),
                                );
                            }
                        }
                        XDRIVE_SERVICE_S3 => {
                            ui.weak(t(lang, Key::SrvXdriveSecretsOrderS3));
                            // The backend needs the access key and the secret
                            // access key, and accepts one session token.
                            if !(2..=3).contains(&s.secrets.len()) {
                                ui.colored_label(
                                    status_colors_of(ui).err,
                                    validation_message(
                                        &ValidationCode::XdriveS3SecretsInvalid,
                                        lang,
                                    ),
                                );
                            }
                        }
                        _ => {}
                    }
                    changed |= xdrive_scalar(
                        ui,
                        lang,
                        t(lang, Key::SrvXdriveSegmentBytes),
                        &mut s.segment_bytes,
                        XDRIVE_MAX_SEGMENT_BYTES,
                        XDRIVE_DEFAULT_SEGMENT_BYTES,
                    );
                    changed |= xdrive_scalar(
                        ui,
                        lang,
                        t(lang, Key::SrvXdriveFlushInterval),
                        &mut s.flush_interval_ms,
                        u32::MAX,
                        XDRIVE_DEFAULT_FLUSH_INTERVAL_MS,
                    );
                    changed |= xdrive_scalar(
                        ui,
                        lang,
                        t(lang, Key::SrvXdrivePollInterval),
                        &mut s.poll_interval_ms,
                        u32::MAX,
                        XDRIVE_DEFAULT_POLL_INTERVAL_MS,
                    );
                    changed |= xdrive_scalar(
                        ui,
                        lang,
                        t(lang, Key::SrvXdriveMaxPollInterval),
                        &mut s.max_poll_interval_ms,
                        u32::MAX,
                        XDRIVE_DEFAULT_MAX_POLL_INTERVAL_MS,
                    );
                    // The core raises a max poll interval below the min poll
                    // interval (transport/internet/xdrive/params.go:65-67); the
                    // model warns for the same pair, so the editor shows it here
                    // where both fields are visible.
                    let effective =
                        |value: u32, default: u32| if value == 0 { default } else { value };
                    if effective(s.max_poll_interval_ms, XDRIVE_DEFAULT_MAX_POLL_INTERVAL_MS)
                        < effective(s.poll_interval_ms, XDRIVE_DEFAULT_POLL_INTERVAL_MS)
                    {
                        ui.colored_label(
                            status_colors_of(ui).warn,
                            validation_message(&ValidationCode::XdriveScalarClamped, lang),
                        );
                    }
                    changed |= xdrive_scalar(
                        ui,
                        lang,
                        t(lang, Key::SrvXdriveSessionTtl),
                        &mut s.session_ttl_seconds,
                        u32::MAX,
                        XDRIVE_DEFAULT_SESSION_TTL_SECONDS,
                    );
                    changed |= xdrive_scalar(
                        ui,
                        lang,
                        t(lang, Key::SrvXdriveConcurrency),
                        &mut s.concurrency,
                        XDRIVE_MAX_CONCURRENCY,
                        XDRIVE_DEFAULT_CONCURRENCY,
                    );
                    changed |= xdrive_scalar(
                        ui,
                        lang,
                        t(lang, Key::SrvXdriveEagerWindow),
                        &mut s.eager_window_ms,
                        u32::MAX,
                        XDRIVE_DEFAULT_EAGER_WINDOW_MS,
                    );
                    changed |= xdrive_scalar(
                        ui,
                        lang,
                        t(lang, Key::SrvXdriveHoleTimeout),
                        &mut s.hole_timeout_ms,
                        u32::MAX,
                        XDRIVE_DEFAULT_HOLE_TIMEOUT_MS,
                    );
                    // The one configuration that writes outside the app's own
                    // state, so the user sees the warning where they type the
                    // path; the apply gate asks for the same acknowledgment.
                    if s.service == XDRIVE_SERVICE_LOCAL && !s.remote_folder.is_empty() {
                        ui.colored_label(
                            status_colors_of(ui).warn,
                            t(lang, Key::SrvXdriveLocalWarning),
                        );
                    }
                    if s.service == XDRIVE_SERVICE_TEMPLATE {
                        let had_template = s.template.is_some();
                        let mut template = s.template.take().unwrap_or_default();
                        if self.xdrive_template_editor(
                            ui,
                            lang,
                            &mut template,
                            s.secrets.len(),
                            masked,
                        ) {
                            changed = true;
                        }
                        if had_template || changed {
                            s.template = Some(template);
                        }
                    }
                    // The s3 backend is four fields, and its object is
                    // created the first time one of them is edited: a fresh
                    // draft has no block until the user states it.
                    if s.service == XDRIVE_SERVICE_S3 {
                        let had_s3 = s.s3.is_some();
                        let mut s3 = s.s3.take().unwrap_or_default();
                        let mut edited = false;
                        widgets::section(ui, t(lang, Key::SrvXdriveS3Section), |ui| {
                            edited |= widgets::text_field(
                                ui,
                                t(lang, Key::SrvXdriveS3Endpoint),
                                &mut s3.endpoint,
                                "https://s3.example.com",
                            );
                            edited |= widgets::text_field(
                                ui,
                                t(lang, Key::SrvXdriveS3Region),
                                &mut s3.region,
                                "us-east-1",
                            );
                            edited |= widgets::text_field(
                                ui,
                                t(lang, Key::SrvXdriveS3Bucket),
                                &mut s3.bucket,
                                "bucket",
                            );
                            // The wire key is a pointer and the loader reads
                            // an absent one as path-style, so the box shows
                            // that default until the user changes it.
                            let mut path_style = s3.path_style();
                            if ui
                                .checkbox(&mut path_style, t(lang, Key::SrvXdriveS3PathStyle))
                                .on_hover_text(t(lang, Key::SrvXdriveS3PathStyleNote))
                                .changed()
                            {
                                s3.path_style = Some(path_style);
                                edited = true;
                            }
                        });
                        if edited {
                            changed = true;
                        }
                        if had_s3 || edited {
                            s.s3 = Some(s3);
                        }
                    }
                    changed |= xmux_section(ui, lang, &mut s.xmux);
                    changed
                });
            }
        }
        changed
    }

    /// The xdrive template backend's editor: the authorization, the four
    /// operations and the retry rules as fields, never a raw JSON box. Each
    /// site that substitutes a variable lists the variables the runtime
    /// expands there, so what the template sends is visible before the value
    /// leaves the app.
    fn xdrive_template_editor(
        &mut self,
        ui: &mut egui::Ui,
        lang: Language,
        template: &mut XdriveTemplate,
        secret_count: usize,
        // Whether the template's credentials render masked (the reveal
        // control).
        masked: bool,
    ) -> bool {
        let mut changed = false;
        widgets::section(ui, t(lang, Key::SrvXdriveTemplate), |ui| {
            changed |= ui
                .checkbox(&mut template.flatten, t(lang, Key::SrvXdriveFlatten))
                .changed();
            changed |= xdrive_scalar(
                ui,
                lang,
                t(lang, Key::SrvXdriveConcurrency),
                &mut template.concurrency,
                XDRIVE_TEMPLATE_MAX_CONCURRENCY,
                XDRIVE_TEMPLATE_DEFAULT_CONCURRENCY,
            );
        });
        widgets::section(ui, t(lang, Key::SrvXdriveAuth), |ui| {
            changed |= self.xdrive_auth_editor(ui, lang, &mut template.auth, secret_count, masked);
        });
        for op in XdriveOperation::ALL {
            let title = match op {
                XdriveOperation::Put => t(lang, Key::SrvXdrivePut),
                XdriveOperation::Get => t(lang, Key::SrvXdriveGet),
                XdriveOperation::Delete => t(lang, Key::SrvXdriveDelete),
                XdriveOperation::List => t(lang, Key::SrvXdriveList),
            };
            let variables = template.substitution_variables(op, secret_count);
            ui.push_id(op.as_str(), |ui| {
                ui.strong(title);
                changed |= self.xdrive_operation_editor(
                    ui,
                    lang,
                    op.as_str(),
                    template.operation_mut(op),
                    &variables,
                    op == XdriveOperation::List,
                );
            });
        }
        widgets::section(ui, t(lang, Key::SrvXdriveRetry), |ui| {
            ui.label(t(lang, Key::SrvXdriveRetryStatus));
            changed |= xdrive_status_list(ui, lang, &mut template.retry.status);
            changed |= widgets::text_field(
                ui,
                t(lang, Key::SrvXdriveRateReason),
                &mut template.retry.rate_reason,
                "",
            );
        });
        changed
    }

    /// One template operation: method, URL, headers and body, plus the list
    /// operation's capture pattern. The URL is required — the runtime refuses
    /// the storage without it — so the field carries the model's verdict.
    fn xdrive_operation_editor(
        &mut self,
        ui: &mut egui::Ui,
        lang: Language,
        name: &'static str,
        op: &mut XdriveTemplateOp,
        variables: &[String],
        list_operation: bool,
    ) -> bool {
        let mut changed = false;
        changed |= widgets::text_field(ui, t(lang, Key::HttpMethod), &mut op.method, "GET");
        changed |= widgets::validated_field(
            ui,
            t(lang, Key::Url),
            &mut op.url,
            t(lang, Key::UrlHint),
            |url| {
                url.is_empty().then(|| {
                    validation_message(
                        &ValidationCode::XdriveTemplateOperationUrlRequired(name.into()),
                        lang,
                    )
                })
            },
        );
        ui.push_id("headers", |ui| {
            changed |= json_map_kv(
                ui,
                lang,
                &mut op.headers,
                t(lang, Key::HeadersKeyHint),
                t(lang, Key::HeadersValueHint),
                &mut self.json_scratch,
            );
        });
        if list_operation {
            changed |= widgets::validated_field(
                ui,
                t(lang, Key::SrvXdriveNamesRegex),
                &mut op.names_regex,
                "name",
                |pattern| {
                    (!crate::model::stream::xdrive_names_regex_supported(pattern)).then(|| {
                        validation_message(&ValidationCode::XdriveTemplateNamesRegexInvalid, lang)
                    })
                },
            );
        }
        changed |= widgets::text_field(ui, t(lang, Key::SrvXdriveBody), &mut op.body, "");
        // Where the variables land: the runtime substitutes them in this
        // operation's URL, headers and body.
        ui.weak(t_fmt(
            lang,
            Key::SrvXdriveSubstitutions,
            &[&variables.join(" ")],
        ));
        changed
    }

    /// The template authorization: a type choice with the fields that type
    /// uses — static headers, the token flow (URL, form, token path, expiry
    /// path) or basic credentials.
    fn xdrive_auth_editor(
        &mut self,
        ui: &mut egui::Ui,
        lang: Language,
        auth: &mut XdriveTemplateAuth,
        secret_count: usize,
        // Whether the authorization's username and password render masked
        // (the reveal control). The token URL stays visible: it names its host,
        // and masking a URL would hide the host with the token.
        masked: bool,
    ) -> bool {
        let mut changed = false;
        changed |= widgets::combo_str_labeled(
            ui,
            t(lang, Key::SrvXdriveAuth),
            &mut auth.r#type,
            XDRIVE_TEMPLATE_AUTH_TYPES,
            t(lang, Key::SrvDefault),
            true,
        );
        let mut variables: Vec<String> = vec!["{folder}".into()];
        for index in 0..secret_count {
            variables.push(format!("{{secret{index}}}"));
        }
        match auth.r#type.as_str() {
            "static" | "oauth2" => {
                ui.push_id("authHeaders", |ui| {
                    changed |= json_map_kv(
                        ui,
                        lang,
                        &mut auth.header,
                        t(lang, Key::HeadersKeyHint),
                        t(lang, Key::HeadersValueHint),
                        &mut self.json_scratch,
                    );
                });
                if auth.r#type == "oauth2" {
                    variables.push("{token}".into());
                    changed |= widgets::validated_field(
                        ui,
                        t(lang, Key::SrvXdriveTokenUrl),
                        &mut auth.token_url,
                        t(lang, Key::UrlHint),
                        |url| {
                            url.is_empty().then(|| {
                                validation_message(
                                    &ValidationCode::XdriveTemplateTokenUrlRequired,
                                    lang,
                                )
                            })
                        },
                    );
                    ui.push_id("authForm", |ui| {
                        changed |= json_map_kv(
                            ui,
                            lang,
                            &mut auth.form,
                            t(lang, Key::HeaderHint),
                            t(lang, Key::ValueHint),
                            &mut self.json_scratch,
                        );
                    });
                    changed |= widgets::text_field(
                        ui,
                        t(lang, Key::SrvXdriveTokenPath),
                        &mut auth.token_path,
                        "access_token",
                    );
                    changed |= widgets::text_field(
                        ui,
                        t(lang, Key::SrvXdriveExpiryPath),
                        &mut auth.expiry_path,
                        "",
                    );
                }
            }
            "basic" => {
                changed |= widgets::masked_text_field(
                    ui,
                    t(lang, Key::SrvXdriveUsername),
                    &mut auth.username,
                    "",
                    masked,
                );
                changed |= widgets::masked_text_field(
                    ui,
                    t(lang, Key::SrvXdrivePassword),
                    &mut auth.password,
                    "",
                    masked,
                );
            }
            _ => {}
        }
        if !variables.is_empty() {
            ui.weak(t_fmt(
                lang,
                Key::SrvXdriveSubstitutions,
                &[&variables.join(" ")],
            ));
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
        target: Option<DraftTarget<'_>>,
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
        // The transport-security pair notice: the model's own verdict for the
        // pair the stream currently carries, so the label, the selector's
        // disabled options and `select_security` all read one rule.
        if let Some(code) = st.transport_security_notice() {
            ui.colored_label(status_colors_of(ui).err, validation_message(&code, lang));
        }
        ui.horizontal(|ui| {
            ui.label(t(lang, Key::SrvSecurity));
            for sec in [Security::None, Security::Tls, Security::Reality] {
                let label = match sec {
                    Security::None => "none",
                    Security::Tls => "tls",
                    Security::Reality => "reality",
                };
                // The selector's disabled state is the model's refusal, not a
                // second copy of the pair predicates.
                let refusal = st.can_select_security(sec).err();
                let response = ui
                    .add_enabled_ui(refusal.is_none(), |ui| {
                        ui.selectable_label(st.security == sec, label)
                    })
                    .inner;
                let response = match refusal {
                    Some(code) => response.on_disabled_hover_text(validation_message(&code, lang)),
                    None => response,
                };
                if response.clicked() && st.security != sec && st.select_security(sec).is_ok() {
                    changed = true;
                }
            }
        });
        ui.separator();
        match st.security {
            Security::Tls => {
                // The MASQUE ALPN advisory is the model's warning
                // (`masque_alpn_prefers_http3`, reported by
                // `validate_masque_stream`), read before the settings block is
                // taken out of the stream below.
                let alpn_warning = st
                    .masque_alpn_prefers_http3()
                    .then(|| validation_message(&ValidationCode::MasqueAlpnPrefersHttp3, lang));
                let had_settings = st.tls_settings.is_some();
                let mut s = st.tls_settings.take().unwrap_or_default();
                let tool_working = self.tool_job.is_some();
                changed |= tls_editor::tls_fields_editor(
                    ui,
                    lang,
                    &mut s,
                    ValidationCode::TlsFingerprintUnsupported,
                    alpn_warning.as_deref(),
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
                            &mut self.probe_for_target(target).domain,
                            t(lang, Key::SrvTlsProbeDomainHint),
                        );
                        let _ = widgets::text_field(
                            ui,
                            t(lang, Key::SrvTlsProbeIpOverride),
                            &mut self.probe_for_target(target).ip,
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
                                self.probe_for_target(target).domain = s.server_name.clone();
                            }
                            if let Some(address) = server_address
                                && ui.small_button(t(lang, Key::SrvUseServerAddress)).clicked()
                            {
                                // A fill re-targets the probe: replace the
                                // domain and drop a stale IP override so the
                                // next handshake dials exactly this address.
                                let probe = self.probe_for_target(target);
                                probe.domain = address.to_owned();
                                probe.ip.clear();
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
                            let probe = self.probe_for_target(target);
                            probe.handshake_ok = false;
                            probe.profile = None;
                            let domain = probe.domain.trim().to_string();
                            let ip = probe.ip.trim().to_string();
                            if domain.is_empty() {
                                self.probe_for_target(target).error =
                                    Some(t(lang, Key::SrvTlsProbeDomainRequired).into());
                            } else if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_err() {
                                self.probe_for_target(target).error =
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
                            let probe = self.probe_for_target(target);
                            probe.handshake_ok = false;
                            probe.profile = None;
                            let domain = probe.domain.trim().to_string();
                            let ip = probe.ip.trim().to_string();
                            if domain.is_empty() {
                                self.probe_for_target(target).error =
                                    Some(t(lang, Key::SrvTlsProbeDomainRequired).into());
                            } else if !ip.is_empty() && ip.parse::<std::net::IpAddr>().is_err() {
                                self.probe_for_target(target).error =
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
                        // The pins belong to the draft whose own probe produced
                        // them: a nested or read-only rendering of this tab has
                        // no draft of its own, so it never shows a pin.
                        let probe = &self
                            .slot(target.map_or(DraftKind::Existing, |target| target.kind))
                            .probe;
                        let pins_are_this_draft = probe.handshake_ok
                            && probe.profile.as_deref() == target.map(|target| target.profile_id);
                        if pins_are_this_draft {
                            match probe.leaf_pin.as_deref() {
                                Some(pin) => {
                                    let mut apply_clicked = false;
                                    ui.horizontal(|ui| {
                                        ui.label(t(lang, Key::SrvLeafPin));
                                        if ui.small_button(t(lang, Key::SrvCopyPin)).clicked() {
                                            ui.ctx().copy_text(pin.to_owned());
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
                                    if !probe.ca_pins.is_empty() {
                                        ui.label(t(lang, Key::SrvCaPins));
                                        for (name, ca_pin) in &probe.ca_pins {
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
                                        let pin = pin.to_owned();
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
                if let Some(error) = &self.probe_for_target(target).error {
                    ui.colored_label(status_colors_of(ui).err, error);
                }
                if self.probe_for_target(target).output.is_some()
                    && ui.small_button(t(lang, Key::SrvShowProbeOutput)).clicked()
                {
                    self.probe_for_target(target).show_output = true;
                }
                // The profile id is part of the certificate widgets' id salt,
                // so their seeded PEM editor buffers re-seed when the draft
                // switches to another profile.
                let profile_id = target.map_or("", |target| target.profile_id);
                changed |= tls_editor::tls_connection_editor(
                    ui,
                    lang,
                    &mut s,
                    profile_id,
                    &mut self.seeded_buffers,
                    ech_sockopt_errors,
                );
                if had_settings || changed {
                    st.tls_settings = Some(s);
                }
            }
            Security::Reality => {
                let had_settings = st.reality_settings.is_some();
                let mut s = st.reality_settings.take().unwrap_or_default();
                changed |= widgets::noted(ui, t(lang, Key::SrvRealityServerNameEmptyNote), |ui| {
                    widgets::text_field(
                        ui,
                        t(lang, Key::SrvServerNameTarget),
                        &mut s.server_name,
                        "example.com",
                    )
                });
                // Warn inline at the field when
                // the value cannot plausibly be a hostname (mirrors the TLS
                // block above). Empty stays untouched (out of scope).
                if server_name_implausible(&s.server_name) {
                    ui.colored_label(
                        status_colors_of(ui).warn,
                        validation_message(&ValidationCode::ServerNameImplausible, lang),
                    );
                }
                changed |= widgets::noted(ui, t(lang, Key::SrvRealityFingerprintNote), |ui| {
                    fingerprint_editor(
                        ui,
                        lang,
                        &mut s.fingerprint,
                        ValidationCode::RealityFingerprintUnsupported,
                    )
                });
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
                    t(lang, Key::SrvRealityPublicKeyHint),
                    |_| None,
                    &KeygenButton {
                        label: t(lang, Key::SrvDerive),
                        hover: "xray x25519 -i <private key>",
                    },
                    // The REALITY key fields are public identifiers the
                    // handshake exchanges in the clear; they are no credential.
                    false,
                );
                changed |= c;
                if g {
                    if let Some(target) = target {
                        self.derive_dialog = Some(DeriveDialog {
                            target: target.owned(),
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
                    t(lang, Key::SrvShortIdHint),
                    |_| None,
                    &KeygenButton {
                        label: t(lang, Key::Generate),
                        hover: t(lang, Key::SrvRandomHexHint),
                    },
                    // A REALITY key field: public, not a credential.
                    false,
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
                    t(lang, Key::SrvMldsa65VerifyHint),
                    |_| None,
                    &KeygenButton {
                        label: t(lang, Key::Generate),
                        hover: t(lang, Key::SrvGenerateMldsa65Hint),
                    },
                    // A REALITY key field: public, not a credential.
                    false,
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
            Security::None => {}
        }
        changed
    }

    // ---------- Advanced tab ----------

    /// One finalmask list: the kind's rows, the reorder/remove application,
    /// and the add button — the chrome both mask kinds share.
    fn finalmask_mask_list<M>(
        ui: &mut egui::Ui,
        lang: Language,
        spec: &MaskListSpec<'_>,
        kind: &MaskKind<M>,
        masks: &mut Vec<M>,
        buffers: &mut SeededBuffers,
    ) -> bool {
        ui.heading(t(lang, spec.heading));
        ui.weak(t(lang, spec.note));
        let len = masks.len();
        let mut remove = None;
        let mut move_to = None;
        let mut changed = false;
        for (index, mask) in masks.iter_mut().enumerate() {
            ui.push_id((spec.group, spec.profile, index), |ui| {
                ui.group(|ui| {
                    let known = (kind.known_type)(mask);
                    // Known masks display their &'static type name — no
                    // per-frame allocation; the translated placeholder is
                    // built only for unknown envelopes.
                    let selected: std::borrow::Cow<'static, str> = match known {
                        Some(kind) => std::borrow::Cow::Borrowed(kind),
                        None => std::borrow::Cow::Owned(t_fmt(
                            lang,
                            Key::SrvUnknownType,
                            &[&(kind.discriminator)(mask).unwrap_or(t(lang, Key::SrvMissingType))],
                        )),
                    };
                    let mut picked: Option<&'static str> = None;
                    ui.horizontal(|ui| {
                        ui.label(t_fmt(lang, spec.ordinal, &[&(index + 1)]));
                        egui::ComboBox::from_id_salt("type")
                            .selected_text(selected.as_ref())
                            .show_ui(ui, |ui| {
                                for candidate in (kind.outbound_types)() {
                                    if ui
                                        .selectable_label(known == Some(candidate), candidate)
                                        .clicked()
                                    {
                                        picked = Some(candidate);
                                    }
                                }
                                if known.is_none() {
                                    // Keep-the-unknown row: clicking it must
                                    // not replace the unknown envelope with a
                                    // known type.
                                    ui.selectable_label(true, selected.as_ref()).clicked();
                                }
                            });
                        finalmask_move_buttons(ui, lang, index, len, &mut move_to, &mut remove);
                    });
                    if picked != known
                        && let Some(replacement) = picked.and_then(kind.from_known_type)
                    {
                        *mask = replacement;
                        changed = true;
                    }
                    changed |= (kind.edit_settings)(
                        ui,
                        lang,
                        mask,
                        RawField {
                            id: FieldKey {
                                key: egui::Id::unique(("fm", spec.profile, spec.tag, index)),
                                profile: spec.profile,
                            },
                            buffers: &mut *buffers,
                        },
                        spec.masked,
                        spec.revision,
                    );
                });
            });
        }
        if let Some((from, to)) = move_to {
            masks.swap(from, to);
            changed = true;
        }
        if let Some(index) = remove {
            masks.remove(index);
            changed = true;
        }
        if ui.button(t(lang, spec.add_label)).clicked() {
            masks.push(
                (kind.from_known_type)("header-custom").expect("registered finalmask mask type"),
            );
            changed = true;
        }
        changed
    }

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
            buffers,
            masked,
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
                t(lang, Key::SrvSendThroughHint),
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

            changed |= Self::finalmask_mask_list(
                ui,
                lang,
                &MaskListSpec {
                    group: "finalmask-tcp",
                    tag: "tcp",
                    profile: key,
                    heading: Key::SrvTcpMasks,
                    note: Key::SrvTcpMaskOrderNote,
                    ordinal: Key::SrvTcpN,
                    add_label: Key::SrvAddTcpMask,
                    masked,
                    revision: set_key.0,
                },
                &tcp_mask_kind(),
                &mut fm.tcp,
                buffers,
            );

            ui.separator();
            changed |= Self::finalmask_mask_list(
                ui,
                lang,
                &MaskListSpec {
                    group: "finalmask-udp",
                    tag: "udp",
                    profile: key,
                    heading: Key::SrvUdpMasks,
                    note: Key::SrvUdpMaskOrderNote,
                    ordinal: Key::SrvUdpN,
                    add_label: Key::SrvAddUdpMask,
                    masked,
                    revision: set_key.0,
                },
                &udp_mask_kind(),
                &mut fm.udp,
                buffers,
            );

            ui.separator();
            changed |= finalmask_quic_editor(ui, lang, "quicParams", &mut fm.quic_params);
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

    fn show_add_draft(&mut self, ctx: &egui::Context, uictx: &mut ServersCtx) {
        let Some(mut draft) = self.add.take() else {
            return;
        };
        let lang = uictx.settings.language;
        let validating = self.profile_validation_in_progress(ProfileValidationOrigin::Draft);
        let core_busy = uictx.busy.is_held();
        let mut validate_clicked = false;
        let mut cancel = false;
        let mut leave_decision: Option<LeaveDecision> = None;
        // The question this window asks about itself is still a question about
        // the app's state, so the main window stays behind it the way it is
        // behind any other confirmation: this window is a sibling of the main
        // window, so the question's own modal cannot reach across to it. A
        // backend with no windows to give renders both in one context, where
        // the question's own modal already covers the window it dims.
        let backdrop_dismissed = self.add_close_is_staged()
            && !ctx.embed_viewports()
            && popup::backdrop(ctx, "servers.leave.add-draft");
        let close_requested = popup::show(
            ctx,
            "servers.add-draft",
            t(lang, Key::SrvAddServerWindow),
            [680.0, 600.0],
            true,
            |ui| {
                // The validation blocks inside render from the draft's memoized
                // verdicts, so refresh before the content: a fresh dialog, a tool
                // application, or a language switch renders same-frame accurate
                // verdicts.
                draft.refresh(lang);
                ui.add_enabled_ui(!validating, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(t(lang, Key::SrvName));
                        ui.add(
                            egui::TextEdit::singleline(&mut draft.profile.name)
                                .desired_width(260.0),
                        );
                        ui.separator();
                        ui.label(t(lang, Key::SrvGroup));
                        if group_picker(ui, uictx.servers, &mut draft.profile) {
                            draft.edited();
                        }
                        ui.separator();
                        ui.label(t(lang, Key::SrvProtocol));
                        ui.monospace(draft.profile.outbound.protocol.as_str());
                    });
                    ui.separator();
                    ui.horizontal(|ui| {
                        for &tab in TABS {
                            ui.selectable_value(&mut self.draft_tab, tab, tab.label(lang));
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            widgets::reveal_toggle(ui, lang, &mut self.revealed_add);
                        });
                    });
                    // The dialog opens revealed (an empty form hides nothing), so
                    // this is what the dialog masks while the user hides it again.
                    let mask = widgets::Mask {
                        secrets: !self.revealed_add,
                        server_info: !self.revealed_add && uictx.settings.hide_server_info,
                    };
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .id_salt("servers.add-draft.scroll")
                        .max_height(430.0)
                        .show(ui, |ui| {
                            // The borrowed identity the tabs below take, built from
                            // the draft's own fields (see [`DraftTarget`]) inside
                            // the frame that renders them: the change protocol after
                            // the tabs mutates the draft as a whole, so the borrow
                            // of its id ends with the tab that reads it.
                            let target = DraftTarget {
                                kind: DraftKind::Add,
                                profile_id: draft.id.as_str(),
                                generation: draft.generation,
                            };
                            let changed = match self.draft_tab {
                                EditorTab::Basic => {
                                    let inline_errors: &[String] = draft
                                        .validation
                                        .as_ref()
                                        .map(|cached| cached.rendered.basic_inline.as_slice())
                                        .unwrap_or(&[]);
                                    self.basic_tab_for_target(
                                        ui,
                                        lang,
                                        &mut draft.profile,
                                        Some(target),
                                        inline_errors,
                                        mask,
                                    )
                                }
                                EditorTab::Transport => {
                                    let OutboundModel {
                                        protocol,
                                        stream,
                                        mux,
                                        ..
                                    } = &mut draft.profile.outbound;
                                    self.transport_tab(
                                        ui,
                                        lang,
                                        stream,
                                        0,
                                        TransportTabCtx {
                                            target: Some(target),
                                            masked: mask.secrets,
                                            protocol: *protocol,
                                            mux: Some(mux),
                                        },
                                    )
                                }
                                EditorTab::Security => {
                                    let address = draft.profile.server_address();
                                    let ech_sockopt_errors: &[String] = draft
                                        .validation
                                        .as_ref()
                                        .map(|cached| cached.rendered.ech_sockopt.as_slice())
                                        .unwrap_or(&[]);
                                    self.security_tab_for_target(
                                        ui,
                                        lang,
                                        Some(target),
                                        &mut draft.profile.outbound.stream,
                                        address.as_deref(),
                                        ech_sockopt_errors,
                                    )
                                }
                                EditorTab::Mux => {
                                    let flow = vless_flow(&draft.profile.outbound.settings);
                                    mux_tab(ui, lang, &mut draft.profile.outbound.mux, flow)
                                }
                                EditorTab::Advanced => {
                                    // The inline finalmask and sockopt verdicts
                                    // ride the draft's memoized validation
                                    // (refreshed above whenever the draft
                                    // generation or language moved): identical
                                    // messages, zero re-validation on idle
                                    // frames.
                                    let finalmask_errors: &[String] = draft
                                        .validation
                                        .as_ref()
                                        .map(|cached| cached.rendered.finalmask.as_slice())
                                        .unwrap_or(&[]);
                                    let stream_sockopt_errors: &[String] = draft
                                        .validation
                                        .as_ref()
                                        .map(|cached| cached.rendered.stream_sockopt.as_slice())
                                        .unwrap_or(&[]);
                                    ServersScreen::advanced_tab(
                                        ui,
                                        lang,
                                        &mut draft.profile,
                                        &uictx.servers.profiles,
                                        AdvancedTabCtx {
                                            set_key: (
                                                uictx.hooks.model_generation(),
                                                uictx.servers.profiles.len(),
                                            ),
                                            finalmask_errors,
                                            stream_sockopt_errors,
                                            dialer_proxy_options: &mut self.add.chain_options,
                                            buffers: &mut self.seeded_buffers,
                                            masked: mask.secrets,
                                        },
                                    )
                                }
                            };
                            // The draft changed this frame: its change protocol runs
                            // so the memoized validation below recomputes. The
                            // reported validation output stays until the next
                            // attempt — it is why this dialog is still open.
                            if changed {
                                draft.edited();
                            }
                        });

                    // Content edits ran the change protocol above; refresh the
                    // memoized verdicts once for the new generation.
                    draft.refresh(lang);
                    let Some(cached) = draft.validation.as_ref() else {
                        return;
                    };
                    let errors = &cached.rendered.blocking;
                    let warnings = &cached.rendered.advisory;
                    let gate = draft.gate(&self.seeded_buffers, validating, core_busy);
                    if !errors.is_empty() {
                        ui.separator();
                        ui.colored_label(
                            status_colors_of(ui).err,
                            t(lang, Key::SrvCompleteRequired),
                        );
                        for error in errors {
                            ui.colored_label(status_colors_of(ui).err, error);
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
                            ui.colored_label(status_colors_of(ui).warn, warning);
                        }
                    }
                    if core_busy {
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
                // The question about this window's own draft is this window's:
                // the user closed it, so it renders here, dimming the draft it
                // asks about, instead of in a second window on top of it.
                // `show_leave_modal` leaves it here for as long as this window
                // is on screen (see its doc).
                if self.add_close_is_staged() {
                    let dismissed = popup::modal(
                        ui.ctx(),
                        "servers.leave.add-draft",
                        t(lang, Key::SrvUnsavedChanges),
                        520.0,
                        |ui| {
                            let gate = draft.gate(&self.seeded_buffers, validating, core_busy);
                            leave_decision = self.leave_confirmation(ui, uictx, Some(gate));
                        },
                    );
                    if leave_decision.is_none() && (dismissed || backdrop_dismissed) {
                        // A dismissal of the question — a click on the dimmed
                        // draft, Escape, or a click on the dimmed main window —
                        // is Cancel, as it is in the main window; a button's
                        // answer wins the frame it lands in.
                        leave_decision = Some(LeaveDecision::Cancel);
                    }
                }
            },
        );

        // Only Discard drops the draft with the window it closed; every other
        // answer — Save holding it for the verdict it starts, Cancel leaving
        // the editor as it was — is what the gate below does with an untouched
        // window.
        // Discard already dropped the draft with the window it closed; every
        // other answer — Save holding it for the verdict it starts, Cancel
        // leaving the editor as it was — is what this gate does with an
        // untouched window.
        let discarded = matches!(leave_decision, Some(LeaveDecision::Discard));
        if !discarded {
            if validate_clicked {
                match self.start_profile_validation(
                    lang,
                    ProfileValidationOrigin::Draft,
                    vec![draft.profile.clone()],
                    Some(draft.target()),
                    uictx,
                ) {
                    Ok(()) => self.add.hold(draft),
                    Err(error) => {
                        self.profile_validation_report = Some(error.clone());
                        self.set_status(StatusLine::err(error));
                        self.add.hold(draft);
                    }
                }
            } else if validating || (!close_requested && !cancel) {
                // A validation in flight holds the dialog: the platform's close
                // on its window is refused with Cancel until the verdict lands,
                // because the draft and the report it will render are what the
                // dialog is open for.
                self.add.hold(draft);
            } else {
                // The draft was closed or cancelled without commit: the close
                // guard clears a derive dialog targeting it, stages the leave
                // modal when the draft is dirty, and otherwise drops the draft
                // with its seeded raw buffers.
                self.close_add_draft(draft);
            }
        }

        // The answer resolves last, with the draft back in its slot: Save's
        // validation reads the slot the same way the editor's own commit does,
        // and Discard closes the draft the gate above held back.
        if let Some(decision) = leave_decision {
            self.resolve_leave(decision, uictx);
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
    /// The probe output window of `kind`'s slot: each slot's own panel opens
    /// its own window, so both editors can show a transcript in one frame. The
    /// window's key carries the slot, or the two would share open/close state.
    fn probe_output_window(&mut self, ctx: &egui::Context, lang: Language, kind: DraftKind) {
        let probe = &mut self.slot_mut(kind).probe;
        if !probe.show_output {
            return;
        }
        // No transcript to show (e.g. a discard cleared it while the window
        // was open): clear the flag so this branch stops running — the
        // open/close gate above keeps idle frames off the transcript.
        let Some(output) = &probe.output else {
            probe.show_output = false;
            return;
        };
        let mut close_clicked = false;
        let close_requested = popup::show(
            ctx,
            ("servers.tls-probe-output", kind),
            t(lang, Key::SrvProbeOutputTitle),
            [560.0, 400.0],
            true,
            |ui| {
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
            },
        );
        self.slot_mut(kind).probe.show_output = !close_requested && !close_clicked;
    }

    /// Commit the group dialog: create a manual or subscription group, or
    /// apply the edited one. A new subscription group is returned so the
    /// caller starts its first fetch.
    fn finish_group_dialog(
        &mut self,
        lang: Language,
        ctx: &egui::Context,
        uictx: &mut ServersCtx<'_>,
    ) {
        let Some(draft) = self.group_dialog.take() else {
            return;
        };
        let fetch = ServersScreen::commit_group_dialog(draft, uictx.servers, uictx.settings);
        uictx.hooks.mark_dirty();
        if let Some(id) = fetch {
            self.start_subscription_fetch(lang, ctx.clone(), uictx, id);
        }
    }

    /// Apply a group dialog draft. A new group starts empty (manual) or with
    /// its feed state (subscription), under a title unique among the groups.
    /// An edited group keeps the kind it was created with: the dialog shows a
    /// subscription's URL fields only for a subscription group, and a manual
    /// group can never gain feed state here.
    fn commit_group_dialog(
        draft: GroupDraft,
        servers: &mut crate::model::ServersFile,
        settings: &mut crate::model::Settings,
    ) -> Option<String> {
        use crate::model::servers::{Group, GroupKind, Subscription};
        if let Some(id) = draft.editing {
            let title = draft.title.trim();
            if !title.is_empty() {
                crate::model::servers::rename_group(servers, settings, &id, title);
            }
            let kind = servers
                .groups
                .iter()
                .find(|group| group.id == id)
                .map(Group::kind)
                .unwrap_or(GroupKind::Manual);
            if kind == GroupKind::Subscription
                && let Some(group) = servers.groups.iter_mut().find(|group| group.id == id)
                && let Some(subscription) = group.subscription.as_mut()
            {
                if !draft.url.trim().is_empty() {
                    subscription.url = draft.url.trim().to_owned();
                }
                subscription.user_agent_custom = draft.custom_user_agent;
                subscription.user_agent = if draft.custom_user_agent {
                    draft.user_agent.trim().to_owned()
                } else {
                    String::new()
                };
                subscription.title_auto = false;
            }
            return None;
        }
        match draft.kind {
            GroupKind::Manual => {
                let title = servers.unique_group_title(draft.title.trim(), None);
                servers.groups.push(Group::new(title));
                None
            }
            GroupKind::Subscription => {
                let url = draft.url.trim().to_owned();
                if url.is_empty() {
                    return None;
                }
                let base = if draft.title.trim().is_empty() {
                    "Subscription"
                } else {
                    draft.title.trim()
                };
                let mut group = Group::new(servers.unique_group_title(base, None));
                group.subscription = Some(Subscription {
                    url,
                    user_agent_custom: draft.custom_user_agent,
                    user_agent: if draft.custom_user_agent {
                        draft.user_agent.trim().to_owned()
                    } else {
                        String::new()
                    },
                    title_auto: draft.title.trim().is_empty(),
                    ..Default::default()
                });
                let id = group.id.clone();
                servers.groups.push(group);
                Some(id)
            }
        }
    }

    fn show_dialogs(&mut self, ctx: &egui::Context, uictx: &mut ServersCtx) {
        let lang = uictx.settings.language;
        // Refresh/import report.
        if let Some(view) = self.report_view.take() {
            let (title, report) = (&view.0, &view.1);
            let close_requested = popup::show(
                ctx,
                "servers.refresh-report",
                title,
                [640.0, 460.0],
                true,
                |ui| {
                    ui.label(t_fmt(
                        lang,
                        Key::SrvReportSummary,
                        &[
                            &report.added,
                            &report.updated,
                            &report.removed,
                            &report.refused,
                            &report.ignored,
                        ],
                    ));
                    if report.route_to_block {
                        ui.colored_label(
                            status_colors_of(ui).warn,
                            t(lang, Key::SrvReportRouteBlock),
                        );
                    }
                    ui.separator();
                    egui::ScrollArea::vertical()
                        .id_salt("servers.refresh-report.rows")
                        .show(ui, |ui| {
                            for (index, row) in report.rows.iter().enumerate() {
                                let label = match row.kind {
                                    crate::model::servers::ReportKind::Added => {
                                        t(lang, Key::SrvReportAdded)
                                    }
                                    crate::model::servers::ReportKind::Updated => {
                                        t(lang, Key::SrvReportUpdated)
                                    }
                                    crate::model::servers::ReportKind::Removed => {
                                        t(lang, Key::SrvReportRemoved)
                                    }
                                    crate::model::servers::ReportKind::Refused => {
                                        t(lang, Key::SrvReportRefused)
                                    }
                                    crate::model::servers::ReportKind::Ignored => {
                                        t(lang, Key::SrvReportIgnored)
                                    }
                                };
                                if row.kind == crate::model::servers::ReportKind::Refused {
                                    egui::CollapsingHeader::new(label).id_salt(index).show(
                                        ui,
                                        |ui| {
                                            ui.add(
                                                egui::Label::new(
                                                    egui::RichText::new(&row.raw).monospace(),
                                                )
                                                .selectable(true)
                                                .wrap(),
                                            );
                                        },
                                    );
                                } else if row.name.is_empty() {
                                    ui.label(label);
                                } else {
                                    ui.label(format!("{label}: {}", row.name));
                                }
                            }
                        });
                },
            );
            if !close_requested {
                self.report_view = Some(view);
            }
        }
        // New group / rename group dialog.
        if self.group_dialog.is_some() {
            let mut commit = false;
            let dialog_title = match self.group_dialog.as_ref() {
                Some(draft) => match (&draft.editing, draft.kind) {
                    (Some(_), crate::model::servers::GroupKind::Manual) => {
                        t(lang, Key::SrvRenameGroupTitle).to_owned()
                    }
                    (Some(_), crate::model::servers::GroupKind::Subscription) => {
                        t(lang, Key::SrvEditSubscription).to_owned()
                    }
                    (None, _) => t(lang, Key::SrvNewGroup).to_owned(),
                },
                None => unreachable!("the dialog is open"),
            };
            let size = [480.0, 300.0];
            let close_requested = popup::show(
                ctx,
                "servers.group-dialog",
                &dialog_title,
                size,
                false,
                |ui| {
                    let draft = self.group_dialog.as_mut().expect("the dialog is open");
                    ui.horizontal(|ui| {
                        ui.label(t(lang, Key::SrvGroupKind));
                        if draft.editing.is_some() {
                            // The kind is fixed at creation: an existing group
                            // never offers the other one.
                            ui.weak(group_kind_label(draft.kind, lang));
                        } else {
                            for kind in [
                                crate::model::servers::GroupKind::Manual,
                                crate::model::servers::GroupKind::Subscription,
                            ] {
                                ui.selectable_value(
                                    &mut draft.kind,
                                    kind,
                                    group_kind_label(kind, lang),
                                );
                            }
                        }
                    });
                    crate::ui::widgets::text_field(
                        ui,
                        t(lang, Key::SrvSubscriptionTitle),
                        &mut draft.title,
                        "",
                    );
                    if draft.kind == crate::model::servers::GroupKind::Subscription {
                        crate::ui::widgets::text_field(
                            ui,
                            t(lang, Key::SrvSubscriptionUrl),
                            &mut draft.url,
                            "https://",
                        );
                        ui.checkbox(&mut draft.custom_user_agent, t(lang, Key::SrvUseCustomUa));
                        if draft.custom_user_agent {
                            crate::ui::widgets::text_field(
                                ui,
                                "User-Agent",
                                &mut draft.user_agent,
                                "",
                            );
                        }
                    }
                    let ready = match draft.kind {
                        crate::model::servers::GroupKind::Manual => true,
                        crate::model::servers::GroupKind::Subscription => {
                            !draft.url.trim().is_empty()
                        }
                    };
                    let label = if draft.editing.is_some() {
                        t(lang, Key::SrvSaveSubscription)
                    } else {
                        t(lang, Key::SrvCreateGroup)
                    };
                    if ui.add_enabled(ready, egui::Button::new(label)).clicked() {
                        commit = true;
                    }
                },
            );
            if commit {
                self.finish_group_dialog(lang, ctx, uictx);
            } else if close_requested {
                self.group_dialog = None;
            }
        }
        // Copy to group. The picker lists the manual groups only, with
        // `Manual` preselected; the dialog is the only place a copy's target
        // is chosen.
        if self.copy_dialog.is_some() {
            let mut commit = false;
            let mut cancel = false;
            let close_requested = popup::show(
                ctx,
                "servers.copy-dialog",
                t(lang, Key::SrvCopyToGroup),
                [420.0, 220.0],
                false,
                |ui| {
                    let dialog = self.copy_dialog.as_mut().expect("the dialog is open");
                    ui.label(t(lang, Key::SrvGroup));
                    for group in &uictx.servers.groups {
                        if group.kind() != crate::model::servers::GroupKind::Manual {
                            continue;
                        }
                        ui.radio_value(&mut dialog.target, group.id.clone(), &group.title);
                    }
                    ui.horizontal(|ui| {
                        if ui.button(t(lang, Key::SrvCopyToGroupConfirm)).clicked() {
                            commit = true;
                        }
                        if ui.button(t(lang, Key::Cancel)).clicked() {
                            cancel = true;
                        }
                    });
                },
            );
            if commit {
                let dialog = self.copy_dialog.take().expect("the dialog is open");
                let mut copied = 0usize;
                for id in &dialog.ids {
                    if uictx.servers.copy_to_manual(id, &dialog.target).is_some() {
                        copied += 1;
                    }
                }
                if copied > 0 {
                    let title = uictx
                        .servers
                        .group_title_of(&dialog.target)
                        .unwrap_or(crate::model::servers::MANUAL_GROUP_TITLE)
                        .to_owned();
                    uictx.hooks.mark_dirty();
                    self.set_status(StatusLine::ok(t_fmt(
                        lang,
                        Key::SrvCopiedToGroup,
                        &[&copied, &title],
                    )));
                }
            } else if cancel || close_requested {
                self.copy_dialog = None;
            }
        }
        // Delete-group confirmation. Only a group tab opens it: the default
        // tabs and the reserved group have no delete action at all.
        if let Some(id) = self.group_delete_pending.clone() {
            let title = uictx
                .servers
                .groups
                .iter()
                .find(|group| group.id == id)
                .map(|group| group.title.clone())
                .unwrap_or_default();
            let mut confirm = false;
            let mut cancel = false;
            let close_requested = popup::show(
                ctx,
                "servers.delete-group",
                t(lang, Key::SrvDeleteGroupTitle),
                [440.0, 150.0],
                false,
                |ui| {
                    ui.label(t_fmt(lang, Key::SrvDeleteGroupConfirm, &[&title]));
                    ui.horizontal(|ui| {
                        if ui.button(t(lang, Key::Delete)).clicked() {
                            confirm = true;
                        }
                        if ui.button(t(lang, Key::Cancel)).clicked() {
                            cancel = true;
                        }
                    });
                },
            );
            if confirm {
                // The fetch belongs to the group it was started for: a group
                // deleted mid-fetch cancels that fetch and no other.
                if self.subscription_fetch_group.as_deref() == Some(id.as_str()) {
                    self.subscription_fetch.cancel();
                    self.subscription_fetch_group = None;
                }
                if uictx.servers.delete_group(&id) {
                    uictx.hooks.mark_dirty();
                }
                self.group_delete_pending = None;
            } else if cancel || close_requested {
                self.group_delete_pending = None;
            }
        }
        for kind in [DraftKind::Existing, DraftKind::Add] {
            self.probe_output_window(ctx, lang, kind);
        }
        self.show_editor_window(ctx, uictx);
        self.show_add_draft(ctx, uictx);
        // Import links.
        if self.import_open {
            let validating = self.profile_validation_in_progress(ProfileValidationOrigin::Import);
            let core_busy = uictx.busy.is_held();
            let mut validate_profiles: Option<Vec<ServerProfile>> = None;
            let close_requested = popup::show(
                ctx,
                "servers.import-links",
                t(lang, Key::SrvImportShareLinks),
                [520.0, 420.0],
                true,
                |ui| {
                    ui.add_enabled_ui(!validating, |ui| {
                        ui.label(t(lang, Key::SrvImportHint));
                        let source_changed = ui
                            .add(
                                egui::TextEdit::multiline(&mut self.import_text)
                                    .desired_rows(6)
                                    .desired_width(f32::INFINITY)
                                    .hint_text(t(lang, Key::SrvImportPasteHint)),
                            )
                            .on_hover_text(t(lang, Key::SrvPasteCtrlV))
                            .changed();
                        if source_changed {
                            self.invalidate_import_preview();
                            self.profile_validation_report = None;
                            self.import_parse_error = None;
                            self.cancel_import_parse();
                        }
                        if ui
                            .add_enabled(
                                !self.import_parse_job.is_pending() && !self.import_text.is_empty(),
                                egui::Button::new(t(lang, Key::SrvParse)),
                            )
                            .clicked()
                        {
                            self.start_import_parse(lang, ui.ctx().clone());
                        }
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
                                    let colors = status_colors_of(ui);
                                    for row in &preview.rows[rows] {
                                        let text = match row.kind {
                                            ImportPreviewKind::Ok => {
                                                RichText::new(row.text.as_str())
                                            }
                                            ImportPreviewKind::Warn => {
                                                RichText::new(row.text.as_str()).color(colors.warn)
                                            }
                                            ImportPreviewKind::Err => {
                                                RichText::new(row.text.as_str()).color(colors.err)
                                            }
                                        };
                                        let response = ui.add(egui::Label::new(text).truncate());
                                        if row.kind != ImportPreviewKind::Ok {
                                            response.on_hover_text(row.text.as_str());
                                        }
                                    }
                                },
                            );
                            if core_busy {
                                ui.colored_label(
                                    status_colors_of(ui).warn,
                                    t(lang, Key::SrvWaitCoreOperationImports),
                                );
                            }
                            if ui
                                .add_enabled(
                                    ok > 0 && !core_busy,
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
                                        .filter_map(|result| {
                                            result
                                                .as_ref()
                                                .ok()
                                                .map(|parsed| parsed.profile.clone())
                                        })
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
                },
            );
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
            // A validation in flight keeps the dialog up, and the platform's
            // close on its window is refused with it: the report the dialog
            // will render is the reason it is still open.
            self.import_open = (!close_requested
                || validating
                || self.profile_validation_in_progress(ProfileValidationOrigin::Import))
                && self.import_open;
            if !self.import_open {
                self.cancel_import_parse();
            }
        }

        // QR export.
        if let Some(qr) = &mut self.qr_dialog {
            let mut close_clicked = false;
            let close_requested = popup::show(
                ctx,
                "servers.share",
                t_fmt(lang, Key::SrvShareTitle, &[&qr.name]).as_str(),
                [340.0, 480.0],
                false,
                |ui| {
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
                },
            );
            if close_requested || close_clicked {
                self.qr_dialog = None;
            }
        }

        // Delete confirmation.
        if let Some(dialog) = &mut self.delete_pending {
            dialog.ids.retain(|id| {
                uictx
                    .servers
                    .profiles
                    .iter()
                    .any(|profile| &profile.id == id)
            });
            if dialog.ids.is_empty() {
                self.delete_pending = None;
            }
        }
        if let Some(dialog) = &self.delete_pending {
            let mut decision: Option<bool> = None;
            let batch = dialog.ids.len() > 1;
            let declined = popup::modal(
                ctx,
                "servers.delete-confirm",
                t(
                    lang,
                    if batch {
                        Key::SrvDeleteServersTitle
                    } else {
                        Key::DeleteServer
                    },
                ),
                460.0,
                |ui| {
                    if dialog.references.is_empty() {
                        if batch {
                            ui.label(t_fmt(
                                lang,
                                Key::SrvDeleteManyCannotUndone,
                                &[&dialog.ids.len()],
                            ));
                        } else {
                            ui.label(t_fmt(lang, Key::SrvDeleteCannotUndone, &[&dialog.name]));
                        }
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
                },
            );
            if decision == Some(true) {
                // Owned copy: the confirm block also mutates `self`
                // (eviction), which the `dialog` borrow would otherwise block.
                let deleted = dialog.ids.clone();
                uictx
                    .servers
                    .profiles
                    .retain(|profile| !deleted.contains(&profile.id));
                if uictx
                    .servers
                    .active
                    .as_deref()
                    .is_some_and(|id| deleted.iter().any(|deleted| deleted == id))
                    || uictx.servers.profiles.is_empty()
                {
                    // A deleted active server — and the last row — lands on
                    // Block: a mistaken deletion must not leak traffic.
                    uictx.servers.active =
                        Some(crate::model::inbound::BLOCK_OUTBOUND_TAG.to_owned());
                }
                if self
                    .selected
                    .as_deref()
                    .is_some_and(|id| deleted.iter().any(|deleted| deleted == id))
                {
                    self.selected = None;
                }
                self.selection.retain(|id| !deleted.contains(id));
                if self
                    .selection_anchor
                    .as_deref()
                    .is_some_and(|anchor| deleted.iter().any(|deleted| deleted == anchor))
                {
                    self.selection_anchor = None;
                }
                for deleted_id in &deleted {
                    self.seeded_buffers.evict_owned(deleted_id);
                    // The deleted profile's memoized latency badge is dead
                    // weight; the row loop would never re-insert it
                    // because the id no longer renders.
                    self.latency_badges.remove(deleted_id);
                }
                uictx.hooks.mark_dirty();
            }
            if declined || decision.is_some() {
                self.delete_pending = None;
            }
        }

        if self.profile_validation_request.is_pending() {
            self.derive_dialog = None;
        }
        // REALITY x25519 public-key derivation. The private key stays in this
        // transient dialog; the result is applied only to its still-current draft.
        if let Some(mut dialog) = self.derive_dialog.take() {
            let mut close_clicked = false;
            let mut derive_clicked = false;
            let close_requested = popup::show(
                ctx,
                "servers.derive-public-key",
                t(lang, Key::SrvDerivePublicKey),
                [420.0, 210.0],
                false,
                |ui| {
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
                },
            );
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
            if !close_requested && !close_clicked {
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
    ///
    /// The toast is an overlay inside the main window: it is anchored to that
    /// window's own corner, so a window of its own would only lose the anchor
    /// that places it.
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

fn addr_port(
    ui: &mut egui::Ui,
    lang: Language,
    address: &mut String,
    port: &mut u16,
    mask: widgets::Mask,
) -> bool {
    // Both halves are server information, so one flag hides the pair: the
    // address and the port a bystander reads together.
    let mut changed = widgets::masked_validated_field(
        ui,
        t(lang, Key::AddressLower),
        address,
        "example.com",
        |v| v_required(lang, v),
        mask.server_info,
    );
    // Port 0 is enforced by the model (SettingsPortZero /
    // TrojanSettingsIncomplete / ShadowsocksSettingsIncomplete) and
    // rendered once through the shared i18n seam — no inline duplicate.
    changed |= widgets::masked_port_field(ui, "port", port, mask.server_info);
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
        .on_hover_text(t(lang, Key::SrvMuxDeprecatedNote))
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
    changed |= widgets::noted(ui, t(lang, Key::SrvXudpProxyUdp443Note), |ui| {
        opt_combo_str(
            ui,
            lang,
            "xudpProxyUDP443",
            &mut m.xudp_proxy_udp443,
            XUDP_PROXY_UDP443_MODES,
        )
    });
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
                changed |= widgets::text_field(
                    ui,
                    "packet",
                    &mut n.packet,
                    t(lang, Key::SrvNoisePacketHint),
                );
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
    use super::keygen::{keygen_value, redacted_tool_args};
    use super::raw_editor::JsonBuf;
    use super::{
        AdvancedTabCtx, Column, DRAG_SCROLL_MAX_SPEED, DeriveDialog, DraftBaseline, DraftKind,
        DraftTarget, EditorTab, EditorValidationCache, EditorValidationFindings,
        EditorValidationRender, FINGERPRINTS, FeedbackLevel, FieldKey, GroupDraft, Language,
        LatencyBadge, LeaveAction, ProfileDraft, RawField, Request, RowCells, RowDetail, RowExtras,
        RowState, RowSwitch, STATUS_TOAST_AUTO_CLEAR, SeededBuffers, ServerProfile, ServerTab,
        ServersScreen, StatusLine, TABLE_CELL_INSET, TABLE_DEFAULT_WIDTHS, TableShape, TlsProbe,
        TransportTabCtx, basic_tab_inline_verdict, column_bounds, drag_divider, drag_scroll_delta,
        ech_sockopt_editor, editor_validation_findings, final_rules_editor,
        finalmask_udp_settings_editor, fingerprint_allowed, frozen_widths, mux_tab, noises_editor,
        reorder_target, sanitized_widths, server_list_row, status_colors_of, status_toast_expired,
        tab_order, table_columns, xmux_section,
    };
    use crate::diag::{Diag, DiagError};
    use crate::i18n::{Key, t, t_fmt, validation_issue_message, validation_message};
    use crate::links;
    use crate::model::settings::{ColumnWidths, SortColumn, ViewSort};
    use crate::model::stream::MasqueradeCfg;
    use crate::model::validation::{
        ValidationCode, ValidationIssue, validate_outbound, validate_sockopt,
    };
    use crate::model::{
        BlackholeResponse, CustomSockopt, FinalmaskHeaderCustomTcp, FinalmaskModel, FinalmaskNoise,
        FinalmaskNoiseItem, FinalmaskQuicParams, FinalmaskRawValue, FinalmaskRealm,
        FinalmaskRealmTls, FinalmaskTcpItem, FinalmaskTcpMask, FinalmaskUdpHop, FinalmaskUdpMask,
        FinalmaskXdns, FinalmaskXdnsDomain, FinalmaskXdnsResolver, FreedomFinalRule,
        HysteriaTransport, Int32Range, MasqueTransport, MasqueWarp, Network, Noise, OutboundModel,
        ProbeOutcome, ProbeSource, ProbeVerdict, Protocol, ProtocolSettings, RealityModel,
        Security, SockoptModel, StreamModel, TlsCert, TlsModel, WireguardPeer, WsSettings,
        XhttpSettings, XmuxConfig,
    };
    use crate::rt::{
        CoreCmd, JobKind, LatencyProbeResult, OutboundStatusView, ProbeFailure,
        ProfileValidationOrigin, ProfileValidationResult, ToolTarget,
    };
    use crate::ui::test_rig::harness_builder;
    use crate::ui::test_rig::{
        DEFAULT_TEST_VIEWPORT, UiTestRig, screen_harness, screen_harness_at, servers_frame_harness,
    };
    use egui_kittest::{Harness, kittest::NodeT as _, kittest::Queryable};
    use serde_json::json;
    use std::time::{Duration, Instant, SystemTime};
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

    /// An editor draft for `profile`, as the editor builds one: the persisted
    /// snapshot is the baseline the draft is compared against, and no sweep
    /// has run yet.
    fn draft_for(profile: &ServerProfile) -> ProfileDraft {
        ProfileDraft::existing(profile).expect("the fixture serializes")
    }

    /// Install `profile` as the selected editor's draft, compared against
    /// `source`, behind the editor's back: no memo covers the new generation,
    /// so the next frame sweeps it.
    fn install_draft(screen: &mut ServersScreen, profile: &ServerProfile, source: &ServerProfile) {
        let generation = screen
            .existing
            .draft
            .as_ref()
            .map_or(1, |draft| draft.generation.wrapping_add(1));
        let mut draft = draft_for(profile);
        draft.baseline = DraftBaseline::of(source).expect("the fixture serializes");
        draft.generation = generation;
        screen.existing.draft = Some(draft);
    }

    /// The borrowed draft identity a tab entry point takes, for the tests that
    /// drive one directly.
    fn draft_target(kind: DraftKind, profile_id: &str, generation: u64) -> Option<DraftTarget<'_>> {
        Some(DraftTarget {
            kind,
            profile_id,
            generation,
        })
    }

    /// The reveal state the render tests drive a tab under: nothing masked, so
    /// the fields they query by label render their editable controls. The
    /// masked state has its own coverage at the screen level.
    fn revealed() -> crate::ui::widgets::Mask {
        crate::ui::widgets::Mask {
            secrets: false,
            server_info: false,
        }
    }

    /// An add-server draft for `profile` carrying the memo a rendered dialog
    /// leaves: an add draft has no committed source, so `changed_from_source`
    /// is its whole unsaved state.
    fn rendered_add_draft(profile: &ServerProfile, changed_from_source: bool) -> ProfileDraft {
        let mut draft = ProfileDraft::add(profile.clone());
        draft.validation = Some(clean_memo(0, changed_from_source));
        draft
    }

    /// The memo a draft's editor leaves when the sweep finds nothing, so a
    /// test can install the verdicts a rendered draft carries without running
    /// the sweep itself.
    fn clean_memo(generation: u64, changed_from_source: bool) -> EditorValidationCache {
        EditorValidationCache {
            generation,
            findings: EditorValidationFindings::default(),
            rendered_language: Language::En,
            rendered: EditorValidationRender::default(),
            changed_from_source,
        }
    }

    /// The editor's open draft.
    fn open_draft(screen: &ServersScreen) -> &ProfileDraft {
        screen
            .existing
            .draft
            .as_ref()
            .expect("the editor holds a draft")
    }

    /// The verdicts the editor rendered its draft with.
    fn editor_memo(screen: &ServersScreen) -> &EditorValidationCache {
        open_draft(screen)
            .validation
            .as_ref()
            .expect("the editor swept the draft")
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
            let mut ctx = rig.ctx();
            screen
                .start_profile_validation(
                    Language::En,
                    ProfileValidationOrigin::Import,
                    vec![tokyo.clone()],
                    None,
                    &mut ctx.servers(),
                )
                .expect("an idle screen accepts a validation request");
        }
        // A command a screen sends asks the shell for the same busy-window
        // head start the shell's own sends take: the frame's requests carry
        // the job kind, and the shell mirrors it while the window is open.
        assert_eq!(
            rig.requests.mirror_operation,
            Some(crate::rt::JobKind::ValidateProfiles),
            "a screen-sent job must ask for the optimistic busy-window mirror"
        );
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
                screen.poll_profile_validation(Language::En, &mut rig.ctx().servers());
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

        screen.poll_profile_validation(Language::En, &mut rig.ctx().servers());

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
        screen.poll_profile_validation(Language::En, &mut rig.ctx().servers());
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
        screen.poll_profile_validation(Language::En, &mut rig.ctx().servers());
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
            let mut harness = harness_builder().build_ui(move |ui| {
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
        let mut harness = harness_builder().build_ui(move |ui| {
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
        let mut harness = harness_builder().build_ui(move |ui| {
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
    fn the_report_window_lists_rows_and_keeps_refused_text() {
        use crate::model::servers::{RefreshReport, ReportKind, ReportRow};

        let report = RefreshReport {
            added: 1,
            refused: 1,
            rows: vec![
                ReportRow {
                    kind: ReportKind::Added,
                    name: "Tokyo".into(),
                    raw: String::new(),
                },
                ReportRow {
                    kind: ReportKind::Refused,
                    name: "bad entry".into(),
                    raw: "vless://broken".into(),
                },
            ],
            ..Default::default()
        };
        let screen = ServersScreen {
            report_view: Some(("Feed report".into(), report)),
            ..ServersScreen::default()
        };
        let mut harness = screen_harness(UiTestRig::default(), screen);
        harness.run();
        assert!(
            harness
                .get_all_by_label_contains("added: Tokyo")
                .next()
                .is_some()
                || harness.get_all_by_label_contains("Tokyo").next().is_some(),
            "an added row is named"
        );
        assert!(
            harness
                .get_all_by_label_contains("refused")
                .next()
                .is_some(),
            "the refused section is present"
        );
        assert!(harness.query_by_label("Feed report").is_some());
    }

    /// A rig with the reserved manual group holding `manual` and one `Feed`
    /// group holding `feed`; every row is emitted.
    fn tab_rig(manual: &[&str], feed: &[&str]) -> (UiTestRig, String) {
        use crate::model::servers::Group;
        let mut rig = UiTestRig::default();
        let group = Group::new("Feed");
        let feed_id = group.id.clone();
        let mut profiles = Vec::new();
        for name in manual {
            let mut profile = ServerProfile::new(*name, OutboundModel::new(Protocol::Freedom));
            profile.enabled = true;
            profiles.push(profile);
        }
        for name in feed {
            let mut profile = ServerProfile::new(*name, OutboundModel::new(Protocol::Freedom));
            profile.group = feed_id.clone();
            profile.enabled = true;
            profiles.push(profile);
        }
        rig.servers.profiles = profiles;
        rig.servers.groups.push(group);
        rig.servers.hydrate_group_titles();
        (rig, feed_id)
    }

    #[test]
    fn the_tab_bar_pins_the_defaults_first_and_bands_the_group_tabs() {
        use crate::model::servers::Group;
        let mut servers = crate::model::ServersFile::default();
        let mut first = Group::new("First");
        first.pinned = true;
        let second = Group::new("Second");
        let mut third = Group::new("Third");
        third.pinned = true;
        let (first_id, second_id, third_id) =
            (first.id.clone(), second.id.clone(), third.id.clone());
        servers.groups = vec![Group::manual(), first, second, third];

        // Pinned groups follow the defaults in stored order, then the
        // unpinned band in stored order.
        assert_eq!(
            tab_order(&servers),
            vec![
                ServerTab::Emitted,
                ServerTab::Manual,
                ServerTab::All,
                ServerTab::Group(first_id),
                ServerTab::Group(third_id),
                ServerTab::Group(second_id),
            ]
        );

        let rig = UiTestRig {
            servers,
            ..UiTestRig::default()
        };
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        let x = |harness: &Harness<'static, (ServersScreen, UiTestRig)>, label: &str| {
            harness.get_by_label(label).rect().center().x
        };
        assert!(
            x(&harness, t(Language::En, Key::SrvTabEmitted))
                < x(&harness, t(Language::En, Key::SrvTabManual))
        );
        assert!(
            x(&harness, t(Language::En, Key::SrvTabManual))
                < x(&harness, t(Language::En, Key::SrvTabAll))
        );
        assert!(x(&harness, t(Language::En, Key::SrvTabAll)) < x(&harness, "First"));
        assert!(x(&harness, "First") < x(&harness, "Third"));
        assert!(x(&harness, "Third") < x(&harness, "Second"));
    }

    #[test]
    fn the_screen_opens_on_emitted_and_all_lists_every_row_with_its_group() {
        use crate::model::servers::Group;
        let mut rig = UiTestRig::default();
        let group = Group::new("Feed");
        let feed_id = group.id.clone();
        let mut active = ServerProfile::new("Active", OutboundModel::new(Protocol::Freedom));
        active.enabled = true;
        let disabled = ServerProfile::new("Disabled", OutboundModel::new(Protocol::Freedom));
        let mut fed = ServerProfile::new("Fed", OutboundModel::new(Protocol::Freedom));
        fed.group = feed_id;
        fed.enabled = true;
        rig.servers.profiles = vec![active, disabled, fed];
        rig.servers.groups.push(group);
        rig.servers.active = Some(rig.servers.profiles[0].id.clone());
        rig.servers.hydrate_group_titles();
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();

        // The opening tab is `Emitted`: the active server leads, switched-off
        // servers are absent, and the row order is the generated order.
        assert_eq!(harness.state().0.view, ServerTab::Emitted);
        assert!(harness.query_by_label("Active").is_some());
        assert!(harness.query_by_label("Fed").is_some());
        assert!(
            harness.query_by_label("Disabled").is_none(),
            "a switched-off server is not emitted"
        );
        let y = |harness: &Harness<'static, (ServersScreen, UiTestRig)>, label: &str| {
            harness.get_by_label(label).rect().center().y
        };
        assert!(y(&harness, "Active") < y(&harness, "Fed"));

        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run();
        assert_eq!(harness.state().0.view, ServerTab::All);
        for name in ["Active", "Disabled", "Fed"] {
            assert!(
                harness.query_by_label(name).is_some(),
                "All must list {name:?}"
            );
        }
        assert!(
            harness
                .query_all_by_label(t(Language::En, Key::SrvColGroup))
                .next()
                .is_some(),
            "All must carry the group column"
        );
        assert!(harness.query_all_by_label("Feed").next().is_some());
    }

    #[test]
    fn a_group_tab_lists_only_its_group_and_search_stays_inside_the_tab() {
        let (rig, feed_id) = tab_rig(&["Alpha"], &["Bravo"]);
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness.get_by_label("Feed").click();
        harness.run();
        assert_eq!(harness.state().0.view, ServerTab::Group(feed_id));
        assert!(harness.query_by_label("Bravo").is_some());
        assert!(
            harness.query_by_label("Alpha").is_none(),
            "a group tab hides the other groups' rows"
        );

        harness.state_mut().0.search = "Alpha".into();
        harness.run();
        assert!(
            harness.query_by_label("Bravo").is_none(),
            "the search matches inside this tab only"
        );
        assert!(harness.query_by_label("Alpha").is_none());

        harness
            .get_by_label(t(Language::En, Key::SrvTabManual))
            .click();
        harness.state_mut().0.search = "Bravo".into();
        harness.run();
        assert!(harness.query_by_label("Alpha").is_none());
        assert!(
            harness.query_by_label("Bravo").is_none(),
            "a feed row never leaks into the Manual tab's search"
        );
    }

    #[test]
    fn switching_tabs_clears_the_selection_and_keeps_the_view_sort() {
        let (rig, _) = tab_rig(&["Alpha", "Bravo"], &["Charlie"]);
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness.get_by_label("Alpha").click();
        harness.run();
        // The clicked row is selected.
        assert_eq!(selected_names(&harness), ["Alpha"]);

        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run();
        assert!(
            harness.state().0.selection.is_empty(),
            "a tab switch must drop the selection with the tab"
        );

        // The view sort is the screen's, not the tab's: the header keeps its
        // arrow and the rows keep their order across the switch.
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::SrvColName),
            )
            .click();
        harness.run();
        assert!(
            harness.query_by_label("▲").is_some(),
            "the sorted column must mark its direction"
        );
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::SrvTabManual),
            )
            .click();
        harness.run();
        assert!(
            harness.query_by_label("▲").is_some(),
            "the view sort survives the tab switch"
        );
        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run();
        assert!(
            harness.query_by_label("▲").is_some(),
            "returning to the tab shows the same view sort"
        );
    }

    #[test]
    fn the_view_sort_saves_as_a_ui_preference_and_loads_on_open() {
        let (rig, _) = tab_rig(&["Bravo", "Alpha"], &[]);
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run();
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::SrvColName),
            )
            .click();
        harness.run();
        assert_eq!(
            harness.state().1.settings.server_table_sort,
            Some(ViewSort {
                column: SortColumn::Name,
                ascending: true,
            }),
            "a header click saves the sort with the UI preferences"
        );
        assert!(
            harness.state().1.requests.ui_dirty,
            "the sort takes the UI-only persist lane"
        );
        assert!(
            !harness.state().1.requests.dirty,
            "a view sort never reaches the configuration pipeline"
        );

        // A screen opened over those settings comes back sorted, and still
        // leaves `Emitted` in the outbound order.
        let settings = harness.state().1.settings.clone();
        let servers = harness.state().1.servers.clone();
        drop(harness);
        let rig = UiTestRig {
            settings,
            servers,
            ..UiTestRig::default()
        };
        let mut reopened = screen_harness(rig, ServersScreen::default());
        reopened.run();
        assert!(
            reopened.query_all_by_label("▲").next().is_none(),
            "Emitted never takes the view sort"
        );
        let y = |harness: &Harness<'static, (ServersScreen, UiTestRig)>, label: &str| {
            harness.get_by_label(label).rect().center().y
        };
        assert!(y(&reopened, "Bravo") < y(&reopened, "Alpha"));
        reopened
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        reopened.run();
        assert!(
            y(&reopened, "Alpha") < y(&reopened, "Bravo"),
            "the saved sort orders the rows on open"
        );
        assert!(
            reopened.query_by_label("▲").is_some(),
            "the saved direction comes back with the sort"
        );
    }

    #[test]
    fn group_tabs_sort_the_view_only_and_emitted_has_no_header_sort() {
        let mut rig = UiTestRig::default();
        for (name, verdict) in [
            (
                "Bravo",
                Some(ProbeVerdict::delay(300, ProbeSource::LatencyTest)),
            ),
            (
                "Alpha",
                Some(ProbeVerdict::delay(20, ProbeSource::LatencyTest)),
            ),
            (
                "Charlie",
                Some(ProbeVerdict::delay(40, ProbeSource::LatencyTest)),
            ),
            (
                "Dead",
                Some(ProbeVerdict::dead(ProbeSource::LatencyTest, None)),
            ),
            ("Never", None),
        ] {
            let mut profile = ServerProfile::new(name, OutboundModel::new(Protocol::Freedom));
            profile.enabled = true;
            profile.verdict = verdict;
            rig.servers.profiles.push(profile);
        }
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        // `Emitted` orders the outbound document: its header offers no sort.
        assert!(
            harness
                .query_by_role_and_label(
                    egui::accesskit::Role::Button,
                    t(Language::En, Key::SrvColName)
                )
                .is_none(),
            "the Emitted tab must not sort"
        );

        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run();
        let stored: Vec<String> = harness
            .state()
            .1
            .servers
            .profiles
            .iter()
            .map(|profile| profile.name.clone())
            .collect();
        let y = |harness: &Harness<'static, (ServersScreen, UiTestRig)>, label: &str| {
            harness.get_by_label(label).rect().center().y
        };
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::SrvColName),
            )
            .click();
        harness.run();
        assert!(y(&harness, "Alpha") < y(&harness, "Bravo"));
        assert!(y(&harness, "Bravo") < y(&harness, "Charlie"));
        assert_eq!(
            harness
                .state()
                .1
                .servers
                .profiles
                .iter()
                .map(|profile| profile.name.clone())
                .collect::<Vec<_>>(),
            stored,
            "a view sort never touches the stored order"
        );

        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::SrvColName),
            )
            .click();
        harness.run();
        assert!(
            y(&harness, "Charlie") < y(&harness, "Bravo"),
            "a second click reverses the view"
        );

        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::SrvColLatency),
            )
            .click();
        harness.run();
        assert!(y(&harness, "Alpha") < y(&harness, "Charlie"));
        assert!(y(&harness, "Charlie") < y(&harness, "Bravo"));
        assert!(
            y(&harness, "Bravo") < y(&harness, "Dead"),
            "a dead verdict sorts after every measured delay"
        );
        assert_eq!(
            harness
                .state()
                .1
                .servers
                .profiles
                .iter()
                .map(|profile| profile.name.clone())
                .collect::<Vec<_>>(),
            stored
        );
    }

    #[test]
    fn a_group_tab_sort_is_a_view_and_survives_leaving_the_tab() {
        use crate::model::servers::Group;
        let mut rig = UiTestRig::default();
        let feed = Group::new("Feed");
        let feed_id = feed.id.clone();
        for name in ["Zulu", "Alpha"] {
            let mut profile = ServerProfile::new(name, OutboundModel::new(Protocol::Freedom));
            profile.enabled = true;
            profile.group = feed_id.clone();
            rig.servers.profiles.push(profile);
        }
        rig.servers.groups.push(feed);
        rig.servers.hydrate_group_titles();
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness.get_by_label("Feed").click();
        harness.run();
        let y = |harness: &Harness<'static, (ServersScreen, UiTestRig)>, label: &str| {
            harness.get_by_label(label).rect().center().y
        };
        assert!(y(&harness, "Zulu") < y(&harness, "Alpha"));

        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::SrvColName),
            )
            .click();
        harness.run();
        assert!(
            y(&harness, "Alpha") < y(&harness, "Zulu"),
            "the group tab sorts its view"
        );
        assert_eq!(
            profile_names(&harness.state().1),
            ["Zulu", "Alpha"],
            "the view sort never rewrites the group's stored order"
        );

        // The sort belongs to the screen, so leaving the tab and coming back
        // keeps it; the stored order stays as it was.
        harness
            .get_by_label(t(Language::En, Key::SrvTabEmitted))
            .click();
        harness.run();
        assert!(harness.state().0.view_sort.is_some());
        harness.get_by_label("Feed").click();
        harness.run();
        assert!(y(&harness, "Alpha") < y(&harness, "Zulu"));
        assert_eq!(
            profile_names(&harness.state().1),
            ["Zulu", "Alpha"],
            "the view sort never rewrites the group's stored order"
        );
    }

    #[test]
    fn creating_a_manual_group_starts_it_empty_and_opens_its_tab() {
        use crate::model::servers::GroupKind;
        let mut rig = UiTestRig::default();
        let mut own = ServerProfile::new("Own", OutboundModel::new(Protocol::Freedom));
        own.enabled = true;
        rig.servers.profiles.push(own);
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();

        harness
            .get_by_label(t(Language::En, Key::SrvNewGroup))
            .click();
        harness.run();
        assert!(
            harness.state().0.group_dialog.is_some(),
            "New group opens one dialog"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvSubscriptionUrl))
                .is_none(),
            "a manual group asks only for a title"
        );
        replace_field_text(
            &mut harness,
            t(Language::En, Key::SrvSubscriptionTitle),
            "Mine",
        );
        harness
            .get_by_label(t(Language::En, Key::SrvCreateGroup))
            .click();
        harness.run();

        let servers = &harness.state().1.servers;
        let group = servers
            .groups
            .iter()
            .find(|group| group.title == "Mine")
            .expect("the dialog creates the group");
        assert_eq!(GroupKind::Manual, group.kind());
        assert!(
            !servers
                .profiles
                .iter()
                .any(|profile| profile.group_id() == group.id),
            "a manual group starts empty"
        );
        assert!(
            harness.query_by_label("Mine").is_some(),
            "the new group owns a tab"
        );
        assert!(
            harness
                .state()
                .1
                .servers
                .groups
                .iter()
                .any(|group| group.title == "Mine"),
            "the group record is stored"
        );
    }

    #[test]
    fn creating_a_group_twice_suffixes_the_second_title() {
        let mut harness = screen_harness(UiTestRig::default(), ServersScreen::default());
        harness.run();
        for _ in 0..2 {
            harness
                .get_by_label(t(Language::En, Key::SrvNewGroup))
                .click();
            harness.run();
            replace_field_text(
                &mut harness,
                t(Language::En, Key::SrvSubscriptionTitle),
                "Mine",
            );
            harness
                .get_by_label(t(Language::En, Key::SrvCreateGroup))
                .click();
            harness.run();
        }
        let titles: Vec<&str> = harness
            .state()
            .1
            .servers
            .groups
            .iter()
            .map(|group| group.title.as_str())
            .filter(|title| *title != crate::model::servers::MANUAL_GROUP_TITLE)
            .collect();
        assert_eq!(
            titles,
            ["Mine", "Mine (1)"],
            "a colliding title takes the existing numeric suffix"
        );
    }

    #[test]
    fn the_group_dialog_reveals_the_feed_fields_only_for_subscription() {
        let mut harness = screen_harness(UiTestRig::default(), ServersScreen::default());
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvNewGroup))
            .click();
        harness.run();
        assert!(
            !harness
                .get_by_label(t(Language::En, Key::SrvCreateGroup))
                .accesskit_node()
                .is_disabled(),
            "a manual group needs no feed URL"
        );

        harness
            .get_by_label(t(Language::En, Key::SrvGroupKindSubscription))
            .click();
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvSubscriptionUrl))
                .is_some(),
            "a subscription group asks for its URL"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvUseCustomUa))
                .is_some(),
            "a subscription group asks for its User-Agent mode"
        );
        assert!(
            harness
                .get_by_label(t(Language::En, Key::SrvCreateGroup))
                .accesskit_node()
                .is_disabled(),
            "a subscription group cannot be created without a URL"
        );
    }

    #[test]
    fn the_group_dialog_creates_a_subscription_group_that_fetches_on_create() {
        use crate::model::servers::{GroupKind, Subscription};
        let mut servers = crate::model::ServersFile::default();
        let draft = GroupDraft {
            kind: GroupKind::Subscription,
            title: "Feed".into(),
            url: "https://example.com/sub".into(),
            custom_user_agent: true,
            user_agent: "broccoli/1".into(),
            ..GroupDraft::default()
        };
        let id = ServersScreen::commit_group_dialog(
            draft,
            &mut servers,
            &mut crate::model::Settings::default(),
        )
        .expect("a new subscription group starts its first fetch");

        let group = servers
            .groups
            .iter()
            .find(|group| group.id == id)
            .expect("the group is stored");
        assert_eq!(GroupKind::Subscription, group.kind());
        assert_eq!("Feed", group.title);
        let subscription: &Subscription = group
            .subscription
            .as_ref()
            .expect("a subscription group carries its feed");
        assert_eq!("https://example.com/sub", subscription.url);
        assert!(subscription.user_agent_custom);
        assert_eq!("broccoli/1", subscription.user_agent);
        assert!(!subscription.title_auto);
    }

    #[test]
    fn an_edited_draft_cannot_convert_a_manual_group_into_a_subscription() {
        use crate::model::servers::{Group, GroupKind};
        let mine = Group::new("Mine");
        let id = mine.id.clone();
        let mut servers = crate::model::ServersFile::default();
        servers.groups.push(mine);
        let draft = GroupDraft {
            editing: Some(id.clone()),
            kind: GroupKind::Subscription,
            title: "Mine".into(),
            url: "https://example.com/sub".into(),
            ..GroupDraft::default()
        };
        let fetch = ServersScreen::commit_group_dialog(
            draft,
            &mut servers,
            &mut crate::model::Settings::default(),
        );
        assert!(fetch.is_none(), "an edited group never starts a fetch");
        let group = servers
            .groups
            .iter()
            .find(|group| group.id == id)
            .expect("the group stays");
        assert_eq!(
            GroupKind::Manual,
            group.kind(),
            "the kind is fixed at creation"
        );
        assert!(group.subscription.is_none());
    }

    #[test]
    fn a_group_tab_renames_its_group_and_every_tag_it_prefixes() {
        use crate::model::servers::Group;
        let mut rig = UiTestRig::default();
        let group = Group::new("Feed");
        let feed_id = group.id.clone();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        tokyo.group = feed_id;
        tokyo.enabled = true;
        rig.servers.profiles.push(tokyo);
        rig.servers.groups.push(group);
        rig.servers.hydrate_group_titles();
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();

        harness.get_by_label("Feed").click_secondary();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvRenameGroup))
            .click();
        harness.run();
        replace_field_text(
            &mut harness,
            t(Language::En, Key::SrvSubscriptionTitle),
            "Mine",
        );
        harness
            .get_by_label(t(Language::En, Key::SrvSaveSubscription))
            .click();
        harness.run();

        let servers = &harness.state().1.servers;
        assert!(
            servers.groups.iter().any(|group| group.title == "Mine"),
            "the group takes the new title"
        );
        assert_eq!(
            "[Mine] Tokyo",
            servers.profiles[0].tag(),
            "the rename rewrites every tag the group prefixes"
        );
        assert!(
            harness.query_by_label("Mine").is_some(),
            "the tab shows the new title"
        );
    }

    #[test]
    fn deleting_a_group_tab_asks_first_then_removes_its_servers_and_moves_the_route() {
        use crate::model::servers::Group;
        let mut rig = UiTestRig::default();
        let group = Group::new("Feed");
        let feed_id = group.id.clone();
        let mut fed = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        fed.group = feed_id.clone();
        fed.enabled = true;
        let fed_id = fed.id.clone();
        let own = ServerProfile::new("Own", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles = vec![own, fed];
        rig.servers.groups.push(group);
        rig.servers.active = Some(fed_id.clone());
        rig.servers.hydrate_group_titles();
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();

        harness.get_by_label("Feed").click_secondary();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvDeleteGroup))
            .click();
        harness.run();
        assert!(
            harness
                .state()
                .1
                .servers
                .groups
                .iter()
                .any(|group| group.id == feed_id),
            "the confirmation has not deleted the group yet"
        );
        harness.get_by_label(t(Language::En, Key::Delete)).click();
        harness.run();

        let servers = &harness.state().1.servers;
        assert!(
            !servers.groups.iter().any(|group| group.id == feed_id),
            "the group record is gone"
        );
        assert!(
            !servers.profiles.iter().any(|profile| profile.id == fed_id),
            "the group's servers are gone"
        );
        assert_eq!(
            Some(crate::model::inbound::BLOCK_OUTBOUND_TAG),
            servers.active.as_deref(),
            "deleting the active server moves the route to Block"
        );
        assert!(
            harness.query_by_label("Feed").is_none(),
            "the group's tab is gone"
        );
    }

    #[test]
    fn the_default_tabs_offer_no_group_rename_or_delete() {
        let (rig, _) = tab_rig(&["Alpha"], &["Bravo"]);
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        for tab in [Key::SrvTabEmitted, Key::SrvTabManual, Key::SrvTabAll] {
            harness.get_by_label(t(Language::En, tab)).click_secondary();
            harness.run();
            assert!(
                harness
                    .query_by_label(t(Language::En, Key::SrvRenameGroup))
                    .is_none(),
                "the {tab:?} tab cannot be renamed"
            );
            assert!(
                harness
                    .query_by_label(t(Language::En, Key::SrvDeleteGroup))
                    .is_none(),
                "the {tab:?} tab cannot be deleted"
            );
        }
    }

    #[test]
    fn the_add_editor_group_defaults_to_the_current_tab() {
        // From the two views, a new server lands in `Manual`.
        let (rig, _) = tab_rig(&["Alpha"], &["Bravo"]);
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        open_add_editor(&mut harness);
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvGroup))
                .is_some(),
            "the add editor offers a group picker"
        );
        let draft = harness
            .state()
            .0
            .add
            .draft
            .as_ref()
            .expect("the add editor opens");
        assert_eq!(
            crate::model::servers::MANUAL_GROUP_ID,
            draft.profile.group_id()
        );

        // From a group tab, the same command targets that group.
        let (rig, feed_id) = tab_rig(&["Alpha"], &["Bravo"]);
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness.get_by_label("Feed").click();
        harness.run();
        open_add_editor(&mut harness);
        let draft = harness
            .state()
            .0
            .add
            .draft
            .as_ref()
            .expect("the add editor opens");
        assert_eq!(feed_id, draft.profile.group_id());
    }

    #[test]
    fn opening_the_import_from_a_group_tab_targets_that_group() {
        let (rig, feed_id) = tab_rig(&["Alpha"], &["Bravo"]);
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness.get_by_label("Feed").click();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvImportLinks))
            .click();
        harness.run();
        assert_eq!(
            Some(feed_id),
            harness.state().0.import_group.clone(),
            "a paste lands in the tab that opened it"
        );

        let (rig, _) = tab_rig(&["Alpha"], &["Bravo"]);
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvImportLinks))
            .click();
        harness.run();
        assert_eq!(
            Some(crate::model::servers::MANUAL_GROUP_ID.to_owned()),
            harness.state().0.import_group.clone(),
            "a view falls back to Manual"
        );
    }

    #[test]
    fn a_group_tab_pins_and_unpins_from_its_context_menu() {
        use crate::model::servers::Group;
        let mut rig = UiTestRig::default();
        let first = Group::new("First");
        let second = Group::new("Second");
        let second_id = second.id.clone();
        rig.servers.groups = vec![Group::manual(), first, second];
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        let x = |harness: &Harness<'static, (ServersScreen, UiTestRig)>, label: &str| {
            harness.get_by_label(label).rect().center().x
        };
        assert!(x(&harness, "First") < x(&harness, "Second"));

        harness.get_by_label("Second").click_secondary();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvPinTab))
            .click();
        harness.run();
        assert!(
            harness
                .state()
                .1
                .servers
                .groups
                .iter()
                .find(|group| group.id == second_id)
                .expect("the group exists")
                .pinned,
            "the pin is stored on the group record"
        );
        assert!(harness.state().1.requests.dirty);
        assert!(
            x(&harness, "Second") < x(&harness, "First"),
            "a pinned tab moves directly after the defaults"
        );

        harness.get_by_label("Second").click_secondary();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvUnpinTab))
            .click();
        harness.run();
        assert!(
            !harness
                .state()
                .1
                .servers
                .groups
                .iter()
                .find(|group| group.id == second_id)
                .expect("the group exists")
                .pinned
        );
        assert!(x(&harness, "First") < x(&harness, "Second"));
    }

    #[test]
    fn dragging_a_group_tab_persists_its_bands_drag_order() {
        use crate::model::servers::Group;
        let mut rig = UiTestRig::default();
        let first = Group::new("First");
        let second = Group::new("Second");
        let (first_id, second_id) = (first.id.clone(), second.id.clone());
        rig.servers.groups = vec![Group::manual(), first, second];
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        let first_rect = harness.get_by_label("First").rect();
        let second_rect = harness.get_by_label("Second").rect();
        drag_list_row(
            &mut harness,
            first_rect.center(),
            egui::pos2(second_rect.right() - 4.0, second_rect.center().y),
        );
        assert!(
            !egui::DragAndDrop::has_any_payload(&harness.ctx),
            "the release must end the drag"
        );
        let ids: Vec<&str> = harness
            .state()
            .1
            .servers
            .groups
            .iter()
            .map(|group| group.id.as_str())
            .collect();
        assert_eq!(
            ids,
            [
                crate::model::servers::MANUAL_GROUP_ID,
                second_id.as_str(),
                first_id.as_str()
            ],
            "the dropped position is the stored group order"
        );
        assert!(
            harness.state().1.requests.dirty,
            "a tab drag persists the new group order"
        );
    }

    #[test]
    fn the_subscription_card_renders_only_on_a_subscription_tab() {
        use crate::model::servers::{Group, RefreshReport, Subscription, SubscriptionMetadata};
        let mut rig = UiTestRig::default();
        let mut group = Group::new("Feed");
        group.subscription = Some(Subscription {
            url: "https://example.com/sub".into(),
            metadata: Some(SubscriptionMetadata {
                upload: 1_000,
                download: 2_000,
                total: 10_000,
                update_interval: 12,
                ..Default::default()
            }),
            report: Some(RefreshReport::default()),
            ..Default::default()
        });
        let feed_id = group.id.clone();
        let mut profile = ServerProfile::new("FeedOne", OutboundModel::new(Protocol::Freedom));
        profile.group = feed_id;
        profile.enabled = true;
        rig.servers.profiles = vec![profile];
        rig.servers.groups.push(group);
        rig.servers.hydrate_group_titles();
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();

        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvRefreshSubscription))
                .is_none(),
            "the Emitted view owns no feed"
        );
        harness
            .get_by_label(t(Language::En, Key::SrvTabManual))
            .click();
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvRefreshSubscription))
                .is_none(),
            "a manual group owns no feed"
        );

        harness.get_by_label("Feed").click();
        harness.run();
        for label in [
            Key::SrvRefreshSubscription,
            Key::SrvShowReport,
            Key::SrvDeleteGroup,
        ] {
            assert!(
                harness.query_by_label(t(Language::En, label)).is_some(),
                "the subscription card must offer {label:?}"
            );
        }
        assert!(
            harness.query_by_label_contains("30%").is_some(),
            "the card shows the quota use"
        );
        assert!(
            harness.query_by_label_contains("12 h").is_some(),
            "the card shows the provider's update hint"
        );
    }

    #[test]
    fn the_servers_screen_is_a_toolbar_over_a_full_width_table() {
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(ServerProfile::new(
            "Tokyo",
            OutboundModel::new(Protocol::Freedom),
        ));
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();

        // The commands sit above the table, and the search field ends the
        // toolbar row.
        for label in [
            t(Language::En, Key::SrvAddServer),
            t(Language::En, Key::SrvNewGroup),
            t(Language::En, Key::SrvImportLinks),
            t(Language::En, Key::TestLatency),
            t(Language::En, Key::SrvFitColumns),
        ] {
            assert!(
                harness
                    .query_by_role_and_label(egui::accesskit::Role::Button, label)
                    .is_some(),
                "the toolbar must render the {label:?} command"
            );
        }
        let search = harness
            .query_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("the toolbar must render the search field");
        assert!(
            search.rect().center().x > DEFAULT_TEST_VIEWPORT.x / 2.0,
            "search must sit at the toolbar's end, on the right of its commands"
        );

        // The table names its columns: switch, name, latency, protocol,
        // address:port.
        for header in [
            t(Language::En, Key::SrvColEnabled),
            t(Language::En, Key::SrvColName),
            t(Language::En, Key::SrvColProtocol),
            t(Language::En, Key::SrvColAddress),
            t(Language::En, Key::SrvColLatency),
        ] {
            assert!(
                harness.query_all_by_label(header).next().is_some(),
                "the table must render the {header:?} column header"
            );
        }

        // No editor occupies the screen until one is opened.
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvValidateAndSave))
                .is_none(),
            "no editor may occupy the screen when nothing is edited"
        );

        // The emitted table's columns run order → switch → name → latency →
        // protocol → address, one x per column.
        let x = |label: &str| {
            harness
                .query_all_by_label(label)
                .next()
                .unwrap_or_else(|| panic!("the table must render the {label:?} column header"))
                .rect()
                .center()
                .x
        };
        for pair in [
            (Key::SrvColOrder, Key::SrvColEnabled),
            (Key::SrvColEnabled, Key::SrvColName),
            (Key::SrvColName, Key::SrvColLatency),
            (Key::SrvColLatency, Key::SrvColProtocol),
            (Key::SrvColProtocol, Key::SrvColAddress),
        ] {
            assert!(
                x(t(Language::En, pair.0)) < x(t(Language::En, pair.1)),
                "{:?} must sit left of {:?}",
                t(Language::En, pair.0),
                t(Language::En, pair.1),
            );
        }

        // A plain click only selects the row: the editor window stays shut.
        // (The disabled fixture is listed on `All`; `Emitted` carries only
        // what the configuration emits.)
        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run();
        harness.get_by_label("Tokyo").click();
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvValidateAndSave))
                .is_none(),
            "a plain click must not open the editor window"
        );
    }

    /// The tab strip clears the toolbar: the rule under the selected tab sits
    /// three points into the gap, so the first control is twelve points below
    /// the rule and fifteen below the tab's label.
    #[test]
    fn the_tab_strip_clears_the_toolbar_by_twelve_points() {
        let mut harness = screen_harness(drag_rig(), ServersScreen::default());
        harness.run();
        let tab = harness.get_by_label(t(Language::En, Key::SrvTabAll)).rect();
        let toolbar = harness
            .get_by_label(t(Language::En, Key::SrvAddServer))
            .rect();
        let gap = toolbar.top() - tab.bottom();
        assert!(
            (gap - 15.0).abs() <= 1.0,
            "the toolbar must clear the tab's rule by twelve points, not {gap}"
        );
    }

    /// The row menu is the whole command surface: a selection adds nothing to
    /// the toolbar, and the switch lives there as one flipping item.
    #[test]
    fn a_selection_adds_no_toolbar_command_and_the_menu_owns_the_switch() {
        let mut harness = screen_harness(drag_rig(), ServersScreen::default());
        harness.run();
        click_row_with(&mut harness, "Alpha", egui::Modifiers::NONE);
        click_row_with(&mut harness, "Bravo", egui::Modifiers::CTRL);
        assert_eq!(selected_names(&harness), ["Alpha", "Bravo"]);
        for key in [
            Key::SrvEnableSelected,
            Key::SrvDisableSelected,
            Key::SrvShare,
            Key::SrvDeleteEllipsis,
        ] {
            assert!(
                harness
                    .query_all_by_label(t(Language::En, key))
                    .next()
                    .is_none(),
                "a selection must not add {key:?} to the toolbar"
            );
        }

        // The menu carries every command, and the switch is one item.
        harness.get_by_label("Bravo").click_secondary();
        harness.run();
        for key in [
            Key::SrvEdit,
            Key::SrvSetActive,
            Key::SrvDuplicate,
            Key::SrvCopyToGroup,
            Key::SrvShare,
            Key::SrvDeleteEllipsis,
        ] {
            assert!(
                harness
                    .query_all_by_label(t(Language::En, key))
                    .next()
                    .is_some(),
                "the row menu must offer {key:?}"
            );
        }
        let switches = harness
            .query_all_by_label(t(Language::En, Key::SrvEnableSelected))
            .count()
            + harness
                .query_all_by_label(t(Language::En, Key::SrvDisableSelected))
                .count();
        assert_eq!(switches, 1, "the menu carries one enable/disable item");
    }

    /// The list offers the same reveal control as the editor while the
    /// privacy setting hides server information, and the revealed endpoint is
    /// the one the row would otherwise hide.
    #[test]
    fn the_list_reveals_hidden_endpoints_when_asked() {
        let mut rig = UiTestRig::default();
        rig.settings.hide_server_info = true;
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Vless));
        let ProtocolSettings::Vless(settings) = &mut tokyo.outbound.settings else {
            unreachable!("Vless is the default protocol");
        };
        settings.address = "203.0.113.7".into();
        settings.port = 443;
        tokyo.enabled = true;
        rig.servers.profiles.push(tokyo);
        let mut harness = wide_table_harness(rig);
        harness.run();
        assert!(
            harness
                .query_all_by_label("203.0.113.7:443")
                .next()
                .is_none(),
            "the endpoint stays masked while the setting hides it"
        );

        harness
            .get_by_label(t(Language::En, Key::SrvRevealSecrets))
            .click();
        harness.run();
        assert!(
            harness
                .query_all_by_label("203.0.113.7:443")
                .next()
                .is_some(),
            "Reveal must show the endpoint the row hides"
        );

        harness
            .get_by_label(t(Language::En, Key::SrvHideSecrets))
            .click();
        harness.run();
        assert!(
            harness
                .query_all_by_label("203.0.113.7:443")
                .next()
                .is_none(),
            "Hide must mask the endpoint again"
        );
    }

    /// The header's names sit exactly over the cells they name: columns that
    /// drift between the header and the rows make the table unreadable,
    /// whatever its colours.
    #[test]
    fn every_row_cell_sits_under_its_column_header() {
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Vless));
        tokyo.enabled = true;
        let ProtocolSettings::Vless(settings) = &mut tokyo.outbound.settings else {
            unreachable!("Vless is the default protocol");
        };
        settings.address = "203.0.113.7".into();
        settings.port = 443;
        tokyo.verdict = Some(ProbeVerdict::delay(12, ProbeSource::LatencyTest));
        rig.servers.profiles.push(tokyo);
        let mut harness = wide_table_harness(rig);
        harness.run();

        let left = |harness: &Harness<'static, (ServersScreen, UiTestRig)>, label: &str| {
            harness
                .query_all_by_label(label)
                .next()
                .unwrap_or_else(|| panic!("the table must render the {label:?} cell"))
                .rect()
                .left()
        };
        for (header, cell) in [
            (Key::SrvColName, "Tokyo"),
            (Key::SrvColProtocol, "vless"),
            (Key::SrvColAddress, "203.0.113.7:443"),
        ] {
            let header_x = left(&harness, t(Language::En, header));
            let cell_x = left(&harness, cell);
            assert!(
                (header_x - cell_x).abs() < 0.5,
                "the {cell:?} cell must start on its column header's x ({cell_x} vs {header_x})"
            );
        }

        // A right-aligned column shares its right edge, and the switch's own
        // control sits on its column's x.
        let right = |harness: &Harness<'static, (ServersScreen, UiTestRig)>, label: &str| {
            harness
                .query_all_by_label(label)
                .next()
                .unwrap_or_else(|| panic!("the table must render the {label:?} cell"))
                .rect()
                .right()
        };
        let header = right(&harness, t(Language::En, Key::SrvColLatency));
        let cell = right(&harness, "12 ms");
        assert!(
            (header - cell).abs() < 0.5,
            "the latency value must end on its column header's right edge ({cell} vs {header})"
        );
        let header = left(&harness, t(Language::En, Key::SrvColEnabled));
        let switch = harness
            .query_all_by_role(egui::accesskit::Role::CheckBox)
            .next()
            .expect("the row must render its switch")
            .rect()
            .left();
        assert!(
            (header - switch).abs() < 0.5,
            "the switch must sit on its column header's x ({switch} vs {header})"
        );

        // The latency column sits between the tag and the protocol, so its
        // header and value end left of where the protocol column starts.
        let latency_end = right(&harness, t(Language::En, Key::SrvColLatency));
        let protocol_start = left(&harness, t(Language::En, Key::SrvColProtocol));
        assert!(
            latency_end <= protocol_start,
            "the latency column must end left of the protocol column ({latency_end} vs {protocol_start})"
        );
    }

    /// A divider drag resizes the column on its left by the pointer's whole
    /// movement and moves nothing else: the neighbour keeps its width and
    /// the table's total absorbs the change.
    #[test]
    fn dragging_a_column_divider_resizes_only_its_left_column() {
        let widths = ColumnWidths {
            name: 400.0,
            ..TABLE_DEFAULT_WIDTHS
        };
        let columns = table_columns(TableShape::default(), widths);
        let resized = drag_divider(widths, Column::Protocol, 20.0);
        assert!((resized.protocol - (widths.protocol + 20.0)).abs() < 0.01);
        assert!(
            (resized.address - widths.address).abs() < 0.01
                && (resized.latency - widths.latency).abs() < 0.01
                && (resized.name - widths.name).abs() < 0.01,
            "a drag must leave every other column's width alone"
        );
        let after = table_columns(TableShape::default(), resized);
        assert!(
            (after.protocol - (columns.protocol + 20.0)).abs() < 0.01,
            "the protocol column must widen by the dragged distance"
        );
        assert!(
            (after.total() - (columns.total() + 20.0)).abs() < 0.01,
            "the table's total must grow with the dragged column"
        );

        // The divider on the name column's right edge resizes the tag alone.
        let resized = drag_divider(widths, Column::Name, 20.0);
        assert!((resized.name - (widths.name + 20.0)).abs() < 0.01);
        assert!((resized.protocol - widths.protocol).abs() < 0.01);

        // A drag that starts from the fit freezes the tag at the on-screen
        // width the fit gave it, so the stored object carries a real tag
        // width from the very first drag.
        let fitted = ColumnWidths {
            name: 0.0,
            ..TABLE_DEFAULT_WIDTHS
        };
        let flex = table_columns(TableShape::default(), fitted);
        let anchor = frozen_widths(fitted, flex);
        assert!((anchor.name - flex.name).abs() < 0.01);
        let resized = drag_divider(anchor, Column::Protocol, 12.0);
        assert!(
            (resized.name - flex.name).abs() < 0.01,
            "the fit's tag width must be frozen by the first drag"
        );
    }

    /// A drag stops at the dragged column's floor instead of squeezing it out
    /// of existence, and the column beside it keeps its width.
    #[test]
    fn a_drag_stops_at_a_columns_floor() {
        let widths = ColumnWidths {
            address: 120.0,
            ..TABLE_DEFAULT_WIDTHS
        };
        let columns = table_columns(TableShape::default(), widths);
        assert_eq!(columns.address, 120.0);
        let unchanged = drag_divider(widths, Column::Address, -10.0);
        assert!(
            (unchanged.address - 120.0).abs() < 0.01,
            "the address column must not shrink below its floor"
        );
        // A drag far past the floor lands on it rather than overshooting.
        let resized = drag_divider(widths, Column::Protocol, -10_000.0);
        assert!((resized.protocol - column_bounds(Column::Protocol).0).abs() < 0.01);
        assert!(
            (resized.address - widths.address).abs() < 0.01,
            "the neighbour must keep its width when the drag hits a floor"
        );
    }

    /// The toolbar's fit command gives the dragged widths back to the
    /// adaptive fit, and the setting it changes is the one the table reads.
    #[test]
    fn the_fit_columns_command_restores_the_adaptive_widths() {
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(ServerProfile::new(
            "Tokyo",
            OutboundModel::new(Protocol::Freedom),
        ));
        rig.settings.server_table_columns = Some(ColumnWidths {
            order: 60.0,
            switch: 70.0,
            protocol: 200.0,
            address: 300.0,
            latency: 90.0,
            name: 400.0,
            group: 150.0,
        });
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvFitColumns))
            .click();
        harness.run();
        assert!(
            harness.state().1.settings.server_table_columns.is_none(),
            "Fit columns must drop the widths a divider drag stored"
        );
    }

    /// A widths object stored before the column move loads by column name and
    /// applies as stored: the move reorders the display, never the fields.
    #[test]
    fn a_stored_widths_object_loads_and_applies_unchanged() {
        let settings: crate::model::Settings = serde_json::from_str(
            r#"{"serverTableColumns":{"order":56,"switch":64,"name":400,
                "protocol":128,"address":240,"latency":84,"group":160}}"#,
        )
        .expect("a stored widths object must load");
        let stored = settings
            .server_table_columns
            .expect("the stored widths must load as widths");
        assert_eq!(
            stored,
            ColumnWidths {
                order: 56.0,
                switch: 64.0,
                name: 400.0,
                protocol: 128.0,
                address: 240.0,
                latency: 84.0,
                group: 160.0,
            }
        );
        assert_eq!(
            sanitized_widths(stored),
            stored,
            "a stored widths object must apply without migration"
        );
    }

    /// The table is not clamped to the window: a stored layout wider than the
    /// viewport lays out past its right edge, so the last column lives beyond
    /// the window and the horizontal scrollbar is what reaches it.
    #[test]
    fn a_table_wider_than_the_viewport_lays_out_past_it() {
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(ServerProfile::new(
            "Tokyo",
            OutboundModel::new(Protocol::Freedom),
        ));
        rig.settings.server_table_columns = Some(ColumnWidths {
            order: 56.0,
            switch: 64.0,
            name: 240.0,
            latency: 84.0,
            protocol: 200.0,
            address: 720.0,
            group: 160.0,
        });
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run();
        let address = harness
            .query_all_by_label(t(Language::En, Key::SrvColAddress))
            .next()
            .expect("the table renders its Address header")
            .rect();
        let group = harness
            .query_all_by_label(t(Language::En, Key::SrvColGroup))
            .next()
            .expect("the wide table still lays its last column out")
            .rect();
        assert!(
            (group.left() - address.left() - 720.0).abs() < 2.0,
            "the address column must hold the width it was given ({:.1})",
            group.left() - address.left()
        );
        assert!(
            group.left() > DEFAULT_TEST_VIEWPORT.x,
            "the table must lay out past the viewport (last column at {:.1})",
            group.left()
        );
    }

    /// `Fit columns` measures the tag like every other column and sets the
    /// measured widths exactly: a long hostname gets its full width (well past
    /// the old 480-point cap), and a column stored wider than its content
    /// shrinks back to the content on the same command.
    #[test]
    fn fit_columns_gives_a_long_address_its_measured_width_and_shrinks_back() {
        let host = "edge-router-with-a-really-long-name-01.department.example.com";
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Vless));
        let ProtocolSettings::Vless(settings) = &mut tokyo.outbound.settings else {
            unreachable!("Vless is the default protocol");
        };
        settings.address = host.into();
        settings.port = 8443;
        rig.servers.profiles.push(tokyo);
        // Stored wider than the address measures: the fit must shrink it.
        rig.settings.server_table_columns = Some(ColumnWidths {
            order: 56.0,
            switch: 64.0,
            name: 240.0,
            latency: 84.0,
            protocol: 200.0,
            address: 1200.0,
            group: 160.0,
        });
        let mut harness = wide_table_harness(rig);
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run();

        let column_width = |harness: &Harness<'static, (ServersScreen, UiTestRig)>| {
            let left = |label: &str| {
                harness
                    .query_all_by_label(label)
                    .next()
                    .unwrap_or_else(|| panic!("the table must render the {label:?} header"))
                    .rect()
                    .left()
            };
            left(t(Language::En, Key::SrvColGroup)) - left(t(Language::En, Key::SrvColAddress))
        };
        assert!(
            (column_width(&harness) - 1200.0).abs() < 2.0,
            "the stored width must be laid out as stored"
        );

        let endpoint = harness.state().1.servers.profiles[0]
            .server_address()
            .expect("the profile has an address");
        harness
            .get_by_label(t(Language::En, Key::SrvFitColumns))
            .click();
        harness.run();

        let style = harness.ctx.style_of(egui::Theme::Dark);
        let font = egui::TextStyle::Monospace.resolve(&style);
        let measured = harness.ctx.fonts_mut(|fonts| {
            fonts
                .layout_no_wrap(endpoint.clone(), font, egui::Color32::WHITE)
                .size()
                .x
        }) + 2.0 * TABLE_CELL_INSET;
        assert!(
            measured > 480.0,
            "the fixture must measure past the old content cap ({measured:.1})"
        );
        let fitted = column_width(&harness);
        assert!(
            (fitted - measured).abs() < 1.5,
            "the fitted address must hold its measured text width ({fitted:.1} vs {measured:.1})"
        );
        assert!(
            harness.state().1.settings.server_table_columns.is_none(),
            "Fit columns must clear the stored widths it replaces"
        );
    }

    /// The fit leaves the tag at its measured width; the width the viewport
    /// has left over stays after the table instead of stretching the tag.
    #[test]
    fn fit_columns_leaves_the_spare_width_after_the_table() {
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(ServerProfile::new(
            "Tokyo",
            OutboundModel::new(Protocol::Freedom),
        ));
        let mut harness = wide_table_harness(rig);
        harness.run();

        // The fit measures every column; the tag no longer absorbs what the
        // viewport has left, so the table ends before the right edge and the
        // empty band sits after it instead of between the tag and latency.
        let address_right = harness
            .query_all_by_label(t(Language::En, Key::SrvColAddress))
            .next()
            .expect("the table must render its Address header")
            .rect()
            .right();
        let viewport = harness.ctx.input(|i| i.viewport_rect().right());
        assert!(
            viewport - address_right > 40.0,
            "the spare width must stay to the right of the table ({:.1})",
            viewport - address_right
        );
    }

    /// A drag on a header divider follows the pointer and resizes only the
    /// column left of it: the address column shifts by the whole dragged
    /// distance while its own width, and the protocol column's start, stay
    /// where they were.
    #[test]
    fn dragging_a_divider_moves_the_target_column_and_leaves_the_neighbour_alone() {
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Vless));
        let ProtocolSettings::Vless(settings) = &mut tokyo.outbound.settings else {
            unreachable!("Vless is the default protocol");
        };
        settings.address = "203.0.113.7".into();
        settings.port = 443;
        rig.servers.profiles.push(tokyo);
        let mut harness = wide_table_harness(rig);
        harness.run();
        // The `All` tab carries the group column, the address column's right
        // edge, so the address width can be read from the header band.
        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run();

        let rect_of = |harness: &Harness<'static, (ServersScreen, UiTestRig)>, label: &str| {
            harness
                .query_all_by_label(label)
                .next()
                .unwrap_or_else(|| panic!("the table must render the {label:?} header"))
                .rect()
        };
        let address = rect_of(&harness, t(Language::En, Key::SrvColAddress));
        let protocol = rect_of(&harness, t(Language::En, Key::SrvColProtocol));
        let group = rect_of(&harness, t(Language::En, Key::SrvColGroup));
        let address_width = group.left() - address.left();
        let protocol_width = address.left() - protocol.left();
        // The divider before the address column sits one cell inset left of
        // the header's text.
        let divider = egui::pos2(address.left() - TABLE_CELL_INSET, address.center().y);
        harness.hover_at(divider);
        harness.step();
        harness.drag_at(divider);
        harness.step();
        // Two moves of ten points: the drag follows the pointer's total
        // movement, so the column lands twenty points wider, not ten.
        for step in 1..=2 {
            let pos = divider + egui::vec2(10.0 * step as f32, 0.0);
            harness.hover_at(pos);
            harness.step();
        }
        // A frame where the pointer does not move adds nothing: the layout
        // comes from the press, not from an accumulation of frames.
        harness.hover_at(divider + egui::vec2(20.0, 0.0));
        harness.step();
        let held = rect_of(&harness, t(Language::En, Key::SrvColAddress));
        assert!(
            (held.left() - address.left() - 20.0).abs() < 2.0,
            "a motionless frame must not move the column again (moved {:.1})",
            held.left() - address.left()
        );
        harness.drop_at(divider + egui::vec2(20.0, 0.0));
        harness.step();

        let moved = rect_of(&harness, t(Language::En, Key::SrvColAddress));
        let moved_protocol = rect_of(&harness, t(Language::En, Key::SrvColProtocol));
        let moved_group = rect_of(&harness, t(Language::En, Key::SrvColGroup));
        assert!(
            (moved.left() - address.left() - 20.0).abs() < 2.0,
            "the address column must follow the pointer (moved {:.1})",
            moved.left() - address.left()
        );
        assert!(
            (moved_protocol.left() - protocol.left()).abs() < 0.5,
            "the protocol column's own start must not move"
        );
        assert!(
            (moved_group.left() - group.left() - 20.0).abs() < 2.0,
            "the columns after the dragged one must shift with it (moved {:.1})",
            moved_group.left() - group.left()
        );
        assert!(
            ((moved_group.left() - moved.left()) - address_width).abs() < 2.0,
            "the address column must keep its width ({:.1} vs {address_width:.1})",
            moved_group.left() - moved.left()
        );
        let widths = harness
            .state()
            .1
            .settings
            .server_table_columns
            .expect("a divider drag must store the widths it made");
        assert!(
            (widths.protocol - (protocol_width + 20.0)).abs() < 2.0,
            "the stored protocol width must carry the dragged distance ({:.1} vs {protocol_width:.1})",
            widths.protocol
        );
    }

    #[test]
    fn double_clicking_a_row_opens_the_editor_window() {
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        tokyo.enabled = true;
        rig.servers.profiles.push(tokyo);
        let mut harness = fast_servers_harness(rig);
        harness.run();
        harness.get_by_label("Tokyo").click();
        harness.get_by_label("Tokyo").click();
        harness.run();

        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvValidateAndSave))
                .is_some(),
            "a double click must open the editor window"
        );
        // The window holds the clicked row's profile: its name field carries
        // the row's name, and the table still lists the row behind it.
        assert!(
            harness
                .query_all_by_role(egui::accesskit::Role::TextInput)
                .any(|node| node.accesskit_node().value().as_deref() == Some("Tokyo")),
            "the editor window must hold the double-clicked profile's draft"
        );
        assert!(harness.query_by_label("Tokyo").is_some());
    }

    #[test]
    fn the_row_context_menu_offers_the_six_commands_and_no_inline_icons() {
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        tokyo.enabled = true;
        rig.servers.profiles.push(tokyo);
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::ProbeRow))
                .is_none()
                && harness
                    .query_by_label(t(Language::En, Key::DeleteRow))
                    .is_none(),
            "a table row must render no inline probe or delete control"
        );

        harness.get_by_label("Tokyo").click_secondary();
        harness.run();
        for label in [
            t(Language::En, Key::SrvEdit),
            t(Language::En, Key::SrvSetActive),
            t(Language::En, Key::SrvDuplicate),
            t(Language::En, Key::TestLatency),
            t(Language::En, Key::SrvShare),
            t(Language::En, Key::SrvDeleteEllipsis),
        ] {
            assert!(
                harness.query_all_by_label(label).next().is_some(),
                "the row menu must offer {label:?}"
            );
        }

        // Edit is the command that opens the same window a double click does.
        harness
            .get_all_by_label(t(Language::En, Key::SrvEdit))
            .last()
            .expect("the row menu offers Edit")
            .click();
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvValidateAndSave))
                .is_some(),
            "the Edit command must open the editor window"
        );
    }

    #[test]
    fn the_row_menu_duplicates_a_profile_beside_it() {
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        tokyo.enabled = true;
        rig.servers.profiles.push(tokyo);
        rig.servers.hydrate_group_titles();
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness.get_by_label("Tokyo").click_secondary();
        harness.run();
        harness
            .get_all_by_label(t(Language::En, Key::SrvDuplicate))
            .last()
            .expect("the row menu offers Duplicate")
            .click();
        harness.run();

        let state = harness.state();
        let profiles = &state.1.servers.profiles;
        assert_eq!(profiles.len(), 2, "the copy lands beside the original");
        assert_eq!(profiles[1].name, "Tokyo copy");
        assert_ne!(profiles[1].id, profiles[0].id, "the copy gets its own id");
        assert_eq!(
            profiles[1].group_id(),
            crate::model::servers::MANUAL_GROUP_ID,
            "the copy stays in the original's group"
        );
        assert!(state.1.requests.dirty, "the copy is a configuration change");
        assert!(
            harness.query_by_label("Tokyo copy").is_some(),
            "the copy renders as a row"
        );
    }

    /// A row's detail cells for the standalone row tests: a protocol with a
    /// security and a visible endpoint.
    fn row_detail_fixture() -> RowDetail {
        RowDetail {
            protocol: "vless · tls".into(),
            endpoint: "203.0.113.7:443".into(),
            endpoint_hidden: false,
        }
    }

    #[test]
    fn server_row_keeps_each_column_inside_its_own_cell() {
        // A long name must truncate at its column boundary, and the protocol,
        // endpoint and latency columns must stay in order and inside the
        // band — a table reads by column, so no cell may paint over the next.
        let long_name = "tokyo-edge-01.example.com very long server name that used to overlap the latency badge and the following columns";
        let width = 900.0;
        let mut harness = harness_builder()
            .with_size(egui::vec2(width, 100.0))
            .build_ui(|ui| {
                let badge = LatencyBadge::new(
                    Some(&ProbeVerdict::delay(12, ProbeSource::LatencyTest)),
                    Language::En,
                    status_colors_of(ui),
                );
                let columns = table_columns(TableShape::default(), TABLE_DEFAULT_WIDTHS);
                let _ = server_list_row(
                    ui,
                    Language::En,
                    columns,
                    RowCells {
                        name: long_name,
                        detail: &row_detail_fixture(),
                        verdict: None,
                        extras: RowExtras::default(),
                    },
                    RowState {
                        selected: false,
                        joined_above: false,
                        joined_below: false,
                        active: false,
                        hop: false,
                        dialers: &[],
                        frozen: false,
                        switch: RowSwitch {
                            checked: false,
                            locked_hint: None,
                        },
                    },
                    &badge,
                );
            });
        harness.run();

        let name = harness.get_by_label(long_name);
        let protocol = harness.get_by_label("vless · tls");
        let endpoint = harness.get_by_label("203.0.113.7:443");
        let latency = harness.get_by_label("12 ms");
        assert!(
            name.rect().max.x <= latency.rect().min.x,
            "the name must stop at its column: name ends at x={}, latency starts at x={}",
            name.rect().max.x,
            latency.rect().min.x,
        );
        assert!(
            latency.rect().max.x <= protocol.rect().min.x,
            "the latency column must stop before the protocol column"
        );
        assert!(
            protocol.rect().max.x <= endpoint.rect().min.x,
            "the protocol column must stop before the endpoint column"
        );
        assert!(
            endpoint.rect().max.x <= width + 0.5,
            "the endpoint column must stay inside the band"
        );
        assert!(
            harness.query_by_label("⚡").is_none() && harness.query_by_label("🗑").is_none(),
            "a table row must not render inline probe or delete controls"
        );
    }

    /// Drive a `server_list_row` in a harness, click the node found by
    /// `click_label`, and return whether the row reported a click.
    ///
    /// The flag accumulates over frames: kittest runs one frame per pointer
    /// event and egui may repaint afterwards, so reading only the last frame
    /// would miss the click.
    fn drive_row_click(click_label: &str) -> bool {
        let clicked = Rc::new(RefCell::new(false));
        let clicked_ui = Rc::clone(&clicked);
        let mut harness = harness_builder().build_ui(move |ui| {
            let badge = LatencyBadge::new(
                Some(&ProbeVerdict::delay(12, ProbeSource::LatencyTest)),
                Language::En,
                status_colors_of(ui),
            );
            let columns = table_columns(TableShape::default(), TABLE_DEFAULT_WIDTHS);
            let clicks = server_list_row(
                ui,
                Language::En,
                columns,
                RowCells {
                    name: "A server",
                    detail: &row_detail_fixture(),
                    verdict: None,
                    extras: RowExtras::default(),
                },
                RowState {
                    selected: false,
                    joined_above: false,
                    joined_below: false,
                    active: false,
                    hop: false,
                    dialers: &[],
                    frozen: false,
                    switch: RowSwitch {
                        checked: false,
                        locked_hint: None,
                    },
                },
                &badge,
            );
            *clicked_ui.borrow_mut() |= clicks.row.clicked() || clicks.name.clicked();
        });
        harness.get_by_label(click_label).click();
        harness.run();
        *clicked.borrow()
    }

    #[test]
    fn the_row_switch_reports_a_toggle_and_a_locked_one_does_not() {
        for locked in [None, Some("dialed through")] {
            let toggled = Rc::new(RefCell::new(false));
            let toggled_ui = Rc::clone(&toggled);
            let mut harness = harness_builder().build_ui(move |ui| {
                let badge = LatencyBadge::new(
                    Some(&ProbeVerdict::delay(12, ProbeSource::LatencyTest)),
                    Language::En,
                    status_colors_of(ui),
                );
                let columns = table_columns(TableShape::default(), TABLE_DEFAULT_WIDTHS);
                let clicks = server_list_row(
                    ui,
                    Language::En,
                    columns,
                    RowCells {
                        name: "A server",
                        detail: &row_detail_fixture(),
                        verdict: None,
                        extras: RowExtras::default(),
                    },
                    RowState {
                        selected: false,
                        joined_above: false,
                        joined_below: false,
                        active: false,
                        hop: false,
                        dialers: &[],
                        frozen: false,
                        switch: RowSwitch {
                            checked: false,
                            locked_hint: locked,
                        },
                    },
                    &badge,
                );
                *toggled_ui.borrow_mut() |= clicks.toggle;
            });
            harness.get_by_role(egui::accesskit::Role::CheckBox).click();
            harness.run();
            assert_eq!(
                *toggled.borrow(),
                locked.is_none(),
                "a locked switch must not report a toggle (locked: {locked:?})"
            );
        }
    }

    #[test]
    fn double_clicking_a_row_reports_the_edit_gesture() {
        let doubled = Rc::new(RefCell::new(false));
        let doubled_ui = Rc::clone(&doubled);
        // A click is one frame per queued pointer event, so the harness's
        // default quarter-second step puts two clicks outside egui's
        // double-click delay. A fifth-second step keeps the gesture inside it.
        let mut harness = harness_builder().with_step_dt(0.05).build_ui(move |ui| {
            let badge = LatencyBadge::new(
                Some(&ProbeVerdict::delay(12, ProbeSource::LatencyTest)),
                Language::En,
                status_colors_of(ui),
            );
            let columns = table_columns(TableShape::default(), TABLE_DEFAULT_WIDTHS);
            let clicks = server_list_row(
                ui,
                Language::En,
                columns,
                RowCells {
                    name: "A server",
                    detail: &row_detail_fixture(),
                    verdict: None,
                    extras: RowExtras::default(),
                },
                RowState {
                    selected: false,
                    joined_above: false,
                    joined_below: false,
                    active: false,
                    hop: false,
                    dialers: &[],
                    frozen: false,
                    switch: RowSwitch {
                        checked: false,
                        locked_hint: None,
                    },
                },
                &badge,
            );
            *doubled_ui.borrow_mut() |= clicks.double_clicked();
        });
        harness.get_by_label("A server").click();
        harness.get_by_label("A server").click();
        harness.run();
        assert!(
            *doubled.borrow(),
            "the second press of a double click must report the edit gesture"
        );
    }

    #[test]
    fn server_row_clicking_the_row_selects_it() {
        // Clicking the latency area (part of the row but not a widget that
        // senses clicks) must select the row.
        assert!(drive_row_click("12 ms"), "clicking the row must select it");
    }

    #[test]
    fn server_row_clicking_the_name_selects_it() {
        // The name button truncates inside its cell, so clicking it must
        // count as selecting the row.
        assert!(
            drive_row_click("A server"),
            "clicking the name must select the row"
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

    /// A three-profile rig, all rows visible on the opening `Emitted` tab, in
    /// list order Alpha → Bravo → Charlie.
    fn drag_rig() -> UiTestRig {
        let mut rig = UiTestRig::default();
        for name in ["Alpha", "Bravo", "Charlie"] {
            let mut profile = ServerProfile::new(name, OutboundModel::new(Protocol::Freedom));
            profile.enabled = true;
            rig.servers.profiles.push(profile);
        }
        rig
    }

    fn drag_harness(rig: UiTestRig) -> Harness<'static, (ServersScreen, UiTestRig)> {
        screen_harness(rig, ServersScreen::default())
    }

    /// Manual [Alpha, Bravo] then Feed [Charlie, Delta], every row emitted and
    /// Alpha active, so `Emitted` shows the active row and then each block:
    /// Alpha → Bravo → Charlie → Delta.
    fn grouped_drag_rig() -> UiTestRig {
        use crate::model::servers::Group;
        let mut rig = UiTestRig::default();
        let feed = Group::new("Feed");
        let feed_id = feed.id.clone();
        for (name, group) in [
            ("Alpha", None),
            ("Bravo", None),
            ("Charlie", Some(feed_id.clone())),
            ("Delta", Some(feed_id)),
        ] {
            let mut profile = ServerProfile::new(name, OutboundModel::new(Protocol::Freedom));
            profile.enabled = true;
            if let Some(group) = group {
                profile.group = group;
            }
            rig.servers.profiles.push(profile);
        }
        rig.servers.groups.push(feed);
        rig.servers.active = Some(rig.servers.profiles[0].id.clone());
        rig.servers.hydrate_group_titles();
        rig
    }

    /// Alpha is the active route and dials through the switched-off Hop;
    /// Bravo and Charlie are enabled siblings, so `Emitted` shows
    /// Alpha → Hop → Bravo → Charlie — the hop between the seed rows.
    fn hop_drag_rig() -> UiTestRig {
        let freedom = || OutboundModel::new(Protocol::Freedom);
        let mut alpha = ServerProfile::new("Alpha", freedom());
        alpha.enabled = true;
        let hop = ServerProfile::new("Hop", freedom());
        let hop_tag = hop.tag();
        alpha.outbound.chain_via(hop_tag);
        let mut bravo = ServerProfile::new("Bravo", freedom());
        bravo.enabled = true;
        let mut charlie = ServerProfile::new("Charlie", freedom());
        charlie.enabled = true;
        let mut rig = UiTestRig::default();
        rig.servers.profiles = vec![alpha, hop, bravo, charlie];
        rig.servers.active = Some(rig.servers.profiles[0].id.clone());
        rig.servers.hydrate_group_titles();
        rig
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

    /// Click the switch of the row labelled `name`. A row switch carries no
    /// text of its own, so the row's name finds the checkbox on its line.
    fn click_row_switch(harness: &mut Harness<'static, (ServersScreen, UiTestRig)>, name: &str) {
        let row_y = harness.get_by_label(name).rect().center().y;
        harness
            .get_all_by_role(egui::accesskit::Role::CheckBox)
            .find(|node| (node.rect().center().y - row_y).abs() < 2.0)
            .unwrap_or_else(|| panic!("the {name:?} row must render a switch"))
            .click();
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
            harness.state().1.requests.dirty,
            "a reorder must mark the model dirty"
        );
        assert!(
            !egui::DragAndDrop::has_any_payload(&harness.ctx),
            "the release must end the drag"
        );
        assert_eq!(
            harness.state().0.selected,
            selected_before,
            "a drag must not change the selection"
        );
    }

    #[test]
    fn dragging_the_last_row_above_the_first_reorders_without_changing_the_route() {
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
        assert!(harness.state().1.requests.dirty);
        // Reordering is not a route choice: the active route stays where the
        // user put it, and only the picker or Set active moves it.
        assert!(
            harness.state().1.servers.active.is_none(),
            "a reorder must not choose the default route"
        );
    }

    #[test]
    fn dragging_a_row_inside_its_block_rewrites_that_groups_order() {
        let mut harness = drag_harness(grouped_drag_rig());
        harness.run();
        let charlie = harness.get_by_label("Charlie").rect();
        let delta = harness.get_by_label("Delta").rect();
        // Delta lands above Charlie: only the Feed block's rows move, and the
        // generated outbounds follow in the same order.
        drag_list_row(
            &mut harness,
            delta.center(),
            egui::pos2(charlie.center().x, charlie.top() + 2.0),
        );
        assert_eq!(
            profile_names(&harness.state().1),
            ["Alpha", "Bravo", "Delta", "Charlie"]
        );
        assert!(
            harness.state().1.requests.dirty,
            "an in-block drag persists the group's row order"
        );
        let rig = &harness.state().1;
        let config = crate::r#gen::generate_with_api_port(&rig.servers, &rig.settings, 10853)
            .expect("generate config");
        let emitted: Vec<&str> = config["outbounds"]
            .as_array()
            .expect("outbounds is an array")
            .iter()
            .take(4)
            .filter_map(|outbound| outbound["tag"].as_str())
            .collect();
        assert_eq!(
            emitted,
            [
                "[Manual] Alpha",
                "[Manual] Bravo",
                "[Feed] Delta",
                "[Feed] Charlie"
            ],
            "the emitted order is the active server, then each block's row order"
        );
    }

    #[test]
    fn a_drop_outside_the_rows_block_is_refused() {
        let mut harness = drag_harness(grouped_drag_rig());
        harness.run();
        let bravo = harness.get_by_label("Bravo").rect();
        let delta = harness.get_by_label("Delta").rect();
        // Delta belongs to Feed; Bravo's gap is inside the Manual block.
        drag_list_row(
            &mut harness,
            delta.center(),
            egui::pos2(bravo.center().x, bravo.top() + 2.0),
        );
        assert_eq!(
            profile_names(&harness.state().1),
            ["Alpha", "Bravo", "Charlie", "Delta"],
            "a cross-block drop must not move the row"
        );
        assert!(
            !harness.state().1.requests.dirty,
            "a refused drop is not a configuration change"
        );
    }

    #[test]
    fn switching_an_emitted_row_off_drops_it_from_the_tab_and_the_configuration() {
        let mut rig = drag_rig();
        rig.servers.active = Some(rig.servers.profiles[0].id.clone());
        let mut harness = drag_harness(rig);
        harness.run();
        click_row_switch(&mut harness, "Bravo");
        harness.run();
        assert!(
            harness.query_by_label("Bravo").is_none(),
            "a switched-off row leaves the Emitted tab"
        );
        assert!(harness.query_by_label("Alpha").is_some());
        assert!(!harness.state().1.servers.profiles[1].enabled);
        assert!(harness.state().1.requests.dirty);
        let rig = &harness.state().1;
        let config = crate::r#gen::generate_with_api_port(&rig.servers, &rig.settings, 10853)
            .expect("generate config");
        let tags: Vec<&str> = config["outbounds"]
            .as_array()
            .expect("outbounds is an array")
            .iter()
            .filter_map(|outbound| outbound["tag"].as_str())
            .collect();
        assert!(
            !tags.contains(&"[Manual] Bravo"),
            "the configuration drops the switched-off server"
        );
        assert!(tags.contains(&"[Manual] Charlie"));
    }

    #[test]
    fn switching_a_group_rows_switch_off_drops_it_from_emitted_too() {
        let mut harness = drag_harness(grouped_drag_rig());
        harness.run();
        harness.get_by_label("Feed").click();
        harness.run();
        click_row_switch(&mut harness, "Charlie");
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvTabEmitted))
            .click();
        harness.run();
        assert!(
            harness.query_by_label("Charlie").is_none(),
            "a row switched off on its group tab leaves Emitted"
        );
        assert!(harness.query_by_label("Delta").is_some());
        // The row still exists, switched off, in `All`.
        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run();
        assert!(harness.query_by_label("Charlie").is_some());
    }

    #[test]
    fn a_chain_only_hop_is_listed_with_a_checked_locked_switch() {
        let freedom = || OutboundModel::new(Protocol::Freedom);
        let mut entry = ServerProfile::new("Entry", freedom());
        entry.enabled = true;
        let hop = ServerProfile::new("Hop", freedom());
        let hop_tag = hop.tag();
        entry.outbound.chain_via(hop_tag);
        let mut rig = UiTestRig::default();
        rig.servers.profiles = vec![entry, hop];
        rig.servers.active = Some(rig.servers.profiles[0].id.clone());
        rig.servers.hydrate_group_titles();
        let mut harness = drag_harness(rig);
        harness.run();
        // The hop is emitted through the chain even though its own switch is
        // off: the row says so — the switch renders checked and locked — and
        // cannot be turned on, so the model stays put.
        assert!(harness.query_by_label("Hop").is_some());
        let row_y = harness.get_by_label("Hop").rect().center().y;
        let switch = harness
            .get_all_by_role(egui::accesskit::Role::CheckBox)
            .find(|node| (node.rect().center().y - row_y).abs() < 2.0)
            .expect("the Hop row must render a switch");
        assert!(
            matches!(
                switch.accesskit_node().toggled(),
                Some(egui::accesskit::Toggled::True)
            ),
            "a chain-only hop is in the generated configuration, so its switch shows checked"
        );
        assert!(
            switch.accesskit_node().is_disabled(),
            "the chain-only switch is locked"
        );
        click_row_switch(&mut harness, "Hop");
        harness.run();
        assert!(harness.query_by_label("Hop").is_some());
        assert!(!harness.state().1.servers.profiles[1].enabled);
        assert!(
            !harness.state().1.requests.dirty,
            "a locked switch is not a configuration change"
        );
    }

    #[test]
    fn a_hop_row_refuses_a_drag_and_the_view_stays_put() {
        let mut harness = drag_harness(hop_drag_rig());
        harness.run();
        let hop = harness.get_by_label("Hop").rect();
        let charlie = harness.get_by_label("Charlie").rect();
        drag_list_row(
            &mut harness,
            hop.center(),
            egui::pos2(charlie.center().x, charlie.bottom() + 8.0),
        );
        assert_eq!(
            profile_names(&harness.state().1),
            ["Alpha", "Hop", "Bravo", "Charlie"],
            "a hop row never lifts, so the stored order stays put"
        );
        assert!(
            !harness.state().1.requests.dirty,
            "a refused hop drag is not a configuration change"
        );
        let y = |name: &str| harness.get_by_label(name).rect().center().y;
        assert!(
            y("Alpha") < y("Hop") && y("Hop") < y("Bravo") && y("Bravo") < y("Charlie"),
            "the Emitted view keeps the hop directly behind its dialer"
        );
    }

    #[test]
    fn dragging_a_seed_left_of_a_hop_still_rewrites_its_group_order() {
        let mut harness = drag_harness(hop_drag_rig());
        harness.run();
        let bravo = harness.get_by_label("Bravo").rect();
        let charlie = harness.get_by_label("Charlie").rect();
        // Charlie's drop point is one visible row above it, but the hop row
        // between the seeds is skipped: the drop lands Charlie before Bravo
        // in the group, not against the hop.
        drag_list_row(
            &mut harness,
            charlie.center(),
            egui::pos2(bravo.center().x, bravo.top() + 2.0),
        );
        assert_eq!(
            profile_names(&harness.state().1),
            ["Alpha", "Hop", "Charlie", "Bravo"],
            "a seed drag rewrites its group's stored order"
        );
        assert!(
            harness.state().1.requests.dirty,
            "a seed drag persists the new group order"
        );
        let y = |name: &str| harness.get_by_label(name).rect().center().y;
        assert!(
            y("Alpha") < y("Hop") && y("Hop") < y("Charlie") && y("Charlie") < y("Bravo"),
            "the hop slot re-derives: it still follows its dialer, now ahead of the seeds"
        );
    }

    #[test]
    fn a_hops_latency_hover_names_the_servers_that_dial_through_it() {
        let freedom = || OutboundModel::new(Protocol::Freedom);
        let mut entry = ServerProfile::new("Entry", freedom());
        entry.enabled = true;
        let mut hop = ServerProfile::new("Hop", freedom());
        let hop_tag = hop.tag();
        entry.outbound.chain_via(hop_tag);
        hop.verdict = Some(ProbeVerdict {
            outcome: ProbeOutcome::Delay(42),
            source: ProbeSource::LatencyTest,
            measured_at: SystemTime::now() - Duration::from_secs(120),
            error: None,
        });
        let mut rig = UiTestRig::default();
        rig.servers.profiles = vec![entry, hop];
        rig.servers.active = Some(rig.servers.profiles[0].id.clone());
        rig.servers.hydrate_group_titles();
        let mut harness = drag_harness(rig);
        harness.run();

        harness.get_by_label("42 ms").hover();
        harness.run();
        harness.run();
        assert!(
            harness
                .query_all_by_label("Dialed by Entry")
                .next()
                .is_some(),
            "a hop's latency hover must name the server that dials through it"
        );
        assert!(
            harness
                .query_all_by_label("Measured 2 minutes ago by a latency test.")
                .next()
                .is_some(),
            "the verdict line stays beside the dialer line"
        );
    }

    #[test]
    fn the_active_row_is_locked_first_and_never_lifts() {
        let mut rig = drag_rig();
        for profile in &mut rig.servers.profiles {
            profile.enabled = true;
        }
        rig.servers.active = Some(rig.servers.profiles[0].id.clone());
        let active_id = rig.servers.profiles[0].id.clone();
        let mut harness = drag_harness(rig);
        harness.run();
        let alpha = harness.get_by_label("Alpha").rect();
        let charlie = harness.get_by_label("Charlie").rect();
        // The active server is always first, so its row never lifts: a press
        // dragged down leaves the stored order alone.
        drag_list_row(
            &mut harness,
            alpha.center(),
            egui::pos2(charlie.center().x, charlie.bottom() + 8.0),
        );
        assert_eq!(
            profile_names(&harness.state().1),
            ["Alpha", "Bravo", "Charlie"]
        );
        assert_eq!(
            harness.state().1.servers.active.as_deref(),
            Some(active_id.as_str())
        );
        assert!(
            !harness.state().1.requests.dirty,
            "dragging the active row is refused, not a configuration change"
        );
        // The active row is a block of its own: no other row can land above
        // it either.
        drag_list_row(
            &mut harness,
            charlie.center(),
            egui::pos2(alpha.center().x, alpha.top() + 2.0),
        );
        assert_eq!(
            profile_names(&harness.state().1),
            ["Alpha", "Bravo", "Charlie"]
        );
        assert!(!harness.state().1.requests.dirty);
    }

    #[test]
    fn set_active_changes_the_route_without_moving_the_row() {
        let mut rig = drag_rig();
        // A balancer owns the default route; choosing a server explicitly must
        // hand it back.
        rig.settings.routing.active_balancer = "route".into();
        let mut harness = drag_harness(rig);
        harness.run();
        harness.get_by_label("Charlie").click_secondary();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvSetActive))
            .click();
        harness.run();
        let rig = &harness.state().1;
        assert_eq!(
            profile_names(rig),
            ["Alpha", "Bravo", "Charlie"],
            "choosing a server does not move its row"
        );
        assert_eq!(
            rig.servers.active.as_deref(),
            Some(rig.servers.profiles[2].id.as_str())
        );
        assert!(
            rig.settings.routing.active_balancer.is_empty(),
            "an explicitly chosen server takes the default route back"
        );
        assert!(rig.requests.dirty);
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
            !harness.state().1.requests.dirty,
            "a cancelled drag must not mark the model dirty"
        );
        assert!(
            !egui::DragAndDrop::has_any_payload(&harness.ctx),
            "the release must end the drag even when it cancels"
        );
    }

    #[test]
    fn holding_a_drag_at_the_lists_bottom_edge_auto_scrolls_and_drops_in_order() {
        let (rig, _ids) = seeded_rig(40);
        let mut harness =
            screen_harness_at(egui::vec2(800.0, 600.0), rig, ServersScreen::default());
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
        // off its own name — is the row the drop must land beside; the
        // assertion below pins that, and that no other row moves.
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
        // The list inserts above a row's midline and below it otherwise, so
        // the drop point is taken just under the label's top edge: that is
        // above the row's midline whatever vertical padding the label carries,
        // and keeps the expected gap independent of the row's pixel height.
        // The edge auto-scroll can still be in flight, so the row is read
        // again after the pointer has settled mid-band and the scroll has run
        // out: dropping at a rect measured a frame early lands one row off.
        let drop_x = target.center().x;
        harness.hover_at(egui::pos2(drop_x, target.top() + 2.0));
        harness.run();
        let target = harness
            .get_by_label(&format!("Server {target_index:02}"))
            .rect();
        let drop_pos = egui::pos2(drop_x, target.top() + 2.0);
        harness.hover_at(drop_pos);
        harness.run();
        harness.drop_at(drop_pos);
        harness.run();
        assert!(
            !egui::DragAndDrop::has_any_payload(&harness.ctx),
            "the release must end the drag"
        );
        assert!(
            harness.state().1.requests.dirty,
            "the drop after an auto-scroll must still move the row"
        );
        let names = profile_names(&harness.state().1);
        // The row under the pointer is measured on the frame that settles the
        // band, not the one that releases the drop, so the gap can be the one
        // above or below it. What a consumer sees is pinned here: the lifted
        // row lands beside the row it was dropped on, and no other row moves.
        let lifted_at = names
            .iter()
            .position(|name| *name == "Server 00")
            .expect("the lifted row stays in the list");
        let target_at = names
            .iter()
            .position(|name| *name == format!("Server {target_index:02}").as_str())
            .expect("the dropped-on row stays in the list");
        assert_eq!(
            lifted_at.abs_diff(target_at),
            1,
            "the lifted row must land at the gap beside the dropped row: {names:?}"
        );
        let mut rest = names.clone();
        rest.remove(lifted_at);
        let expected_rest: Vec<String> =
            (1..40).map(|index| format!("Server {index:02}")).collect();
        assert_eq!(
            rest, expected_rest,
            "the drop must move the lifted row and nothing else"
        );
    }

    #[test]
    fn row_probe_button_requests_one_profile_and_shows_dedicated_feedback() {
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        tokyo.enabled = true;
        let mut osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        osaka.enabled = true;
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka);
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness.get_by_label("Tokyo").click_secondary();
        harness.run();
        harness
            .get_all_by_label(t(Language::En, Key::TestLatency))
            .last()
            .expect("the row menu offers Test latency")
            .click();
        // `click` only queues events, and the pending flag is set at the end
        // of the frame that processes them, so the spinner needs one more
        // frame to appear. The spinner repaints forever, so `run` would never
        // settle — advance the frames by hand.
        harness.run_steps(2);
        harness.state_mut().1.probe_progress = crate::rt::ProbeProgress { done: 0, total: 1 };
        harness.step();

        // The row's command sends exactly the first profile, tagged as single.
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
            harness.query_by_label("Testing 0 of 1").is_some(),
            "a pending probe must render its progress strip"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::TestLatency))
                .is_none(),
            "the strip replaces the toolbar's commands while a probe runs"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::Cancel))
                .is_some(),
            "the strip must offer Cancel"
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
                progress: crate::rt::ProbeProgress { done: 1, total: 1 },
            });
        harness.run();
        assert!(
            harness
                .query_by_label("Server 'Tokyo' responded in 23 ms.")
                .is_some(),
            "a single-probe result must render the dedicated name-based toast"
        );
        assert!(
            harness.query_by_label("Testing 0 of 1").is_none(),
            "the strip must clear once the result is consumed"
        );
    }

    #[test]
    fn a_latency_verdict_renders_its_outcome_and_hover_provenance() {
        let mut rig = UiTestRig::default();
        let mk = |name: &str, verdict: Option<ProbeVerdict>| {
            let mut profile = ServerProfile::new(name, OutboundModel::new(Protocol::Freedom));
            profile.enabled = true;
            profile.verdict = verdict;
            profile
        };
        let two_minutes_ago = SystemTime::now() - Duration::from_secs(120);
        rig.servers.profiles.push(mk(
            "Alive",
            Some(ProbeVerdict {
                outcome: ProbeOutcome::Delay(230),
                source: ProbeSource::LatencyTest,
                measured_at: two_minutes_ago,
                error: None,
            }),
        ));
        rig.servers.profiles.push(mk(
            "Dead",
            Some(ProbeVerdict {
                outcome: ProbeOutcome::Dead,
                source: ProbeSource::Monitoring,
                measured_at: two_minutes_ago,
                error: Some("connection refused".into()),
            }),
        ));
        rig.servers.profiles.push(mk("Blank", None));
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();

        assert!(
            harness.query_by_label("230 ms").is_some(),
            "a delay verdict renders its number"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::LatencyTimeout))
                .is_some(),
            "a dead verdict renders the timeout word instead of an old delay"
        );

        harness.get_by_label("230 ms").hover();
        harness.run();
        harness.run();
        assert!(
            harness
                .query_all_by_label("Measured 2 minutes ago by a latency test.")
                .next()
                .is_some(),
            "the hover must name the source and the relative age"
        );

        harness
            .get_by_label(t(Language::En, Key::LatencyTimeout))
            .hover();
        harness.run();
        harness.run();
        assert!(
            harness
                .get_all_by_label_contains("Error: connection refused")
                .next()
                .is_some(),
            "a dead verdict's hover must carry the captured core error"
        );
    }

    #[test]
    fn a_running_latency_test_freezes_the_list_and_cancel_restores_the_toolbar() {
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        tokyo.enabled = true;
        let mut osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        osaka.enabled = true;
        osaka.verdict = Some(ProbeVerdict::delay(55, ProbeSource::Monitoring));
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::TestLatency))
            .click();
        harness.step();
        assert_eq!(
            harness.state().0.pending_latency_probe,
            Some(false),
            "the toolbar probe must be pending"
        );
        assert!(
            matches!(
                harness
                    .state_mut()
                    .1
                    ._cmd_rx
                    .try_recv()
                    .expect("the probe command"),
                CoreCmd::ProbeLatency { .. }
            ),
            "the test must start with the probe command"
        );

        harness.state_mut().1.probe_progress = crate::rt::ProbeProgress { done: 1, total: 2 };
        harness.step();
        assert!(
            harness.query_by_label("Testing 1 of 2").is_some(),
            "the strip must count the tags the probe reported"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::Cancel))
                .is_some(),
            "Cancel must stay reachable while the test runs"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::TestLatency))
                .is_none()
                && harness
                    .query_by_label(t(Language::En, Key::SrvAddServer))
                    .is_none(),
            "the strip replaces the list commands"
        );

        harness.get_by_label("Tokyo").click();
        harness.step();
        assert!(
            harness.state().0.selection.is_empty(),
            "a frozen list must not take row clicks"
        );

        harness.get_by_label(t(Language::En, Key::Cancel)).click();
        harness.step();
        assert!(
            matches!(
                harness
                    .state_mut()
                    .1
                    ._cmd_rx
                    .try_recv()
                    .expect("the cancel command"),
                CoreCmd::CancelLatencyProbe
            ),
            "Cancel must ask the runtime to end the probe"
        );

        harness
            .state_mut()
            .1
            .probe_feedback
            .park(LatencyProbeResult {
                tags: vec![tokyo.tag(), osaka.tag()],
                result: Err(ProbeFailure::plain(Diag::new(Key::ProbeCancelledByUser))),
                progress: crate::rt::ProbeProgress { done: 1, total: 2 },
            });
        harness.run();
        assert_eq!(
            harness.state().0.pending_latency_probe,
            None,
            "the terminal returns the toolbar"
        );
        assert!(
            harness
                .query_by_label("Latency test cancelled after 1 of 2.")
                .is_some(),
            "the status line must report how far the cancelled test got"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::TestLatency))
                .is_some(),
            "the toolbar's commands must be back"
        );
    }

    #[test]
    fn row_probe_button_includes_chain_dependencies_in_the_child() {
        // A profile chaining via sockopt.dialerProxy references another
        // profile's outbound tag; the isolated probe child must contain the
        // whole chain or the core refuses to start.
        let mut rig = UiTestRig::default();
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        tokyo.enabled = true;
        let mut osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        osaka.enabled = true;
        tokyo.outbound.chain_via(osaka.tag());
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        let mut harness = screen_harness(rig, ServersScreen::default());
        harness.run();
        harness.get_by_label("Tokyo").click_secondary();
        harness.run();
        harness
            .get_all_by_label(t(Language::En, Key::TestLatency))
            .last()
            .expect("the row menu offers Test latency")
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
                progress: crate::rt::ProbeProgress { done: 1, total: 2 },
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
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let mut osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        // Both rows must be on the opening Emitted tab: with nothing selected
        // the toolbar probes the current tab, not the whole profile list.
        tokyo.enabled = true;
        osaka.enabled = true;
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        let mut harness = screen_harness(rig, ServersScreen::default());
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
                progress: crate::rt::ProbeProgress { done: 2, total: 2 },
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
        tokyo.enabled = true;
        let mut osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        osaka.enabled = true;
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.profiles.push(osaka.clone());
        let mut harness = screen_harness(rig, ServersScreen::default());
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
                progress: crate::rt::ProbeProgress { done: 2, total: 2 },
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
        let mut harness = harness_builder().build_ui(move |ui| {
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
        let findings = validate_sockopt(&modeled, "stream.sockopt");
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
            let _harness = harness_builder().build_ui(|ui| {
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
        assert!(validate_sockopt(&modeled, "stream.sockopt").is_empty());

        let rendered = Rc::new(RefCell::new(Some(modeled)));
        let rendered_for_ui = Rc::clone(&rendered);
        let mut reported_changed = false;
        {
            let _harness = harness_builder().build_ui(|ui| {
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
    fn sockopt_verdicts_are_scoped_to_the_block_s_wire_path() {
        let modeled = SockoptModel {
            domain_strategy: "future-strategy".into(),
            ..Default::default()
        };
        let stream_findings = validate_sockopt(&modeled, "stream.sockopt");
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
        let ech_findings = validate_sockopt(&modeled, "stream.tlsSettings.echSockopt");
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
        let mut harness = harness_builder()
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
            import_parsed: vec![Ok(links::ParsedLink {
                profile: ServerProfile::default(),
                ignored: Vec::new(),
            })],
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
        let findings = editor_validation_findings(&invalid);
        // The refusal is the model's verdict, not an editor-minted copy: a
        // fresh VLESS draft's missing address and id come back as
        // `validate_outbound` findings with their wire paths.
        let model = validate_outbound(&invalid.outbound);
        assert_eq!(
            findings.blocking,
            model.blocking().cloned().collect::<Vec<_>>(),
            "the editor's blocking half is the model sweep"
        );
        for (code, path) in [
            (ValidationCode::ServerAddressRequired, "settings.address"),
            (ValidationCode::VlessIdRequired, "settings.id"),
        ] {
            let issue = finding(&findings.blocking, code);
            assert_eq!(issue.path.as_deref(), Some(path), "{issue:?}");
        }
        // `new()` normalizes the empty encryption to `none`; the missing-value
        // rule fires once a draft clears the field, and it is the model's.
        let mut cleared = invalid;
        let ProtocolSettings::Vless(settings) = &mut cleared.outbound.settings else {
            unreachable!()
        };
        settings.encryption.clear();
        let cleared = editor_validation_findings(&cleared);
        let issue = finding(&cleared.blocking, ValidationCode::VlessEncryptionRequired);
        assert_eq!(
            issue.path.as_deref(),
            Some("settings.encryption"),
            "{issue:?}"
        );

        let valid = ServerProfile::new("direct", OutboundModel::new(Protocol::Freedom));
        let findings = editor_validation_findings(&valid);
        assert!(findings.blocking.is_empty());
        assert!(findings.advisory.is_empty());
    }

    /// The inline finalmask verdict is the block's own: the outbound-filter
    /// advisories the sweep folds into the warnings list stay out of it, so
    /// the Advanced tab paints only the mask findings under the mask list
    /// while the amber list keeps the sweep's advisories.
    #[test]
    fn editor_inline_finalmask_verdict_excludes_the_sweep_s_filter_advisories() {
        let mut profile = ServerProfile::new("filter", OutboundModel::new(Protocol::Freedom));
        profile.outbound.stream = serde_json::from_value(json!({
            "network": "raw",
            "finalmask": {
                "tcp": [{"type": "filter", "settings": {"blockedSourceIPs": ["geoip:private"]}}],
                "udp": [{"type": "filter", "settings": {"allowedSourceIPs": ["10.0.0.0/8"]}}]
            }
        }))
        .expect("fixture is a valid stream");

        let findings = editor_validation_findings(&profile);
        assert!(
            !findings
                .finalmask
                .iter()
                .any(|issue| issue.code == ValidationCode::FinalmaskFilterOnOutbound),
            "the inline verdict must not carry the sweep's filter advisories: {:#?}",
            findings.finalmask
        );
        assert_eq!(
            codes_of(&findings.advisory),
            vec![
                ValidationCode::FinalmaskFilterOnOutbound,
                ValidationCode::FinalmaskFilterOnOutbound,
            ],
            "the warnings list keeps the aggregated advisories: {:#?}",
            findings.advisory
        );
        assert!(findings.blocking.is_empty(), "{:#?}", findings.blocking);
    }

    /// The model's required-value findings are the rendered Save gate: an
    /// edited VLESS draft with an empty address and id paints the model's
    /// messages in the error list and takes Validate-and-save dark while
    /// Discard stays live.
    #[test]
    fn empty_vless_address_and_id_block_the_rendered_save_gate() {
        let clean = {
            let mut profile = ServerProfile::new("vless", OutboundModel::new(Protocol::Vless));
            let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
                unreachable!()
            };
            settings.address = "1.2.3.4".into();
            settings.port = 443;
            settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
            settings.encryption = "none".into();
            profile
        };
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(clean.clone());
        rig.servers.active = Some(clean.id.clone());
        let mut harness = wide_servers_harness(rig);
        harness.run();

        let mut empty = clean.clone();
        {
            let ProtocolSettings::Vless(settings) = &mut empty.outbound.settings else {
                unreachable!()
            };
            settings.address.clear();
            settings.id.clear();
        }
        install_draft(&mut harness.state_mut().0, &empty, &clean);
        harness.run();

        let blocking = editor_blocking(&harness);
        for (code, path) in [
            (ValidationCode::ServerAddressRequired, "settings.address"),
            (ValidationCode::VlessIdRequired, "settings.id"),
        ] {
            let issue = finding(&blocking, code);
            assert_eq!(issue.path.as_deref(), Some(path), "the model owns the rule");
            let message = validation_issue_message(&issue, Language::En);
            let bullet = t_fmt(Language::En, Key::ErrorBullet, &[&message]);
            assert!(
                harness.query_by_label(bullet.as_str()).is_some(),
                "the error list must render {message:?}"
            );
        }
        assert_eq!(
            action_row_disabled(&harness),
            (true, false),
            "a draft the model refuses must not be saveable"
        );
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

    /// One-channel guard for the stream rules the sweep used to re-derive: a
    /// non-string header value, an empty TLS certificate row, and `fromMitm`
    /// beside another ALPN name each surface exactly one blocking line — the
    /// model's, on the field path, with the certificate rule naming the
    /// offending row.
    #[test]
    fn stream_rule_findings_report_once_through_the_model_channel() {
        fn base_profile() -> ServerProfile {
            let mut profile = ServerProfile::new("stream", OutboundModel::new(Protocol::Vless));
            let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings else {
                unreachable!()
            };
            settings.address = "example.com".into();
            settings.port = 443;
            settings.id = "b831381d-6324-4d53-ad4f-8cda48b30811".into();
            settings.encryption = "none".into();
            let _ = profile.outbound.stream.select_security(Security::Tls);
            profile
        }

        // A ws header map whose JSON value is not a string: one error line on
        // the headers path (a re-introduced UI push would double it).
        let mut profile = base_profile();
        profile.outbound.stream.network = Network::Ws;
        profile.outbound.stream.ws_settings = Some(WsSettings {
            headers: json!({"Host": 123}).as_object().unwrap().clone(),
            ..Default::default()
        });
        let blocking = editor_validation_findings(&profile).blocking;
        assert_eq!(
            blocking.len(),
            1,
            "a non-string ws header value must surface exactly one finding: {blocking:#?}"
        );
        assert_eq!(
            blocking[0].code,
            ValidationCode::HeaderValuesNotStrings(Network::Ws)
        );
        assert_eq!(
            blocking[0].path.as_deref(),
            Some("stream.wsSettings.headers")
        );

        // The TLS block: the empty certificate row and the fromMitm ALPN list
        // report once each, on their own field path.
        let mut profile = base_profile();
        let tls = profile
            .outbound
            .stream
            .tls_settings
            .as_mut()
            .expect("select_security materializes the TLS block");
        tls.certificates = vec![TlsCert::default()];
        tls.alpn = vec!["fromMitm".into(), "h2".into()];
        let blocking = editor_validation_findings(&profile).blocking;
        assert_eq!(
            codes_of(&blocking),
            vec![
                ValidationCode::TlsFromMitmAlpnShort,
                ValidationCode::TlsCertificateRequired
            ],
            "{blocking:#?}"
        );
        assert_eq!(blocking[0].path.as_deref(), Some("stream.tlsSettings.alpn"));
        assert_eq!(
            blocking[1].path.as_deref(),
            Some("stream.tlsSettings.certificates[0]")
        );
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
        let mut harness = harness_builder().build_ui(|ui| {
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
        let mut harness = harness_builder().build_ui(|ui| {
            mux_tab(ui, Language::En, &mut mux, Some("xtls-rprx-vision"));
        });
        harness.run();
        assert!(harness.query_by_label(warning).is_none());
        drop(harness);

        // Mux without mux, or a non-VLESS profile context, never warns.
        mux.concurrency = Some(8);
        mux.enabled = false;
        let mut harness = harness_builder().build_ui(|ui| {
            mux_tab(ui, Language::En, &mut mux, Some("xtls-rprx-vision"));
        });
        harness.run();
        assert!(harness.query_by_label(warning).is_none());
        drop(harness);

        mux.enabled = true;
        let mut harness = harness_builder().build_ui(|ui| {
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
        let mut harness = harness_builder().build_ui(|ui| {
            let _ =
                screen.basic_tab_for_target(ui, Language::En, &mut profile, None, &[], revealed());
        });
        harness.run();
        assert!(
            harness.query_by_label(warning).is_some(),
            "the flow combo must warn inline while mux carries TCP under vision"
        );
        drop(harness);
        // Flipping the mux escape hatch off the conflict clears it live.
        profile.outbound.mux.concurrency = Some(-1);
        let mut harness = harness_builder().build_ui(|ui| {
            let _ =
                screen.basic_tab_for_target(ui, Language::En, &mut profile, None, &[], revealed());
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
        let message = validation_issue_message(&public_endpoint, Language::En);
        assert!(
            rendered
                .blocking
                .contains(&t_fmt(Language::En, Key::ErrorBullet, &[&message])),
            "the error list holds the bulleted line the panel paints"
        );
        let inline = rendered.basic_inline;
        assert_eq!(
            inline,
            vec![message],
            "the Basic tab's verdict is the error list's finding, rendered the same"
        );
        let mut screen = ServersScreen::default();
        {
            let mut harness = harness_builder().build_ui(|ui| {
                let _ = screen.basic_tab_for_target(
                    ui,
                    Language::En,
                    &mut profile,
                    None,
                    &inline,
                    revealed(),
                );
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
        let mut harness = harness_builder().build_ui(|ui| {
            let _ = screen.basic_tab_for_target(
                ui,
                Language::En,
                &mut profile,
                None,
                &sentinel,
                revealed(),
            );
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

    /// The security tab's pair notice and disabled options are the model's
    /// verdict (`transport_security_notice` / `can_select_security`): a
    /// Hysteria stream without TLS paints the model's message above the row
    /// and disables the modes the model refuses, while TLS stays selectable.
    #[test]
    fn security_tab_renders_the_model_pair_verdict_and_disables_refused_modes() {
        let notice =
            validation_message(&ValidationCode::HysteriaTransportRequiresTls, Language::En);
        let mut stream = StreamModel {
            network: Network::Hysteria,
            security: Security::None,
            ..Default::default()
        };
        {
            let mut screen = ServersScreen::default();
            let mut harness = harness_builder().build_ui(|ui| {
                let _ = screen.security_tab(ui, Language::En, None, &mut stream, None, &[]);
            });
            harness.run();
            assert!(
                harness.query_by_label(notice.as_str()).is_some(),
                "the notice must be the model's own message"
            );
            for refused in ["none", "reality"] {
                assert!(
                    harness.get_by_label(refused).accesskit_node().is_disabled(),
                    "{refused} must be disabled on the hysteria transport"
                );
            }
            assert!(
                !harness.get_by_label("tls").accesskit_node().is_disabled(),
                "TLS is the one mode the transport runs"
            );
        }

        // Selecting the accepted pair clears the notice; the refused modes
        // stay disabled because they are still refusals for this transport.
        stream
            .select_security(Security::Tls)
            .expect("hysteria runs over TLS");
        let mut screen = ServersScreen::default();
        let mut harness = harness_builder().build_ui(|ui| {
            let _ = screen.security_tab(ui, Language::En, None, &mut stream, None, &[]);
        });
        harness.run();
        assert!(
            harness.query_by_label(notice.as_str()).is_none(),
            "a pair the model accepts renders no notice"
        );
        assert!(
            !harness.get_by_label("tls").accesskit_node().is_disabled(),
            "TLS stays selectable"
        );
    }

    /// The transport tab's pair notice is that same model verdict: a MASQUE
    /// stream without TLS paints the model's message and its "Switch to TLS"
    /// button repairs the pair through `select_security`.
    #[test]
    fn transport_tab_renders_the_model_pair_notice_and_switches_to_tls() {
        let notice = validation_message(&ValidationCode::MasqueTransportRequiresTls, Language::En);
        let switch = t(Language::En, Key::SrvSwitchToTls);
        let stream = Rc::new(RefCell::new(StreamModel {
            network: Network::Masque,
            security: Security::None,
            ..Default::default()
        }));
        let stream_for_ui = Rc::clone(&stream);
        let screen = Rc::new(RefCell::new(ServersScreen::default()));
        let screen_for_ui = Rc::clone(&screen);
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().transport_tab(
                ui,
                Language::En,
                &mut stream_for_ui.borrow_mut(),
                0,
                TransportTabCtx {
                    target: None,
                    masked: false,
                    protocol: Protocol::Masque,
                    mux: None,
                },
            );
        });
        harness.run();
        assert!(
            harness.query_by_label(notice.as_str()).is_some(),
            "the notice must be the model's own message"
        );
        harness.get_by_label(switch).click();
        harness.run();
        assert_eq!(
            stream.borrow().security,
            Security::Tls,
            "the switch button repairs the pair through the model"
        );
        assert!(
            harness.query_by_label(notice.as_str()).is_none(),
            "the accepted pair renders no notice"
        );
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
            let mut harness = harness_builder().build_ui(|ui| {
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
            let mut harness = harness_builder().build_ui(|ui| {
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
        let mut harness = harness_builder().build_ui(|ui| {
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
            let mut harness = harness_builder().build_ui(|ui| {
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
        let mut harness = harness_builder().build_ui(|ui| {
            let _ = screen.security_tab(ui, Language::En, None, &mut stream, None, &[]);
        });
        harness.run();
        assert!(
            harness.query_by_label(blocking.as_str()).is_some(),
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
                let _harness = harness_builder().build_ui(|ui| {
                    reported_changed |= screen.basic_tab_for_target(
                        ui,
                        Language::En,
                        &mut profile,
                        None,
                        &[],
                        revealed(),
                    );
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
        let target = || draft_target(DraftKind::Existing, id, 7);

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
                    draft_target(DraftKind::Existing, id, 8),
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
                    draft_target(DraftKind::Add, "fedcba9876543210", 8),
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

        let mut harness = harness_builder()
            .with_size(egui::vec2(900.0, 2400.0))
            .build_ui_state(
                |ui, screen: &mut ServersScreen| {
                    let _ = screen.transport_tab(
                        ui,
                        Language::En,
                        &mut stream,
                        0,
                        TransportTabCtx {
                            target: draft_target(DraftKind::Existing, "0123456789abcdef", 1),
                            masked: false,
                            protocol: Protocol::Vless,
                            mux: None,
                        },
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

    /// The transport selector offers the masque transport only for a masque
    /// outbound, and only it for one — the two mismatches the model reports
    /// stay unreachable through the editor.
    #[test]
    fn transport_selector_offers_masque_only_for_a_masque_outbound() {
        {
            let mut stream = StreamModel {
                network: Network::Ws,
                ..Default::default()
            };
            let mut screen = ServersScreen::default();
            let harness = harness_builder().build_ui(|ui| {
                let _ = screen.transport_tab(
                    ui,
                    Language::En,
                    &mut stream,
                    0,
                    TransportTabCtx {
                        target: None,
                        masked: false,
                        protocol: Protocol::Vless,
                        mux: None,
                    },
                );
            });
            assert!(
                harness
                    .query_all_by_label_contains("masque")
                    .next()
                    .is_none(),
                "a non-masque outbound must not offer the masque transport"
            );
            assert!(
                harness
                    .query_all_by_label_contains("httpupgrade")
                    .next()
                    .is_some(),
                "a non-masque outbound offers the other transports"
            );
        }
        {
            let mut stream = StreamModel {
                network: Network::Masque,
                security: Security::Tls,
                ..Default::default()
            };
            let mut screen = ServersScreen::default();
            let harness = harness_builder().build_ui(|ui| {
                let _ = screen.transport_tab(
                    ui,
                    Language::En,
                    &mut stream,
                    0,
                    TransportTabCtx {
                        target: None,
                        masked: false,
                        protocol: Protocol::Masque,
                        mux: None,
                    },
                );
            });
            assert!(
                harness
                    .query_all_by_label_contains("masque")
                    .next()
                    .is_some(),
                "a masque outbound must offer the masque transport"
            );
            assert!(
                harness
                    .query_all_by_label_contains("httpupgrade")
                    .next()
                    .is_none(),
                "a masque outbound must offer no other transport"
            );
        }
    }

    /// The transport selector offers xdrive only while the outbound protocol
    /// is VLESS: every other protocol stays on the transport list the core
    /// accepts for it.
    #[test]
    fn transport_selector_offers_xdrive_only_for_a_vless_outbound() {
        for (protocol, offered) in [(Protocol::Vless, true), (Protocol::Trojan, false)] {
            let mut stream = StreamModel {
                network: Network::Raw,
                ..Default::default()
            };
            let mut screen = ServersScreen::default();
            let harness = harness_builder().build_ui(|ui| {
                let _ = screen.transport_tab(
                    ui,
                    Language::En,
                    &mut stream,
                    0,
                    TransportTabCtx {
                        target: None,
                        masked: false,
                        protocol,
                        mux: None,
                    },
                );
            });
            assert_eq!(
                harness
                    .query_all_by_label_contains("xdrive")
                    .next()
                    .is_some(),
                offered,
                "{protocol:?}"
            );
        }
    }

    /// Selecting xdrive seeds Mux.Cool for the outbound, and the mux switch
    /// stays the user's to change.
    #[test]
    fn selecting_xdrive_enables_the_outbound_mux() {
        let mut stream = StreamModel::default();
        let mut mux = crate::model::outbound::MuxModel::default();
        let mut screen = ServersScreen::default();
        let mut harness = harness_builder().build_ui(|ui| {
            let _ = screen.transport_tab(
                ui,
                Language::En,
                &mut stream,
                0,
                TransportTabCtx {
                    target: None,
                    masked: false,
                    protocol: Protocol::Vless,
                    mux: Some(&mut mux),
                },
            );
        });
        harness.run();
        harness.get_by_label("xdrive").click();
        harness.run();
        drop(harness);
        assert_eq!(stream.network, Network::Xdrive);
        assert!(mux.enabled, "selecting xdrive seeds the mux switch");
    }

    /// Leaving VLESS while xdrive is selected resets the transport to raw and
    /// tells the user why; the stored transport is only reset by this switch.
    #[test]
    fn leaving_vless_with_xdrive_resets_the_transport_with_a_note() {
        let mut profile = ServerProfile::new("xdrive", OutboundModel::new(Protocol::Vless));
        profile
            .outbound
            .stream
            .select_network(Network::Xdrive)
            .expect("xdrive needs no security mode");
        profile.outbound.mux.enabled = true;
        let mut screen = ServersScreen::default();
        assert!(screen.switch_draft_protocol(&mut profile, Protocol::Freedom, Language::En));
        assert_eq!(profile.outbound.protocol, Protocol::Freedom);
        assert_eq!(profile.outbound.stream.network, Network::Raw);
        let status = screen.status.as_ref().expect("the reset note must show");
        assert_eq!(status.text, t(Language::En, Key::SrvXdriveResetToRaw));
        assert!(!status.is_error);
    }

    /// The masque transport's options render as real widgets — host, path,
    /// and the two credentials — instead of a raw JSON box.
    #[test]
    fn masque_transport_editor_renders_its_fields() {
        let mut stream = StreamModel {
            network: Network::Masque,
            security: Security::Tls,
            masque_settings: Some(MasqueTransport {
                host: "masque.example.com".into(),
                path: crate::model::stream::MASQUE_DEFAULT_PATH.into(),
                user: "user".into(),
                pass: "pass".into(),
                warp: Some(MasqueWarp {
                    private_key: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH".into(),
                    public_key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE".into(),
                    address: vec!["172.16.0.2".into()],
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut screen = ServersScreen::default();
        let harness = harness_builder().build_ui(|ui| {
            let _ = screen.transport_tab(
                ui,
                Language::En,
                &mut stream,
                0,
                TransportTabCtx {
                    target: None,
                    masked: false,
                    protocol: Protocol::Masque,
                    mux: None,
                },
            );
        });
        for label in [
            "host",
            "path",
            "user",
            "pass",
            "WARP",
            "Private key",
            "Public key",
            "Addresses",
        ] {
            assert!(
                harness.query_all_by_label_contains(label).next().is_some(),
                "the masque editor must render its {label:?} field"
            );
        }
    }

    /// The masque transport's settings carry the shared XMUX section, and
    /// the block the section owns lands on that transport.
    #[test]
    fn masque_transport_editor_carries_the_xmux_section() {
        let stream = Rc::new(RefCell::new(StreamModel {
            network: Network::Masque,
            security: Security::Tls,
            masque_settings: Some(MasqueTransport::default()),
            ..Default::default()
        }));
        let stream_for_ui = Rc::clone(&stream);
        let mut screen = ServersScreen::default();
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = screen.transport_tab(
                ui,
                Language::En,
                &mut stream_for_ui.borrow_mut(),
                0,
                TransportTabCtx {
                    target: None,
                    masked: false,
                    protocol: Protocol::Masque,
                    mux: None,
                },
            );
        });
        harness.get_by_label(t(Language::En, Key::SrvXmux));
        harness
            .get_by_label(t(Language::En, Key::SrvEnableXmux))
            .click();
        harness.run();
        assert!(
            stream
                .borrow()
                .masque_settings
                .as_ref()
                .is_some_and(|settings| settings.xmux.is_some()),
            "the masque editor must write the xmux block it renders"
        );
    }

    /// The xdrive editor renders the service choice, the folder and every
    /// scalar as widgets, and the template backend as its own structured
    /// editor — the four operations, the authorization and the retry rules as
    /// fields, with the substitution variables shown where they land.
    #[test]
    fn xdrive_transport_editor_renders_scalars_and_template_fields() {
        let mut stream = StreamModel {
            network: Network::Xdrive,
            xdrive_settings: Some(Box::new(crate::model::stream::XdriveTransport {
                service: crate::model::stream::XDRIVE_SERVICE_TEMPLATE.into(),
                remote_folder: "token".into(),
                secrets: vec!["client-id".into(), "client-secret".into()],
                ..Default::default()
            })),
            ..Default::default()
        };
        let mut screen = ServersScreen::default();
        let harness = harness_builder().build_ui(|ui| {
            let _ = screen.transport_tab(
                ui,
                Language::En,
                &mut stream,
                0,
                TransportTabCtx {
                    target: None,
                    masked: false,
                    protocol: Protocol::Vless,
                    mux: None,
                },
            );
        });
        for label in [
            "Service",
            "Remote folder",
            "Secrets",
            "Segment bytes",
            "Flush interval",
            "Poll interval",
            "Max poll interval",
            "Session TTL",
            "Concurrency",
            "Eager window",
            "Hole timeout",
        ] {
            assert!(
                harness.query_all_by_label_contains(label).next().is_some(),
                "the xdrive editor must render its {label:?} field"
            );
        }
        // The template backend is authored as fields: the four operations and
        // their URL fields, not a raw JSON box.
        for label in ["Put", "Get", "Delete", "List", "Authorization", "Retry"] {
            assert!(
                harness.query_all_by_label_contains(label).next().is_some(),
                "the template editor must render {label:?}"
            );
        }
        assert_eq!(
            harness.query_all_by_label("URL").count(),
            4,
            "every operation exposes its own URL field"
        );
        assert_eq!(
            harness
                .query_all_by_label_contains("Substituted here")
                .count(),
            5,
            "each substitution site lists the variables it expands"
        );
    }

    /// The xdrive transport settings carry the shared XMUX section: the enable
    /// switch, the chosen connection limit, and the reuse knobs every xmux
    /// transport shows.
    #[test]
    fn xdrive_transport_editor_renders_the_xmux_section() {
        let stream = Rc::new(RefCell::new(StreamModel {
            network: Network::Xdrive,
            xdrive_settings: Some(Box::new(crate::model::stream::XdriveTransport {
                service: crate::model::stream::XDRIVE_SERVICE_LOCAL.into(),
                remote_folder: "store".into(),
                xmux: Some(XmuxConfig {
                    max_connections: Some(Int32Range::single(2)),
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        }));
        let stream_for_ui = Rc::clone(&stream);
        let mut screen = ServersScreen::default();
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = screen.transport_tab(
                ui,
                Language::En,
                &mut stream_for_ui.borrow_mut(),
                0,
                TransportTabCtx {
                    target: None,
                    masked: false,
                    protocol: Protocol::Vless,
                    mux: None,
                },
            );
        });
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvXmux))
                .is_some(),
            "the xdrive editor must mount the xmux section"
        );
        assert!(
            harness.query_by_label("cMaxReuseTimes").is_some(),
            "the section must render the transport's stored block"
        );
        harness
            .get_by_label(t(Language::En, Key::SrvEnableXmux))
            .click();
        harness.run();
        assert!(
            stream
                .borrow()
                .xdrive_settings
                .as_ref()
                .expect("the transport keeps its settings")
                .xmux
                .is_none(),
            "the section must write the xdrive transport's block"
        );
    }

    /// The s3 backend's section exists only while that service is chosen, and
    /// its path-style box shows the loader's default — on — until the user
    /// changes it, which writes the explicit choice.
    #[test]
    fn xdrive_s3_editor_appears_only_for_s3_and_defaults_to_path_style() {
        // Render the xdrive editor for `service`; `None` when the s3 section
        // is absent, the written `pathStyle` when the box was unchecked.
        let render = |service: &'static str| -> Option<Option<bool>> {
            let stream = Rc::new(RefCell::new(StreamModel {
                network: Network::Xdrive,
                xdrive_settings: Some(Box::new(crate::model::stream::XdriveTransport {
                    service: service.into(),
                    remote_folder: "streams/".into(),
                    secrets: vec!["access-key".into(), "secret-key".into()],
                    ..Default::default()
                })),
                ..Default::default()
            }));
            let stream_for_ui = Rc::clone(&stream);
            let mut screen = ServersScreen::default();
            let mut harness = harness_builder().build_ui(move |ui| {
                let _ = screen.transport_tab(
                    ui,
                    Language::En,
                    &mut stream_for_ui.borrow_mut(),
                    0,
                    TransportTabCtx {
                        target: None,
                        masked: false,
                        protocol: Protocol::Vless,
                        mux: None,
                    },
                );
            });
            harness.run();
            let section = harness
                .query_all_by_label_contains(t(Language::En, Key::SrvXdriveS3Section))
                .next()
                .is_some();
            if service != crate::model::stream::XDRIVE_SERVICE_S3 {
                assert!(!section, "{service} must not show the s3 section");
                return None;
            }
            assert!(section, "the s3 service renders its section");
            for label in [
                Key::SrvXdriveS3Endpoint,
                Key::SrvXdriveS3Region,
                Key::SrvXdriveS3Bucket,
                Key::SrvXdriveS3PathStyle,
            ] {
                assert!(
                    harness
                        .query_all_by_label_contains(t(Language::En, label))
                        .next()
                        .is_some(),
                    "the s3 section must render {label:?}"
                );
            }
            // The absent key reads as path-style, so the box starts checked;
            // unchecking it writes the explicit choice.
            harness
                .get_by_label(t(Language::En, Key::SrvXdriveS3PathStyle))
                .click();
            harness.run();
            let written = stream
                .borrow()
                .xdrive_settings
                .as_ref()
                .and_then(|settings| settings.s3.as_ref())
                .and_then(|s3| s3.path_style);
            Some(written)
        };

        for service in [
            crate::model::stream::XDRIVE_SERVICE_LOCAL,
            crate::model::stream::XDRIVE_SERVICE_DRIVE,
            crate::model::stream::XDRIVE_SERVICE_TEMPLATE,
        ] {
            assert_eq!(
                render(service),
                None,
                "{service} must not show the s3 section"
            );
        }
        assert_eq!(
            render(crate::model::stream::XDRIVE_SERVICE_S3),
            Some(Some(false)),
            "unchecking path-style writes the explicit choice"
        );
    }

    /// A transport profile whose settings carry a template the runtime builds
    /// must round-trip through the editor without the draft changing on an
    /// idle frame.
    #[test]
    fn xdrive_template_editor_is_render_idempotent() {
        let mut stream = StreamModel {
            network: Network::Xdrive,
            xdrive_settings: Some(Box::new(crate::model::stream::XdriveTransport {
                service: crate::model::stream::XDRIVE_SERVICE_TEMPLATE.into(),
                remote_folder: "token".into(),
                template: Some(crate::model::stream::XdriveTemplate {
                    put: crate::model::stream::XdriveTemplateOp {
                        url: "https://api/{name}".into(),
                        ..Default::default()
                    },
                    get: crate::model::stream::XdriveTemplateOp {
                        url: "https://api/{name}".into(),
                        ..Default::default()
                    },
                    delete: crate::model::stream::XdriveTemplateOp {
                        url: "https://api/{name}".into(),
                        ..Default::default()
                    },
                    list: crate::model::stream::XdriveTemplateOp {
                        url: "https://api/{prefix}".into(),
                        names_regex: "(.*)".into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                ..Default::default()
            })),
            ..Default::default()
        };
        let before = serde_json::to_value(&stream).unwrap();
        let mut screen = ServersScreen::default();
        let mut reported_changed = false;
        {
            let _harness = harness_builder().build_ui(|ui| {
                reported_changed |= screen.transport_tab(
                    ui,
                    Language::En,
                    &mut stream,
                    0,
                    TransportTabCtx {
                        target: None,
                        masked: false,
                        protocol: Protocol::Vless,
                        mux: None,
                    },
                );
            });
        }
        assert!(!reported_changed);
        assert_eq!(serde_json::to_value(&stream).unwrap(), before);
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
            Network::Masque,
            Network::Xdrive,
        ] {
            let mut stream = StreamModel {
                network,
                ..Default::default()
            };
            let before = serde_json::to_value(&stream).unwrap();
            let mut screen = ServersScreen::default();
            let mut reported_changed = false;
            {
                let _harness = harness_builder().build_ui(|ui| {
                    reported_changed |= screen.transport_tab(
                        ui,
                        Language::En,
                        &mut stream,
                        0,
                        TransportTabCtx {
                            target: None,
                            masked: false,
                            protocol: if network == Network::Masque {
                                Protocol::Masque
                            } else {
                                Protocol::Vless
                            },
                            mux: None,
                        },
                    );
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
                let _harness = harness_builder().build_ui(|ui| {
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
            let _harness = harness_builder().build_ui(|ui| {
                reported_changed |= ServersScreen::advanced_tab(
                    ui,
                    Language::En,
                    &mut profile,
                    &[],
                    AdvancedTabCtx {
                        set_key: (0, 0),
                        finalmask_errors: &[],
                        stream_sockopt_errors: &[],
                        dialer_proxy_options: &mut screen.existing.chain_options,
                        buffers: &mut screen.seeded_buffers,
                        masked: false,
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
            let _harness = harness_builder().build_ui(|ui| {
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
        let mut harness = harness_builder().build_ui(move |ui| {
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
    fn tls_trust_switch_edits_the_outbound_tls_settings_only() {
        // The switch writes the same TLS block the editor already holds, and
        // its note rides the row's hover. REALITY carries no TLS settings, so
        // the control disappears with that block.
        let note = t(Language::En, Key::SrvTlsUseSystemCaNote);
        let stream = Rc::new(RefCell::new(StreamModel {
            security: Security::Tls,
            tls_settings: Some(TlsModel::default()),
            ..Default::default()
        }));
        let stream_for_ui = Rc::clone(&stream);
        let screen = Rc::new(RefCell::new(ServersScreen::default()));
        let screen_for_ui = Rc::clone(&screen);
        let mut harness = harness_builder().build_ui(move |ui| {
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

        // An untouched frame writes no key: the bundled-roots default.
        assert!(
            serde_json::to_value(&*stream.borrow()).unwrap()["tlsSettings"]
                .get("useSystemCA")
                .is_none()
        );
        assert!(
            harness.query_by_label(note).is_none(),
            "the note is the row's hover, never a rendered line"
        );

        harness.get_by_label("useSystemCA").scroll_to_me();
        harness.run();
        harness.get_by_label("useSystemCA").hover();
        harness.run();
        harness.run();
        assert!(
            harness.query_all_by_label(note).next().is_some(),
            "the switch's hover must carry the note"
        );

        harness.get_by_label("useSystemCA").click();
        harness.run();
        assert!(stream.borrow().tls_settings.as_ref().unwrap().use_system_ca);
        assert_eq!(
            serde_json::to_value(&*stream.borrow()).unwrap()["tlsSettings"]["useSystemCA"],
            json!(true)
        );

        harness.get_by_label("reality").click();
        harness.run();
        assert!(
            harness.query_by_label("useSystemCA").is_none(),
            "REALITY holds no TLS settings, so the trust switch must not render there"
        );
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
        let screen = Rc::new(RefCell::new(ServersScreen::default()));
        screen.borrow_mut().existing.probe = TlsProbe {
            leaf_pin: Some(leaf.to_owned()),
            output: Some(
                "TLS ping:  example.com:443\nPinging without SNI\nHandshake succeeded\n\
                 TLS Version:  TLS 1.3\nCert's leaf SHA256:\t7f9c2b3d4e5f60718293a4b5c6d7e8f9"
                    .to_owned(),
            ),
            ca_pins: vec![
                (
                    "DigiCert TLS RSA SHA256 2020 CA1".to_owned(),
                    "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90".to_owned(),
                ),
                (
                    "DigiCert Global Root R11".to_owned(),
                    "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2".to_owned(),
                ),
            ],
            handshake_ok: true,
            profile: Some("profile-1".to_owned()),
            ..Default::default()
        };
        let screen_for_ui = Rc::clone(&screen);
        // The TLS-arm informational hint rows push the probe
        // panel's lower buttons past the default 800x600 kittest viewport;
        // the real app scrolls, so the harness just gets a taller one.
        let mut harness = harness_builder()
            .with_size(egui::vec2(800.0, 700.0))
            .build_ui(move |ui| {
                let _ = screen_for_ui.borrow_mut().security_tab(
                    ui,
                    Language::En,
                    draft_target(DraftKind::Existing, "profile-1", 0),
                    &mut stream_for_ui.borrow_mut(),
                    None,
                    &[],
                );
                screen_for_ui.borrow_mut().probe_output_window(
                    ui.ctx(),
                    Language::En,
                    DraftKind::Existing,
                );
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
        let screen = Rc::new(RefCell::new(ServersScreen::default()));
        screen.borrow_mut().existing.probe = TlsProbe {
            handshake_ok: true,
            profile: Some("profile-1".to_owned()),
            ..Default::default()
        };
        let screen_for_ui = Rc::clone(&screen);
        let mut stream = StreamModel {
            security: Security::Tls,
            tls_settings: Some(TlsModel::default()),
            ..Default::default()
        };
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().security_tab(
                ui,
                Language::En,
                draft_target(DraftKind::Existing, "profile-1", 0),
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
        let screen = Rc::new(RefCell::new(ServersScreen::default()));
        screen.borrow_mut().existing.probe = TlsProbe {
            leaf_pin: Some(leaf.to_owned()),
            handshake_ok: true,
            profile: Some("profile-1".to_owned()),
            ..Default::default()
        };
        let screen_for_ui = Rc::clone(&screen);
        let stream = Rc::new(RefCell::new(StreamModel {
            security: Security::Tls,
            tls_settings: Some(TlsModel::default()),
            ..Default::default()
        }));
        let stream_for_ui = Rc::clone(&stream);
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().security_tab(
                ui,
                Language::En,
                draft_target(DraftKind::Existing, "profile-2", 0),
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
        let screen = Rc::new(RefCell::new(ServersScreen::default()));
        screen.borrow_mut().existing.probe = TlsProbe {
            // A stale override from an earlier probe must not survive the
            // fill: the next handshake would dial the old IP otherwise.
            ip: "9.9.9.9".into(),
            ..Default::default()
        };
        let screen_for_ui = Rc::clone(&screen);
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().security_tab(
                ui,
                Language::En,
                draft_target(DraftKind::Existing, "profile-1", 0),
                &mut stream_for_ui.borrow_mut(),
                Some(&address),
                &[],
            );
        });

        harness.get_by_label("Probe TLS certificate").click();
        harness.run();
        harness.get_by_label("Use server address:port").click();
        harness.run();

        assert_eq!(screen.borrow().existing.probe.domain, "1.2.3.4:8443");
        assert!(screen.borrow().existing.probe.ip.is_empty());
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
            let _harness = harness_builder().build_ui(|ui| {
                let _ = screen.basic_tab_for_target(
                    ui,
                    Language::En,
                    &mut profile,
                    None,
                    &[],
                    revealed(),
                );
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
        let mut noise_harness = harness_builder().build_ui(move |ui| {
            let _ = noises_editor(ui, Language::En, &mut noises_for_ui.borrow_mut());
        });
        noise_harness.get_by_label("+ noise").click();
        noise_harness.run();
        drop(noise_harness);

        let rules = Rc::new(RefCell::new(Vec::<FreedomFinalRule>::new()));
        let rules_for_ui = Rc::clone(&rules);
        let mut rule_harness = harness_builder().build_ui(move |ui| {
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
        let mut fragment_harness = harness_builder().build_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().basic_tab_for_target(
                ui,
                Language::En,
                &mut profile_for_ui.borrow_mut(),
                None,
                &[],
                revealed(),
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
            let mut harness = harness_builder().build_ui(|ui| {
                let _ = screen.basic_tab_for_target(
                    ui,
                    Language::En,
                    &mut profile,
                    None,
                    &[],
                    revealed(),
                );
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
        let mut harness = harness_builder().build_ui(move |ui| {
            // `Harness::run` may step several frames; keep any edit a frame
            // reports instead of letting a later quiet frame clear it.
            *changed_for_ui.borrow_mut() |= screen.basic_tab_for_target(
                ui,
                Language::En,
                &mut profile_for_ui.borrow_mut(),
                None,
                &[],
                revealed(),
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
            let _harness = harness_builder().build_ui(|ui| {
                reported_changed |= screen.transport_tab(
                    ui,
                    Language::En,
                    &mut stream,
                    0,
                    TransportTabCtx {
                        target: None,
                        masked: false,
                        protocol: Protocol::Vless,
                        mux: None,
                    },
                );
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
        let _harness = harness_builder().build_ui(|ui| screen.show(ui, &mut rig.ctx().servers()));
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
        screen.import_parsed = links::parse_bulk(&paste)
            .into_iter()
            .map(|result| result.map_err(|error| error.to_string()))
            .collect();
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
        let _harness = harness_builder().build_ui(|ui| {
            let _ = ServersScreen::advanced_tab(
                ui,
                Language::En,
                profile,
                &[],
                AdvancedTabCtx {
                    set_key: (0, 0),
                    finalmask_errors: &[],
                    stream_sockopt_errors: &[],
                    dialer_proxy_options: &mut screen.existing.chain_options,
                    buffers: &mut screen.seeded_buffers,
                    masked: false,
                },
            );
        });
    }

    #[test]
    fn mask_lists_render_their_order_captions() {
        // Both mask lists carry an order caption. The UDP list names the
        // types the wrap pins to the last entry; the TCP list states that no
        // type is pinned, because only a UDP mask declares `HandleDial` or
        // `HandleListen` (`transport/internet/finalmask/finalmask.go`).
        let mut screen = ServersScreen::default();
        let mut profile =
            ServerProfile::new("caption-order", OutboundModel::new(Protocol::Freedom));
        profile.outbound.stream.finalmask = Some(FinalmaskModel::default());
        let mut harness = harness_builder()
            .with_size(egui::vec2(1200.0, 2000.0))
            .build_ui(|ui| {
                let _ = ServersScreen::advanced_tab(
                    ui,
                    Language::En,
                    &mut profile,
                    &[],
                    AdvancedTabCtx {
                        set_key: (0, 0),
                        finalmask_errors: &[],
                        stream_sockopt_errors: &[],
                        dialer_proxy_options: &mut screen.existing.chain_options,
                        buffers: &mut screen.seeded_buffers,
                        masked: false,
                    },
                );
            });
        harness.run();
        for key in [Key::SrvTcpMaskOrderNote, Key::SrvUdpMaskOrderNote] {
            let caption = t(Language::En, key);
            assert!(
                harness.query_by_label(caption).is_some(),
                "the mask lists must render {key:?}: {caption:?}"
            );
        }
        let udp = t(Language::En, Key::SrvUdpMaskOrderNote);
        for name in ["udphop", "xicmp"] {
            assert!(udp.contains(name), "{udp:?} must name {name}");
        }
        for absent in ["realm", "sudoku"] {
            assert!(!udp.contains(absent), "{udp:?} must not name {absent}");
        }
    }

    /// The Advanced tab renders the finalmask verdict the gate computes: a
    /// resolver row the editor creates with no address shows its blocking
    /// finding under the mask list.
    #[test]
    fn advanced_tab_renders_the_empty_xdns_resolver_finding() {
        let mut profile = ServerProfile::new("xdns-empty", OutboundModel::new(Protocol::Freedom));
        profile.outbound.stream.finalmask = Some(
            serde_json::from_value(json!({
                "udp": [{"type": "xdns", "settings": {
                    "domains": [{"names": ["a.example"], "types": [1]}],
                    "resolvers": [{"addrs": []}]
                }}]
            }))
            .expect("fixture is a valid finalmask"),
        );
        let findings = editor_validation_findings(&profile).finalmask;
        let issue = finding(&findings, ValidationCode::FinalmaskXdnsResolverAddrsEmpty);
        let message = validation_message(&issue.code, Language::En);
        let errors = super::render_findings(findings.iter(), Language::En);
        assert_eq!(errors.len(), 1, "{errors:?}");
        let rendered = errors
            .iter()
            .find(|error| error.contains(&message))
            .expect("the empty resolver row's finding is rendered");

        let mut screen = ServersScreen::default();
        let mut harness = harness_builder()
            .with_size(egui::vec2(1200.0, 2000.0))
            .build_ui(|ui| {
                let _ = ServersScreen::advanced_tab(
                    ui,
                    Language::En,
                    &mut profile,
                    &[],
                    AdvancedTabCtx {
                        set_key: (0, 0),
                        finalmask_errors: &errors,
                        stream_sockopt_errors: &[],
                        dialer_proxy_options: &mut screen.existing.chain_options,
                        buffers: &mut screen.seeded_buffers,
                        masked: false,
                    },
                );
            });
        harness.run();
        assert!(
            harness.query_by_label(rendered).is_some(),
            "the editor must render the empty resolver row's finding: {errors:?}"
        );
    }

    /// Selecting the xdns type in the mask editor builds the default
    /// settings, whose domain and resolver lists hold no rows. The client
    /// refuses both empty lists, so the Advanced tab must render one finding
    /// for each under the mask list.
    #[test]
    fn advanced_tab_renders_the_empty_xdns_mask_findings() {
        let mut profile = ServerProfile::new("xdns-new", OutboundModel::new(Protocol::Freedom));
        profile.outbound.stream.finalmask = Some(FinalmaskModel {
            udp: vec![
                FinalmaskUdpMask::from_known_type("xdns")
                    .expect("the mask editor offers the xdns type"),
            ],
            ..Default::default()
        });
        let findings = editor_validation_findings(&profile).finalmask;
        let errors = super::render_findings(findings.iter(), Language::En);
        let mut rendered = Vec::new();
        for code in [
            ValidationCode::FinalmaskXdnsDomainsEmpty,
            ValidationCode::FinalmaskXdnsResolversEmpty,
        ] {
            let issue = finding(&findings, code);
            let message = validation_message(&issue.code, Language::En);
            rendered.push(
                errors
                    .iter()
                    .find(|error| error.contains(&message))
                    .expect("the empty list's finding is rendered")
                    .clone(),
            );
        }

        let mut screen = ServersScreen::default();
        let mut harness = harness_builder()
            .with_size(egui::vec2(1200.0, 2000.0))
            .build_ui(|ui| {
                let _ = ServersScreen::advanced_tab(
                    ui,
                    Language::En,
                    &mut profile,
                    &[],
                    AdvancedTabCtx {
                        set_key: (0, 0),
                        finalmask_errors: &errors,
                        stream_sockopt_errors: &[],
                        dialer_proxy_options: &mut screen.existing.chain_options,
                        buffers: &mut screen.seeded_buffers,
                        masked: false,
                    },
                );
            });
        harness.run();
        for message in rendered {
            assert!(
                harness.query_by_label(&message).is_some(),
                "the editor must render the empty xdns mask's finding: {message:?}"
            );
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
        assert_eq!(screen.seeded_buffers.json().len(), 2);

        // Evicting a profile that never rendered is a no-op for the cache.
        screen
            .seeded_buffers
            .evict_owned("00000000000000000000000000000000");
        assert_eq!(screen.seeded_buffers.json().len(), 2);

        // Deleting alpha evicts exactly its buffer; beta's stays untouched.
        screen.seeded_buffers.evict_owned(&alpha_id);
        assert_eq!(
            screen.seeded_buffers.json().len(),
            1,
            "only the deleted profile's buffer may be evicted"
        );
        assert!(
            screen
                .seeded_buffers
                .json()
                .values()
                .all(|buffer| buffer.profile == beta_id)
        );

        // Idle re-render of the surviving profile: its entry is reused, so
        // the map does not grow.
        render_advanced_tab(&mut screen, &mut beta);
        assert_eq!(screen.seeded_buffers.json().len(), 1);

        // Re-rendering the deleted profile recreates its buffer; the map
        // follows the live size.
        render_advanced_tab(&mut screen, &mut alpha);
        assert_eq!(screen.seeded_buffers.json().len(), 2);
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
        assert_eq!(screen.seeded_buffers.json().len(), 1);
        let seeded_text = screen
            .seeded_buffers
            .json()
            .values()
            .next()
            .unwrap()
            .text
            .clone();

        // A rename changes only the display name — the profile id is
        // immutable, so the buffer keys stay valid: repeated renames must
        // not grow the cache or re-seed buffers.
        for rename in 0..5 {
            profile.name = format!("renamed-{rename}");
            render_advanced_tab(&mut screen, &mut profile);
        }
        assert_eq!(screen.seeded_buffers.json().len(), 1);
        let surviving = screen.seeded_buffers.json().values().next().unwrap();
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
        rig.servers.active = Some(tokyo.id);
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
                .seeded_buffers
                .json()
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

    /// Open the editor window on the selected profile (or the active one, or
    /// the first) the way a double click does, and render the frame that
    /// shows it.
    fn open_selected_editor(harness: &mut Harness<'static, (ServersScreen, UiTestRig)>) {
        {
            let state = harness.state_mut();
            if state.0.existing.draft.is_some() {
                return;
            }
            let id = state
                .0
                .selected
                .clone()
                .or_else(|| state.1.servers.active.clone())
                .or_else(|| state.1.servers.profiles.first().map(|p| p.id.clone()));
            let Some(id) = id else {
                return;
            };
            let lang = state.1.settings.language;
            state.0.open_editor(&state.1.servers, lang, &id);
        }
        harness.run();
    }

    /// Full-servers-screen harness with the editor window open on the
    /// selected profile and the leave modal wired every frame, mirroring the
    /// app-shell frame tail.
    fn unsaved_harness(rig: UiTestRig) -> Harness<'static, (ServersScreen, UiTestRig)> {
        let mut harness = leave_modal_harness(DEFAULT_TEST_VIEWPORT, rig);
        open_selected_editor(&mut harness);
        harness
    }

    /// Like [`unsaved_harness`] in a window tall enough that the Advanced
    /// tab's finalmask section (below the envelope section) is on screen for
    /// click-driven tests; the app-sized default would fold it under the
    /// editor's scroll viewport.
    fn wide_servers_harness(rig: UiTestRig) -> Harness<'static, (ServersScreen, UiTestRig)> {
        let mut harness = leave_modal_harness(egui::vec2(1100.0, 700.0), rig);
        open_selected_editor(&mut harness);
        harness
    }

    /// The app-sized table with no editor window open: the harness for tests
    /// that drive the table itself (virtualization, scrolling, search).
    fn wide_table_harness(rig: UiTestRig) -> Harness<'static, (ServersScreen, UiTestRig)> {
        leave_modal_harness(egui::vec2(1100.0, 700.0), rig)
    }

    /// The screen at the app viewport with a fifth-second frame step: kittest
    /// runs one frame per queued pointer event, so the default quarter-second
    /// step puts two clicks outside egui's double-click delay.
    fn fast_servers_harness(rig: UiTestRig) -> Harness<'static, (ServersScreen, UiTestRig)> {
        harness_builder()
            .with_step_dt(0.05)
            .with_size(DEFAULT_TEST_VIEWPORT)
            .build_ui_state(
                |ui, state: &mut (ServersScreen, UiTestRig)| {
                    state.0.show(ui, &mut state.1.ctx().servers());
                },
                (ServersScreen::default(), rig),
            )
    }

    /// The servers screen plus the every-frame leave modal the app shell
    /// wires after it — the shell's frame tail, through the shared harness.
    fn leave_modal_harness(
        size: egui::Vec2,
        rig: UiTestRig,
    ) -> Harness<'static, (ServersScreen, UiTestRig)> {
        servers_frame_harness(size, rig, |_, _, _| {})
    }

    /// Dirty the selected profile's editor draft the way an edit does:
    /// mutate the profile and bump the generation so the memoized
    /// validation recomputes on the next frame.
    fn edit_existing_draft(screen: &mut ServersScreen) {
        let draft = screen.existing.draft.as_mut().unwrap();
        draft.profile.name.push('-');
        draft.generation = draft.generation.wrapping_add(1);
    }

    /// Select a profile through the screen's own guarded selection path — the
    /// action a row click performs. The editor window floats over the table in
    /// the headless harness, so a pointer click on a row underneath would land
    /// on the window instead.
    fn select_row(harness: &mut Harness<'static, (ServersScreen, UiTestRig)>, id: &str) {
        harness.state_mut().0.guard_select(id.to_owned());
        harness.run();
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
            state.0.existing.draft.is_some(),
            "Discard must keep the editor open with a fresh draft"
        );
        assert_eq!(
            state.0.existing.draft.as_ref().unwrap().profile.name,
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
        select_row(&mut harness, &osaka.id);
        let state = harness.state();
        assert_eq!(
            state.0.leave_pending,
            Some(LeaveAction::Select(osaka.id)),
            "a selection switch with unsaved changes must stage the leave modal"
        );
        assert_eq!(
            state.0.selected.as_deref(),
            Some(tokyo.id.as_str()),
            "the selection must not switch while the modal is staged"
        );
        assert!(
            state.0.existing.draft.is_some(),
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
            state.0.existing.draft.is_some(),
            "Cancel must keep the draft"
        );
        assert!(
            harness.query_by_label("●").is_some(),
            "the draft must still be dirty after Cancel"
        );
    }

    #[test]
    fn closing_an_edited_editor_asks_the_unsaved_question_in_its_window() {
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        rig.servers.active = Some(tokyo.id);
        let mut harness = unsaved_harness(rig);
        harness.run();
        edit_existing_draft(&mut harness.state_mut().0);
        harness.run();

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, t(Language::En, Key::Close))
            .click();
        harness.run();
        assert_eq!(
            harness.state().0.leave_pending,
            Some(LeaveAction::CloseExisting),
            "closing an edited draft must stage the unsaved question"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvUnsavedChanges))
                .is_some(),
            "the question must render inside the editor window"
        );

        // Cancel keeps the draft and the window open.
        harness.get_by_label(t(Language::En, Key::Cancel)).click();
        harness.run();
        assert!(harness.state().0.leave_pending.is_none());
        assert!(
            harness.state().0.existing.draft.is_some(),
            "Cancel must keep the editor window with its draft"
        );
    }

    #[test]
    fn select_guard_discard_reverts_the_editor_and_switches_selection() {
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
        select_row(&mut harness, &osaka.id);
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
            state
                .0
                .existing
                .draft
                .as_ref()
                .map(|draft| draft.id.as_str()),
            Some(tokyo.id.as_str()),
            "a plain click must not retarget the editor to the clicked row"
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
        screen.selected = Some(tokyo.id);
        // Only the add draft is dirty: the add window is a plain window, so
        // the list stays clickable behind it — a row click staged a Select
        // while the modal's Save must target the add draft.
        let added = ServerProfile::new("Added", OutboundModel::new(Protocol::Vless));
        screen.add.draft = Some(rendered_add_draft(&added, true));
        screen.leave_pending = Some(LeaveAction::Select(osaka.id));
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
        screen.poll_profile_validation(Language::En, &mut rig.ctx().servers());
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
        harness.state_mut().0.seeded_buffers.json_mut().insert(
            egui::Id::unique("finalmask-test"),
            JsonBuf {
                key: Some(egui::Id::unique("finalmask-test")),
                text: "{ invalid".into(),
                error: Some("parse failed".into()),
                dirty: true,
                profile: tokyo.id.clone(),
            },
        );
        harness.run();
        select_row(&mut harness, &osaka.id);
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
            state.0.seeded_buffers.json().is_empty(),
            "Discard must clear the raw buffers"
        );
    }

    #[test]
    fn add_draft_close_stages_close_leave_when_the_draft_is_dirty() {
        let mut screen = ServersScreen::default();
        let draft = ServerProfile::new("New Freedom server", OutboundModel::new(Protocol::Freedom));
        // The dialog has rendered, so its memo carries the flag: a fresh add
        // draft is unsaved by definition (it has no committed source).
        screen.close_add_draft(rendered_add_draft(&draft, true));
        assert_eq!(
            screen.leave_pending,
            Some(LeaveAction::CloseAdd),
            "closing the add dialog with a dirty draft must stage CloseAdd"
        );
        assert_eq!(
            screen.add.draft.as_ref().map(|d| d.id.as_str()),
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
        screen.close_add_draft(rendered_add_draft(&draft, false));
        assert!(
            screen.leave_pending.is_none(),
            "a clean add draft must not stage the leave modal"
        );
        assert!(
            screen.add.draft.is_none(),
            "a clean add draft must be dropped on close"
        );
    }

    #[test]
    fn add_draft_close_clears_a_targeting_derive_dialog_and_keeps_the_guard() {
        let mut screen = ServersScreen::default();
        let draft = ServerProfile::new("New Freedom server", OutboundModel::new(Protocol::Freedom));
        // The dialog has rendered, so its memo carries the flag: a fresh add
        // draft is unsaved by definition.
        screen.derive_dialog = Some(DeriveDialog {
            target: ToolTarget::AddDraft {
                profile_id: draft.id.clone(),
                generation: 0,
            },
            private_key: String::new(),
            error: None,
            pending: false,
        });
        screen.close_add_draft(rendered_add_draft(&draft, true));
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
            screen.add.draft.as_ref().map(|d| d.id.as_str()),
            Some(draft.id.as_str()),
            "the staged draft must stay in the dialog until the modal resolves"
        );
    }

    /// The question about a dirty add draft belongs to the editor window: while
    /// that window is on screen the shell's tail renders nothing, so the frame
    /// holds one copy of the question — the one inside the editor — and not a
    /// second window on top of it.
    #[test]
    fn the_add_windows_leave_question_renders_in_the_editor_alone() {
        let mut harness = unsaved_harness(UiTestRig::default());
        let draft = ServerProfile::new("New Freedom server", OutboundModel::new(Protocol::Freedom));
        {
            let screen = &mut harness.state_mut().0;
            screen.add.draft = Some(rendered_add_draft(&draft, true));
            screen.leave_pending = Some(LeaveAction::CloseAdd);
        }
        harness.run();
        assert_eq!(
            harness
                .get_all_by_label(t(Language::En, Key::SrvDiscardChanges))
                .count(),
            1,
            "the editor window owns the question about its own draft"
        );
    }

    /// Discard in the question inside the editor closes the draft with the
    /// window the user asked to close: the editor does not come back empty.
    #[test]
    fn discard_in_the_add_windows_leave_question_closes_the_draft() {
        let mut harness = unsaved_harness(UiTestRig::default());
        let draft = ServerProfile::new("New Freedom server", OutboundModel::new(Protocol::Freedom));
        {
            let screen = &mut harness.state_mut().0;
            screen.add.draft = Some(rendered_add_draft(&draft, true));
            screen.leave_pending = Some(LeaveAction::CloseAdd);
        }
        harness.run();
        harness
            .get_all_by_label(t(Language::En, Key::SrvDiscardChanges))
            .last()
            .expect("the question must render inside the editor")
            .click();
        harness.run();
        let state = harness.state();
        assert!(
            state.0.add.draft.is_none(),
            "Discard must drop the draft with the window it closed"
        );
        assert!(
            state.0.leave_pending.is_none(),
            "Discard must clear the staged close"
        );
    }

    /// Save in the question inside the editor keeps the editor open: the
    /// question renders again with the verdict's spinner, over the draft it is
    /// waiting on.
    #[test]
    fn save_in_the_add_windows_leave_question_keeps_the_editor_open() {
        let mut harness = unsaved_harness(UiTestRig::default());
        let draft = ServerProfile::new("New Freedom server", OutboundModel::new(Protocol::Freedom));
        {
            let screen = &mut harness.state_mut().0;
            screen.add.draft = Some(rendered_add_draft(&draft, true));
            screen.leave_pending = Some(LeaveAction::CloseAdd);
        }
        harness.run();
        harness
            .get_all_by_label(t(Language::En, Key::SrvUnsavedLeaveSave))
            .last()
            .expect("the question must render its Save button")
            .click();
        // The verdict it starts renders a spinner, so the frame keeps asking
        // for repaints: step rather than run to a settled frame.
        harness.run_steps(2);
        let state = harness.state();
        assert!(
            state.0.profile_validation_request.is_pending(),
            "Save must start the draft's validation"
        );
        assert!(
            state.0.add.draft.is_some(),
            "Save must hold the draft for the verdict it starts"
        );
        assert_eq!(
            state.0.leave_pending,
            Some(LeaveAction::CloseAdd),
            "the staged close must stay staged until the verdict lands"
        );
    }

    /// A dismissal of the question inside the editor is its Cancel: the staged
    /// close is cleared and the editor stays open, the way it was before the
    /// user closed it.
    #[test]
    fn dismissing_the_add_windows_leave_question_keeps_the_editor_open() {
        let mut harness = unsaved_harness(UiTestRig::default());
        let draft = ServerProfile::new("New Freedom server", OutboundModel::new(Protocol::Freedom));
        {
            let screen = &mut harness.state_mut().0;
            screen.add.draft = Some(rendered_add_draft(&draft, true));
            screen.leave_pending = Some(LeaveAction::CloseAdd);
        }
        harness.run();
        harness.key_press(egui::Key::Escape);
        harness.run();
        let state = harness.state();
        assert!(
            state.0.leave_pending.is_none(),
            "a dismissal must clear the staged close"
        );
        assert!(
            state.0.add.draft.is_some(),
            "a dismissal must leave the editor open"
        );
    }

    /// Off the servers screen the editor window is gone with the screen: the
    /// question falls back to the main window, so a staged close stays
    /// answerable instead of waiting for the user to come back.
    #[test]
    fn the_leave_question_falls_back_to_the_main_window_off_screen() {
        let rig = UiTestRig::default();
        let mut harness = harness_builder()
            .with_size(DEFAULT_TEST_VIEWPORT)
            .build_ui_state(
                |ui, state: &mut (ServersScreen, UiTestRig)| {
                    // The shell's tail alone: the screen, and with it the editor
                    // window, is not rendered this frame.
                    state
                        .0
                        .show_leave_modal(ui.ctx(), &mut state.1.ctx().servers(), false);
                },
                (ServersScreen::default(), rig),
            );
        let draft = ServerProfile::new("New Freedom server", OutboundModel::new(Protocol::Freedom));
        {
            let screen = &mut harness.state_mut().0;
            screen.add.draft = Some(rendered_add_draft(&draft, true));
            screen.leave_pending = Some(LeaveAction::CloseAdd);
        }
        harness.run();
        assert_eq!(
            harness
                .get_all_by_label(t(Language::En, Key::SrvDiscardChanges))
                .count(),
            1,
            "the question must render its own window when the editor is not on screen"
        );
    }

    #[test]
    fn unsaved_changes_uses_the_memo_and_recomputes_only_when_stale() {
        let mut screen = ServersScreen::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        let mut edited = tokyo.clone();
        edited.name = "Tokyo-2".into();
        let mut draft = draft_for(&tokyo);
        draft.profile = edited;
        draft.generation = 3;
        screen.existing.draft = Some(draft);
        assert!(
            !screen.unsaved_changes(),
            "a fresh draft carries no memo and is never dirty"
        );
        screen.existing.draft.as_mut().unwrap().validation = Some(clean_memo(3, false));
        assert!(
            !screen.unsaved_changes(),
            "a fresh memo must be authoritative"
        );
        screen.existing.draft.as_mut().unwrap().generation = 4;
        assert!(
            screen.unsaved_changes(),
            "a stale memo must recompute the flag inline (same-frame accuracy)"
        );
        screen.existing.draft.as_mut().unwrap().validation = Some(clean_memo(4, false));
        screen.seeded_buffers.json_mut().insert(
            egui::Id::unique("raw-field"),
            JsonBuf {
                key: None,
                text: "{".into(),
                error: Some("unterminated".into()),
                dirty: true,
                profile: tokyo.id,
            },
        );
        assert!(
            screen.unsaved_changes(),
            "a raw buffer holding uncommitted text must be dirty regardless of the memo"
        );
        // The add draft contributes independently.
        screen.seeded_buffers.clear();
        let new_profile =
            ServerProfile::new("New VLESS server", OutboundModel::new(Protocol::Vless));
        screen.add.draft = Some(rendered_add_draft(&new_profile, true));
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
        let mut draft = draft_for(&tokyo);
        draft.generation = 7;
        screen.existing.draft = Some(draft);
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
                profile_id: tokyo.id,
                generation: 7,
            }),
        }))
        .unwrap();
        screen.poll_profile_validation(Language::En, &mut rig.ctx().servers());
        assert!(
            screen.leave_pending.is_none(),
            "a rejected validation must cancel the staged leave action"
        );
        assert!(
            screen.existing.draft.is_some(),
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
        let mut draft = draft_for(&tokyo);
        draft.profile = edited.clone();
        draft.generation = 3;
        draft.validation = Some(clean_memo(3, true));
        screen.existing.draft = Some(draft);
        // The add draft stays dirty after the existing draft commits: the
        // quit must remain staged for a second Save.
        let add = ServerProfile::new("New VLESS server", OutboundModel::new(Protocol::Vless));
        screen.add.draft = Some(rendered_add_draft(&add, true));
        screen.leave_pending = Some(LeaveAction::Quit);
        let (tx, rx) = tokio::sync::oneshot::channel();
        screen.profile_validation_request = Request::reply(rx);
        screen.profile_validation_origin = Some(ProfileValidationOrigin::Draft);
        tx.send(Ok(ProfileValidationResult {
            origin: ProfileValidationOrigin::Draft,
            accepted: vec![edited],
            rejected: Vec::new(),
            import_source: None,
            draft_target: Some(ToolTarget::ExistingDraft {
                profile_id: tokyo.id,
                generation: 3,
            }),
        }))
        .unwrap();
        screen.poll_profile_validation(Language::En, &mut rig.ctx().servers());
        assert_eq!(
            screen.leave_pending,
            Some(LeaveAction::Quit),
            "the quit must stay staged while the add draft is dirty"
        );
        assert!(!rig.requests.quit_resume, "the quit must not resume yet");
        assert!(
            screen.existing.draft.is_none(),
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
        screen.poll_profile_validation(Language::En, &mut rig.ctx().servers());
        assert!(
            screen.leave_pending.is_none(),
            "the staged quit must clear on the final commit"
        );
        assert!(
            rig.requests.quit_resume,
            "the quit must resume once nothing is dirty"
        );
        assert!(
            std::mem::take(&mut rig.requests.quit_resume),
            "the shell's drain must observe the resume"
        );
        assert!(
            !rig.requests.quit_resume,
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
        let mut draft = draft_for(&tokyo);
        draft.validation = Some(clean_memo(0, true));
        screen.existing.draft = Some(draft);
        let add = ServerProfile::new("New VLESS server", OutboundModel::new(Protocol::Vless));
        screen.add.draft = Some(rendered_add_draft(&add, true));
        screen.discard_leave_action(LeaveAction::Quit, &mut rig.ctx().servers());
        assert!(
            screen.existing.draft.is_none(),
            "Quit discard must drop the existing draft"
        );
        assert!(
            screen.add.draft.is_none(),
            "Quit discard must drop the add draft"
        );
        assert!(
            rig.requests.quit_resume,
            "Quit discard must resume the quit"
        );
    }

    #[test]
    fn select_discard_reverts_only_the_existing_draft() {
        let mut screen = ServersScreen::default();
        let mut rig = UiTestRig::default();
        let tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        rig.servers.profiles.push(tokyo.clone());
        let mut draft = draft_for(&tokyo);
        draft.validation = Some(clean_memo(0, true));
        screen.existing.draft = Some(draft);
        // An open add dialog is independent of the selection switch: the
        // Select discard reverts the existing draft but keeps the add draft.
        let add = ServerProfile::new("New VLESS server", OutboundModel::new(Protocol::Vless));
        screen.add.draft = Some(ProfileDraft::add(add.clone()));
        screen.discard_leave_action(
            LeaveAction::Select("osaka-target-id".into()),
            &mut rig.ctx().servers(),
        );
        assert_eq!(
            screen
                .existing
                .draft
                .as_ref()
                .map(|draft| (draft.id.as_str(), draft.profile.name.as_str())),
            Some((tokyo.id.as_str(), tokyo.name.as_str())),
            "Select discard must revert the existing draft in place"
        );
        assert!(
            screen
                .existing
                .draft
                .as_ref()
                .is_some_and(|draft| !draft.changed_from_source()),
            "the reverted draft must be clean"
        );
        assert_eq!(
            screen.add.draft.as_ref().map(|d| d.id.as_str()),
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

    /// The editor action row's rendered enablement, one gate fact moved at a
    /// time: a pristine draft (neither control), an edited draft that nothing
    /// blocks (both live), a draft that still matches its source while a raw
    /// buffer holds text that never reached it (Discard only), an edited
    /// draft carrying a blocking finding (Discard only), an edited draft
    /// whose validation job is in flight (neither), and an edited draft under
    /// a held busy window (Discard only). Every fact the row's gate reads
    /// moves in one of these, so a fact that stops reaching the rendered
    /// enablement reds this test.
    #[test]
    fn editor_action_row_renders_the_gate_fact_combinations() {
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
        install_draft(&mut harness.state_mut().0, &edited, &clean);
        harness.run();
        assert_eq!(
            action_row_disabled(&harness),
            (false, false),
            "an edited draft that nothing blocks must be saveable and discardable"
        );

        // A raw buffer holding text that never reached the draft: the draft
        // itself still matches its source, so Save must refuse (committing
        // it would leave the unsaved text behind) while Discard stays live,
        // or the user would be stuck with the error text.
        install_draft(&mut harness.state_mut().0, &clean, &clean);
        harness.state_mut().0.seeded_buffers.json_mut().insert(
            egui::Id::unique("finalmask-raw-action-row"),
            JsonBuf {
                key: None,
                text: "{ invalid".into(),
                error: Some("parse failed".into()),
                dirty: true,
                profile: clean.id.clone(),
            },
        );
        harness.run();
        assert_eq!(
            action_row_disabled(&harness),
            (true, false),
            "uncommitted raw text must offer Discard even when the draft is unchanged"
        );
        harness.state_mut().0.seeded_buffers.clear();

        // The edit plus a blocking finding: Discard stays, Save goes dark.
        let mut blocked = edited;
        blocked.outbound.stream.finalmask = Some(bad_finalmask_model());
        install_draft(&mut harness.state_mut().0, &blocked, &clean);
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

        // The edited draft while its validation job is in flight: the row
        // waits the job out rather than offering a commit its answer may
        // refuse.
        let (tx, rx) = tokio::sync::oneshot::channel();
        harness.state_mut().0.profile_validation_request = Request::reply(rx);
        harness.state_mut().0.profile_validation_origin = Some(ProfileValidationOrigin::Draft);
        // The in-flight state shows the validation spinner, whose repaint
        // request never settles, so the frame budget is pinned instead of run
        // to quiescence.
        harness.run_steps(4);
        assert_eq!(
            action_row_disabled(&harness),
            (true, true),
            "an in-flight validation must hold the whole action row"
        );

        // The edited draft under a held busy window: the exclusive job owns
        // the commit, so Save waits it out; Discard is not a commit.
        harness.state_mut().0.profile_validation_request.cancel();
        harness.state_mut().0.profile_validation_origin = None;
        harness.state_mut().1.operation = Some(JobKind::Start);
        harness.run();
        assert_eq!(
            action_row_disabled(&harness),
            (true, false),
            "a held busy window must take Save dark without touching Discard"
        );
        drop(tx);
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
        let mut draft = draft_for(&profile);
        draft.generation = 1;

        draft.refresh(Language::En);
        let swept = draft
            .validation
            .as_ref()
            .expect("the first refresh sweeps the draft");
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
        draft.refresh(Language::En);
        let reused = draft.validation.as_ref().expect("the memo stays populated");
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
        let current = draft.profile.clone();
        draft.baseline = DraftBaseline::of(&current).expect("the fixture serializes");
        draft.generation = 2;
        draft.refresh(Language::En);
        let reswept = draft.validation.as_ref().expect("the memo stays populated");
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
        rig.servers.active = Some(tokyo.id);
        let mut harness = unsaved_harness(rig);
        harness.run();
        harness.get_by_label("Advanced").click();
        harness.run();
        assert!(
            harness.query_by_label(BAD_TCP_ITEM_MESSAGE).is_some(),
            "the finalmask verdict must render inline on the Advanced tab"
        );
        assert_eq!(
            editor_memo(&harness.state().0)
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
        let draft = state.0.existing.draft.as_mut().unwrap();
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
            .existing
            .draft
            .as_ref()
            .expect("the editor keeps the edited draft")
            .generation;
        let cache = open_draft(&harness.state().0)
            .validation
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
        editor_memo(&harness.state().0).findings.blocking.clone()
    }

    /// The draft's advisory findings, as the editor's own sweep produced them.
    fn editor_advisory(
        harness: &Harness<'static, (ServersScreen, UiTestRig)>,
    ) -> Vec<ValidationIssue> {
        editor_memo(&harness.state().0).findings.advisory.clone()
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
            harness.state().0.existing.draft.is_some(),
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
                .existing
                .draft
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
            .filter(|label| label.starts_with('[') || matches!(*label, "direct" | "block"))
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
            .existing
            .draft
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
        rig.servers.active = Some(tokyo.id);
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
            .existing
            .draft
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
                .existing
                .draft
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
        rig.servers.active = Some(alpha.id);
        let mut harness = unsaved_harness(rig);
        harness.run();
        harness.get_by_label("Advanced").click();
        harness.run();
        // The options list's allocation identity is the memo, and its
        // generation is the profile-set signal it was built for.
        let built_for = harness
            .state()
            .0
            .existing
            .chain_options
            .as_ref()
            .expect("the first Advanced frame builds the chain-target options once")
            .generation;
        assert_eq!(
            built_for.1, 2,
            "the options must be built for the rendered profile set"
        );
        let options = harness
            .state()
            .0
            .existing
            .chain_options
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
                .existing
                .chain_options
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
            .existing
            .chain_options
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
                .existing
                .chain_options
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
            .existing
            .draft
            .as_ref()
            .expect("the draft opens")
            .profile
            .clone();
        assert!(
            harness
                .query_by_label("The app removes the retired key. The server dials directly.")
                .is_none(),
            "the removal is the control's job; no note line states it"
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
            .existing
            .draft
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
            .existing
            .draft
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
        rig.servers.active = Some(profile.id);
        rig
    }

    /// The draft's `quicParams` as the editor holds it.
    fn draft_quic_params(
        harness: &Harness<'static, (ServersScreen, UiTestRig)>,
    ) -> FinalmaskQuicParams {
        harness
            .state()
            .0
            .existing
            .draft
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
            .existing
            .draft
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
        // QUIC parameters: the editor opens on it, the amber advisory list
        // names the mask and the equivalence, and only building the mask
        // resolves the key.
        let mut harness = wide_servers_harness(retired_hop_rig());
        harness.run();
        assert!(
            harness.state().0.existing.draft.is_some(),
            "a profile with the retired key must stay editable"
        );
        let hop = finding(
            &editor_advisory(&harness),
            ValidationCode::FinalmaskQuicHopMoved,
        );
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
            .existing
            .draft
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
            !editor_advisory(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::FinalmaskQuicHopMoved),
            "{:#?}",
            editor_advisory(&harness)
        );
        let draft = &harness.state().0.existing.draft.as_ref().unwrap().profile;
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
            .existing
            .draft
            .as_ref()
            .expect("the draft opens")
            .profile
            .clone();
        assert!(
            harness
                .query_by_label("The app removes the retired key. The hop stops working.")
                .is_none(),
            "the removal is the control's job; no note line states it"
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
        let draft = &harness.state().0.existing.draft.as_ref().unwrap().profile;
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
            !editor_advisory(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::FinalmaskQuicHopMoved),
            "{:#?}",
            editor_advisory(&harness)
        );
    }

    /// A WireGuard profile carrying the retired `settings.domainStrategy`
    /// key in the shape a stored file would hold.
    fn wireguard_domain_strategy_rig(strategy: &str) -> UiTestRig {
        let mut profile = ServerProfile::new("wg", OutboundModel::new(Protocol::Wireguard));
        if let ProtocolSettings::Wireguard(settings) = &mut profile.outbound.settings {
            settings.domain_strategy = strategy.to_owned();
        }
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(profile.clone());
        rig.servers.active = Some(profile.id);
        rig
    }

    /// A profile whose single `udphop` UDP mask carries the retired `sockopt`
    /// key in the shape a stored file would hold.
    fn udphop_sockopt_rig() -> UiTestRig {
        let mut profile = ServerProfile::new("Hy", OutboundModel::new(Protocol::Freedom));
        profile.outbound.stream.finalmask = Some(FinalmaskModel {
            udp: vec![FinalmaskUdpMask::Udphop {
                settings: Box::new(FinalmaskUdpHop {
                    sockopt: Some(SockoptModel {
                        domain_strategy: "UseIPv4".into(),
                        interface: "eth0".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                extra: serde_json::Map::new(),
            }],
            ..Default::default()
        });
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(profile.clone());
        rig.servers.active = Some(profile.id);
        rig
    }

    #[test]
    fn wireguard_domain_strategy_offers_no_picker_and_its_notice_clears_the_key() {
        // The pinned core deleted the field, so the editor offers no way to
        // set it: a retained value draws the advisory inline with a control
        // that drops it, and clearing leaves the generated document without
        // the key.
        let message = validation_message(
            &ValidationCode::WireguardDomainStrategyRetired,
            Language::En,
        );
        let mut harness = wide_servers_harness(wireguard_domain_strategy_rig("ForceIPv4"));
        harness.run();

        assert!(
            harness
                .get_all_by_role(egui::accesskit::Role::ComboBox)
                .all(|node| node.value().as_deref() != Some("ForceIPv4")),
            "no picker may offer the retired strategy"
        );
        assert!(
            harness.query_by_label("domain strategy").is_none(),
            "the strategy combo's own label must be gone"
        );
        assert!(
            editor_advisory(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::WireguardDomainStrategyRetired),
            "{:#?}",
            editor_advisory(&harness)
        );

        let remove = t(Language::En, Key::SrvRemoveWgDomainStrategyKey);
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, remove)
            .scroll_to_me();
        harness.run();
        // The model's message renders here as well as in the warnings list.
        assert!(
            harness
                .query_all_by_label_contains(message.as_str())
                .next()
                .is_some(),
            "the advisory's own text must render with its removal control"
        );
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, remove)
            .click();
        harness.run();
        harness.run();

        let draft = harness
            .state()
            .0
            .existing
            .draft
            .as_ref()
            .expect("the editor stays open")
            .profile
            .clone();
        let ProtocolSettings::Wireguard(settings) = &draft.outbound.settings else {
            panic!("the draft stays a WireGuard profile");
        };
        assert!(
            settings.domain_strategy.is_empty(),
            "the removal must clear the stored value"
        );
        assert!(
            !editor_advisory(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::WireguardDomainStrategyRetired),
            "{:#?}",
            editor_advisory(&harness)
        );
        assert!(
            draft.outbound.to_wire("wg")["settings"]
                .get("domainStrategy")
                .is_none(),
            "the cleared key must stay out of the generated document"
        );
    }

    #[test]
    fn wireguard_domain_strategy_notice_stays_quiet_for_a_fresh_profile() {
        let message = validation_message(
            &ValidationCode::WireguardDomainStrategyRetired,
            Language::En,
        );
        let harness = wide_servers_harness(wireguard_domain_strategy_rig(""));
        assert!(
            harness
                .query_all_by_label_contains(message.as_str())
                .next()
                .is_none(),
            "an empty strategy must not draw the notice"
        );
        assert!(
            harness
                .query_all_by_label(t(Language::En, Key::SrvRemoveWgDomainStrategyKey))
                .next()
                .is_none(),
            "an empty strategy must not draw the removal control"
        );
    }

    #[test]
    fn udphop_sockopt_has_no_sub_editor_and_its_notice_clears_the_key() {
        // The core removed the per-hop `sockopt` key, so the mask editor drops
        // its sub-editor: a retained block draws the advisory inline with a
        // control that drops it, while the mask's own fields stay.
        let message =
            validation_message(&ValidationCode::FinalmaskUdpHopSockoptRetired, Language::En);
        let remove = t(Language::En, Key::SrvRemoveUdpHopSockoptKey);
        let mut harness = wide_servers_harness(udphop_sockopt_rig());
        harness.run();
        harness.get_by_label("Advanced").click();
        harness.run();

        assert_eq!(
            harness
                .query_all_by_role_and_label(egui::accesskit::Role::CheckBox, "sockopt")
                .count(),
            0,
            "the mask sockopt sub-editor's switch must be gone"
        );
        assert!(
            harness
                .get_all_by_role(egui::accesskit::Role::ComboBox)
                .all(|node| node.value().as_deref() != Some("UseIPv4")),
            "the retired block's values must not be editable"
        );

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, remove)
            .scroll_to_me();
        harness.run();
        assert!(
            harness
                .query_all_by_label_contains(message.as_str())
                .next()
                .is_some(),
            "the advisory's own text must render with its removal control"
        );
        // The mask's own live fields keep rendering.
        assert!(
            harness
                .get_by_role_and_label(egui::accesskit::Role::CheckBox, "perConnRemote")
                .accesskit_node()
                .toggled()
                .is_some(),
            "the mask's mode switches must stay"
        );
        assert!(
            harness.query_all_by_label("remotePorts").next().is_some(),
            "the mask's remote port field must stay"
        );

        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, remove)
            .click();
        harness.run();
        harness.run();

        let draft = harness
            .state()
            .0
            .existing
            .draft
            .as_ref()
            .expect("the editor stays open")
            .profile
            .clone();
        let mask = draft
            .outbound
            .stream
            .finalmask
            .as_ref()
            .and_then(|finalmask| finalmask.udp.first())
            .expect("the draft keeps the mask");
        let FinalmaskUdpMask::Udphop { settings, .. } = mask else {
            panic!("the draft keeps the udphop mask");
        };
        assert!(
            settings.sockopt.is_none(),
            "the removal must clear the stored block"
        );
        assert!(
            !editor_memo(&harness.state().0)
                .findings
                .finalmask
                .iter()
                .any(|issue| issue.code == ValidationCode::FinalmaskUdpHopSockoptRetired),
            "{:#?}",
            editor_memo(&harness.state().0).findings.finalmask
        );
        let wire = draft.outbound.to_wire("Hy");
        assert!(
            wire["streamSettings"]["finalmask"]["udp"][0]["settings"]
                .get("sockopt")
                .is_none(),
            "the cleared block must stay out of the generated document: {wire}"
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
        rig.servers.active = Some(profile.id);
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
            .existing
            .draft
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
            .existing
            .draft
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
        rig.servers.active = Some(profile.id);
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
                .is_none(),
            "the retired per-mask socket options must not render an editor"
        );

        // intervalLocal joins the set; the stored unknown token rides along.
        // The window's own scroll must bring the mode row into view first.
        harness
            .get_by_role_and_label(egui::accesskit::Role::CheckBox, "intervalLocal")
            .scroll_to_me();
        harness.run();
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

    /// The add draft is swept through the same refresher as the editor's
    /// draft, over its own baseline: a refresh at the same generation keeps
    /// the findings it holds, a moved generation sweeps again, and its strings
    /// follow the findings it swept.
    #[test]
    fn add_draft_memo_reuses_findings_until_the_generation_moves() {
        let mut draft = ProfileDraft::add(profile_with_bad_finalmask());
        draft.refresh(Language::En);
        let swept = draft
            .validation
            .as_ref()
            .expect("the first refresh sweeps the add draft");
        assert!(
            swept.changed_from_source,
            "a fresh add draft differs from the empty baseline it was created against"
        );
        let verdicts = codes_of(&swept.findings.finalmask);
        assert_eq!(verdicts.len(), 1, "{:#?}", swept.findings.finalmask);
        let rendered = swept.rendered.finalmask.clone();

        // The same generation with an edited profile behind it: the memo
        // answers with the sweep it made (the dialog bumps the generation on
        // every content edit, so this is the idle-frame path).
        draft.profile.name = "edited".into();
        draft.refresh(Language::En);
        let reused = draft.validation.as_ref().expect("the memo stays populated");
        assert_eq!(
            codes_of(&reused.findings.finalmask),
            verdicts,
            "a same-generation refresh must not re-sweep: {:#?}",
            reused.findings.finalmask
        );
        assert_eq!(reused.rendered.finalmask, rendered);

        // A moved generation sweeps the clean profile the draft now carries.
        draft.profile = ServerProfile::new("direct", OutboundModel::new(Protocol::Freedom));
        draft.generation = 1;
        draft.refresh(Language::En);
        let reswept = draft.validation.as_ref().expect("the memo stays populated");
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
        rig.servers.active = Some(tokyo.id);
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
                .existing
                .draft
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
            editor_memo(&harness.state().0).generation,
            open_draft(&harness.state().0).generation,
            "the conversion edit must re-validate exactly once"
        );
        // Re-picking the current type of a known mask is a no-op: the draft
        // generation — the key every edit bumps and the memo sweeps on —
        // must not move.
        let generation = harness
            .state()
            .0
            .existing
            .draft
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
                .existing
                .draft
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
                .existing
                .draft
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
            let mut profile = ServerProfile::new(
                format!("Server {i:02}"),
                OutboundModel::new(Protocol::Freedom),
            );
            profile.enabled = true;
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
        let mut harness = wide_table_harness(rig);
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
        let mut harness = wide_table_harness(rig);
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
                source: egui::MouseWheelSource::Unknown,
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

        // The row's context menu is its whole command surface. Delete… stages
        // the confirmation dialog for that profile.
        harness
            .query_by_role_and_label(egui::accesskit::Role::Button, "Server 63")
            .expect("the last row is laid out")
            .click_secondary();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvDeleteEllipsis))
            .click();
        harness.run_steps(2);
        assert_eq!(
            harness
                .state()
                .0
                .delete_pending
                .as_ref()
                .map(|dialog| dialog.name.as_str()),
            Some("Server 63"),
            "the delete dialog must target the row whose menu was opened"
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

        // Test latency in the row's menu sends exactly that profile. It runs
        // last: the pending probe's toolbar row shifts the table below.
        harness
            .query_by_role_and_label(egui::accesskit::Role::Button, "Server 63")
            .expect("the last row is laid out")
            .click_secondary();
        harness.run();
        harness
            .get_all_by_label(t(Language::En, Key::TestLatency))
            .last()
            .expect("the row menu offers Test latency")
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
                    "the probe must carry the row whose menu was opened"
                );
            }
            other => panic!("expected ProbeLatency, got {other:?}"),
        }
        assert_eq!(
            harness.state().0.pending_latency_probe,
            Some(true),
            "the row probe must mark the pending slot"
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
        rig.servers.active = Some(profile.id);
        rig
    }

    /// The peer fields of a WireGuard profile whose secret key is set and
    /// whose first peer is empty.
    fn wireguard_peer_rig() -> UiTestRig {
        let mut profile = ServerProfile::new("wg", OutboundModel::new(Protocol::Wireguard));
        if let ProtocolSettings::Wireguard(settings) = &mut profile.outbound.settings {
            settings.secret_key = "01".repeat(32);
            settings.peers.push(WireguardPeer::default());
        }
        let mut rig = UiTestRig::default();
        rig.servers.profiles.push(profile.clone());
        rig.servers.active = Some(profile.id.clone());
        rig
    }

    /// Type `text` into the peer field the editor labels `label`: click it like
    /// a user, then send the keystrokes.
    fn type_into_peer_field(
        harness: &mut Harness<'static, (ServersScreen, UiTestRig)>,
        label: &str,
        text: &str,
    ) {
        let field = harness
            .query_all_by_role_and_label(egui::accesskit::Role::TextInput, label)
            .next()
            .unwrap_or_else(|| panic!("the {label:?} row must render"));
        field.scroll_to_me();
        harness.run();
        harness
            .query_all_by_role_and_label(egui::accesskit::Role::TextInput, label)
            .next()
            .expect("the field renders")
            .click();
        harness.run_steps(2);
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.is_focused())
            .unwrap_or_else(|| panic!("the clicked {label:?} field takes focus"))
            .type_text(text);
        harness.run_steps(2);
    }

    /// Open the add editor on the Freedom protocol through the toolbar menu.
    fn open_add_editor(harness: &mut Harness<'static, (ServersScreen, UiTestRig)>) {
        harness
            .get_by_label(t(Language::En, Key::SrvAddServer))
            .click();
        harness.run();
        harness
            .query_all_by_role_and_label(egui::accesskit::Role::Button, Protocol::Freedom.as_str())
            .next()
            .expect("the protocol menu offers Freedom")
            .click();
        harness.run();
    }

    /// Replace the text of the text field `label`: click it like a user,
    /// select all, then type over the selection.
    fn replace_field_text(
        harness: &mut Harness<'static, (ServersScreen, UiTestRig)>,
        label: &str,
        text: &str,
    ) {
        let field = harness
            .query_all_by_role_and_label(egui::accesskit::Role::TextInput, label)
            .next()
            .unwrap_or_else(|| panic!("the {label:?} field must render"));
        field.scroll_to_me();
        harness.run();
        harness
            .query_all_by_role_and_label(egui::accesskit::Role::TextInput, label)
            .next()
            .expect("the field renders")
            .click();
        harness.run_steps(2);
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.is_focused())
            .unwrap_or_else(|| panic!("the clicked {label:?} field takes focus"))
            .type_text(text);
        harness.run_steps(2);
    }

    /// Every inline verdict line the peers section paints between two fields,
    /// as its text.
    fn verdict_rows_between(
        harness: &Harness<'static, (ServersScreen, UiTestRig)>,
        above: egui::Rect,
        below: egui::Rect,
    ) -> Vec<String> {
        let mut rows: Vec<(f32, String)> = harness
            .query_all_by_role(egui::accesskit::Role::Label)
            .filter_map(|node| {
                let rect = node.rect();
                let text = node.accesskit_node().value()?;
                (rect.top() >= above.bottom() && rect.top() < below.top())
                    .then_some((rect.top(), text))
            })
            .collect();
        rows.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
        rows.into_iter().map(|(_, text)| text).collect()
    }

    /// A peer filled in one row at a time: every edit drops the filled row's
    /// verdict line, which moves the auto ids of the fields below it. A
    /// verdict must follow the field it belongs to and not the slot — an
    /// empty pre-shared key carries no error (`v_optional_wg_key` accepts
    /// empty), so the endpoint's disappearing "required" line must not land
    /// there.
    #[test]
    fn filling_a_peer_row_by_row_keeps_each_verdict_on_its_own_field() {
        let key = "01".repeat(32);
        let mut harness = wide_servers_harness(wireguard_peer_rig());
        harness.run();

        type_into_peer_field(&mut harness, "public key", &key);
        type_into_peer_field(&mut harness, "endpoint", "peer.example:51820");

        let draft = harness
            .state()
            .0
            .existing
            .draft
            .as_ref()
            .expect("the editor stays open");
        let ProtocolSettings::Wireguard(settings) = &draft.profile.outbound.settings else {
            panic!("the draft stays a WireGuard profile");
        };
        let peer = settings.peers.first().expect("the peer stays");
        assert_eq!(peer.public_key, key, "the public key edit must land");
        assert_eq!(
            peer.endpoint, "peer.example:51820",
            "the endpoint edit must land"
        );
        assert!(
            peer.pre_shared_key.is_empty(),
            "the test leaves the peer's pre-shared key empty"
        );

        // By its accessible name, not by its role: the editor masks the
        // credential rows, so this one renders the masked stand-in while the
        // peer's public key and endpoint stay editable.
        let psk = harness
            .query_all_by_label("pre-shared key")
            .next()
            .expect("the pre-shared key row renders");
        // The row's paint area: from the field's own line down to the header of
        // the next row (the peer's allowed-IPs list).
        let allowed_header = harness
            .query_by_label(t(Language::En, Key::SrvWgAllowedIps))
            .expect("the allowed-IPs header renders under the pre-shared key row");
        let rows = verdict_rows_between(&harness, psk.rect(), allowed_header.rect());
        assert!(
            rows.is_empty(),
            "the empty pre-shared key row must carry no verdict, found {rows:?}"
        );
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
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsInvalid))
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
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsInvalid))
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
            .existing
            .draft
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
    fn wireguard_remote_dns_rejects_the_retired_sentinel() {
        // The retired `local` sentinel is refused wherever it sits: the core
        // parses every entry as an address and the process dies when it
        // cannot, so the row reports its own verdict and the profile gates.
        let mut harness = wide_servers_harness(wireguard_rig(&["local"]));
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsInvalid))
                .is_some(),
            "the sentinel row must report its own verdict"
        );
        assert!(
            editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::WireguardRemoteDnsInvalid),
            "{:#?}",
            editor_blocking(&harness)
        );
        drop(harness);

        // Address literals, the zoned IPv6 form included, stay silent.
        let mut harness = wide_servers_harness(wireguard_rig(&["1.1.1.1", "fe80::1%eth0"]));
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsInvalid))
                .is_none(),
            "address literals must not report"
        );
        assert!(
            !editor_blocking(&harness)
                .iter()
                .any(|issue| issue.code == ValidationCode::WireguardRemoteDnsInvalid),
            "{:#?}",
            editor_blocking(&harness)
        );

        // A fresh empty row reports its own verdict, and the profile gates.
        let last_row_y = remote_dns_row(&harness, "fe80::1%eth0").rect().center().y;
        remote_dns_add_button(&harness, last_row_y).click();
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SrvWgRemoteDnsInvalid))
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
        // One store serves both halves: the realm mask's raw-JSON fields and
        // its PEM certificate lists seed into it.
        let buffers = Rc::new(RefCell::new(SeededBuffers::default()));
        let buffers_for_ui = Rc::clone(&buffers);
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = finalmask_udp_settings_editor(
                ui,
                Language::En,
                &mut mask_for_ui.borrow_mut(),
                RawField {
                    id: FieldKey {
                        key: egui::Id::unique("realm-editor-test"),
                        profile: "profile-test",
                    },
                    buffers: &mut buffers_for_ui.borrow_mut(),
                },
                false,
                0,
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
                .is_none(),
            "the ipMode note is the combo's hover, never a rendered line"
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
    fn realm_tls_allow_insecure_has_no_authoring_control_and_clears_on_demand() {
        // The core refuses the removed `allowInsecure` field, so the realm
        // TLS editor offers no way to set it: a retained value draws the
        // model's own message with a control that drops it.
        fn realm_tls(mask: &FinalmaskUdpMask) -> FinalmaskRealmTls {
            match mask {
                FinalmaskUdpMask::Realm { settings, .. } => settings
                    .tls_config
                    .clone()
                    .expect("the fixture carries tlsConfig"),
                other => panic!("the harness renders a realm mask, got {other:?}"),
            }
        }

        let message = validation_message(
            &ValidationCode::FinalmaskRealmAllowInsecureRemoved,
            Language::En,
        );
        let remove = t(Language::En, Key::SrvRemoveAllowInsecureKey);
        let mask = Rc::new(RefCell::new(FinalmaskUdpMask::Realm {
            settings: Box::new(FinalmaskRealm {
                url: "realm://token@realm.example/id".into(),
                tls_config: Some(FinalmaskRealmTls {
                    allow_insecure: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            extra: Default::default(),
        }));
        let mask_for_ui = Rc::clone(&mask);
        let buffers = Rc::new(RefCell::new(SeededBuffers::default()));
        let buffers_for_ui = Rc::clone(&buffers);
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = finalmask_udp_settings_editor(
                ui,
                Language::En,
                &mut mask_for_ui.borrow_mut(),
                RawField {
                    id: FieldKey {
                        key: egui::Id::unique("realm-allow-insecure-test"),
                        profile: "profile-test",
                    },
                    buffers: &mut buffers_for_ui.borrow_mut(),
                },
                false,
                0,
            );
        });
        harness.run();

        assert!(
            harness.query_by_label("allowInsecure (removed)").is_none(),
            "the removed allowInsecure switch must not come back"
        );
        assert!(
            harness.query_by_label_contains(message.as_str()).is_some(),
            "the removed-key notice must render while the value stands"
        );
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, remove)
            .scroll_to_me();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::Button, remove)
            .click();
        harness.run();
        assert!(
            realm_tls(&mask.borrow()).allow_insecure.is_none(),
            "the removal must clear the stored value"
        );
        assert!(
            harness.query_by_label_contains(message.as_str()).is_none(),
            "the notice must clear with the value"
        );
    }

    #[test]
    fn realm_tls_trust_switch_edits_the_mask_tls_config() {
        // The realm mask dials through its own TLS block, so the trust switch
        // is the same control with the same note as the outbound TLS editor.
        fn realm_tls(mask: &FinalmaskUdpMask) -> FinalmaskRealmTls {
            match mask {
                FinalmaskUdpMask::Realm { settings, .. } => settings
                    .tls_config
                    .clone()
                    .expect("the fixture carries tlsConfig"),
                other => panic!("the harness renders a realm mask, got {other:?}"),
            }
        }

        let note = t(Language::En, Key::SrvTlsUseSystemCaNote);
        let mask = Rc::new(RefCell::new(FinalmaskUdpMask::Realm {
            settings: Box::new(FinalmaskRealm {
                url: "realm://token@realm.example/id".into(),
                tls_config: Some(FinalmaskRealmTls::default()),
                ..Default::default()
            }),
            extra: Default::default(),
        }));
        let mask_for_ui = Rc::clone(&mask);
        let buffers = Rc::new(RefCell::new(SeededBuffers::default()));
        let buffers_for_ui = Rc::clone(&buffers);
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = finalmask_udp_settings_editor(
                ui,
                Language::En,
                &mut mask_for_ui.borrow_mut(),
                RawField {
                    id: FieldKey {
                        key: egui::Id::unique("realm-trust-switch-test"),
                        profile: "profile-test",
                    },
                    buffers: &mut buffers_for_ui.borrow_mut(),
                },
                false,
                0,
            );
        });
        harness.run();

        assert!(
            harness.query_by_label(note).is_none(),
            "the note is the row's hover, never a rendered line"
        );
        harness.get_by_label("useSystemCA").scroll_to_me();
        harness.run();
        harness.get_by_label("useSystemCA").hover();
        harness.run();
        harness.run();
        assert!(
            harness.query_all_by_label(note).next().is_some(),
            "the switch's hover must carry the note"
        );

        harness.get_by_label("useSystemCA").click();
        harness.run();
        assert!(realm_tls(&mask.borrow()).use_system_ca);
        assert_eq!(
            serde_json::to_value(&*mask.borrow()).unwrap()["settings"]["tlsConfig"]["useSystemCA"],
            json!(true)
        );
    }

    #[test]
    fn xdns_mask_editor_edits_names_addresses_and_worker() {
        fn xdns(mask: &FinalmaskUdpMask) -> &FinalmaskXdns {
            match mask {
                FinalmaskUdpMask::Xdns { settings, .. } => settings,
                other => panic!("the harness renders an xdns mask, got {other:?}"),
            }
        }
        let mask = Rc::new(RefCell::new(FinalmaskUdpMask::Xdns {
            settings: FinalmaskXdns {
                domains: vec![FinalmaskXdnsDomain {
                    names: vec!["a.example".into()],
                    len_limit: 255,
                    label_limit: 63,
                    types: vec![1],
                    ..Default::default()
                }],
                resolvers: vec![FinalmaskXdnsResolver {
                    addrs: vec!["1.1.1.1:53".into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            extra: Default::default(),
        }));
        let mask_for_ui = Rc::clone(&mask);
        let buffers = Rc::new(RefCell::new(SeededBuffers::default()));
        let buffers_for_ui = Rc::clone(&buffers);
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = finalmask_udp_settings_editor(
                ui,
                Language::En,
                &mut mask_for_ui.borrow_mut(),
                RawField {
                    id: FieldKey {
                        key: egui::Id::unique("xdns-editor-test"),
                        profile: "profile-test",
                    },
                    buffers: &mut buffers_for_ui.borrow_mut(),
                },
                false,
                0,
            );
        });
        harness.run();

        // The stored name and address each edit through their own text row,
        // and the worker row renders beside them.
        let name = harness
            .query_all_by_role_and_label(egui::accesskit::Role::TextInput, "name")
            .next()
            .expect("the domain name row renders");
        assert_eq!(name.value().as_deref(), Some("a.example"));
        name.click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.is_focused())
            .expect("the name field takes focus")
            .type_text(".alt");
        harness.run();
        assert_eq!(
            xdns(&mask.borrow()).domains[0].names,
            vec!["a.example.alt".to_string()]
        );
        let addr = harness
            .query_all_by_role_and_label(egui::accesskit::Role::TextInput, "addr")
            .next()
            .expect("the resolver address row renders");
        assert_eq!(addr.value().as_deref(), Some("1.1.1.1:53"));
        assert!(
            harness.query_by_label("worker").is_some(),
            "the resolver renders its worker row"
        );

        // The add actions append a name, an address, and a whole row; a new
        // domain keeps the A and AAAA record types instead of the core's
        // TXT-only empty default.
        harness
            .get_by_label(t(Language::En, Key::SrvAddXdnsName))
            .click();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvAddXdnsAddr))
            .click();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvAddXdnsDomain))
            .click();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvAddXdnsResolver))
            .click();
        harness.run();
        {
            let settings = mask.borrow();
            let settings = xdns(&settings);
            assert_eq!(settings.domains[0].names.len(), 2);
            assert_eq!(settings.resolvers[0].addrs.len(), 2);
            match &settings.domains[..] {
                [_, domain] => {
                    assert_eq!(domain.len_limit, 255);
                    assert_eq!(domain.label_limit, 63);
                    assert_eq!(domain.types, vec![1, 28]);
                    assert_eq!(domain.edns0, 0);
                }
                other => panic!("the add-domain action must append one row, got {other:?}"),
            }
            match &settings.resolvers[..] {
                [_, resolver] => {
                    assert!(resolver.addrs.is_empty());
                    assert_eq!(resolver.worker, 0);
                    assert!(resolver.tls_config.is_none());
                }
                other => panic!("the add-resolver action must append one row, got {other:?}"),
            }
        }

        // The first remove action clears the first domain row, the second the
        // next one.
        let remove = |harness: &mut Harness<'_, ()>| {
            harness
                .query_all_by_label(t(Language::En, Key::SrvRemove))
                .next()
                .expect("a row renders its remove action")
                .click();
            harness.run();
        };
        remove(&mut harness);
        assert_eq!(xdns(&mask.borrow()).domains.len(), 1);
        remove(&mut harness);
        assert!(xdns(&mask.borrow()).domains.is_empty());
    }

    #[test]
    fn xdns_resolver_tls_and_quic_sections_edit_the_mask() {
        fn resolver(mask: &FinalmaskUdpMask) -> FinalmaskXdnsResolver {
            match mask {
                FinalmaskUdpMask::Xdns { settings, .. } => settings
                    .resolvers
                    .first()
                    .cloned()
                    .expect("the fixture carries one resolver"),
                other => panic!("the harness renders an xdns mask, got {other:?}"),
            }
        }

        let mask = Rc::new(RefCell::new(FinalmaskUdpMask::Xdns {
            settings: FinalmaskXdns {
                resolvers: vec![FinalmaskXdnsResolver {
                    addrs: vec!["https://dns.example/dns-query".into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            extra: Default::default(),
        }));
        let mask_for_ui = Rc::clone(&mask);
        let buffers = Rc::new(RefCell::new(SeededBuffers::default()));
        let buffers_for_ui = Rc::clone(&buffers);
        let mut harness = harness_builder()
            // The resolver editor stacks the TLS and QUIC blocks; the QUIC
            // gate sits past the default harness height, where a click lands
            // outside the viewport.
            .with_size(egui::vec2(800.0, 1000.0))
            .build_ui(move |ui| {
                let _ = finalmask_udp_settings_editor(
                    ui,
                    Language::En,
                    &mut mask_for_ui.borrow_mut(),
                    RawField {
                        id: FieldKey {
                            key: egui::Id::unique("xdns-doh-test"),
                            profile: "profile-test",
                        },
                        buffers: &mut buffers_for_ui.borrow_mut(),
                    },
                    false,
                    0,
                );
            });
        harness.run();

        // The TLS block starts absent; enabling it is the same `TlsModel`
        // editor the outbound TLS surface uses, including the trust switch
        // and its note.
        assert!(resolver(&mask.borrow()).tls_config.is_none());
        let note = t(Language::En, Key::SrvTlsUseSystemCaNote);
        harness.get_by_label("tlsConfig").click();
        harness.run();
        assert!(resolver(&mask.borrow()).tls_config.is_some());
        assert!(
            harness.query_by_label(note).is_none(),
            "the note is the row's hover, never a rendered line"
        );
        harness.get_by_label("useSystemCA").scroll_to_me();
        harness.run();
        harness.get_by_label("useSystemCA").hover();
        harness.run();
        harness.run();
        assert!(
            harness.query_all_by_label(note).next().is_some(),
            "the switch's hover must carry the note"
        );
        harness.get_by_label("useSystemCA").click();
        harness.run();
        // The resolver's QUIC parameters gate behind their own key and, once
        // enabled, expose the same editor and rule set as the mask-level
        // block.
        assert!(resolver(&mask.borrow()).quic_config.is_none());
        harness.get_by_label("quicConfig").click();
        harness.run();
        assert!(resolver(&mask.borrow()).quic_config.is_some());
        assert!(
            harness.query_by_label("congestion").is_some(),
            "the QUIC section renders its controls"
        );

        let resolver = resolver(&mask.borrow());
        assert!(resolver.tls_config.expect("TLS was enabled").use_system_ca);
        let wire = serde_json::to_value(&*mask.borrow()).unwrap();
        assert_eq!(
            wire["settings"]["resolvers"][0]["tlsConfig"]["useSystemCA"],
            json!(true)
        );
        assert_eq!(wire["settings"]["resolvers"][0]["quicConfig"], json!({}));
    }

    /// Every `xdns` name and address row keeps its Remove action inside the
    /// row's clip rect at a narrow width. The rows share one right-to-left
    /// shape: the button pins to the right edge and the field fills the rest.
    /// A left-to-right row puts the unbounded field first and lays the button
    /// out past the clip rect, where egui never hit-tests it.
    #[test]
    fn xdns_text_rows_keep_their_remove_buttons_on_screen() {
        let mask = Rc::new(RefCell::new(FinalmaskUdpMask::Xdns {
            settings: FinalmaskXdns {
                domains: vec![FinalmaskXdnsDomain {
                    names: vec!["a.example".into()],
                    len_limit: 255,
                    label_limit: 63,
                    types: vec![1, 28],
                    ..Default::default()
                }],
                resolvers: vec![FinalmaskXdnsResolver {
                    addrs: vec!["1.1.1.1:53".into()],
                    ..Default::default()
                }],
                ..Default::default()
            },
            extra: Default::default(),
        }));
        let mask_for_ui = Rc::clone(&mask);
        let buffers = Rc::new(RefCell::new(SeededBuffers::default()));
        let buffers_for_ui = Rc::clone(&buffers);
        let width = 360.0;
        let height = 1600.0;
        let mut harness = harness_builder()
            .with_size(egui::vec2(width, height))
            .build_ui(move |ui| {
                let _ = finalmask_udp_settings_editor(
                    ui,
                    Language::En,
                    &mut mask_for_ui.borrow_mut(),
                    RawField {
                        id: FieldKey {
                            key: egui::Id::unique("xdns-remove-clip-test"),
                            profile: "profile-test",
                        },
                        buffers: &mut buffers_for_ui.borrow_mut(),
                    },
                    false,
                    0,
                );
            });
        harness.run();

        let viewport = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(width, height));
        let buttons: Vec<egui::Rect> = harness
            .query_all_by_label(t(Language::En, Key::SrvRemove))
            .map(|node| node.rect())
            .collect();
        assert!(
            buttons.len() >= 4,
            "the fixture renders a domain, a name, a resolver, and an address row: {buttons:?}"
        );
        for rect in buttons {
            assert!(
                viewport.contains_rect(rect),
                "an xdns Remove button must stay inside the clip rect: {rect:?} outside {viewport:?}"
            );
        }
    }

    #[test]
    fn noise_exp_item_offers_its_type_and_edits_as_text() {
        fn noise(mask: &FinalmaskUdpMask) -> &FinalmaskNoise {
            match mask {
                FinalmaskUdpMask::Noise { settings, .. } => settings,
                other => panic!("the harness renders a noise mask, got {other:?}"),
            }
        }

        // A loaded `exp` item: the type sits outside the byte-encoding kinds,
        // so it reaches the editor through its own combo and edits as text.
        let mask = Rc::new(RefCell::new(FinalmaskUdpMask::Noise {
            settings: FinalmaskNoise {
                noise: vec![FinalmaskNoiseItem {
                    encoding: "exp".into(),
                    packet: FinalmaskRawValue::Present(json!("<b 0x12>")),
                    ..Default::default()
                }],
                ..Default::default()
            },
            extra: Default::default(),
        }));
        let mask_for_ui = Rc::clone(&mask);
        let buffers = Rc::new(RefCell::new(SeededBuffers::default()));
        let buffers_for_ui = Rc::clone(&buffers);
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = finalmask_udp_settings_editor(
                ui,
                Language::En,
                &mut mask_for_ui.borrow_mut(),
                RawField {
                    id: FieldKey {
                        key: egui::Id::unique("noise-editor-test"),
                        profile: "profile-test",
                    },
                    buffers: &mut buffers_for_ui.borrow_mut(),
                },
                false,
                0,
            );
        });
        harness.run();

        // The type combo shows the loaded type and offers `exp`.
        harness
            .get_all_by_role(egui::accesskit::Role::ComboBox)
            .into_iter()
            .find(|node| node.value().as_deref() == Some("exp"))
            .expect("the packet type combo shows the loaded exp type")
            .click();
        harness.run();
        harness.get_by_label("exp").click();
        harness.run();

        // The packet edits as a text field carrying the stored expression,
        // never as a JSON buffer quoting it.
        let field = harness
            .query_all_by_role_and_label(egui::accesskit::Role::TextInput, "packet")
            .next()
            .expect("the exp packet edits as a text field");
        assert_eq!(field.value().as_deref(), Some("<b 0x12>"));
        field.click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.is_focused())
            .expect("the packet field takes focus")
            .type_text("<z>");
        harness.run();

        let borrowed = mask.borrow();
        assert_eq!(
            noise(&borrowed).noise[0].packet.value().cloned(),
            Some(json!("<b 0x12><z>"))
        );
        assert!(
            harness
                .query_by_label(&t_fmt(
                    Language::En,
                    Key::FinalmaskNoiseExpUnknownToken,
                    &[&"z"]
                ))
                .is_some(),
            "the exp finding must render inline under the field"
        );
    }

    #[test]
    fn noise_script_row_toggles_the_path_and_reports_the_pair_conflict() {
        fn noise(mask: &FinalmaskUdpMask) -> &FinalmaskNoise {
            match mask {
                FinalmaskUdpMask::Noise { settings, .. } => settings,
                other => panic!("the harness renders a noise mask, got {other:?}"),
            }
        }

        // The mask already owns one item, so turning the script row on makes
        // the pair the core refuses: the row must show that same finding.
        let mask = Rc::new(RefCell::new(FinalmaskUdpMask::Noise {
            settings: FinalmaskNoise {
                noise: vec![FinalmaskNoiseItem {
                    encoding: "hex".into(),
                    packet: FinalmaskRawValue::Present(json!("00")),
                    ..Default::default()
                }],
                ..Default::default()
            },
            extra: Default::default(),
        }));
        let mask_for_ui = Rc::clone(&mask);
        let buffers = Rc::new(RefCell::new(SeededBuffers::default()));
        let buffers_for_ui = Rc::clone(&buffers);
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = finalmask_udp_settings_editor(
                ui,
                Language::En,
                &mut mask_for_ui.borrow_mut(),
                RawField {
                    id: FieldKey {
                        key: egui::Id::unique("noise-script-editor-test"),
                        profile: "profile-test",
                    },
                    buffers: &mut buffers_for_ui.borrow_mut(),
                },
                false,
                0,
            );
        });
        harness.run();
        assert!(
            noise(&mask.borrow()).script.is_none(),
            "the fixture starts without a script"
        );

        harness
            .get_by_label(t(Language::En, Key::SrvNoiseScriptToggle))
            .click();
        harness.run();
        assert_eq!(
            noise(&mask.borrow()).script.as_deref(),
            Some(""),
            "the switch seeds the empty path its field then judges"
        );

        // The path goes in through the row's own text field; the shared
        // structural rule passes and the mask's exclusivity rule fires.
        let field = harness
            .query_all_by_role_and_label(
                egui::accesskit::Role::TextInput,
                t(Language::En, Key::SrvNoiseScriptPath),
            )
            .next()
            .expect("the script row owns a path field");
        field.click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.is_focused())
            .expect("the path field takes focus")
            .type_text("/tmp/noise.lua");
        harness.run();
        assert_eq!(
            noise(&mask.borrow()).script.as_deref(),
            Some("/tmp/noise.lua")
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::FinalmaskNoiseScriptConflict))
                .is_some(),
            "the row renders the same conflict the apply gate refuses"
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
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = screen_for_ui.borrow_mut().transport_tab(
                ui,
                Language::En,
                &mut stream_for_ui.borrow_mut(),
                0,
                TransportTabCtx {
                    target: None,
                    masked: false,
                    protocol: Protocol::Vless,
                    mux: None,
                },
            );
        });
        harness.run();
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

    /// The XMUX section edits the block it is given: the chosen limit mode
    /// owns the model, and the fields the mode does not use disappear.
    #[test]
    fn xmux_section_writes_the_chosen_limit_mode() {
        let xmux = Rc::new(RefCell::new(Some(XmuxConfig {
            max_connections: Some(Int32Range::single(2)),
            ..Default::default()
        })));
        let xmux_for_ui = Rc::clone(&xmux);
        let mut harness = harness_builder().build_ui(move |ui| {
            let _ = xmux_section(ui, Language::En, &mut xmux_for_ui.borrow_mut());
        });
        assert!(harness.query_by_label("maxConnections").is_some());
        assert!(harness.query_by_label("maxConcurrency").is_none());

        harness.get_by_label("max concurrency").click();
        harness.run();

        let edited = xmux.borrow();
        let edited = edited.as_ref().expect("the block stays enabled");
        assert_eq!(edited.max_connections, None);
        assert_eq!(edited.max_concurrency, Some(Int32Range::single(1)));
        assert!(harness.query_by_label("maxConcurrency").is_some());
        assert!(harness.query_by_label("maxConnections").is_none());
    }

    /// The section renders every control the XHTTP editor carried, with the
    /// core-defaults choice when the block holds no limit.
    #[test]
    fn xmux_section_renders_the_shared_controls() {
        let xmux = Rc::new(RefCell::new(Some(XmuxConfig::default())));
        let xmux_for_ui = Rc::clone(&xmux);
        let harness = harness_builder().build_ui(move |ui| {
            let _ = xmux_section(ui, Language::En, &mut xmux_for_ui.borrow_mut());
        });
        for caption in [
            t(Language::En, Key::SrvXmux),
            t(Language::En, Key::SrvEnableXmux),
            t(Language::En, Key::SrvConnectionLimit),
            t(Language::En, Key::SrvCoreDefaults),
            t(Language::En, Key::SrvMaxConcurrency),
            t(Language::En, Key::SrvMaxConnections),
            "cMaxReuseTimes",
            "hMaxRequestTimes",
            "hMaxReusableSecs",
            t(Language::En, Key::SrvHKeepAlivePeriodS),
        ] {
            harness.get_by_label(caption);
        }
        assert!(harness.query_by_label("maxConcurrency").is_none());
        assert!(harness.query_by_label("maxConnections").is_none());
    }

    /// A block carrying both limits renders the exclusivity finding instead
    /// of either limit's field, and leaves the stored pair for the user to
    /// resolve.
    #[test]
    fn xmux_section_reports_a_both_set_limit() {
        let xmux = Rc::new(RefCell::new(Some(XmuxConfig {
            max_concurrency: Some(Int32Range::single(8)),
            max_connections: Some(Int32Range::single(2)),
            ..Default::default()
        })));
        let xmux_for_ui = Rc::clone(&xmux);
        let harness = harness_builder().build_ui(move |ui| {
            let _ = xmux_section(ui, Language::En, &mut xmux_for_ui.borrow_mut());
        });
        harness.get_by_label(t(Language::En, Key::SrvMutuallyExclusive));
        assert!(harness.query_by_label("maxConcurrency").is_none());
        assert!(harness.query_by_label("maxConnections").is_none());
        let stored = xmux.borrow();
        let stored = stored.as_ref().expect("the block stays enabled");
        assert_eq!(stored.max_concurrency, Some(Int32Range::single(8)));
        assert_eq!(stored.max_connections, Some(Int32Range::single(2)));
    }

    /// The enable switch owns the optional block: on seeds the core's
    /// defaults, off clears it, and both directions report the edit.
    #[test]
    fn xmux_section_owns_the_enable_switch() {
        let xmux: Rc<RefCell<Option<XmuxConfig>>> = Rc::new(RefCell::new(None));
        let changed = Rc::new(std::cell::Cell::new(false));
        let xmux_for_ui = Rc::clone(&xmux);
        let changed_for_ui = Rc::clone(&changed);
        let mut harness = harness_builder().build_ui(move |ui| {
            if xmux_section(ui, Language::En, &mut xmux_for_ui.borrow_mut()) {
                changed_for_ui.set(true);
            }
        });
        assert!(!changed.get());

        harness
            .get_by_label(t(Language::En, Key::SrvEnableXmux))
            .click();
        harness.run();
        assert!(changed.get());
        let enabled = xmux.borrow().clone().expect("enabling seeds the block");
        assert!(enabled.max_concurrency.is_none());
        assert!(enabled.max_connections.is_none());
        assert!(enabled.c_max_reuse_times.is_none());
        assert!(enabled.h_max_request_times.is_none());
        assert!(enabled.h_max_reusable_secs.is_none());
        assert!(enabled.h_keep_alive_period.is_none());

        changed.set(false);
        harness
            .get_by_label(t(Language::En, Key::SrvEnableXmux))
            .click();
        harness.run();
        assert!(changed.get());
        assert!(xmux.borrow().is_none());
    }

    /// The XHTTP transport settings mount the shared XMUX control and write
    /// the transport's own block.
    #[test]
    fn xhttp_transport_settings_mount_the_shared_xmux_control() {
        let stream = Rc::new(RefCell::new(StreamModel {
            network: Network::Xhttp,
            xhttp_settings: Some(XhttpSettings {
                xmux: Some(XmuxConfig {
                    c_max_reuse_times: Some(Int32Range::single(100)),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }));
        let stream_for_ui = Rc::clone(&stream);
        let mut harness = harness_builder()
            .with_size(egui::vec2(900.0, 3600.0))
            .build_ui_state(
                |ui, screen: &mut ServersScreen| {
                    let _ = screen.transport_tab(
                        ui,
                        Language::En,
                        &mut stream_for_ui.borrow_mut(),
                        0,
                        TransportTabCtx {
                            target: draft_target(DraftKind::Existing, "profile-1", 0),
                            masked: false,
                            protocol: Protocol::Vless,
                            mux: None,
                        },
                    );
                },
                ServersScreen::default(),
            );
        harness.get_by_label(t(Language::En, Key::SrvXmux));
        harness
            .get_by_label(t(Language::En, Key::SrvEnableXmux))
            .click();
        harness.run();
        assert!(
            stream
                .borrow()
                .xhttp_settings
                .as_ref()
                .expect("the transport keeps its settings")
                .xmux
                .is_none()
        );
    }

    // ---------- multi-selection and batch commands ----------

    /// Press a row's name with `modifiers` and release, the way the user's
    /// Ctrl and Shift clicks arrive.
    fn click_row_with(
        harness: &mut Harness<'static, (ServersScreen, UiTestRig)>,
        label: &str,
        modifiers: egui::Modifiers,
    ) {
        let pos = harness.get_by_label(label).rect().center();
        harness
            .input_mut()
            .events
            .push(egui::Event::ModifiersChanged(modifiers));
        harness
            .input_mut()
            .events
            .push(egui::Event::PointerMoved(pos));
        for pressed in [true, false] {
            harness.input_mut().events.push(egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers,
            });
        }
        harness.run_steps(2);
        harness
            .input_mut()
            .events
            .push(egui::Event::ModifiersChanged(egui::Modifiers::NONE));
        harness.step();
    }

    /// Click the point `y` below the row labelled `last`, where a short list
    /// leaves empty space.
    fn click_blank_below(harness: &mut Harness<'static, (ServersScreen, UiTestRig)>, last: &str) {
        let bottom = harness.get_by_label(last).rect().bottom();
        let pos = egui::pos2(240.0, bottom + 40.0);
        harness
            .input_mut()
            .events
            .push(egui::Event::PointerMoved(pos));
        for pressed in [true, false] {
            harness.input_mut().events.push(egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            });
        }
        harness.run_steps(2);
    }

    /// The selected rows' names, sorted: the selection is a set, and the
    /// names are what a test can compare against the table.
    fn selected_names(harness: &Harness<'static, (ServersScreen, UiTestRig)>) -> Vec<String> {
        let state = harness.state();
        let mut names: Vec<String> = state
            .0
            .selection
            .iter()
            .map(|id| {
                state
                    .1
                    .servers
                    .profiles
                    .iter()
                    .find(|profile| &profile.id == id)
                    .map_or_else(|| id.clone(), |profile| profile.name.clone())
            })
            .collect();
        names.sort();
        names
    }

    fn id_of(rig: &UiTestRig, name: &str) -> String {
        rig.servers
            .profiles
            .iter()
            .find(|profile| profile.name == name)
            .unwrap_or_else(|| panic!("the rig lists {name:?}"))
            .id
            .clone()
    }

    #[test]
    fn plain_ctrl_and_shift_clicks_shape_the_selection() {
        let mut harness = wide_table_harness(drag_rig());
        harness.run();
        assert!(
            harness.state().0.selection.is_empty(),
            "opening the screen focuses a row but selects none"
        );

        // A plain click replaces the selection with one row.
        click_row_with(&mut harness, "Alpha", egui::Modifiers::NONE);
        assert_eq!(selected_names(&harness), ["Alpha"]);
        assert_eq!(
            harness.state().0.selected.as_deref(),
            Some(id_of(&harness.state().1, "Alpha").as_str())
        );

        // Ctrl adds another row.
        click_row_with(&mut harness, "Charlie", egui::Modifiers::CTRL);
        assert_eq!(selected_names(&harness), ["Alpha", "Charlie"]);

        // Shift extends from the last Ctrl-clicked anchor: Charlie is the
        // anchor, so the range back to Alpha covers all three rows.
        click_row_with(&mut harness, "Alpha", egui::Modifiers::SHIFT);
        assert_eq!(selected_names(&harness), ["Alpha", "Bravo", "Charlie"]);

        // A plain click collapses the selection back to one row.
        click_row_with(&mut harness, "Bravo", egui::Modifiers::NONE);
        assert_eq!(selected_names(&harness), ["Bravo"]);
    }

    #[test]
    fn ctrl_a_selects_the_visible_rows_and_a_blank_click_clears() {
        let mut harness = wide_table_harness(drag_rig());
        harness.run();
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
        harness.run_steps(2);
        assert_eq!(selected_names(&harness), ["Alpha", "Bravo", "Charlie"]);

        click_blank_below(&mut harness, "Charlie");
        assert!(
            harness.state().0.selection.is_empty(),
            "a click on empty space clears the selection"
        );
        assert_eq!(harness.state().0.selected, None);
    }

    #[test]
    fn changing_tabs_clears_the_selection() {
        let mut harness = wide_table_harness(drag_rig());
        harness.run();
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
        harness.run_steps(2);
        assert_eq!(selected_names(&harness), ["Alpha", "Bravo", "Charlie"]);

        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run_steps(2);
        assert!(
            harness.state().0.selection.is_empty(),
            "a tab switch must drop the selection with the tab"
        );
        assert_eq!(harness.state().0.selected, None);
        assert_eq!(harness.state().0.selection_anchor, None);
    }

    #[test]
    fn filtering_a_row_out_drops_it_from_the_selection() {
        let mut harness = wide_table_harness(drag_rig());
        harness.run();
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
        harness.run_steps(2);
        assert_eq!(selected_names(&harness), ["Alpha", "Bravo", "Charlie"]);

        harness
            .query_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("the toolbar carries the search field")
            .click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .find(|node| node.is_focused())
            .expect("the search field takes focus")
            .type_text("Alpha");
        harness.run_steps(2);
        assert_eq!(
            selected_names(&harness),
            ["Alpha"],
            "a filtered-out row must leave the selection"
        );
    }

    #[test]
    fn the_context_menu_replaces_a_conflicting_selection_and_gates_set_active() {
        let mut harness = wide_table_harness(drag_rig());
        harness.run();
        click_row_with(&mut harness, "Alpha", egui::Modifiers::NONE);
        click_row_with(&mut harness, "Bravo", egui::Modifiers::CTRL);
        assert_eq!(selected_names(&harness), ["Alpha", "Bravo"]);

        // Opening the menu on a row inside the selection keeps it, and Set
        // active is disabled because two rows are selected.
        harness.get_by_label("Bravo").click_secondary();
        harness.run();
        assert_eq!(selected_names(&harness), ["Alpha", "Bravo"]);
        assert!(
            harness
                .get_all_by_label(t(Language::En, Key::SrvSetActive))
                .last()
                .expect("the row menu offers Set active")
                .accesskit_node()
                .is_disabled(),
            "Set active needs exactly one selected row"
        );

        // Opening it on a row outside the selection replaces the selection
        // with that row first, which makes Set active available.
        harness.key_press(egui::Key::Escape);
        harness.run();
        harness.get_by_label("Charlie").click_secondary();
        harness.run();
        assert_eq!(selected_names(&harness), ["Charlie"]);
        assert!(
            !harness
                .get_all_by_label(t(Language::En, Key::SrvSetActive))
                .last()
                .expect("the row menu offers Set active")
                .accesskit_node()
                .is_disabled(),
            "one selected row enables Set active"
        );
    }

    /// A subscription row `Tokyo` in `Feed` as the active route, a plain
    /// manual `Alpha`, and a manual `Backup` group that already holds a
    /// `Tokyo` of its own so a copy's name has to be suffixed.
    fn copy_rig() -> (UiTestRig, String, String) {
        use crate::model::servers::{Group, ProfileOrigin, Subscription};
        let mut rig = UiTestRig::default();
        let mut feed = Group::new("Feed");
        feed.subscription = Some(Subscription::default());
        let feed_id = feed.id.clone();
        let backup = Group::new("Backup");
        let backup_id = backup.id.clone();
        let mut alpha = ServerProfile::new("Alpha", OutboundModel::new(Protocol::Freedom));
        alpha.enabled = true;
        let mut tokyo = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        tokyo.enabled = true;
        tokyo.group = feed_id.clone();
        tokyo.origin = Some(ProfileOrigin {
            content_key: "content".into(),
            identity_key: "identity".into(),
            ..Default::default()
        });
        let mut osaka = ServerProfile::new("Osaka", OutboundModel::new(Protocol::Freedom));
        osaka.enabled = true;
        osaka.group = feed_id.clone();
        osaka.origin = Some(ProfileOrigin {
            content_key: "osaka".into(),
            identity_key: "osaka".into(),
            ..Default::default()
        });
        let mut taken = ServerProfile::new("Tokyo", OutboundModel::new(Protocol::Freedom));
        taken.group = backup_id;
        let source_id = tokyo.id.clone();
        rig.servers.profiles = vec![alpha, tokyo, osaka, taken];
        rig.servers.groups = vec![Group::manual(), backup, feed];
        rig.servers.active = Some(source_id.clone());
        rig.servers.hydrate_group_titles();
        (rig, feed_id, source_id)
    }

    /// Whether the radio button `label` is the checked one.
    fn radio_checked(harness: &Harness<'static, (ServersScreen, UiTestRig)>, label: &str) -> bool {
        harness
            .get_by_role_and_label(egui::accesskit::Role::RadioButton, label)
            .accesskit_node()
            .toggled()
            .is_some_and(|toggled| matches!(toggled, egui::accesskit::Toggled::True))
    }

    #[test]
    fn copy_to_group_is_available_only_on_subscription_rows() {
        let (rig, _, _) = copy_rig();
        let mut harness = wide_table_harness(rig);
        harness.run();

        // A manual row shown on `Emitted` is not a subscription row.
        harness.get_by_label("Alpha").click_secondary();
        harness.run();
        assert!(
            harness
                .get_all_by_label(t(Language::En, Key::SrvCopyToGroup))
                .last()
                .expect("the row menu offers Copy to group")
                .accesskit_node()
                .is_disabled(),
            "a manual row cannot be copied"
        );
        assert!(
            harness
                .query_all_by_label_contains("Move to group")
                .next()
                .is_none(),
            "the screen has no Move to group command"
        );

        // The subscription row offers it.
        harness.key_press(egui::Key::Escape);
        harness.run();
        harness.get_by_label("Tokyo").click_secondary();
        harness.run();
        assert!(
            !harness
                .get_all_by_label(t(Language::En, Key::SrvCopyToGroup))
                .last()
                .expect("the row menu offers Copy to group")
                .accesskit_node()
                .is_disabled(),
            "a subscription row can be copied"
        );
    }

    #[test]
    fn copy_to_group_places_a_switched_off_copy_in_the_picked_group() {
        use crate::model::servers::{GroupKind, MANUAL_GROUP_ID, SubscriptionEntry};
        let (rig, feed_id, source_id) = copy_rig();
        let mut harness = wide_table_harness(rig);
        harness.run();
        let source_index = harness
            .state()
            .1
            .servers
            .profiles
            .iter()
            .position(|profile| profile.id == source_id)
            .expect("the subscription row");
        let rows = harness.state().1.servers.profiles.len();

        harness.get_by_label("Tokyo").click_secondary();
        harness.run();
        harness
            .get_all_by_label(t(Language::En, Key::SrvCopyToGroup))
            .last()
            .expect("the row menu offers Copy to group")
            .click();
        harness.run();

        // The picker opens on `Manual` and offers manual groups alone.
        assert_eq!(
            harness
                .state()
                .0
                .copy_dialog
                .as_ref()
                .expect("the picker opens")
                .target,
            MANUAL_GROUP_ID,
            "Manual is preselected"
        );
        assert!(radio_checked(&harness, "Manual"));
        assert!(
            harness
                .query_by_role_and_label(egui::accesskit::Role::RadioButton, "Feed")
                .is_none(),
            "a subscription group is not a copy target"
        );
        harness
            .get_by_role_and_label(egui::accesskit::Role::RadioButton, "Backup")
            .click();
        harness.run();
        assert!(radio_checked(&harness, "Backup"));
        assert!(!radio_checked(&harness, "Manual"));

        harness
            .get_by_label(t(Language::En, Key::SrvCopyToGroupConfirm))
            .click();
        harness.run();
        assert!(
            harness.state().0.copy_dialog.is_none(),
            "the picker closes on Copy"
        );

        // One switched-off copy lands in `Backup`; the subscription row and
        // the active route stay exactly as they were.
        let state = harness.state();
        let servers = &state.1.servers;
        assert_eq!(servers.profiles.len(), rows + 1, "one copy per row");
        let copy = servers
            .profiles
            .iter()
            .filter(|profile| profile.name == "Tokyo (1)")
            .collect::<Vec<_>>();
        assert_eq!(copy.len(), 1, "the used name takes the usual suffix");
        let copy = copy[0];
        let backup = servers
            .groups
            .iter()
            .find(|group| group.title == "Backup")
            .expect("the target group");
        assert_eq!(GroupKind::Manual, backup.kind());
        assert_eq!(copy.group_id(), backup.id);
        assert_eq!(
            copy.tag(),
            "[Backup] Tokyo (1)",
            "the target title prefixes the copy"
        );
        assert!(!copy.enabled, "the copy starts switched off");
        assert!(copy.origin.is_none(), "a copy is not a subscription row");
        assert_eq!(
            servers
                .profiles
                .iter()
                .position(|profile| profile.id == source_id),
            Some(source_index),
            "the subscription row keeps its position"
        );
        let source = &servers.profiles[source_index];
        assert_eq!(
            source.group_id(),
            feed_id,
            "the subscription row keeps its group"
        );
        assert!(source.enabled, "the subscription row keeps its switch");
        assert!(source.origin.is_some(), "the feed still owns the row");
        assert_eq!(
            servers.active.as_deref(),
            Some(source_id.as_str()),
            "the copy never takes the active route"
        );
        assert!(state.1.requests.dirty, "copying is a model edit");

        // The copy shows in its target's tab and in `All`, off `Emitted`.
        harness.run();
        harness.get_by_label("Backup").click();
        harness.run();
        assert!(
            harness.query_by_label("Tokyo (1)").is_some(),
            "the copy appears in its target group's tab"
        );
        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run();
        assert!(
            harness.query_by_label("Tokyo (1)").is_some(),
            "the copy appears in All"
        );
        harness
            .get_by_label(t(Language::En, Key::SrvTabEmitted))
            .click();
        harness.run();
        assert!(
            harness.query_by_label("Tokyo (1)").is_none(),
            "a switched-off copy stays out of the configuration"
        );

        // A refresh of the subscription leaves the copy alone.
        let entry = {
            let source = harness
                .state()
                .1
                .servers
                .profiles
                .iter()
                .find(|profile| profile.id == source_id)
                .expect("the subscription row")
                .clone();
            SubscriptionEntry {
                profile: source,
                content_key: "content".into(),
                identity_key: "identity".into(),
            }
        };
        let mut settings = crate::model::Settings::default();
        harness.state_mut().1.servers.refresh_subscription_group(
            &mut settings,
            &feed_id,
            vec![entry],
        );
        harness.run();
        let state = harness.state();
        let copy = state
            .1
            .servers
            .profiles
            .iter()
            .find(|profile| profile.name == "Tokyo (1)")
            .expect("a refresh neither deletes nor renames the copy");
        assert_eq!(copy.tag(), "[Backup] Tokyo (1)");
        assert!(!copy.enabled, "a refresh never switches a copy on");
    }

    #[test]
    fn copy_to_group_copies_every_selected_subscription_row() {
        use crate::model::servers::MANUAL_GROUP_ID;
        let (rig, feed_id, source_id) = copy_rig();
        let mut harness = wide_table_harness(rig);
        harness.run();
        let osaka_id = harness
            .state()
            .1
            .servers
            .profiles
            .iter()
            .find(|profile| profile.name == "Osaka")
            .expect("the second subscription row")
            .id
            .clone();

        // A mixed batch: the manual row is selected too, and stays behind.
        click_row_with(&mut harness, "Alpha", egui::Modifiers::NONE);
        click_row_with(&mut harness, "Tokyo", egui::Modifiers::CTRL);
        click_row_with(&mut harness, "Osaka", egui::Modifiers::CTRL);
        assert_eq!(selected_names(&harness), ["Alpha", "Osaka", "Tokyo"]);
        harness.get_by_label("Tokyo").click_secondary();
        harness.run();
        harness
            .get_all_by_label(t(Language::En, Key::SrvCopyToGroup))
            .last()
            .expect("the row menu offers Copy to group")
            .click();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvCopyToGroupConfirm))
            .click();
        harness.run();

        let state = harness.state();
        let servers = &state.1.servers;
        let copies: Vec<&ServerProfile> = servers
            .profiles
            .iter()
            .filter(|profile| {
                profile.group_id() == MANUAL_GROUP_ID
                    && !profile.enabled
                    && profile.origin.is_none()
            })
            .collect();
        assert_eq!(copies.len(), 2, "one copy per selected subscription row");
        assert_eq!(
            copies
                .iter()
                .map(|copy| copy.tag())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([
                "[Manual] Osaka".to_owned(),
                "[Manual] Tokyo".to_owned(),
            ]),
            "the default target is Manual"
        );
        let alpha = servers
            .profiles
            .iter()
            .find(|profile| profile.name == "Alpha")
            .expect("the manual row stays");
        assert!(
            alpha.enabled && alpha.group_id() == MANUAL_GROUP_ID,
            "a manual row in the selection is neither copied nor changed"
        );
        for id in [&source_id, &osaka_id] {
            let original = servers
                .profiles
                .iter()
                .find(|profile| &profile.id == id)
                .expect("the subscription row stays");
            assert_eq!(original.group_id(), feed_id);
            assert!(original.enabled);
            assert!(original.origin.is_some());
        }
        assert_eq!(
            servers.active.as_deref(),
            Some(source_id.as_str()),
            "copying never changes the active route"
        );
    }

    #[test]
    fn enter_sets_the_focused_row_active() {
        let mut harness = wide_table_harness(drag_rig());
        harness.run();
        click_row_with(&mut harness, "Bravo", egui::Modifiers::NONE);

        harness.key_press(egui::Key::Enter);
        harness.run_steps(2);
        assert_eq!(
            harness.state().1.servers.active.as_deref(),
            Some(id_of(&harness.state().1, "Bravo").as_str()),
            "Enter must activate the focused row"
        );
        assert!(
            harness.state().1.requests.dirty,
            "activating a row is a model edit"
        );
    }

    fn probed_names(harness: &mut Harness<'static, (ServersScreen, UiTestRig)>) -> Vec<String> {
        let command = harness
            .state_mut()
            .1
            ._cmd_rx
            .try_recv()
            .expect("the latency command must reach the runtime");
        match command {
            CoreCmd::ProbeLatency { profiles, .. } => {
                profiles.into_iter().map(|profile| profile.name).collect()
            }
            other => panic!("expected a latency probe, got {other:?}"),
        }
    }

    #[test]
    fn the_latency_command_targets_the_selection_or_the_current_tab() {
        // A selection probes exactly the selected rows.
        let mut harness = wide_table_harness(grouped_drag_rig());
        harness.run();
        click_row_with(&mut harness, "Alpha", egui::Modifiers::NONE);
        click_row_with(&mut harness, "Bravo", egui::Modifiers::CTRL);
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::TestLatency),
            )
            .click();
        harness.run_steps(2);
        assert_eq!(probed_names(&mut harness), ["Alpha", "Bravo"]);

        // With nothing selected the command covers the current tab only:
        // Manual shows Alpha and Bravo, while the Feed rows stay out.
        let mut harness = wide_table_harness(grouped_drag_rig());
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvTabManual))
            .click();
        harness.run_steps(2);
        assert!(harness.state().0.selection.is_empty());
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::TestLatency),
            )
            .click();
        harness.run_steps(2);
        assert_eq!(probed_names(&mut harness), ["Alpha", "Bravo"]);
    }

    /// Alpha is the active server and Hop is a chain-only hop, so both are
    /// locked; Bravo and Charlie are free to switch.
    fn locked_rows_rig() -> UiTestRig {
        let mut rig = drag_rig();
        let mut hop = ServerProfile::new("Hop", OutboundModel::new(Protocol::Freedom));
        hop.enabled = false;
        let hop_tag = hop.tag();
        rig.servers.profiles.push(hop);
        rig.servers.profiles[1].outbound.stream.sockopt = Some(SockoptModel {
            dialer_proxy: hop_tag,
            ..Default::default()
        });
        rig.servers.active = Some(rig.servers.profiles[0].id.clone());
        rig
    }

    fn enabled_of(harness: &Harness<'static, (ServersScreen, UiTestRig)>, name: &str) -> bool {
        harness
            .state()
            .1
            .servers
            .profiles
            .iter()
            .find(|profile| profile.name == name)
            .unwrap_or_else(|| panic!("the rig lists {name:?}"))
            .enabled
    }

    #[test]
    fn the_one_menu_item_enables_or_disables_the_selection_and_skips_locked_rows() {
        let mut harness = wide_table_harness(locked_rows_rig());
        harness.run();
        // The All tab keeps every row on screen after a batch switches rows
        // off; `Emitted` drops a switched-off row by design.
        harness
            .get_by_label(t(Language::En, Key::SrvTabAll))
            .click();
        harness.run_steps(2);
        // Alpha is the route and therefore locked; Bravo and Charlie follow
        // the batch.
        click_row_with(&mut harness, "Alpha", egui::Modifiers::NONE);
        click_row_with(&mut harness, "Bravo", egui::Modifiers::CTRL);
        click_row_with(&mut harness, "Charlie", egui::Modifiers::CTRL);
        assert_eq!(selected_names(&harness), ["Alpha", "Bravo", "Charlie"]);

        // Every selected row is on, so the one item offers to disable them.
        harness.get_by_label("Bravo").click_secondary();
        harness.run();
        assert!(
            harness
                .query_all_by_label(t(Language::En, Key::SrvEnableSelected))
                .next()
                .is_none(),
            "a selection that is on offers Disable, not Enable"
        );
        harness
            .get_by_label(t(Language::En, Key::SrvDisableSelected))
            .click();
        harness.run_steps(2);
        assert!(!enabled_of(&harness, "Bravo") && !enabled_of(&harness, "Charlie"));
        assert!(
            enabled_of(&harness, "Alpha"),
            "the active server is locked on"
        );
        assert!(
            !enabled_of(&harness, "Hop"),
            "the chain-only hop stays as it was"
        );
        assert_eq!(
            harness
                .state()
                .0
                .status
                .as_ref()
                .map(|status| status.text.as_str()),
            Some(t_fmt(Language::En, Key::SrvBatchDisabled, &[&2_u32, &1_u32]).as_str()),
            "the batch reports what it changed and what it skipped"
        );

        // A row of the selection is off now, so the item flips to Enable.
        harness.get_by_label("Bravo").click_secondary();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvEnableSelected))
            .click();
        harness.run_steps(2);
        assert!(enabled_of(&harness, "Bravo") && enabled_of(&harness, "Charlie"));
        assert!(
            !enabled_of(&harness, "Hop"),
            "a hop listed with a switched-off dialer is not in the selection"
        );
        assert_eq!(
            harness
                .state()
                .0
                .status
                .as_ref()
                .map(|status| status.text.as_str()),
            Some(t_fmt(Language::En, Key::SrvBatchEnabled, &[&2_u32, &1_u32]).as_str())
        );
    }

    #[test]
    fn batch_delete_asks_once_for_the_whole_selection() {
        let mut harness = wide_table_harness(drag_rig());
        harness.run();
        click_row_with(&mut harness, "Alpha", egui::Modifiers::NONE);
        click_row_with(&mut harness, "Bravo", egui::Modifiers::CTRL);

        harness.get_by_label("Bravo").click_secondary();
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::SrvDeleteEllipsis))
            .click();
        harness.run_steps(2);
        let dialog = harness
            .state()
            .0
            .delete_pending
            .as_ref()
            .expect("the batch must ask for one confirmation");
        assert_eq!(dialog.ids.len(), 2, "one dialog covers both rows");
        assert_eq!(
            dialog.name,
            t_fmt(Language::En, Key::SrvSelectedServers, &[&2_u32])
        );
        assert!(
            harness
                .query_all_by_label(
                    t_fmt(Language::En, Key::SrvDeleteManyCannotUndone, &[&2_u32]).as_str()
                )
                .next()
                .is_some(),
            "the dialog must name the batch size"
        );

        harness.get_by_label(t(Language::En, Key::Delete)).click();
        harness.run_steps(2);
        assert_eq!(harness.state().1.servers.profiles.len(), 1);
        assert_eq!(
            harness.state().1.servers.profiles[0].name,
            "Charlie",
            "only the unselected row survives"
        );
        assert!(harness.state().0.selection.is_empty());
    }

    /// Two profiles the share grammar can carry, so Share has links to copy.
    fn shareable_rig() -> UiTestRig {
        let mut rig = UiTestRig::default();
        for (name, host) in [
            ("Alpha", "alpha.example.com"),
            ("Bravo", "bravo.example.com"),
        ] {
            let link = format!(
                "vless://5783a3e7-e373-51cd-8642-c83782b807c5@{host}:443\
                 ?encryption=none&security=tls&sni={host}&type=tcp#{name}"
            );
            let mut profile = links::parse_link(&link)
                .unwrap_or_else(|error| panic!("the fixture link must parse: {error}"))
                .profile;
            profile.enabled = true;
            rig.servers.profiles.push(profile);
        }
        rig
    }

    #[test]
    fn batch_share_puts_every_selected_link_on_the_clipboard() {
        let mut harness = wide_table_harness(shareable_rig());
        harness.run();
        click_row_with(&mut harness, "Alpha", egui::Modifiers::NONE);
        click_row_with(&mut harness, "Bravo", egui::Modifiers::CTRL);

        harness.get_by_label("Bravo").click_secondary();
        harness.run();
        harness.get_by_label(t(Language::En, Key::SrvShare)).click();
        harness.run_steps(2);
        assert!(
            harness.state().0.qr_dialog.is_none(),
            "a multi-row share does not open a single row's QR window"
        );
        assert_eq!(
            harness
                .state()
                .0
                .status
                .as_ref()
                .map(|status| status.text.as_str()),
            Some(t_fmt(Language::En, Key::SrvLinksCopiedToClipboard, &[&2_u32]).as_str())
        );
    }
}
