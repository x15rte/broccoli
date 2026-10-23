//! The TLS settings editor shared by the outbound TLS block and the DoH
//! resolver's nested `tlsConfig`.
//!
//! Both surfaces read and write [`TlsModel`], so they carry the same field
//! names, defaults, and captions. A caller keeps the controls that belong to
//! its own surface: the outbound probe and the pin-compute action target a
//! profile draft, which a resolver row does not have.

use crate::i18n::{Key, t, t_fmt, validation_message};
use crate::model::settings::Language;
use crate::model::validation::{ValidationCode, server_name_implausible};
use crate::model::{TlsCert, TlsModel};
use crate::ui::status::status_colors_of;
use crate::ui::widgets;

use super::raw_editor::{SeededBuffers, pem_lines_editor};
use super::{TLS_VERSIONS, ech_sockopt_editor, fingerprint_editor, path_field};

/// The plain TLS settings, from the server name through the certificate pin.
///
/// `fingerprint_code` is the model code that judges this context's
/// fingerprint — the stream TLS block and its DoH copy share
/// `TlsFingerprintUnsupported`, while the realm block has its own. The
/// caller's transport-specific ALPN note, when it has one, renders under the
/// ALPN list.
pub(super) fn tls_fields_editor(
    ui: &mut egui::Ui,
    lang: Language,
    tls: &mut TlsModel,
    fingerprint_code: ValidationCode,
    alpn_warning: Option<&str>,
) -> bool {
    let mut changed = false;
    changed |= widgets::noted(ui, t(lang, Key::SrvTlsServerNameEmptyNote), |ui| {
        widgets::text_field(
            ui,
            t(lang, Key::SrvServerNameSni),
            &mut tls.server_name,
            "example.com",
        )
    });
    // Warn inline at the field when the value cannot plausibly be a
    // hostname — the model's own predicate, so the inline hint can never
    // drift from the sweep. Empty stays untouched (out of scope by design).
    if server_name_implausible(&tls.server_name) {
        ui.colored_label(
            status_colors_of(ui).warn,
            validation_message(&ValidationCode::ServerNameImplausible, lang),
        );
    }
    changed |= widgets::string_list(
        ui,
        lang,
        t(lang, Key::SrvAlpn),
        &mut tls.alpn,
        t(lang, Key::SrvAlpnHint),
    );
    if let Some(warning) = alpn_warning {
        ui.colored_label(status_colors_of(ui).warn, warning);
    }
    changed |= widgets::noted(ui, t(lang, Key::SrvTlsFingerprintNote), |ui| {
        fingerprint_editor(ui, lang, &mut tls.fingerprint, fingerprint_code)
    });
    changed |= widgets::combo_str_labeled(
        ui,
        t(lang, Key::SrvMinVersion),
        &mut tls.min_version,
        &TLS_VERSIONS,
        t(lang, Key::SrvDefault),
        false,
    );
    changed |= widgets::combo_str_labeled(
        ui,
        t(lang, Key::SrvMaxVersion),
        &mut tls.max_version,
        &TLS_VERSIONS,
        t(lang, Key::SrvDefault),
        false,
    );
    if let (Some(min), Some(max)) = (
        crate::model::validation::tls_version_rank(&tls.min_version),
        crate::model::validation::tls_version_rank(&tls.max_version),
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
        &mut tls.cipher_suites,
        t(lang, Key::SrvCipherSuitesHint),
    );
    changed |= widgets::string_list(
        ui,
        lang,
        t(lang, Key::SrvCurvePreferences),
        &mut tls.curve_preferences,
        "X25519MLKEM768",
    );
    changed |= widgets::opt_bool(
        ui,
        "disableSystemRoot",
        &mut tls.disable_system_root,
        t(lang, Key::SrvUnset),
    );
    changed |= widgets::noted(ui, t(lang, Key::SrvTlsUseSystemCaNote), |ui| {
        ui.checkbox(&mut tls.use_system_ca, "useSystemCA").changed()
    });
    changed |= widgets::opt_bool(
        ui,
        "enableSessionResumption",
        &mut tls.enable_session_resumption,
        t(lang, Key::SrvUnset),
    );
    changed |= widgets::text_field(
        ui,
        "pinnedPeerCertSha256",
        &mut tls.pinned_peer_cert_sha256,
        t(lang, Key::SrvPinnedPeerCertSha256Hint),
    );
    changed
}

/// The TLS settings that follow the certificate pin: the verification
/// overrides, the ECH block, and the client certificates. `profile` and
/// `buffers` are the seeded PEM editor's identity and storage.
pub(super) fn tls_connection_editor(
    ui: &mut egui::Ui,
    lang: Language,
    tls: &mut TlsModel,
    profile: &str,
    buffers: &mut SeededBuffers,
    ech_sockopt_errors: &[String],
) -> bool {
    let mut changed = false;
    changed |= widgets::text_field(
        ui,
        "verifyPeerCertByName",
        &mut tls.verify_peer_cert_by_name,
        "",
    );
    changed |= path_field(ui, lang, "masterKeyLog", &mut tls.master_key_log, true);
    changed |= widgets::text_field(
        ui,
        "echConfigList",
        &mut tls.ech_config_list,
        t(lang, Key::SrvEchConfigListHint),
    );
    changed |= ech_sockopt_editor(ui, lang, &mut tls.ech_sockopt, ech_sockopt_errors);
    if tls.alpn.len() > 1 && tls.alpn.iter().any(|value| value == "fromMitm") {
        ui.colored_label(status_colors_of(ui).err, t(lang, Key::SrvFromMitmOnlyAlpn));
    }
    let mut certs = !tls.certificates.is_empty();
    if ui
        .checkbox(&mut certs, t(lang, Key::SrvCustomCertificate))
        .changed()
    {
        tls.certificates = if certs {
            vec![TlsCert::default()]
        } else {
            Vec::new()
        };
        changed = true;
    }
    let mut remove_cert: Option<usize> = None;
    // The profile id is part of the id salt so widgets inside the group
    // (including the seeded PEM editor buffers) re-seed when the edited
    // profile switches to another one.
    for (index, certificate) in tls.certificates.iter_mut().enumerate() {
        ui.push_id(("tls-cert", profile, index), |ui| {
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label(t_fmt(lang, Key::SrvCertificateN, &[&(index + 1)]));
                    if ui.small_button(t(lang, Key::SrvRemove)).clicked() {
                        remove_cert = Some(index);
                    }
                });
                changed |= path_field(
                    ui,
                    lang,
                    t(lang, Key::SrvCertificateFile),
                    &mut certificate.certificate_file,
                    false,
                );
                changed |= path_field(
                    ui,
                    lang,
                    t(lang, Key::SrvKeyFile),
                    &mut certificate.key_file,
                    false,
                );
                changed |= pem_lines_editor(
                    ui,
                    t(lang, Key::SrvCertificatePem),
                    profile,
                    &mut certificate.certificate,
                    "-----BEGIN CERTIFICATE-----",
                    buffers,
                );
                changed |= pem_lines_editor(
                    ui,
                    t(lang, Key::SrvKeyPem),
                    profile,
                    &mut certificate.key,
                    "-----BEGIN PRIVATE KEY-----",
                    buffers,
                );
                changed |= widgets::combo_str_labeled(
                    ui,
                    "usage",
                    &mut certificate.usage,
                    &["", "encipherment", "verify", "issue"],
                    t(lang, Key::SrvDefault),
                    false,
                );
                changed |= widgets::opt_num(
                    ui,
                    t(lang, Key::SrvOcspStaplingS),
                    &mut certificate.ocsp_stapling,
                    0..=u64::MAX,
                );
                changed |= widgets::opt_bool(
                    ui,
                    "oneTimeLoading",
                    &mut certificate.one_time_loading,
                    t(lang, Key::SrvUnset),
                );
                changed |= widgets::opt_bool(
                    ui,
                    "buildChain",
                    &mut certificate.build_chain,
                    t(lang, Key::SrvUnset),
                );
                if certificate.certificate_file.trim().is_empty()
                    && certificate
                        .certificate
                        .iter()
                        .all(|line| line.trim().is_empty())
                {
                    ui.colored_label(
                        status_colors_of(ui).err,
                        t(lang, Key::SrvCertificateFileRequired),
                    );
                }
            });
        });
    }
    if let Some(index) = remove_cert {
        tls.certificates.remove(index);
        changed = true;
    }
    if ui.button(t(lang, Key::SrvAddCertificate)).clicked() {
        tls.certificates.push(TlsCert::default());
        changed = true;
    }
    changed
}
