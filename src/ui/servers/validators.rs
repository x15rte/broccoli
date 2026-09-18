//! Per-field validator closures of the servers screen: each maps one field
//! value to its localized validation error message, or `None` when the
//! value is acceptable. The editor's validation sweep and the validated /
//! keygen row entry points in the parent module call through these.
//! Private to the screen.
//!
//! The TLS/REALITY
//! security-format checks (public key, short id, spiderX, mldsa65Verify,
//! cert pins, fingerprints) moved into the model — they fire from
//! `validate_outbound` as `ValidationCode` issues and render through the
//! shared i18n seam. The predicates live in `crate::model::validation` /
//! `crate::model::fingerprint`; this module only keeps the validators for
//! rules the model cannot express — requiredness of draft fields, hostname
//! shapes, WireGuard formats — plus tool-output guards. The UUID and
//! vless-encryption FORMAT checks moved into the model too
//! (SettingsIdNotUuid / VlessEncryptionUnsupported): the keygen rows call
//! the `…_required` helpers below so one message channel carries each
//! value, while the full `v_uuid` / `v_vless_encryption` stay
//! for tool-output validation only.

use base64::Engine as _;

use crate::i18n::{Key, t};
use crate::model::outbound::{is_valid_wireguard_key, wireguard_remote_dns_entry_supported};
use crate::model::settings::Language;

// ---------- validators ----------

pub(super) fn v_required(lang: Language, v: &str) -> Option<String> {
    v.trim()
        .is_empty()
        .then(|| t(lang, Key::SrvRequired).to_string())
}

pub(super) fn v_uuid(lang: Language, v: &str) -> Option<String> {
    if v.is_empty() {
        Some(t(lang, Key::SrvUuidRequired).into())
    } else if uuid::Uuid::parse_str(v).is_ok() {
        None
    } else {
        Some(t(lang, Key::SrvMustBeUuid).into())
    }
}

/// Keystroke requiredness for the VLESS/VMess id fields: empty alone is a
/// draft state the model deliberately accepts (`SettingsIdNotUuid` owns the
/// non-empty non-canonical format check — one message channel).
/// The full [`v_uuid`] stays for tool-output guards.
pub(super) fn v_uuid_required(lang: Language, v: &str) -> Option<String> {
    v.is_empty().then(|| t(lang, Key::SrvUuidRequired).into())
}

/// Keystroke requiredness for the VLESS encryption field: empty alone is a
/// draft state the model deliberately accepts (`VlessEncryptionUnsupported`
/// owns the non-empty format check — one message channel). The
/// full [`v_vless_encryption`] stays for tool-output guards.
pub(super) fn v_vless_encryption_required(lang: Language, v: &str) -> Option<String> {
    if v == "none" || !v.is_empty() {
        None
    } else {
        Some(t(lang, Key::SrvVlessEncryptionRequired).into())
    }
}

pub(super) fn v_wg_key(lang: Language, v: &str) -> Option<String> {
    if is_valid_wireguard_key(v) {
        None
    } else {
        Some(t(lang, Key::SrvWgKey).into())
    }
}

pub(super) fn v_optional_wg_key(lang: Language, v: &str) -> Option<String> {
    if v.is_empty() {
        None
    } else {
        v_wg_key(lang, v)
    }
}

/// Per-entry verdict for the WireGuard in-network DNS list. `entry_count` is
/// the list length because the core reads `local` as the sentinel only when
/// the list holds nothing else (proxy/wireguard/client.go:117-124); the
/// sentinel entry itself carries the mixed-list verdict, every other
/// unacceptable entry the format verdict.
pub(super) fn v_wg_remote_dns_entry(
    lang: Language,
    entry: &str,
    entry_count: usize,
) -> Option<String> {
    if wireguard_remote_dns_entry_supported(entry, entry_count) {
        return None;
    }
    if entry == "local" {
        Some(t(lang, Key::SrvWgRemoteDnsLocalOnly).to_string())
    } else {
        Some(t(lang, Key::SrvWgRemoteDnsEntryInvalid).to_string())
    }
}

pub(super) fn v_vless_encryption(lang: Language, v: &str) -> Option<String> {
    if v == "none" {
        return None;
    }
    if v.is_empty() {
        return Some(t(lang, Key::SrvVlessEncryptionRequired).into());
    }
    let parts: Vec<_> = v.split('.').collect();
    let shape_ok = parts.len() >= 4
        && parts[0] == "mlkem768x25519plus"
        && matches!(parts[1], "native" | "xorpub" | "random")
        && matches!(parts[2], "1rtt" | "0rtt");
    let keys_ok = shape_ok
        && parts[3..].iter().all(|part| {
            part.len() < 20
                || base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(part)
                    .is_ok_and(|bytes| matches!(bytes.len(), 32 | 1184))
        });
    if keys_ok {
        None
    } else {
        Some(t(lang, Key::SrvVlessEncryptionFormat).into())
    }
}
