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
//! for tool-output validation only — each delegating its format branch to
//! the model's one definition (`is_canonical_uuid` /
//! `vless_encryption_supported`).

use crate::i18n::{Key, t, validation_message};
use crate::model::outbound::vless_encryption_supported;
use crate::model::settings::Language;
use crate::model::validation::{
    ValidationCode, is_canonical_uuid, masque_remote_dns_verdict,
    wireguard_peer_public_key_verdict, wireguard_preshared_key_verdict,
    wireguard_remote_dns_verdict, wireguard_secret_key_verdict,
};

// ---------- validators ----------

pub(super) fn v_required(lang: Language, v: &str) -> Option<String> {
    v.trim()
        .is_empty()
        .then(|| t(lang, Key::SrvRequired).to_string())
}

/// The tool-output guard for a generated id: delegates the format branch to
/// the model's one UUID definition ([`is_canonical_uuid`]), so this screen,
/// the share-link grammar, and the model finding agree about which ids dial
/// the configured account. Empty stays a requiredness error here.
pub(super) fn v_uuid(lang: Language, v: &str) -> Option<String> {
    if v.is_empty() {
        Some(t(lang, Key::SrvUuidRequired).into())
    } else if is_canonical_uuid(v) {
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

/// Render one model verdict as the row's inline error: the code's message in
/// the active language. The rule and its text are the model's; a row only
/// shows them.
fn verdict_error(lang: Language, verdict: Option<ValidationCode>) -> Option<String> {
    verdict.map(|code| validation_message(&code, lang))
}

/// The WireGuard `secretKey` field's verdict: the model refuses an empty key
/// and one it cannot parse with the same code the pass reports.
pub(super) fn v_wg_secret_key(lang: Language, v: &str) -> Option<String> {
    verdict_error(lang, wireguard_secret_key_verdict(v))
}

/// One WireGuard peer's `publicKey` verdict (see [`v_wg_secret_key`]).
pub(super) fn v_wg_public_key(lang: Language, v: &str) -> Option<String> {
    verdict_error(lang, wireguard_peer_public_key_verdict(v))
}

/// The same for a peer's optional pre-shared key: empty is the core's zero
/// shape, and anything else must be a key it builds.
pub(super) fn v_optional_wg_key(lang: Language, v: &str) -> Option<String> {
    verdict_error(lang, wireguard_preshared_key_verdict(v))
}

/// Per-entry verdict for the WireGuard in-network DNS list: the entry must be
/// an address literal (an IPv6 literal may carry a zone), because the core
/// parses every entry with `netip.MustParseAddr` and a bad one crashes the
/// process. The retired `local` sentinel is refused like any other non-address
/// entry. The model's list rule reads the same verdict.
pub(super) fn v_wg_remote_dns_entry(lang: Language, entry: &str) -> Option<String> {
    verdict_error(lang, wireguard_remote_dns_verdict(entry))
}

/// Per-entry verdict for the MASQUE in-tunnel DNS list: the entry must be an
/// address literal, because the core parses every entry with `netip.ParseAddr`
/// while it builds the outbound and refuses the config
/// (infra/conf/masque.go:27-30).
pub(super) fn v_masque_remote_dns_entry(lang: Language, entry: &str) -> Option<String> {
    verdict_error(lang, masque_remote_dns_verdict(entry))
}

/// The tool-output guard for a generated encryption value. Delegates to the
/// shared model predicate (`vless_encryption_supported`), so the keygen row,
/// the import grammar, and the field's model finding agree about what the
/// core loads. Empty stays a requiredness error here.
pub(super) fn v_vless_encryption(lang: Language, v: &str) -> Option<String> {
    if v.is_empty() {
        return Some(t(lang, Key::SrvVlessEncryptionRequired).into());
    }
    if vless_encryption_supported(v) {
        None
    } else {
        Some(t(lang, Key::SrvVlessEncryptionFormat).into())
    }
}
