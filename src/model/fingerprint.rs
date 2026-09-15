//! Canonical uTLS fingerprint vocabulary.
//!
//! Every fingerprint name broccoli can render in the server editor, accept
//! from a share link, or validate on the wire is defined here, once. The
//! contexts that previously carried their own copies of the list — the
//! server editor's selectable options (`src/ui/servers.rs`), the share-link
//! import predicates (`src/links/mod.rs`), and the validation passes
//! (`src/model/validation.rs`: the stream TLS/REALITY blocks and the
//! finalmask realm-TLS allow-list) — derive from this module:
//!
//! - the full vocabulary is [`FINGERPRINTS`] followed by
//!   [`VALIDATION_ONLY_FINGERPRINTS`];
//! - editor options and the share-link TLS grammar: [`FINGERPRINTS`]
//!   verbatim;
//! - share-link REALITY grammar: [`reality_import_supported`], the editor
//!   set minus the names the REALITY grammar never carries;
//! - wire validation: [`wire_validation_supported`], the full vocabulary —
//!   the stream TLS block's accept-set (and the finalmask realm-TLS
//!   allow-list);
//! - REALITY wherever the wire is concerned (the stream REALITY block's
//!   model rule and the editor's REALITY inline verdict):
//!   [`reality_wire_supported`], the wire vocabulary minus the private
//!   `REALITY_REJECTED_FINGERPRINTS` (`unsafe`, `hellogolang`), compared
//!   ASCII case-insensitively;
//! - the server editor's REALITY combo options: [`reality_editor_supported`]
//!   (the exact-case editor table minus the two rejected names).
//!
//! Adding a fingerprint from a future Xray release is one row in
//! [`FINGERPRINTS`] when it belongs in the editor (the common case — it then
//! lands in every context), or in [`VALIDATION_ONLY_FINGERPRINTS`] when the
//! wire accepts it but the editor must not offer it.
//!
//! Every entry is the exact string stored in profiles — profiles round-trip
//! unchanged. The whole-config raw override stays unrestricted
//! and never consults this table.

/// Canonical fingerprint table in the server editor's historical display
/// order: every name broccoli renders or imports, with the exact strings
/// stored in profiles. Together with [`VALIDATION_ONLY_FINGERPRINTS`] (the
/// trailing wire-only names) it is the full vocabulary.
pub const FINGERPRINTS: &[&str] = &[
    "",
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
    "randomizednoalpn",
    "unsafe",
    "hellogolang",
    "hellorandomized",
    "hellorandomizedalpn",
    "hellorandomizednoalpn",
    "hellofirefox_120",
    "hellofirefox_148",
    "hellochrome_120",
    "hellochrome_131",
    "hellochrome_133",
    "helloios_13",
    "helloios_14",
    "helloedge_106",
    "hellosafari_26_3",
    "hello360_11_0",
    "helloqq_11_1",
    "hellofirefox_auto",
    "hellochrome_auto",
    "helloios_auto",
    "helloedge_auto",
    "hellosafari_auto",
    "hello360_auto",
    "helloqq_auto",
    "hellofirefox_55",
    "hellofirefox_56",
    "hellofirefox_63",
    "hellofirefox_65",
    "hellofirefox_99",
    "hellofirefox_102",
    "hellofirefox_105",
    "hellochrome_58",
    "hellochrome_62",
    "hellochrome_70",
    "hellochrome_72",
    "hellochrome_83",
    "hellochrome_87",
    "hellochrome_96",
    "hellochrome_100",
    "hellochrome_102",
    "hellochrome_106_shuffle",
    "helloios_11_1",
    "helloios_12_1",
    "helloandroid_11_okhttp",
    "helloedge_85",
    "hellosafari_16_0",
    "hello360_7_5",
    "hellochrome_100_psk",
    "hellochrome_112_psk_shuf",
    "hellochrome_114_padding_psk_shuf",
    "hellochrome_115_pq",
    "hellochrome_115_pq_psk",
    "hellochrome_120_pq",
];

/// Wire-validation members of the vocabulary that the editor never offers
/// and the share-link import rejects (the historical finalmask realm-TLS
/// allow-list accepted them; the editor and grammar lists did not). Appended
/// to [`FINGERPRINTS`] to form the full canonical vocabulary.
pub const VALIDATION_ONLY_FINGERPRINTS: &[&str] = &["randomizedalpn"];

/// Fingerprint names REALITY refuses wherever the wire is concerned —
/// `unsafe` and `hellogolang` (they have no uTLS ClientHello and make
/// REALITY fingerprinting pointless). The single exclusion list: every
/// REALITY context derives from it instead of re-listing the names.
const REALITY_REJECTED_FINGERPRINTS: &[&str] = &["unsafe", "hellogolang"];

/// The server editor's REALITY combo accept-set: [`FINGERPRINTS`] minus
/// [`REALITY_REJECTED_FINGERPRINTS`] (empty is tolerated here — the
/// REALITY default option — unlike the share-link grammar).
pub fn reality_editor_supported(name: &str) -> bool {
    FINGERPRINTS.contains(&name) && !REALITY_REJECTED_FINGERPRINTS.contains(&name)
}

/// The share-link REALITY grammar's fingerprint accept-set: every editor
/// option except the three names the REALITY grammar never carries — `""`
/// (a REALITY fingerprint is required), `unsafe`, and `hellogolang`.
pub fn reality_import_supported(name: &str) -> bool {
    !name.is_empty() && reality_editor_supported(name)
}

/// The wire-validation accept-set: the full canonical vocabulary (editor
/// table plus wire-only names). ASCII case-insensitive, mirroring the
/// historical validation allow-list which lowercased the value before
/// matching — profiles written by hand in any casing of a table name stay
/// accepted.
pub fn wire_validation_supported(name: &str) -> bool {
    FINGERPRINTS
        .iter()
        .chain(VALIDATION_ONLY_FINGERPRINTS)
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
}

/// The REALITY wire-validation accept-set (the stream-block model rule, and
/// the server editor's REALITY inline verdict): [`wire_validation_supported`]
/// minus [`REALITY_REJECTED_FINGERPRINTS`], with the exclusion compared
/// ASCII case-insensitively — Xray lowercases the fingerprint before its
/// checks (conf/transport_security.go client branch). Wire-only names such
/// as `randomizedalpn` are accepted here even though the editor never offers
/// them.
pub fn reality_wire_supported(name: &str) -> bool {
    wire_validation_supported(name)
        && !REALITY_REJECTED_FINGERPRINTS
            .iter()
            .any(|rejected| rejected.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Adding a fingerprint must be a one-row edit: every context derives
    /// from the same compiled tables, so walk them and check each context's
    /// decision against expectations derived from the tables themselves
    /// (never from a duplicated literal list).
    #[test]
    fn contexts_derive_from_the_canonical_tables() {
        for &name in FINGERPRINTS.iter().chain(VALIDATION_ONLY_FINGERPRINTS) {
            let editor_option = FINGERPRINTS.contains(&name);
            // Wire validation accepts the full vocabulary ...
            assert!(
                wire_validation_supported(name),
                "wire validation rejects {name:?}"
            );
            // ... with the historical ASCII-case tolerance.
            assert!(
                wire_validation_supported(&name.to_ascii_uppercase()),
                "wire validation rejects upper-cased {name:?}"
            );
            // REALITY import accepts editor options except the three names
            // the REALITY grammar never carries; wire-only names stay out.
            let expected = editor_option && !matches!(name, "" | "unsafe" | "hellogolang");
            assert_eq!(
                reality_import_supported(name),
                expected,
                "REALITY import mismatch for {name:?}"
            );
            // The REALITY editor filter only excludes the two core
            // rejections (empty is a valid option there).
            let editor_expected = editor_option && !REALITY_REJECTED_FINGERPRINTS.contains(&name);
            assert_eq!(
                reality_editor_supported(name),
                editor_expected,
                "REALITY editor mismatch for {name:?}"
            );
            // REALITY wire validation accepts everything the wire accepts
            // except the two core rejections — wire-only names included.
            let wire_expected = !REALITY_REJECTED_FINGERPRINTS.contains(&name);
            assert_eq!(
                reality_wire_supported(name),
                wire_expected,
                "REALITY wire mismatch for {name:?}"
            );
            // The ASCII-case tolerance applies to every accepted name; the
            // two excluded names stay excluded in any casing (asserted
            // below).
            if wire_expected {
                assert!(
                    reality_wire_supported(&name.to_ascii_uppercase()),
                    "REALITY wire rejects upper-cased {name:?}"
                );
            }
        }
        // The exclusion is case-insensitive on the wire (Xray lowercases
        // first) and exact in the editor/import predicates.
        for rejected in REALITY_REJECTED_FINGERPRINTS {
            assert!(!reality_wire_supported(&rejected.to_ascii_uppercase()));
            assert!(!reality_editor_supported(rejected));
            assert!(!reality_import_supported(rejected));
        }
        assert!(!reality_wire_supported("not-a-fingerprint"));
    }

    #[test]
    fn entries_are_unique_lowercase_profile_strings() {
        let all: Vec<&str> = FINGERPRINTS
            .iter()
            .chain(VALIDATION_ONLY_FINGERPRINTS)
            .copied()
            .collect();
        for (index, &name) in all.iter().enumerate() {
            assert!(
                !all[..index].contains(&name),
                "duplicate vocabulary entry {name:?}"
            );
            assert!(
                name.bytes().all(|byte| !byte.is_ascii_uppercase()),
                "vocabulary entry {name:?} is not lowercase"
            );
            assert!(name.is_ascii(), "vocabulary entry {name:?} is not ASCII");
        }
        // Wire-only entries stay out of the editor table.
        for &name in VALIDATION_ONLY_FINGERPRINTS {
            assert!(
                !FINGERPRINTS.contains(&name),
                "{name:?} is wire-only but appears in the editor table"
            );
        }
        // The historical REALITY rejections remain exactly those three names.
        let rejected = FINGERPRINTS
            .iter()
            .copied()
            .filter(|name| !reality_import_supported(name))
            .collect::<Vec<_>>();
        assert_eq!(rejected, ["", "unsafe", "hellogolang"]);
    }
}
