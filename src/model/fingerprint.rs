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
//! - the server editor's TLS and realm-TLS combos, and the share-link TLS
//!   grammar: [`FINGERPRINTS`] verbatim;
//! - the server editor's REALITY combo options: [`REALITY_EDITOR_OPTIONS`],
//!   the empty default plus the known-good browser names (`chrome`,
//!   `firefox`, `safari`). The trim is an option-list decision only — every
//!   other canonical name stays accepted in a stored profile and a share
//!   link;
//! - share-link REALITY grammar: [`reality_import_supported`], the canonical
//!   table minus the names the REALITY grammar never carries;
//! - wire validation: [`wire_validation_supported`], the full vocabulary —
//!   the stream TLS block's accept-set (and the finalmask realm-TLS
//!   allow-list);
//! - REALITY wherever the wire is concerned (the stream REALITY block's
//!   model rule and the editor's REALITY inline verdict):
//!   [`reality_wire_supported`], the wire vocabulary minus the private
//!   `REALITY_REJECTED_FINGERPRINTS` (`unsafe`, `hellogolang`), compared
//!   ASCII case-insensitively;
//! - the untested-value advisory (the stream REALITY block's
//!   `RealityFingerprintUntested` warning and the editor's REALITY inline
//!   verdict): [`reality_fingerprint_outside_known_good`], the complement of
//!   [`REALITY_EDITOR_OPTIONS`], compared ASCII case-insensitively.
//!
//! Adding a fingerprint from a future Xray release is one row in
//! [`FINGERPRINTS`] when it belongs in the editor (the common case — it then
//! lands in every context except the REALITY combo options), or in
//! [`VALIDATION_ONLY_FINGERPRINTS`] when the wire accepts it but the editor
//! must not offer it. Add a row to [`REALITY_EDITOR_OPTIONS`] once upstream's
//! own tests exercise the new name for REALITY.
//!
//! Every entry is the exact string stored in profiles — profiles round-trip
//! unchanged. The whole-config raw override stays unrestricted
//! and never consults this table.

/// Canonical fingerprint table in the server editor's historical display
/// order: every name broccoli renders in the TLS and realm-TLS combos,
/// imports, or validates on the wire, with the exact strings stored in
/// profiles. Together with [`VALIDATION_ONLY_FINGERPRINTS`] (the trailing
/// wire-only names) it is the full vocabulary. The REALITY combo offers
/// [`REALITY_EDITOR_OPTIONS`] instead.
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
/// REALITY accept-set derives from it instead of re-listing the names.
const REALITY_REJECTED_FINGERPRINTS: &[&str] = &["unsafe", "hellogolang"];

/// The server editor's REALITY combo options: the empty default plus the
/// known-good browser names (`chrome`, `firefox`, `safari`) upstream's own
/// scenario suite exercises. The list is trimmed to these — every other
/// canonical name stays accepted in a stored profile, a share link
/// ([`reality_import_supported`]), and wire validation
/// ([`reality_wire_supported`]).
pub const REALITY_EDITOR_OPTIONS: &[&str] = &["", "chrome", "firefox", "safari"];

/// True when a REALITY fingerprint is outside the known-good set the editor
/// offers ([`REALITY_EDITOR_OPTIONS`]: the empty default plus `chrome`,
/// `firefox`, and `safari`). The value is wire-valid and Xray still accepts
/// it, but upstream's REALITY scenarios no longer exercise it, so it
/// warrants the advisory. Compared ASCII case-insensitively, matching the
/// wire predicates — Xray lowercases the fingerprint before its checks
/// (conf/transport_security.go client branch).
pub fn reality_fingerprint_outside_known_good(name: &str) -> bool {
    !REALITY_EDITOR_OPTIONS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
}

/// The share-link REALITY grammar's fingerprint accept-set: [`FINGERPRINTS`]
/// minus the three names the REALITY grammar never carries — `""` (a
/// REALITY fingerprint is required), `unsafe`, and `hellogolang`. The set is
/// independent of the trimmed [`REALITY_EDITOR_OPTIONS`]: a link naming any
/// other canonical fingerprint imports as before.
pub fn reality_import_supported(name: &str) -> bool {
    !name.is_empty()
        && FINGERPRINTS.contains(&name)
        && !REALITY_REJECTED_FINGERPRINTS.contains(&name)
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
            // REALITY import accepts the canonical table except the three
            // names the REALITY grammar never carries; wire-only names stay
            // out. The trimmed REALITY combo options never narrow this set.
            let expected = editor_option && !matches!(name, "" | "unsafe" | "hellogolang");
            assert_eq!(
                reality_import_supported(name),
                expected,
                "REALITY import mismatch for {name:?}"
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
        // first) and exact in the import predicate.
        for rejected in REALITY_REJECTED_FINGERPRINTS {
            assert!(!reality_wire_supported(&rejected.to_ascii_uppercase()));
            assert!(!reality_import_supported(rejected));
        }
        assert!(!reality_wire_supported("not-a-fingerprint"));
    }

    /// The REALITY combo is the one context trimmed to a positive option
    /// list: the empty default plus the browser names upstream's own tests
    /// exercise. The trim is an option-list decision only — acceptance
    /// (import, wire validation) never consults it.
    #[test]
    fn reality_editor_options_are_the_empty_default_plus_the_tested_browsers() {
        assert_eq!(
            REALITY_EDITOR_OPTIONS,
            ["", "chrome", "firefox", "safari"],
            "the REALITY combo option set"
        );
        for &option in REALITY_EDITOR_OPTIONS {
            assert!(
                FINGERPRINTS.contains(&option),
                "REALITY combo option {option:?} is outside the canonical table"
            );
            assert!(
                !REALITY_REJECTED_FINGERPRINTS.contains(&option),
                "REALITY combo option {option:?} is one of the wire rejections"
            );
        }
        // Names the trim dropped stay wire-valid and importable: a stored
        // profile or a share link carrying one is accepted as before.
        for name in ["ios", "edge", "qq", "android", "random", "randomized"] {
            assert!(!REALITY_EDITOR_OPTIONS.contains(&name));
            assert!(
                reality_wire_supported(name),
                "{name:?} must stay wire-valid"
            );
            assert!(
                reality_import_supported(name),
                "{name:?} must stay importable"
            );
        }
        // The wire-only name stays wire-valid and out of the share-link
        // grammar, exactly as before the trim.
        assert!(reality_wire_supported("randomizedalpn"));
        assert!(!reality_import_supported("randomizedalpn"));
    }

    /// The advisory predicate is the complement of the REALITY option set:
    /// the empty default and every ASCII casing of the three names sit
    /// inside, every other table name sits outside, and the wire-rejected
    /// names sit outside too — the model pairs this predicate with the wire
    /// accept-set, so a rejected name never also warns.
    #[test]
    fn advisory_predicate_is_the_complement_of_the_reality_option_set() {
        for name in ["", "chrome", "firefox", "safari", "Chrome", "FIREFOX"] {
            assert!(
                !reality_fingerprint_outside_known_good(name),
                "{name:?} is inside the known-good set"
            );
        }
        for name in [
            "ios",
            "edge",
            "qq",
            "android",
            "random",
            "randomized",
            "randomizedalpn",
        ] {
            assert!(
                reality_fingerprint_outside_known_good(name),
                "{name:?} is outside the known-good set"
            );
        }
        for rejected in REALITY_REJECTED_FINGERPRINTS {
            assert!(
                reality_fingerprint_outside_known_good(rejected),
                "{rejected:?} is outside the known-good set (the model fires its Error instead)"
            );
        }
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
