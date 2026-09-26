//! Corpus check over `ValidationCode`: one constructed entry per variant, and
//! one complete sentence per entry in every locale the app ships.
//!
//! The corpus data and the generated variant list live in the [`corpus`]
//! module beside this file (`tests/common/validation_corpus.rs`); this file is
//! the driver. Coverage is mechanical at both ends: the generated
//! `variant_name` matches the enum with no wildcard arm, so a variant added to
//! the enum and left out of the list is a compile error, and the coverage test
//! below fails when a listed variant has no corpus entry.

use broccoli::i18n::validation_message;
use broccoli::model::settings::Language;
use corpus::{VARIANT_COUNT, VARIANT_NAMES, all_codes, variant_name};

#[path = "common/validation_corpus.rs"]
mod corpus;

/// Every locale the renderer ships. Adding a locale is one entry here.
const LANGUAGES: &[Language] = &[Language::En];

/// The corpus lists every variant once: its entries' names are exactly
/// [`VARIANT_NAMES`], each of them present once.
#[test]
fn corpus_lists_every_variant_once() {
    let codes = all_codes();
    assert_eq!(
        codes.len(),
        VARIANT_COUNT,
        "the corpus must carry one entry per ValidationCode variant"
    );
    let mut listed: Vec<&str> = codes.iter().map(variant_name).collect();
    listed.sort_unstable();
    let mut expected = VARIANT_NAMES.to_vec();
    expected.sort_unstable();
    assert_eq!(
        listed, expected,
        "the corpus must carry one entry per variant, and no variant twice"
    );
}

/// Every entry renders one complete sentence in every locale the app ships:
/// non-empty, no placeholder left unfilled, no trailing space. The renderer
/// asserts its own template and placeholder counts, but only for the codes
/// other tests happen to render; this walks the whole universe, so a rule that
/// lost a placeholder fails here instead of reaching the user.
#[test]
fn every_code_renders_a_complete_sentence() {
    for code in all_codes() {
        for &language in LANGUAGES {
            let message = validation_message(&code, language);
            let context = format!("{code:?} in {language:?}");
            assert!(!message.is_empty(), "{context}: empty message");
            assert!(
                !message.contains('{') && !message.contains('}'),
                "{context}: unfilled placeholder in {message:?}"
            );
            assert!(
                !message.ends_with(' '),
                "{context}: trailing space in {message:?}"
            );
        }
    }
}
