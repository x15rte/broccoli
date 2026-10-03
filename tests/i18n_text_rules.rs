//! Corpus check over the locale table: every English string in the table must
//! obey the text standard.
//!
//! The rules live in the [`standard`] module beside this file
//! (`tests/common/standard.rs`), with the text they govern and the vocabulary
//! they report through: the rule ids, the word caps, the exception rows, and
//! the finding type. This file is the driver — it walks `broccoli::i18n::ALL`,
//! asks the engine for the verdict on each key, prints the advisories, and
//! fails on any hard finding. The tests below also drive the engine over
//! strings that are not in the table, so a rule that stops firing is caught
//! even while no shipped string shows the breach.
//!
//! `EXCEPTIONS` lists the strings that knowingly keep a violation: the key,
//! the rule id, and the reason the rule does not apply. A row with an empty
//! reason, or with a rule id that is not declared, fails this test.

use broccoli::i18n::{ALL, Key, t};
use broccoli::model::settings::Language;
use standard::{
    EXCEPTIONS, INSTRUCTION_WORD_CAP, LOG_LINE_ADVISORY_CHARS, LOG_LINE_CHAR_CAP, RULE_ARITY,
    RULE_AVOIDED_TERM, RULE_BANNED_TERM, RULE_COMPOUND_TENSE, RULE_CONTRACTION, RULE_IDS,
    RULE_INSTRUCTION_LENGTH, RULE_LOG_ACTOR, RULE_LOG_CAPITALIZATION, RULE_LOG_LENGTH,
    RULE_LOG_TERMINATOR, RULE_NOMINALIZATION, RULE_NOUN_CLUSTER, RULE_PASSIVE, RULE_PLACEHOLDER,
    RULE_POSSESSIVE, RULE_SEMICOLON, RULE_SENTENCE_LENGTH, SENTENCE_WORD_CAP, advisory_findings,
    arity_findings, exempt, hard_findings, key_findings, log_advisory_findings, log_hard_findings,
};

#[path = "common/standard.rs"]
mod standard;

#[test]
fn locale_table_follows_the_text_standard() {
    assert!(!ALL.is_empty(), "i18n::ALL must list every key");
    for &(key, rule, reason) in EXCEPTIONS {
        assert!(
            !reason.trim().is_empty(),
            "exception for {key:?} [{rule}] needs a reason"
        );
        assert!(
            RULE_IDS.contains(&rule),
            "exception for {key:?} names the unknown rule {rule:?}"
        );
    }

    let mut violations: Vec<String> = Vec::new();
    let mut advisories: Vec<String> = Vec::new();
    for &key in ALL {
        let text = t(Language::En, key);
        let findings = key_findings(key);
        for finding in findings.hard {
            violations.push(format!(
                "{key:?} [{}] {text:?}: {}",
                finding.rule, finding.detail
            ));
        }
        for finding in findings.advisory {
            advisories.push(format!("{key:?} [{}]: {}", finding.rule, finding.detail));
        }
    }

    if !advisories.is_empty() {
        eprintln!(
            "text standard advisories ({}):\n{}",
            advisories.len(),
            advisories.join("\n")
        );
    }
    assert!(
        violations.is_empty(),
        "text standard violations ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// A sentence of `count` words that starts with `first`.
fn padded_sentence(first: &str, count: usize) -> String {
    let mut sentence = first.to_string();
    while sentence.split_whitespace().count() < count {
        sentence.push_str(" filler");
    }
    sentence.push('.');
    sentence
}

/// The rule ids the hard checks report for one string.
fn hard_rules(text: &str) -> Vec<&'static str> {
    hard_findings(text)
        .iter()
        .map(|finding| finding.rule)
        .collect()
}

/// The rule ids the advisory checks report for one string.
fn advisory_rules(text: &str) -> Vec<&'static str> {
    advisory_findings(text)
        .iter()
        .map(|finding| finding.rule)
        .collect()
}

/// The rule ids the log hard checks report for one string.
fn log_hard_rules(text: &str) -> Vec<&'static str> {
    log_hard_findings(text)
        .iter()
        .map(|finding| finding.rule)
        .collect()
}

/// The rule ids the log advisory checks report for one string.
fn log_advisory_rules(text: &str) -> Vec<&'static str> {
    log_advisory_findings(text)
        .iter()
        .map(|finding| finding.rule)
        .collect()
}

#[test]
fn a_log_line_holds_no_sentence_terminator() {
    assert_eq!(log_hard_rules("core ready."), vec![RULE_LOG_TERMINATOR]);
    assert_eq!(
        log_hard_rules("core ready! again"),
        vec![RULE_LOG_TERMINATOR]
    );
    assert!(log_hard_rules("core ready").is_empty());
    // A value keeps its own punctuation: only the template is checked, and a
    // placeholder's inner text is not the line's punctuation.
    assert!(log_hard_rules("probe failed: {}").is_empty());
    assert!(log_hard_rules("probe failed: {server:?}").is_empty());
    // An address literal is not a sentence split.
    assert!(log_hard_rules("endpoint committed: 127.0.0.1:{}").is_empty());
}

#[test]
fn a_log_line_names_no_actor() {
    assert_eq!(
        log_hard_rules("the app applied the config"),
        vec![RULE_LOG_ACTOR]
    );
    assert_eq!(
        log_hard_rules("The app stops the core"),
        vec![RULE_LOG_ACTOR, RULE_LOG_CAPITALIZATION]
    );
    // The core and the helper are other actors and stay nameable.
    assert!(log_hard_rules("the core exited: code 23").is_empty());
}

#[test]
fn a_log_line_starts_lowercase_unless_it_is_a_technical_name() {
    assert_eq!(log_hard_rules("Core ready"), vec![RULE_LOG_CAPITALIZATION]);
    assert!(log_hard_rules("core ready").is_empty());
    assert!(log_hard_rules("TUN inbound closed").is_empty());
    assert!(log_hard_rules("Xray logger restarted").is_empty());
}

#[test]
fn a_log_line_is_capped_in_characters() {
    assert!(log_hard_rules(&"x".repeat(LOG_LINE_CHAR_CAP)).is_empty());
    assert_eq!(
        log_hard_rules(&"x".repeat(LOG_LINE_CHAR_CAP + 1)),
        vec![RULE_LOG_LENGTH]
    );
    let advisory = "x".repeat(LOG_LINE_ADVISORY_CHARS + 1);
    assert!(log_hard_rules(&advisory).is_empty());
    assert_eq!(log_advisory_rules(&advisory), vec![RULE_LOG_LENGTH]);
}

#[test]
fn a_log_line_allows_a_semicolon_and_reads_no_passive_voice() {
    assert!(log_hard_rules("TUN core alive; stopping it now").is_empty());
    assert!(log_hard_findings("the file was written by the helper").is_empty());
    assert!(log_advisory_findings("connect rejected by the core").is_empty());
}

#[test]
fn a_log_line_keeps_the_shared_hard_rules() {
    assert!(log_hard_rules("connect didn't start").contains(&RULE_CONTRACTION));
    assert!(log_hard_rules("a seamless start").contains(&RULE_BANNED_TERM));
    assert!(log_hard_rules("{unclosed").contains(&RULE_PLACEHOLDER));
    assert!(log_hard_rules(" trailing ").contains(&RULE_PLACEHOLDER));
}

#[test]
fn the_prose_profile_still_applies_to_a_ui_key() {
    assert_eq!(Key::Close.class(), broccoli::i18n::TextClass::Ui);
    assert!(Key::Close.level().is_none());
}

#[test]
fn a_log_key_declares_its_level() {
    assert_eq!(Key::RtLogCoreReady.class(), broccoli::i18n::TextClass::Log);
    assert_eq!(
        Key::RtLogCoreReady.level(),
        Some(broccoli::i18n::LogLevel::Info)
    );
}

#[test]
fn clean_strings_report_nothing() {
    for text in [
        "Downloading…",
        "{}/{} bytes",
        "{} and {}",
        "Remove the panel, then restart.",
        "· {}",
        "—",
        "🗑",
    ] {
        assert!(hard_findings(text).is_empty(), "hard: {text:?}");
        assert!(advisory_findings(text).is_empty(), "advisory: {text:?}");
    }
}

#[test]
fn instructions_use_the_lower_cap() {
    assert!(hard_findings(&padded_sentence("Verify", INSTRUCTION_WORD_CAP)).is_empty());
    assert_eq!(
        hard_rules(&padded_sentence("Verify", INSTRUCTION_WORD_CAP + 1)),
        vec![RULE_INSTRUCTION_LENGTH]
    );
}

#[test]
fn other_sentences_use_the_upper_cap() {
    assert!(hard_findings(&padded_sentence("The core writes", SENTENCE_WORD_CAP)).is_empty());
    assert_eq!(
        hard_rules(&padded_sentence("The core writes", SENTENCE_WORD_CAP + 1)),
        vec![RULE_SENTENCE_LENGTH]
    );
}

#[test]
fn cap_counts_each_sentence_of_a_string() {
    let text = format!(
        "{} {}",
        padded_sentence("Verify", INSTRUCTION_WORD_CAP + 1),
        padded_sentence("The core writes", SENTENCE_WORD_CAP + 1)
    );
    assert_eq!(
        hard_rules(&text),
        vec![RULE_INSTRUCTION_LENGTH, RULE_SENTENCE_LENGTH]
    );
}

#[test]
fn semicolons_fail() {
    assert_eq!(
        hard_rules("Remove the panel; then restart."),
        vec![RULE_SEMICOLON]
    );
}

#[test]
fn contractions_fail() {
    assert_eq!(hard_rules("It's ready."), vec![RULE_CONTRACTION]);
    for text in [
        "The app doesn't write here.",
        "We're connected.",
        "We've finished.",
        "They'll retry.",
        "He'd restart the core.",
        "I'm waiting.",
        "That's the active server.",
    ] {
        assert!(hard_rules(text).contains(&RULE_CONTRACTION), "{text:?}");
    }
}

#[test]
fn possessives_are_advisory() {
    assert!(hard_findings("Xray's core").is_empty(), "hard");
    assert_eq!(advisory_rules("Xray's core"), vec![RULE_POSSESSIVE]);
    assert!(hard_findings("Keep the server's pin.").is_empty(), "hard");
    assert_eq!(
        advisory_rules("Keep the server's pin."),
        vec![RULE_POSSESSIVE]
    );
}

#[test]
fn apostrophes_outside_contractions_stay_clean() {
    for text in [
        "Use 'auto' for the mode.",
        "Open 'localhost' in the browser.",
        "The '{0}' value is empty.",
        "The servers' pins are unique.",
    ] {
        assert!(hard_findings(text).is_empty(), "hard: {text:?}");
        assert!(advisory_findings(text).is_empty(), "advisory: {text:?}");
    }
}

#[test]
fn banned_terms_fail() {
    assert_eq!(hard_rules("A seamless experience."), vec![RULE_BANNED_TERM]);
    assert_eq!(hard_rules("A cutting-edge icon."), vec![RULE_BANNED_TERM]);
    assert_eq!(hard_rules("A cutting edge icon."), vec![RULE_BANNED_TERM]);
    for text in ["Spin up the core.", "Reach out to the server."] {
        assert!(hard_rules(text).contains(&RULE_BANNED_TERM), "{text:?}");
    }
}

#[test]
fn placeholder_defects_fail() {
    assert_eq!(hard_rules("{unclosed"), vec![RULE_PLACEHOLDER]);
    assert_eq!(hard_rules("unopened }"), vec![RULE_PLACEHOLDER]);
    assert_eq!(
        hard_rules("value: {{name}}"),
        vec![RULE_PLACEHOLDER, RULE_PLACEHOLDER]
    );
    assert_eq!(hard_rules(" padded "), vec![RULE_PLACEHOLDER]);
    assert_eq!(hard_rules(""), vec![RULE_PLACEHOLDER]);
}

#[test]
fn declared_arity_must_match_the_english_text() {
    // The key declares one placeholder; the text must hold exactly one.
    assert!(arity_findings(Key::LatencyMs, "{} ms").is_empty());
    let dropped = arity_findings(Key::LatencyMs, "ms");
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped[0].rule, RULE_ARITY);
    let added = arity_findings(Key::Close, "{value}");
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].rule, RULE_ARITY);
}

#[test]
fn non_prose_strings_skip_the_wording_rules() {
    assert!(hard_findings("· {}").is_empty());
    assert!(hard_findings("🗑").is_empty());
    assert!(advisory_findings("—").is_empty());
    // Structural rules still apply to them.
    assert_eq!(hard_rules(" · {}"), vec![RULE_PLACEHOLDER]);
}

#[test]
fn compound_tense_is_advisory() {
    assert_eq!(
        advisory_rules("We have received your request."),
        vec![RULE_COMPOUND_TENSE]
    );
    for text in [
        "The core has not been started.",
        "The app will have finished.",
    ] {
        assert!(
            advisory_rules(text).contains(&RULE_COMPOUND_TENSE),
            "{text:?}"
        );
    }
    assert!(hard_findings("We have received your request.").is_empty());
}

#[test]
fn passive_voice_is_advisory() {
    assert!(advisory_rules("The file was written by the app.").contains(&RULE_PASSIVE));
    assert!(advisory_rules("The file was not written.").contains(&RULE_PASSIVE));
    assert!(hard_findings("The file was written by the app.").is_empty());
}

#[test]
fn nominalization_is_advisory() {
    assert!(advisory_rules("Perform an evaluation of the log.").contains(&RULE_NOMINALIZATION));
    assert!(advisory_rules("Carry out the migration.").contains(&RULE_NOMINALIZATION));
    assert!(advisory_rules("Perform the check.").is_empty());
}

#[test]
fn noun_clusters_are_advisory() {
    assert!(
        advisory_rules("The server certificate pin store is empty.").contains(&RULE_NOUN_CLUSTER)
    );
    assert!(advisory_rules("The server certificate pin is empty.").is_empty());
}

#[test]
fn avoided_terms_are_advisory() {
    assert!(advisory_rules("Start the xray process.").contains(&RULE_AVOIDED_TERM));
    assert!(advisory_rules("Restart the daemons now.").contains(&RULE_AVOIDED_TERM));
    assert!(advisory_rules("Connect the active server.").is_empty());
}

#[test]
fn exception_rows_exempt_one_key_and_rule() {
    let rows: &[(Key, &str, &str)] = &[(Key::Close, RULE_SEMICOLON, "quoted text")];
    assert!(exempt(rows, Key::Close, RULE_SEMICOLON));
    assert!(!exempt(rows, Key::Close, RULE_CONTRACTION));
    assert!(!exempt(rows, Key::Cancel, RULE_SEMICOLON));
}
