//! Corpus lint over the locale table: every English string in `broccoli::i18n`
//! must obey the text standard documented in the module.
//!
//! Hard rules fail this test:
//!
//! - A sentence holds at most 25 words, or at most 20 when its first word is
//!   an imperative verb (`IMPERATIVE_VERBS`). Sentences split on `.`, `!`,
//!   and `?`; an ellipsis is not a terminator.
//! - No semicolons and no contractions: the `n't` family, `'re`, `'ve`,
//!   `'ll`, `'d`, `'m`, and the fixed `'s` forms `it's`, `that's`, `there's`,
//!   `here's`, `what's`, `who's`, `let's`.
//! - No marketing adjectives and no soft two-word verbs (`BANNED_TERMS`).
//! - Placeholder integrity: balanced braces, no `{{`/`}}` escapes, no leading
//!   or trailing whitespace, never empty.
//!
//! A string without an ASCII letter (a glyph, a format-only entry such as
//! `· {}`) carries no prose: the wording rules skip it while the structural
//! rules still apply.
//!
//! Advisory rules never fail the test. Their findings collect into one
//! summary printed after the run: passive voice, compound tenses, action
//! nouns, noun clusters of four or more words, possessive `'s` on a noun
//! ("Xray's core" — prefer "the X of Y"), and the synonyms the terminology
//! table of the `i18n` module rules out (`AVOIDED_TERMS`).
//!
//! `EXCEPTIONS` lists the strings that knowingly keep a violation: the key,
//! the rule id, and the reason the rule does not apply. A row with an empty
//! reason, or with a rule id that is not declared below, fails the test.

use broccoli::i18n::{ALL, Key, t};
use broccoli::model::settings::Language;

/// Sentence word cap for a sentence that does not start with an imperative
/// verb.
const SENTENCE_WORD_CAP: usize = 25;

/// Sentence word cap for an instruction: a sentence whose first word is an
/// imperative verb.
const INSTRUCTION_WORD_CAP: usize = 20;

/// Nouns in a row that trigger the cluster advisory; the standard allows
/// three ("server certificate pin").
const NOUN_CLUSTER_LIMIT: usize = 3;

/// Words that may separate the two parts of a passive or compound pattern
/// ("has not been", "is already loaded").
const GAP_LIMIT: usize = 2;

/// Rule id: a sentence longer than its word cap.
const RULE_SENTENCE_LENGTH: &str = "sentence-length";
/// Rule id: an instruction longer than its word cap.
const RULE_INSTRUCTION_LENGTH: &str = "instruction-length";
/// Rule id: a semicolon.
const RULE_SEMICOLON: &str = "semicolon";
/// Rule id: a contraction.
const RULE_CONTRACTION: &str = "contraction";
/// Rule id: a banned marketing adjective or two-word verb.
const RULE_BANNED_TERM: &str = "banned-term";
/// Rule id: a placeholder or whitespace defect.
const RULE_PLACEHOLDER: &str = "placeholder";
/// Rule id: advisory passive voice.
const RULE_PASSIVE: &str = "passive-voice";
/// Rule id: advisory compound tense.
const RULE_COMPOUND_TENSE: &str = "compound-tense";
/// Rule id: advisory action noun after "perform", "provide", and friends.
const RULE_NOMINALIZATION: &str = "nominalization";
/// Rule id: advisory noun cluster of four or more words.
const RULE_NOUN_CLUSTER: &str = "noun-cluster";
/// Rule id: advisory synonym the terminology table rules out.
const RULE_AVOIDED_TERM: &str = "avoided-term";
/// Rule id: advisory possessive `'s` on a noun.
const RULE_POSSESSIVE: &str = "possessive";

/// Every rule id, so an exception row that misspells one cannot silently
/// exempt nothing.
const RULE_IDS: &[&str] = &[
    RULE_SENTENCE_LENGTH,
    RULE_INSTRUCTION_LENGTH,
    RULE_SEMICOLON,
    RULE_CONTRACTION,
    RULE_BANNED_TERM,
    RULE_PLACEHOLDER,
    RULE_PASSIVE,
    RULE_COMPOUND_TENSE,
    RULE_NOMINALIZATION,
    RULE_NOUN_CLUSTER,
    RULE_AVOIDED_TERM,
    RULE_POSSESSIVE,
];

/// A sentence that starts with one of these verbs is an instruction.
const IMPERATIVE_VERBS: &[&str] = &[
    "add",
    "apply",
    "cancel",
    "check",
    "choose",
    "clear",
    "close",
    "confirm",
    "connect",
    "continue",
    "copy",
    "delete",
    "disable",
    "discard",
    "disconnect",
    "download",
    "drag",
    "edit",
    "enable",
    "enter",
    "export",
    "import",
    "install",
    "keep",
    "load",
    "move",
    "open",
    "pick",
    "remove",
    "rename",
    "reset",
    "retry",
    "run",
    "save",
    "select",
    "set",
    "show",
    "start",
    "stop",
    "test",
    "update",
    "use",
    "verify",
    "wait",
];

/// Marketing adjectives and soft two-word verbs the standard bans.
const BANNED_TERMS: &[&str] = &[
    "seamless",
    "robust",
    "powerful",
    "blazing",
    "effortless",
    "cutting-edge",
    "state-of-the-art",
    "best-in-class",
    "world-class",
    "revolutionary",
    "stunning",
    "spin up",
    "kick off",
    "reach out",
    "dive into",
    "fire up",
];

/// Synonyms the terminology table rules out. The table also lists `node`,
/// `profile`, `config`, `start`, `stop`, `commit`, and `revert`; the lint
/// leaves those alone because each is a correct word in another sense inside
/// this table ("config file", "start the core", "cannot be committed"), so
/// flagging them would report strings the standard accepts.
const AVOIDED_TERMS: &[&str] = &[
    "xray process",
    "daemon",
    "deploy",
    "turn on",
    "tunnel mode",
    "proxy mode",
    "default server",
    "main server",
    "probe test",
];

/// Suffixes that mark a verb contraction (`we're`, `we've`, `they'll`).
const CONTRACTION_SUFFIXES: &[&str] = &["'re", "'ve", "'ll", "'d", "'m"];

/// The `'s` forms that are contractions; every other `'s` is possessive.
const CONTRACTION_S_WORDS: &[&str] = &[
    "here's", "it's", "let's", "that's", "there's", "what's", "who's",
];

/// Words that never join a noun cluster: function words, pronouns, numbers,
/// and the common modifiers that break a run of nouns.
const FUNCTION_WORDS: &[&str] = &[
    "a", "an", "the", "of", "to", "in", "on", "at", "by", "for", "with", "from", "into", "onto",
    "over", "under", "above", "below", "and", "or", "but", "if", "when", "while", "that", "this",
    "these", "those", "it", "its", "you", "your", "we", "our", "us", "they", "their", "them", "he",
    "she", "his", "her", "i", "me", "my", "as", "than", "so", "then", "such", "not", "no", "none",
    "never", "only", "also", "very", "more", "most", "less", "least", "all", "any", "each",
    "every", "some", "both", "up", "out", "off", "down", "away", "back", "again", "about", "after",
    "before", "between", "during", "without", "within", "via", "per", "is", "are", "was", "were",
    "be", "been", "being", "am", "have", "has", "had", "do", "does", "did", "can", "cannot",
    "could", "will", "would", "shall", "should", "may", "might", "must", "new", "old", "current",
    "active", "next", "last", "first", "second", "third", "one", "two", "three", "four", "five",
    "six", "seven", "eight", "nine", "ten",
];

/// Forms of `be` that introduce a passive construction.
const BE_FORMS: &[&str] = &["is", "are", "was", "were", "be", "been", "being", "am"];

/// Adverbs that may sit inside a passive or compound pattern.
const INTERVENING_ADVERBS: &[&str] = &[
    "again",
    "already",
    "also",
    "always",
    "automatically",
    "correctly",
    "directly",
    "exactly",
    "fully",
    "immediately",
    "never",
    "not",
    "now",
    "often",
    "only",
    "silently",
    "sometimes",
    "still",
    "temporarily",
    "then",
    "usually",
];

/// Past participles that do not end in `-ed`.
const IRREGULAR_PARTICIPLES: &[&str] = &[
    "arisen",
    "become",
    "been",
    "begun",
    "bought",
    "broken",
    "brought",
    "built",
    "caught",
    "chosen",
    "come",
    "cost",
    "cut",
    "dealt",
    "done",
    "drawn",
    "driven",
    "felt",
    "flown",
    "forgotten",
    "found",
    "frozen",
    "given",
    "gotten",
    "grown",
    "heard",
    "held",
    "hidden",
    "hit",
    "hurt",
    "kept",
    "known",
    "laid",
    "led",
    "left",
    "lost",
    "made",
    "meant",
    "met",
    "paid",
    "put",
    "read",
    "risen",
    "run",
    "said",
    "seen",
    "sent",
    "set",
    "shaken",
    "shown",
    "sold",
    "spent",
    "split",
    "spread",
    "struck",
    "stuck",
    "taken",
    "thrown",
    "told",
    "understood",
    "worn",
    "won",
    "written",
];

/// Words that end in `-ed` without being past participles.
const NON_PARTICIPLE_ED: &[&str] = &[
    "breed", "feed", "hundred", "indeed", "need", "seed", "shed", "speed", "weed",
];

/// Verbs that hide an action behind a noun ("perform an evaluation").
const NOMINALIZING_VERBS: &[&str] = &[
    "carried",
    "carries",
    "carry",
    "carrying",
    "made",
    "make",
    "makes",
    "making",
    "perform",
    "performed",
    "performing",
    "performs",
    "provide",
    "provided",
    "provides",
    "providing",
];

/// The members of [`NOMINALIZING_VERBS`] that need `out` to form the verb.
const PHRASAL_NOMINALIZING_VERBS: &[&str] = &["carried", "carries", "carry", "carrying"];

/// Noun endings that mark an action noun.
const NOMINALIZATION_ENDINGS: &[&str] = &["tion", "ment", "ance", "ence"];

/// Strings that knowingly keep a rule violation: the key, the rule id, and
/// the reason. An empty reason fails the test.
const EXCEPTIONS: &[(Key, &str, &str)] = &[];

/// One finding: the rule that fired and the text that explains it.
struct Finding {
    rule: &'static str,
    detail: String,
}

impl Finding {
    fn new(rule: &'static str, detail: impl Into<String>) -> Self {
        Self {
            rule,
            detail: detail.into(),
        }
    }
}

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
        for finding in hard_findings(text) {
            if is_exempt(key, finding.rule) {
                continue;
            }
            violations.push(format!(
                "{key:?} [{}] {text:?}: {}",
                finding.rule, finding.detail
            ));
        }
        for finding in advisory_findings(text) {
            if is_exempt(key, finding.rule) {
                continue;
            }
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

/// Hard-rule findings for one string.
fn hard_findings(text: &str) -> Vec<Finding> {
    let mut findings = structural_findings(text);
    if !has_ascii_letter(text) {
        return findings;
    }
    findings.extend(length_findings(text));
    findings.extend(term_findings(
        text,
        BANNED_TERMS,
        RULE_BANNED_TERM,
        "banned term",
    ));
    if text.contains(';') {
        findings.push(Finding::new(RULE_SEMICOLON, "write two sentences"));
    }
    if let Some(token) = contraction(text) {
        findings.push(Finding::new(RULE_CONTRACTION, token));
    }
    findings
}

/// Advisory findings for one string; none of them fail the test.
fn advisory_findings(text: &str) -> Vec<Finding> {
    if !has_ascii_letter(text) {
        return Vec::new();
    }
    let mut findings = term_findings(text, AVOIDED_TERMS, RULE_AVOIDED_TERM, "avoided term");
    for sentence in sentences(text) {
        let words = tokens(sentence);
        findings.extend(compound_tense_findings(&words));
        findings.extend(passive_findings(&words));
        findings.extend(nominalization_findings(&words));
        findings.extend(noun_cluster_findings(&words));
    }
    if let Some(token) = possessive(text) {
        findings.push(Finding::new(
            RULE_POSSESSIVE,
            format!("{token} (prefer the X of Y form)"),
        ));
    }
    findings
}

/// Emptiness, whitespace padding, and brace defects.
fn structural_findings(text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    if text.is_empty() {
        findings.push(Finding::new(RULE_PLACEHOLDER, "string is empty"));
        return findings;
    }
    if text.trim() != text {
        findings.push(Finding::new(
            RULE_PLACEHOLDER,
            "leading or trailing whitespace",
        ));
    }
    for error in brace_errors(text) {
        findings.push(Finding::new(RULE_PLACEHOLDER, error));
    }
    findings
}

/// Every `{` closes, every `}` opens, and the `{{`/`}}` escapes that the
/// substitution helpers do not support are absent.
fn brace_errors(text: &str) -> Vec<String> {
    let mut errors = Vec::new();
    if text.contains("{{") {
        errors.push("'{{' is not a supported escape".to_string());
    }
    if text.contains("}}") {
        errors.push("'}}' is not a supported escape".to_string());
    }
    let mut open = 0i32;
    for c in text.chars() {
        match c {
            '{' => open += 1,
            '}' => {
                open -= 1;
                if open < 0 {
                    errors.push("'}' without a matching '{'".to_string());
                    return errors;
                }
            }
            _ => {}
        }
    }
    if open > 0 {
        errors.push(format!("{open} '{{' without a matching '}}'"));
    }
    errors
}

/// Sentences longer than their word cap.
fn length_findings(text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for sentence in sentences(text) {
        let count = sentence.split_whitespace().count();
        if starts_with_imperative(sentence) {
            if count > INSTRUCTION_WORD_CAP {
                findings.push(Finding::new(
                    RULE_INSTRUCTION_LENGTH,
                    format!("{count} words in {sentence:?}"),
                ));
            }
        } else if count > SENTENCE_WORD_CAP {
            findings.push(Finding::new(
                RULE_SENTENCE_LENGTH,
                format!("{count} words in {sentence:?}"),
            ));
        }
    }
    findings
}

/// Splits on sentence-ending punctuation; an ellipsis is not a terminator.
fn sentences(text: &str) -> impl Iterator<Item = &str> {
    text.split(['.', '!', '?'])
        .map(str::trim)
        .filter(|sentence| !sentence.is_empty())
}

/// Whether the first word of the sentence, lowercased and stripped of
/// punctuation, is an imperative verb.
fn starts_with_imperative(sentence: &str) -> bool {
    let Some(first) = sentence.split_whitespace().next() else {
        return false;
    };
    let word = first.trim_matches(|c: char| !c.is_alphabetic());
    IMPERATIVE_VERBS
        .iter()
        .any(|verb| word.eq_ignore_ascii_case(verb))
}

/// Strings without a letter are glyphs and formats, not prose.
fn has_ascii_letter(text: &str) -> bool {
    text.chars().any(|c| c.is_ascii_alphabetic())
}

/// Words written with an apostrophe: lowercased, surrounding punctuation
/// removed, and right single quotes normalized to `'`.
fn apostrophe_words(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|token| {
            token
                .trim_matches(|c: char| !c.is_alphanumeric() && c != '\'' && c != '\u{2019}')
                .to_lowercase()
                .replace('\u{2019}', "'")
        })
        .collect()
}

/// The first contraction in the string: the `n't` family, a verb suffix
/// (`'re`, `'ve`, `'ll`, `'d`, `'m`), or a fixed `'s` form. A possessive `'s`
/// on a noun is not a contraction (see [`possessive`]).
fn contraction(text: &str) -> Option<String> {
    apostrophe_words(text)
        .into_iter()
        .find(|word| is_contraction(word))
}

/// Whether the word is a contraction and therefore not a possessive.
fn is_contraction(word: &str) -> bool {
    word.contains("n't")
        || CONTRACTION_SUFFIXES
            .iter()
            .any(|suffix| word.ends_with(suffix))
        || CONTRACTION_S_WORDS.contains(&word)
}

/// The first possessive `'s` on a noun ("Xray's core"): advisory only, the
/// reworded "the X of Y" form reads better.
fn possessive(text: &str) -> Option<String> {
    apostrophe_words(text)
        .into_iter()
        .find(|word| word.ends_with("'s") && !CONTRACTION_S_WORDS.contains(&word.as_str()))
}

/// Lowercase word tokens: maximal runs of alphanumeric characters. Every
/// other character splits, so "cutting-edge" and "cutting edge" tokenize the
/// same way.
fn tokens(text: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    for c in text.chars() {
        if c.is_alphanumeric() {
            current.extend(c.to_lowercase());
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// One finding per listed term the text uses.
fn term_findings(text: &str, terms: &[&str], rule: &'static str, label: &str) -> Vec<Finding> {
    let words = tokens(text);
    let mut findings = Vec::new();
    for term in terms {
        if contains_term(&words, term) {
            findings.push(Finding::new(rule, format!("{label} {term:?}")));
        }
    }
    findings
}

/// A multi-word term matches a contiguous token run; a one-word term also
/// matches its plural.
fn contains_term(words: &[String], term: &str) -> bool {
    let parts = tokens(term);
    if parts.is_empty() {
        return false;
    }
    if parts.len() > 1 {
        return words.windows(parts.len()).any(|run| run == parts);
    }
    words
        .iter()
        .any(|word| word == &parts[0] || is_plural_of(word, &parts[0]))
}

/// Whether `word` is `term` with a trailing `s`.
fn is_plural_of(word: &str, term: &str) -> bool {
    word.strip_suffix('s') == Some(term)
}

/// `has/have/had been`, `is/are/was/were being`, `will have`, and the perfect
/// forms with any other participle ("we have received").
fn compound_tense_findings(words: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, word) in words.iter().enumerate() {
        let tail = match word.as_str() {
            "has" | "have" | "had" => word_after_gap(words, index, is_past_participle),
            "is" | "are" | "was" | "were" => word_after_gap(words, index, |next| next == "being"),
            "will" => word_after_gap(words, index, |next| next == "have"),
            _ => None,
        };
        if let Some(tail) = tail {
            findings.push(Finding::new(
                RULE_COMPOUND_TENSE,
                format!("{word} ... {tail}"),
            ));
        }
    }
    findings
}

/// `be` plus a past participle ("the file was written").
fn passive_findings(words: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, word) in words.iter().enumerate() {
        if !BE_FORMS.contains(&word.as_str()) {
            continue;
        }
        if let Some(participle) = word_after_gap(words, index, is_past_participle) {
            findings.push(Finding::new(
                RULE_PASSIVE,
                format!("{word} ... {participle}"),
            ));
        }
    }
    findings
}

/// Whether the token reads as a past participle.
fn is_past_participle(word: &str) -> bool {
    IRREGULAR_PARTICIPLES.contains(&word)
        || (word.len() >= 4 && word.ends_with("ed") && !NON_PARTICIPLE_ED.contains(&word))
}

/// The first word one or two positions after `index` that `wanted` accepts,
/// provided only tolerated adverbs sit in between ("has not been").
fn word_after_gap(words: &[String], index: usize, wanted: impl Fn(&str) -> bool) -> Option<&str> {
    (1..=GAP_LIMIT).find_map(|distance| {
        let target = words.get(index + distance)?;
        if !wanted(target) {
            return None;
        }
        let gap = words.get(index + 1..index + distance)?;
        gap.iter()
            .all(|word| INTERVENING_ADVERBS.contains(&word.as_str()))
            .then_some(target.as_str())
    })
}

/// `perform`, `provide`, `carry out`, or `make` with an action noun.
fn nominalization_findings(words: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, word) in words.iter().enumerate() {
        if !NOMINALIZING_VERBS.contains(&word.as_str()) {
            continue;
        }
        let mut cursor = index + 1;
        if PHRASAL_NOMINALIZING_VERBS.contains(&word.as_str()) {
            if words.get(cursor).map(String::as_str) != Some("out") {
                continue;
            }
            cursor += 1;
        }
        if matches!(
            words.get(cursor).map(String::as_str),
            Some("a" | "an" | "the")
        ) {
            cursor += 1;
        }
        let Some(noun) = words.get(cursor) else {
            continue;
        };
        if let Some(ending) = NOMINALIZATION_ENDINGS
            .iter()
            .find(|ending| noun.ends_with(**ending))
        {
            findings.push(Finding::new(
                RULE_NOMINALIZATION,
                format!("{word} ... {noun} ({ending})"),
            ));
        }
    }
    findings
}

/// Four or more noun-like words in a row ("server certificate pin store").
fn noun_cluster_findings(words: &[String]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut run: Vec<&str> = Vec::new();
    for index in 0..=words.len() {
        let noun_like = words
            .get(index)
            .is_some_and(|word| index > 0 && is_noun_like(word));
        if noun_like {
            run.push(words[index].as_str());
            continue;
        }
        if run.len() > NOUN_CLUSTER_LIMIT {
            findings.push(Finding::new(
                RULE_NOUN_CLUSTER,
                format!("noun cluster: {}", run.join(" ")),
            ));
        }
        run.clear();
    }
    findings
}

/// Whether the token reads as a noun. The first word of a sentence is never
/// one: it may be a verb this lint does not list.
fn is_noun_like(word: &str) -> bool {
    word.len() > 1
        && word.chars().all(|c| c.is_ascii_alphabetic())
        && !FUNCTION_WORDS.contains(&word)
        && !IMPERATIVE_VERBS.contains(&word)
}

/// Whether an exception row covers this key and rule.
fn exempt(rows: &[(Key, &str, &str)], key: Key, rule: &str) -> bool {
    rows.iter()
        .any(|&(row_key, row_rule, _)| row_key == key && row_rule == rule)
}

/// Whether [`EXCEPTIONS`] covers this key and rule.
fn is_exempt(key: Key, rule: &str) -> bool {
    exempt(EXCEPTIONS, key, rule)
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
