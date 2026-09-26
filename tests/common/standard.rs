//! Text-standard check: one string in, one finding per breach.
//!
//! The standard itself — the writing rules and the terminology table — is
//! documented in the *Text standard* section of `broccoli::i18n`, because the
//! text is what those rules are about. This module is the check that enforces
//! them, so the rules live with the table they govern instead of inside the
//! test that drives them. Nothing in the app calls it and only the test binary
//! that declares this module compiles it: the frame loop never runs a lint, so
//! the engine lives in the test tree rather than on a surface the shipped
//! library carries.
//!
//! Include it beside `common`, from the file that drives it:
//!
//! ```text
//! #[path = "common/standard.rs"]
//! mod standard;
//! ```
//!
//! # Hard rules
//!
//! A hard finding fails the corpus check:
//!
//! - A sentence holds at most [`SENTENCE_WORD_CAP`] words, or at most
//!   [`INSTRUCTION_WORD_CAP`] when its first word is an imperative verb
//!   (`IMPERATIVE_VERBS`). Sentences split on `.`, `!`, and `?`; an ellipsis
//!   is not a terminator.
//! - No semicolons and no contractions: the `n't` family, `'re`, `'ve`,
//!   `'ll`, `'d`, `'m`, and the fixed `'s` forms `it's`, `that's`, `there's`,
//!   `here's`, `what's`, `who's`, `let's`.
//! - No marketing adjectives and no soft two-word verbs (`BANNED_TERMS`).
//! - Placeholder integrity: balanced braces, no `{{`/`}}` escapes, no leading
//!   or trailing whitespace, never empty.
//! - Placeholder arity: the number of `{` in the English text equals the count
//!   the key declares in `keys!` ([`Key::arity`]), which every fill site is
//!   written against. A wording change that adds or drops a placeholder fails
//!   here even for a key no other check exercises. No key departs from its
//!   declared count; an [`EXCEPTIONS`] row records the reason if one ever must.
//!
//! A string without an ASCII letter (a glyph, a format-only entry such as
//! `· {}`) carries no prose: the wording rules skip it while the structural
//! rules still apply.
//!
//! # Advisory rules
//!
//! An advisory finding never fails the check; the corpus check prints them and
//! exits clean. They report passive voice, compound tenses, action nouns, noun
//! clusters of four or more words, a possessive `'s` on a noun ("Xray's core" —
//! prefer "the X of Y"), and the synonyms the terminology table rules out
//! (`AVOIDED_TERMS`).
//!
//! # Exceptions
//!
//! [`EXCEPTIONS`] lists the strings that knowingly keep a violation: the key,
//! the rule id, and the reason the rule does not apply. A row with an empty
//! reason, or with a rule id that is not in [`RULE_IDS`], is a defect in the
//! table itself and fails the corpus check. [`key_findings`] applies the rows,
//! so a caller reads one verdict per key.

use broccoli::i18n::{Key, t};
use broccoli::model::settings::Language;

/// Sentence word cap for a sentence that does not start with an imperative
/// verb.
pub const SENTENCE_WORD_CAP: usize = 25;

/// Sentence word cap for an instruction: a sentence whose first word is an
/// imperative verb.
pub const INSTRUCTION_WORD_CAP: usize = 20;

/// Nouns in a row that trigger the cluster advisory; the standard allows
/// three ("server certificate pin").
const NOUN_CLUSTER_LIMIT: usize = 3;

/// Words that may separate the two parts of a passive or compound pattern
/// ("has not been", "is already loaded").
const GAP_LIMIT: usize = 2;

/// Rule id: a sentence longer than its word cap.
pub const RULE_SENTENCE_LENGTH: &str = "sentence-length";
/// Rule id: an instruction longer than its word cap.
pub const RULE_INSTRUCTION_LENGTH: &str = "instruction-length";
/// Rule id: a semicolon.
pub const RULE_SEMICOLON: &str = "semicolon";
/// Rule id: a contraction.
pub const RULE_CONTRACTION: &str = "contraction";
/// Rule id: a banned marketing adjective or two-word verb.
pub const RULE_BANNED_TERM: &str = "banned-term";
/// Rule id: a placeholder or whitespace defect.
pub const RULE_PLACEHOLDER: &str = "placeholder";
/// Rule id: the English text's `{` count differs from the declared arity.
pub const RULE_ARITY: &str = "placeholder-arity";
/// Rule id: advisory passive voice.
pub const RULE_PASSIVE: &str = "passive-voice";
/// Rule id: advisory compound tense.
pub const RULE_COMPOUND_TENSE: &str = "compound-tense";
/// Rule id: advisory action noun after "perform", "provide", and friends.
pub const RULE_NOMINALIZATION: &str = "nominalization";
/// Rule id: advisory noun cluster of four or more words.
pub const RULE_NOUN_CLUSTER: &str = "noun-cluster";
/// Rule id: advisory synonym the terminology table rules out.
pub const RULE_AVOIDED_TERM: &str = "avoided-term";
/// Rule id: advisory possessive `'s` on a noun.
pub const RULE_POSSESSIVE: &str = "possessive";

/// Every rule id, so an exception row that misspells one cannot silently
/// exempt nothing.
pub const RULE_IDS: &[&str] = &[
    RULE_SENTENCE_LENGTH,
    RULE_INSTRUCTION_LENGTH,
    RULE_SEMICOLON,
    RULE_CONTRACTION,
    RULE_BANNED_TERM,
    RULE_PLACEHOLDER,
    RULE_ARITY,
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
/// the reason the rule does not apply. An empty reason, or a rule id that is
/// not in [`RULE_IDS`], is a defect in this table and fails the corpus check.
pub const EXCEPTIONS: &[(Key, &str, &str)] = &[];

/// One finding: the rule that fired and the text that explains it.
pub struct Finding {
    /// The rule id, one of [`RULE_IDS`].
    pub rule: &'static str,
    /// What the rule saw: the sentence and its word count, the offending
    /// token, or the defect in the string.
    pub detail: String,
}

impl Finding {
    fn new(rule: &'static str, detail: impl Into<String>) -> Self {
        Self {
            rule,
            detail: detail.into(),
        }
    }
}

/// Hard-rule findings for one string. The wording rules and the structural
/// rules need no key; the placeholder-arity rule is [`arity_findings`], and
/// [`key_findings`] runs both over one catalogue entry.
pub fn hard_findings(text: &str) -> Vec<Finding> {
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

/// Advisory findings for one string; none of them fail the corpus check.
pub fn advisory_findings(text: &str) -> Vec<Finding> {
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

/// Findings for one catalogue key, with the exception rows applied.
pub struct KeyFindings {
    /// Violations of the hard rules: a non-empty list fails the corpus check.
    pub hard: Vec<Finding>,
    /// Findings of the advisory rules: they never fail the check.
    pub advisory: Vec<Finding>,
}

/// Check one catalogue key against the standard: read its English text, run
/// the hard rules and the placeholder-arity check, run the advisory rules, and
/// drop the findings an [`EXCEPTIONS`] row covers.
///
/// The catalogue read happens here, so no caller can check a key against text
/// that is not the key's own, and a caller cannot forget the arity check or
/// the exemption rows. A translation is checked the same way: swap the locale
/// in the read below.
pub fn key_findings(key: Key) -> KeyFindings {
    let text = t(Language::En, key);
    KeyFindings {
        hard: hard_findings(text)
            .into_iter()
            .chain(arity_findings(key, text))
            .filter(|finding| !is_exempt(key, finding.rule))
            .collect(),
        advisory: advisory_findings(text)
            .into_iter()
            .filter(|finding| !is_exempt(key, finding.rule))
            .collect(),
    }
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

/// The declared placeholder count and the `{` count of the English text must
/// agree.
pub fn arity_findings(key: Key, text: &str) -> Vec<Finding> {
    let declared = key.arity();
    let actual = text.matches('{').count();
    if declared == actual {
        return Vec::new();
    }
    vec![Finding::new(
        RULE_ARITY,
        format!("declares {declared} placeholder(s), the text holds {actual}"),
    )]
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

/// Whether an exception row covers this key and rule. A row exempts one key
/// and one rule, never the key alone, so a second breach on the same key still
/// reports. [`EXCEPTIONS`] holds the corpus rows; taking the rows as an
/// argument lets a caller with its own table ask the same question.
pub fn exempt(rows: &[(Key, &str, &str)], key: Key, rule: &str) -> bool {
    rows.iter()
        .any(|&(row_key, row_rule, _)| row_key == key && row_rule == rule)
}

/// Whether [`EXCEPTIONS`] covers this key and rule.
fn is_exempt(key: Key, rule: &str) -> bool {
    exempt(EXCEPTIONS, key, rule)
}
