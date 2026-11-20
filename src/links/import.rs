//! One import batch: a decoded body in, one record per source item out.
//!
//! A subscription body may be a plain link list, one Base64 blob around it,
//! or a document shape a converter claims. Every source item — an accepted
//! link, a refused entry, a document section the converter skipped, one
//! compatibility parameter it dropped — becomes one [`ImportRecord`] carrying
//! its kind, the keyed reason (never a rendered sentence), the bounded raw
//! source text, and its ordinal in the decoded body.
//!
//! The batch is the only place that counts, bounds rows, and renders the
//! preview. The refresh report, the import report, the raw viewer and the
//! report window are projections of the same records, so their counts cannot
//! disagree.

use super::body::{CompatibilityParameter, MAX_RAW_CHARS, decode_whole_body, leading_comments};
use super::{LinkError, ParsedLink, parse_link};
use crate::diag::{Diag, DiagArg};
use crate::i18n::{Key, t_fmt, validation_reason_parts};
use crate::model::ServerProfile;
use crate::model::servers::{RefreshReport, ReportArg, ReportKind, ReportReason, ReportRow};
use crate::model::settings::Language;
use crate::model::validation::ValidationIssue;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

/// What one record is: the four outcomes the import walk can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportKind {
    /// A profile the batch accepts, with every compatibility parameter it
    /// dropped recorded beside it.
    Accepted,
    /// A source item that names no importable profile.
    Refused,
    /// A document section the converter skipped.
    IgnoredSection,
    /// One compatibility parameter an accepted entry dropped.
    IgnoredParameter,
}

/// Why an item was refused. Every variant is keyed, so a persisted report
/// renders in the active language instead of freezing the parser's English.
#[derive(Clone, Debug)]
pub enum ImportReason {
    /// A share-link grammar or model failure: the keyed `LinkError`. A model
    /// finding travels as [`LinkError::InvalidModel`], which keeps its
    /// `ValidationIssue` keyed.
    Link(Box<LinkError>),
    /// The core's own `xray run -test` output. External text, passed through
    /// verbatim under a keyed report sentence.
    Core(String),
}

impl ImportReason {
    /// A grammar or model refusal.
    pub fn link(error: LinkError) -> Self {
        Self::Link(Box::new(error))
    }

    /// Render the reason in `language`.
    pub fn text(&self, language: Language) -> String {
        match self {
            Self::Link(error) => error.text(language),
            Self::Core(output) => output.clone(),
        }
    }

    /// The reason's persisted shape. Placeholder values that name another
    /// rule's sentence render in `language`; the reason's own template
    /// renders in whichever language is active when the report opens.
    pub fn report_reason(&self, language: Language) -> ReportReason {
        match self {
            Self::Link(error) => match error.as_ref() {
                LinkError::InvalidModel { prefix, issue } => {
                    let reason = issue_reason(issue, language);
                    match prefix {
                        Some(prefix) => ReportReason::keyed(*prefix).arg_message(reason),
                        None => reason,
                    }
                }
                LinkError::Unsupported(diag)
                | LinkError::Malformed(diag)
                | LinkError::Lossy(diag) => diag_reason(diag),
            },
            Self::Core(output) => ReportReason::keyed(Key::SrvReportCoreRejected).arg(output),
        }
    }
}

/// One keyed message, with its nested messages kept nested.
fn diag_reason(diag: &Diag) -> ReportReason {
    let mut reason = ReportReason {
        key: diag.key().name().to_owned(),
        args: Vec::new(),
        path: None,
    };
    for arg in diag.args() {
        reason.args.push(match arg {
            DiagArg::Text(text) => ReportArg::Text(text.clone()),
            DiagArg::Message(message) => ReportArg::Message(Box::new(diag_reason(message))),
        });
    }
    reason
}

/// A model finding as a keyed reason: the rule's key, its placeholder
/// values, and the field path the finding names.
fn issue_reason(issue: &ValidationIssue, language: Language) -> ReportReason {
    let (key, args) = validation_reason_parts(&issue.code, language);
    let mut reason = ReportReason {
        key: key.name().to_owned(),
        args: args.into_iter().map(ReportArg::Text).collect(),
        path: None,
    };
    if let Some(path) = issue.path.clone().filter(|path| !path.is_empty()) {
        reason.path = Some(path);
    }
    reason
}

/// What one record carries.
#[derive(Clone, Debug)]
enum ImportItem {
    Accepted(Box<ServerProfile>),
    Refused {
        /// The entry's own name, when the parser knows one.
        label: String,
        reason: ImportReason,
    },
    IgnoredSection {
        name: String,
    },
    IgnoredParameter {
        /// The report heading: the owner's name plus `parameter=value`, or
        /// just the pair when the owner has no name.
        name: String,
        parameter: CompatibilityParameter,
    },
}

/// One source item of the decoded body.
#[derive(Clone, Debug)]
pub struct ImportRecord {
    ordinal: usize,
    raw: String,
    item: ImportItem,
}

impl ImportRecord {
    /// The item's 0-based ordinal in the decoded body. Ignored parameters
    /// carry the ordinal of the entry they came from; a verdict the profile
    /// validation step returned carries the ordinal after the body walk.
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }

    /// The bounded source text the item came from.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// What the record is.
    pub fn kind(&self) -> ImportKind {
        match &self.item {
            ImportItem::Accepted(_) => ImportKind::Accepted,
            ImportItem::Refused { .. } => ImportKind::Refused,
            ImportItem::IgnoredSection { .. } => ImportKind::IgnoredSection,
            ImportItem::IgnoredParameter { .. } => ImportKind::IgnoredParameter,
        }
    }

    /// The accepted profile.
    pub fn profile(&self) -> Option<&ServerProfile> {
        match &self.item {
            ImportItem::Accepted(profile) => Some(profile),
            _ => None,
        }
    }

    /// The keyed reason of a refused record.
    pub fn reason(&self) -> Option<&ImportReason> {
        match &self.item {
            ImportItem::Refused { reason, .. } => Some(reason),
            _ => None,
        }
    }

    /// The dropped compatibility parameter of an ignored-parameter record.
    pub fn parameter(&self) -> Option<&CompatibilityParameter> {
        match &self.item {
            ImportItem::IgnoredParameter { parameter, .. } => Some(parameter),
            _ => None,
        }
    }
}

/// One accepted entry as the reconciliation reads it: the profile, its
/// bounded source text, and the compatibility parameters its grammar
/// dropped.
#[derive(Clone, Debug)]
pub struct AcceptedEntry<'a> {
    pub profile: &'a ServerProfile,
    pub raw: &'a str,
    /// The compatibility parameters this entry's grammar dropped, in link
    /// order.
    pub ignored: Vec<&'a CompatibilityParameter>,
}

/// How one preview row reads: a clean link, a link whose compatibility
/// parameters were dropped, or a refused item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreviewKind {
    Ok,
    Warn,
    Err,
}

/// One formatted preview row.
#[derive(Clone, Debug)]
pub struct PreviewRow {
    pub text: String,
    pub kind: PreviewKind,
}

/// The import dialog's preview, rendered once per language.
#[derive(Clone, Debug)]
pub struct Preview {
    pub language: Language,
    /// How many entries parsed into a profile: the caption and the
    /// "validate and add" gate read it.
    pub ok: usize,
    pub rows: Vec<PreviewRow>,
}

/// One row of the raw viewer's parsed pane, projected from the records.
#[derive(Clone, Debug)]
pub enum BatchRow<'a> {
    Accepted { name: &'a str, raw: &'a str },
    Refused { reason: String, raw: &'a str },
    Ignored { name: &'a str, raw: &'a str },
}

/// A decoded body's whole outcome.
#[derive(Clone, Debug, Default)]
pub struct ImportBatch {
    records: Vec<ImportRecord>,
    comments: BTreeMap<String, String>,
    next_ordinal: usize,
}

impl ImportBatch {
    /// An empty batch carrying the body's leading metadata comments.
    pub fn with_comments(comments: BTreeMap<String, String>) -> Self {
        Self {
            comments,
            ..Self::default()
        }
    }

    /// The body's leading `#`/`//` `key: value` comments, the metadata
    /// fallback when the provider sends no headers.
    pub fn comments(&self) -> &BTreeMap<String, String> {
        &self.comments
    }

    /// Every record, in body order.
    pub fn records(&self) -> &[ImportRecord] {
        &self.records
    }

    /// The next body ordinal; the parser allocates one per source item.
    pub(crate) fn begin_item(&mut self) -> usize {
        let ordinal = self.next_ordinal;
        self.next_ordinal += 1;
        ordinal
    }

    /// Record one accepted entry and one record per compatibility parameter
    /// it dropped, all at the entry's ordinal.
    pub(crate) fn push_accepted(
        &mut self,
        ordinal: usize,
        profile: ServerProfile,
        raw: String,
        ignored: Vec<CompatibilityParameter>,
    ) {
        let owner = profile.name.clone();
        for parameter in ignored {
            let key = parameter.key();
            let name = if owner.is_empty() {
                key
            } else {
                format!("{owner}: {key}")
            };
            self.records.push(ImportRecord {
                ordinal,
                raw: raw.clone(),
                item: ImportItem::IgnoredParameter { name, parameter },
            });
        }
        self.records.push(ImportRecord {
            ordinal,
            raw,
            item: ImportItem::Accepted(Box::new(profile)),
        });
    }

    /// Record one refused item.
    pub(crate) fn push_refused(
        &mut self,
        ordinal: usize,
        label: impl Into<String>,
        reason: ImportReason,
        raw: String,
    ) {
        self.records.push(ImportRecord {
            ordinal,
            raw,
            item: ImportItem::Refused {
                label: label.into(),
                reason,
            },
        });
    }

    /// Record one document section the converter skipped.
    pub(crate) fn push_ignored_section(&mut self, ordinal: usize, name: impl Into<String>) {
        self.records.push(ImportRecord {
            ordinal,
            raw: String::new(),
            item: ImportItem::IgnoredSection { name: name.into() },
        });
    }

    /// Record one profile the core's `xray run -test` refused. The output is
    /// external text; the report sentence around it stays keyed.
    pub fn reject_core(&mut self, label: impl Into<String>, output: impl Into<String>) {
        let ordinal = self.begin_item();
        self.push_refused(
            ordinal,
            label,
            ImportReason::Core(output.into()),
            String::new(),
        );
    }

    /// The accepted profiles with the bounded source text they came from and
    /// the compatibility parameters they dropped. The parameter records of an
    /// entry sit directly before it, at the same ordinal.
    pub fn entries(&self) -> Vec<AcceptedEntry<'_>> {
        let mut entries = Vec::new();
        for (index, record) in self.records.iter().enumerate() {
            let Some(profile) = record.profile() else {
                continue;
            };
            let mut ignored = Vec::new();
            for candidate in self.records[..index].iter().rev() {
                if candidate.ordinal != record.ordinal {
                    break;
                }
                if let Some(parameter) = candidate.parameter() {
                    ignored.push(parameter);
                }
            }
            ignored.reverse();
            entries.push(AcceptedEntry {
                profile,
                raw: record.raw(),
                ignored,
            });
        }
        entries
    }

    /// The refused records, in body order.
    pub fn refused(&self) -> impl Iterator<Item = &ImportRecord> {
        self.records
            .iter()
            .filter(|record| record.kind() == ImportKind::Refused)
    }

    /// The ignored records — sections and dropped parameters — in body order.
    pub fn ignored(&self) -> impl Iterator<Item = &ImportRecord> {
        self.records.iter().filter(|record| {
            matches!(
                record.kind(),
                ImportKind::IgnoredSection | ImportKind::IgnoredParameter
            )
        })
    }

    /// Whether the batch holds no accepted profile.
    pub fn is_empty(&self) -> bool {
        !self.records.iter().any(|record| record.profile().is_some())
    }

    pub fn accepted_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.kind() == ImportKind::Accepted)
            .count()
    }

    pub fn refused_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.kind() == ImportKind::Refused)
            .count()
    }

    pub fn ignored_count(&self) -> usize {
        self.records
            .iter()
            .filter(|record| {
                matches!(
                    record.kind(),
                    ImportKind::IgnoredSection | ImportKind::IgnoredParameter
                )
            })
            .count()
    }

    /// Render the import dialog's preview in `language`.
    pub fn preview(&self, language: Language) -> Preview {
        let mut ok = 0;
        let mut rows = Vec::new();
        for record in &self.records {
            match &record.item {
                ImportItem::Accepted(profile) => {
                    ok += 1;
                    let protocol = profile.outbound.protocol.as_str();
                    let ignored: Vec<String> = self
                        .records
                        .iter()
                        .filter(|candidate| candidate.ordinal == record.ordinal)
                        .filter_map(|candidate| candidate.parameter())
                        .map(CompatibilityParameter::key)
                        .collect();
                    if ignored.is_empty() {
                        rows.push(PreviewRow {
                            text: t_fmt(
                                language,
                                Key::SrvImportOkMark,
                                &[&profile.name, &protocol],
                            ),
                            kind: PreviewKind::Ok,
                        });
                    } else {
                        let ignored = ignored.join(", ");
                        rows.push(PreviewRow {
                            text: t_fmt(
                                language,
                                Key::SrvImportIgnoredMark,
                                &[&profile.name, &protocol, &ignored],
                            ),
                            kind: PreviewKind::Warn,
                        });
                    }
                }
                ImportItem::Refused { reason, .. } => rows.push(PreviewRow {
                    text: t_fmt(language, Key::SrvImportErrMark, &[&reason.text(language)]),
                    kind: PreviewKind::Err,
                }),
                ImportItem::IgnoredSection { .. } | ImportItem::IgnoredParameter { .. } => {}
            }
        }
        Preview { language, ok, rows }
    }

    /// Append this batch's refused and ignored counts and rows to `report`.
    /// The row bound lives on the report; the counts stay exact either way.
    pub fn extend_report(&self, report: &mut RefreshReport, language: Language) {
        report.refused += self.refused_count();
        report.ignored += self.ignored_count();
        for record in &self.records {
            match &record.item {
                ImportItem::Refused { label, reason } => report.push_row(ReportRow {
                    kind: ReportKind::Refused,
                    name: label.clone(),
                    key: String::new(),
                    raw: record.raw.clone(),
                    reason: Some(reason.report_reason(language)),
                }),
                ImportItem::IgnoredSection { name } => report.push_row(ReportRow {
                    kind: ReportKind::Ignored,
                    name: name.clone(),
                    key: String::new(),
                    raw: String::new(),
                    reason: None,
                }),
                ImportItem::IgnoredParameter { name, parameter } => {
                    report.push_row(ReportRow {
                        kind: ReportKind::Ignored,
                        name: name.clone(),
                        key: parameter.key(),
                        raw: parameter.raw.clone(),
                        reason: None,
                    });
                }
                ImportItem::Accepted(_) => {}
            }
        }
    }

    /// The report one manual import produces: one Added row per accepted
    /// profile, then this batch's refused and ignored counts and rows. The
    /// batch is the only counter, so a row and its count cannot disagree.
    pub fn import_report(&self, at: u64, added: &[String], language: Language) -> RefreshReport {
        let mut report = RefreshReport {
            at,
            added: added.len(),
            ..Default::default()
        };
        for name in added {
            report.push_row(ReportRow {
                kind: ReportKind::Added,
                name: name.clone(),
                key: String::new(),
                raw: String::new(),
                reason: None,
            });
        }
        self.extend_report(&mut report, language);
        report
    }

    /// The raw viewer's row count: one row per record.
    pub fn view_row_count(&self) -> usize {
        self.records.len()
    }

    /// The raw viewer's row at `index`, rendered in `language`.
    pub fn view_row(&self, index: usize, language: Language) -> Option<BatchRow<'_>> {
        let record = self.records.get(index)?;
        Some(match &record.item {
            ImportItem::Accepted(profile) => BatchRow::Accepted {
                name: &profile.name,
                raw: record.raw(),
            },
            ImportItem::Refused { reason, .. } => BatchRow::Refused {
                reason: reason.text(language),
                raw: record.raw(),
            },
            ImportItem::IgnoredSection { name } => BatchRow::Ignored { name, raw: "" },
            ImportItem::IgnoredParameter { name, parameter } => BatchRow::Ignored {
                name,
                raw: &parameter.raw,
            },
        })
    }

    /// The raw viewer's parsed pane as one copied block.
    pub fn view_text(&self, language: Language) -> String {
        let mut text = String::new();
        for index in 0..self.view_row_count() {
            let Some(row) = self.view_row(index, language) else {
                continue;
            };
            if !text.is_empty() {
                text.push('\n');
            }
            match row {
                BatchRow::Accepted { name, raw } => {
                    text.push_str(name);
                    if !raw.is_empty() {
                        text.push_str(": ");
                        text.push_str(raw);
                    }
                }
                BatchRow::Refused { reason, raw } => {
                    text.push_str(&reason);
                    if !raw.is_empty() {
                        text.push_str(": ");
                        text.push_str(raw);
                    }
                }
                BatchRow::Ignored { name, raw } => {
                    text.push_str(name);
                    if !raw.is_empty() {
                        text.push_str(": ");
                        text.push_str(raw);
                    }
                }
            }
        }
        text
    }
}

/// Parse one decoded body. The synchronous wrapper over
/// [`parse_body_cancellable`].
pub fn parse_body(text: &str) -> ImportBatch {
    parse_body_cancellable(text, &AtomicBool::new(false))
}

/// Parse one fetched or pasted body. A cancelled parse returns the records
/// collected so far; the caller drops them.
///
/// The body size is the caller's bound: the import dialog refuses a paste
/// over [`MAX_BULK_LEN`](super::MAX_BULK_LEN) before a worker starts, and a
/// fetched subscription is already bounded by the fetch's own body cap. A
/// cap here would refuse a body the fetch accepted.
pub fn parse_body_cancellable(text: &str, stop: &AtomicBool) -> ImportBatch {
    let decoded = decode_whole_body(text);
    let mut batch = ImportBatch::with_comments(leading_comments(&decoded));
    if super::convert::convert_document(&decoded, &mut batch) {
        return batch;
    }
    for line in decoded.lines() {
        if stop.load(Ordering::Relaxed) {
            return batch;
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        let ordinal = batch.begin_item();
        match per_item_text(line) {
            Some(item) => match classify(&item) {
                Ok(link) => {
                    batch.push_accepted(ordinal, link.profile, bound_raw(line), link.ignored)
                }
                Err(reason) => batch.push_refused(ordinal, "", reason, bound_raw(line)),
            },
            None => batch.push_refused(
                ordinal,
                "",
                ImportReason::link(super::malformed(Diag::new(Key::LinkEntryNotText))),
                bound_raw(line),
            ),
        }
    }
    batch
}

/// One line, decoded when the line itself is Base64.
fn per_item_text(line: &str) -> Option<String> {
    if !looks_base64(line) {
        return Some(line.to_owned());
    }
    for engine in [
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::URL_SAFE,
    ] {
        use base64::Engine as _;
        if let Ok(bytes) = engine.decode(line.as_bytes())
            && let Ok(decoded) = String::from_utf8(bytes)
            && looks_like_body(&decoded)
        {
            return Some(decoded);
        }
    }
    // A line that is not Base64 at all is still an item; classification
    // reports why it is not a profile.
    Some(line.to_owned())
}

fn looks_like_body(text: &str) -> bool {
    let trimmed = text.trim_start();
    text.contains("://")
        || text.contains('\n')
        || trimmed.starts_with('{')
        || text.contains("proxies:")
        || text.contains("mixed-port:")
        || text.contains("outbounds")
        || text.contains("[Interface]")
        || (text.contains("server:") && (text.contains("port:") || text.contains("auth:")))
}

fn looks_base64(text: &str) -> bool {
    text.len() >= 8
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "+/=_-".contains(character))
}

/// Classify one item: a share link, a nested subscription URL (refused), or a
/// document shape a converter must claim.
fn classify(item: &str) -> Result<ParsedLink, ImportReason> {
    let lower = item.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Err(ImportReason::link(super::malformed(Diag::new(
            Key::LinkNestedSubscription,
        ))));
    }
    if lower.contains("proxies:")
        || lower.starts_with('{')
        || lower.contains("[interface]")
        || lower.starts_with("server:")
        || lower.contains("outbounds")
        || lower.contains("\"servers\"")
    {
        return Err(ImportReason::link(super::malformed(Diag::new(
            Key::LinkUnsupportedDocument,
        ))));
    }
    parse_link(item).map_err(ImportReason::link)
}

/// The bounded copy of a source line kept per record.
fn bound_raw(text: &str) -> String {
    text.chars().take(MAX_RAW_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::t_fmt;
    use crate::model::servers::{RefreshReport, ReportKind};

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    /// One body with one accepted entry and its dropped parameter, one
    /// grammar refusal, and one converter refusal.
    fn mixed() -> ImportBatch {
        parse_body(
            "trojan://pw@alpha.example.com:443?allowInsecure=1#Alpha\n\
             vless://nope\n\
             proxies:\n",
        )
    }

    #[test]
    fn one_record_per_source_item_carries_kind_reason_ordinal_and_raw() {
        let batch = mixed();
        let kinds: Vec<ImportKind> = batch.records().iter().map(|r| r.kind()).collect();
        assert_eq!(
            kinds,
            vec![
                ImportKind::IgnoredParameter,
                ImportKind::Accepted,
                ImportKind::Refused,
                ImportKind::Refused,
            ],
            "the parameter record precedes the entry it belongs to"
        );
        let ordinals: Vec<usize> = batch.records().iter().map(|r| r.ordinal()).collect();
        assert_eq!(ordinals, vec![0, 0, 1, 2]);

        let accepted = batch
            .records()
            .iter()
            .find(|record| record.kind() == ImportKind::Accepted)
            .expect("one accepted entry");
        assert_eq!(accepted.profile().map(|p| p.name.as_str()), Some("Alpha"));
        assert!(accepted.reason().is_none());

        let parameter = batch
            .records()
            .iter()
            .find_map(|record| record.parameter())
            .expect("the dropped parameter is recorded");
        assert_eq!(parameter.key(), "allowInsecure=1");
        assert!(parameter.raw.starts_with("trojan://"));

        let reasons: Vec<&ImportReason> = batch.refused().filter_map(|r| r.reason()).collect();
        assert_eq!(reasons.len(), 2);
        match reasons[0] {
            ImportReason::Link(error) => match error.as_ref() {
                LinkError::Malformed(diag) => {
                    assert_eq!(diag.key(), Key::LinkUserinfoMissing);
                }
                other => panic!("expected a grammar refusal, got {other:?}"),
            },
            other => panic!("expected a grammar refusal, got {other:?}"),
        }
        match reasons[1] {
            ImportReason::Link(error) => match error.as_ref() {
                LinkError::Malformed(diag) => {
                    assert_eq!(diag.key(), Key::LinkUnsupportedDocument);
                }
                other => panic!("expected a converter refusal, got {other:?}"),
            },
            other => panic!("expected a converter refusal, got {other:?}"),
        }
        for record in batch.records() {
            assert!(record.raw().chars().count() <= MAX_RAW_CHARS);
        }
    }

    #[test]
    fn every_record_raw_text_stays_bounded() {
        let long = format!(
            "trojan://pw@example.com:443?allowInsecure=1&tcp_fast_open={}",
            "a".repeat(MAX_RAW_CHARS * 2)
        );
        let batch = parse_body(&long);
        assert!(!batch.records().is_empty());
        for record in batch.records() {
            assert_eq!(record.raw().chars().count(), MAX_RAW_CHARS);
        }
    }

    #[test]
    fn an_overlong_line_is_refused_and_its_neighbours_survive() {
        let long = format!("vless://{}:443", "b".repeat(crate::links::MAX_LINK_LEN));
        let text = format!(
            "vless://{UUID}@ok.local:443?encryption=none#Ok\n\
             {long}\n\
             vless://{UUID}@ok2.local:443?encryption=none#Ok2\n"
        );
        let batch = parse_body(&text);
        let kinds: Vec<ImportKind> = batch.records().iter().map(|r| r.kind()).collect();
        assert_eq!(
            kinds,
            vec![
                ImportKind::Accepted,
                ImportKind::Refused,
                ImportKind::Accepted
            ]
        );
        let refused = batch.refused().next().expect("the long line is refused");
        match refused.reason() {
            Some(ImportReason::Link(error)) => match error.as_ref() {
                LinkError::Malformed(diag) => assert_eq!(diag.key(), Key::LinkTooLong),
                other => panic!("expected the line cap, got {other:?}"),
            },
            other => panic!("expected a grammar refusal, got {other:?}"),
        }
        assert_eq!(refused.ordinal(), 1, "the refusal keeps its line");
    }

    #[test]
    fn report_counts_equal_rows_for_every_kind() {
        let batch = mixed();
        let mut report = RefreshReport::default();
        batch.extend_report(&mut report, Language::En);
        assert_eq!(report.refused, batch.refused_count());
        assert_eq!(
            report.refused,
            report
                .rows
                .iter()
                .filter(|row| row.kind == ReportKind::Refused)
                .count()
        );
        assert_eq!(report.ignored, batch.ignored_count());
        assert_eq!(
            report.ignored,
            report
                .rows
                .iter()
                .filter(|row| row.kind == ReportKind::Ignored)
                .count()
        );
        assert_eq!(report.rows.len(), report.refused + report.ignored);
    }

    #[test]
    fn a_core_refusal_becomes_a_row_with_its_keyed_reason() {
        let mut batch = parse_body(&format!("vless://{UUID}@a.local:443?encryption=none#A\n"));
        assert_eq!(batch.accepted_count(), 1);
        batch.reject_core("A", "[stderr] invalid config: unknown field");
        let report = batch.import_report(0, &["A".to_owned()], Language::En);
        assert_eq!(report.added, 1);
        assert_eq!(
            report
                .rows
                .iter()
                .filter(|row| row.kind == ReportKind::Added)
                .count(),
            1
        );
        assert_eq!(report.refused, 1);
        assert_eq!(
            report
                .rows
                .iter()
                .filter(|row| row.kind == ReportKind::Refused)
                .count(),
            1
        );
        assert_eq!(
            report.rows.len(),
            report.added + report.refused + report.ignored,
            "every count has its row"
        );
        let row = report
            .rows
            .iter()
            .find(|row| row.kind == ReportKind::Refused)
            .expect("the core refusal is a row");
        let reason = row.reason.as_ref().expect("the row carries a keyed reason");
        assert_eq!(reason.key, Key::SrvReportCoreRejected.name());
        let text = row.reason_text(Language::En).expect("the row renders");
        assert!(text.contains("[stderr] invalid config: unknown field"));
    }

    #[test]
    fn a_persisted_report_keeps_the_key_and_renders_later() {
        let batch = mixed();
        let mut report = RefreshReport::default();
        batch.extend_report(&mut report, Language::En);
        let stored = serde_json::to_string(&report).expect("the report serializes");
        assert!(
            stored.contains("LinkUserinfoMissing"),
            "the report stores the keyed reason: {stored}"
        );
        let grammar_sentence = t_fmt(Language::En, Key::LinkUserinfoMissing, &[&"vless"]);
        assert!(
            !stored.contains(&grammar_sentence),
            "a rendered grammar sentence must never be persisted"
        );
        let loaded: RefreshReport = serde_json::from_str(&stored).expect("the report loads");
        let reason = loaded
            .rows
            .iter()
            .find_map(|row| row.reason.as_ref())
            .expect("the keyed reason round-trips");
        assert_eq!(reason.key, Key::LinkUserinfoMissing.name());
        // The stored reason is the key and its values, so the display
        // boundary renders it in whichever language is active when the
        // report opens.
        assert_eq!(reason.text(Language::En), grammar_sentence);
    }
}
