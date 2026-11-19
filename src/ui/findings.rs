//! The validation findings every screen presents: the generation pair that
//! says when a screen's derived verdicts went stale, the memo that keeps them
//! across frames, and the renderers that turn findings into the lines a list,
//! a tier or an inline verdict shows.
//!
//! Each screen derives its own texts — the servers editor's sweep, the TUN
//! screen's privacy references, the inbounds screen's listener verdicts — so
//! only the staleness rule and the line spelling live here. A screen holds
//! its texts in [`widgets::Memo`](crate::ui::widgets::Memo), keyed on
//! [`Generations`] (plus whatever else its payload addresses), and renders
//! them with the functions below.

use crate::i18n::{Key, t_fmt, validation_issue_message};
use crate::model::settings::Language;
use crate::model::validation::ValidationIssue;

/// The two generations a validation-derived screen keys its verdicts on: the
/// model's edit generation and the generation the shell's published verdict
/// judged.
///
/// The stamps are separate because the throttled persist publishes a verdict
/// on a later frame than the edit it covers, and stamps it with that edit's
/// generation: an edit-only key still matches on the frame the publish
/// arrives, so the screen would keep rendering the previous verdict. Holding
/// both makes the publish a key change like any edit, while an idle frame
/// moves neither.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct Generations {
    model: u64,
    verdict: u64,
}

impl Generations {
    /// One frame's generation pair: the model generation it rendered and the
    /// generation the published verdict judged.
    pub(crate) fn new(model: u64, verdict: u64) -> Self {
        Self { model, verdict }
    }
}

/// Render one finding as the line every list shows: its `path: message`
/// text, or the message alone for a finding with no path. The message and
/// the path prefix are i18n's ([`validation_issue_message`]); this names the
/// seam the lists and tiers share so no screen spells the line a second way.
pub(crate) fn finding_line(issue: &ValidationIssue, lang: Language) -> String {
    validation_issue_message(issue, lang)
}

/// Render one finding list as the editor's list lines: the shared bullet
/// composed with each finding's line.
pub(crate) fn render_bulleted<'a>(
    findings: impl Iterator<Item = &'a ValidationIssue>,
    lang: Language,
) -> Vec<String> {
    findings
        .map(|issue| {
            let line = finding_line(issue, lang);
            t_fmt(lang, Key::ErrorBullet, &[&line])
        })
        .collect()
}

/// Render one finding list as bare lines, without the list's bullet — the
/// inline verdict a tab shows under its own field.
pub(crate) fn render_findings<'a>(
    findings: impl Iterator<Item = &'a ValidationIssue>,
    lang: Language,
) -> Vec<String> {
    findings.map(|issue| finding_line(issue, lang)).collect()
}

/// Render one non-blocking finding tier under its own header: the header and
/// the lines in the tier's colour, inside a bounded scroll area when
/// `scroll_id` names one (the editor window's fixed height), plain otherwise
/// (the add window grows with its content).
pub(crate) fn render_finding_tier(
    ui: &mut egui::Ui,
    header: &str,
    color: egui::Color32,
    lines: &[String],
    scroll_id: Option<&str>,
) {
    if lines.is_empty() {
        return;
    }
    ui.separator();
    ui.colored_label(color, header);
    match scroll_id {
        Some(id) => {
            egui::ScrollArea::vertical()
                .id_salt(id)
                .max_height(140.0)
                .show(ui, |ui| {
                    for line in lines {
                        ui.colored_label(color, line);
                    }
                });
        }
        None => {
            for line in lines {
                ui.colored_label(color, line);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Generations, finding_line};
    use crate::i18n::validation_message;
    use crate::model::settings::Language;
    use crate::model::validation::{ValidationCode, ValidationIssue};
    use crate::ui::widgets::Memo;

    /// A screen's memo derives once per generation pair and never on an idle
    /// repeat: the model edit and the later published verdict are two
    /// separate key changes.
    #[test]
    fn the_generations_memo_rebuilds_once_per_key_change() {
        let mut builds = 0;
        let mut memo: Memo<Generations, u32> = Memo::default();
        let edited = Generations::new(7, 3);
        assert_eq!(
            *memo.get(&edited, || {
                builds += 1;
                1
            }),
            1
        );
        assert_eq!(
            *memo.get(&edited, || {
                builds += 1;
                2
            }),
            1,
            "an idle frame must reuse the value"
        );
        assert_eq!(builds, 1);

        let next_edit = Generations::new(8, 3);
        assert_eq!(
            *memo.get(&next_edit, || {
                builds += 1;
                3
            }),
            3
        );
        assert_eq!(builds, 2);

        // The publish that follows the edit moved the verdict stamp only:
        // that alone must rebuild, or the previous verdict would stay
        // rendered for the edit it does not cover.
        let published = Generations::new(8, 4);
        memo.get(&published, || {
            builds += 1;
            4
        });
        assert_eq!(builds, 3);
    }

    /// A finding's line is its path and message; a finding with no path is
    /// the message alone.
    #[test]
    fn a_finding_line_prefixes_its_path_only_when_it_has_one() {
        let code = ValidationCode::VlessIdRequired;
        let message = validation_message(&code, Language::En);
        let located = ValidationIssue {
            path: Some("outbound.settings.vnext[0].users[0].id".into()),
            ..ValidationIssue::error(code.clone())
        };
        assert_eq!(
            finding_line(&located, Language::En),
            format!("outbound.settings.vnext[0].users[0].id: {message}")
        );
        let whole = ValidationIssue::error(code);
        assert_eq!(finding_line(&whole, Language::En), message);
    }
}
