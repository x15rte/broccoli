//! Shared form widgets for broccoli screens.
//!
//! Every editor returns `true` iff the wrapped value changed this frame, so
//! screens can OR the results and call `UiCtx::mark_dirty()` once.

use egui::{RichText, Stroke, StrokeKind};

use crate::i18n::{Key, t};
use crate::model::DurationMs;
use crate::model::Int32Range;
use crate::model::settings::Language;
use crate::ui::status::status_colors_of;

/// One validated field's memoized verdict: the buffer text
/// a verdict was computed from, plus the verdict itself. Validators are
/// pure parses of the text, so an unchanged buffer (idle repaint frames)
/// reuses the memoized verdict — validation runs only on the frame the text
/// first appears or changed (typed, or rewritten by the model). Stored in
/// egui temp data (never persisted) keyed by the TextEdit's own id, the
/// `timeout_editor` buffer precedent.
#[derive(Clone)]
struct ValidationMemo {
    value: String,
    error: Option<String>,
}

/// Label + single-line text field with a hint. Grows to fill the row.
pub fn text_field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) -> bool {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(
            egui::TextEdit::singleline(value)
                .hint_text(hint)
                .desired_width(f32::INFINITY),
        )
        .changed()
    })
    .inner
}

/// Label + validated single-line text field. When `validate` returns
/// `Some(msg)` the field gets a red border, a hover tooltip, and the message
/// in red under the field. `validate` is a pure parse of the text and runs
/// only when the text changed (or on first display); only an actual edit
/// (not the error state) counts as "changed".
pub fn validated_field(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    validate: impl Fn(&str) -> Option<String>,
) -> bool {
    validated_field_impl(ui, label, value, hint, validate, None)
}

/// Label + validated single-line text field with an additional amber warning
/// channel. `warning` renders as an amber border, an amber small-text line
/// under the field, and a hover tooltip mirroring the error trio. The warning
/// is an additional channel, not a replacement: when `validate` also reports
/// an error, the error wins the border color and tooltip, and the red error
/// line renders first — the amber warning text still shows beneath it.
pub fn validated_field_with_warning(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    validate: impl Fn(&str) -> Option<String>,
    warning: Option<&str>,
) -> bool {
    validated_field_impl(ui, label, value, hint, validate, warning)
}

/// Shared body of [`validated_field`] and [`validated_field_with_warning`]:
/// renders the labeled field, then the error/warning lines. Precedence: an
/// error wins the border color and the hover tooltip, but the warning text
/// still renders beneath the error text.
fn validated_field_impl(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    validate: impl Fn(&str) -> Option<String>,
    warning: Option<&str>,
) -> bool {
    let (changed, rect, error) = ui
        .horizontal(|ui| {
            ui.label(label);
            let r = ui.add(
                egui::TextEdit::singleline(value)
                    .hint_text(hint)
                    .desired_width(f32::INFINITY),
            );
            // Verdict cache: the validator is a pure parse
            // of the buffer (every call site's contract), so the verdict is
            // memoized per widget id and recomputed only when the text no
            // longer matches the memo — the frame the user typed, the
            // field's first display, or an external rewrite of the buffer —
            // never on idle repaint frames. Temp data (the `timeout_editor`
            // buffer precedent) keys off the TextEdit's own id, so the memo
            // follows egui focus semantics for free; a stale memo from a
            // recycled widget slot self-heals through the value comparison.
            let error = ui.data_mut(|data| {
                match data
                    .get_temp_raw_mut(egui::util::id_type_map::RawKey::new::<ValidationMemo>(r.id))
                    .and_then(|slot| slot.downcast_mut::<ValidationMemo>())
                {
                    Some(memo) if memo.value == *value => memo.error.clone(),
                    Some(memo) => {
                        *memo = ValidationMemo {
                            value: value.clone(),
                            error: validate(value),
                        };
                        memo.error.clone()
                    }
                    None => {
                        let error = validate(value);
                        data.insert_temp(
                            r.id,
                            ValidationMemo {
                                value: value.clone(),
                                error: error.clone(),
                            },
                        );
                        error
                    }
                }
            });
            let r = match error.as_deref().or(warning) {
                Some(message) => r.on_hover_text(message),
                None => r,
            };
            (r.changed(), r.rect, error)
        })
        .inner;
    // The border is the error's channel; a warning only tints it while no
    // error is present.
    let stroke = match (&error, warning) {
        (Some(_), _) => Some(Stroke::new(1.5, status_colors_of(ui).err)),
        (None, Some(_)) => Some(Stroke::new(1.5, status_colors_of(ui).warn)),
        (None, None) => None,
    };
    if let Some(stroke) = stroke {
        ui.painter().rect_stroke(
            rect,
            ui.style().visuals.widgets.inactive.corner_radius,
            stroke,
            StrokeKind::Inside,
        );
    }
    if let Some(msg) = &error {
        ui.horizontal(|ui| {
            ui.add_space(ui.spacing().indent);
            ui.colored_label(status_colors_of(ui).err, RichText::new(msg).small());
        });
    }
    if let Some(msg) = warning {
        ui.horizontal(|ui| {
            ui.add_space(ui.spacing().indent);
            ui.colored_label(status_colors_of(ui).warn, RichText::new(msg).small());
        });
    }
    changed
}

/// Label + port number drag value. `0` remains representable as the model's
/// unset sentinel; validation belongs to the owning editor, not rendering.
pub fn port_field(ui: &mut egui::Ui, label: &str, value: &mut u16) -> bool {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(egui::DragValue::new(value).range(0..=65535))
            .changed()
    })
    .inner
}

/// Optional number: "set" checkbox + DragValue constrained to `range`.
/// The DragValue is enabled iff the value is `Some`; checking the box sets
/// the range start, unchecking clears. Generic over any egui-numeric type,
/// so screens can edit `Option<u64>` / `Option<i64>` fields the typed
/// convenience wrappers [`opt_u32`] and [`opt_i32`] do not cover.
pub fn opt_num<Num: egui::emath::Numeric>(
    ui: &mut egui::Ui,
    label: &str,
    v: &mut Option<Num>,
    range: std::ops::RangeInclusive<Num>,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        let mut set = v.is_some();
        if ui.checkbox(&mut set, label).changed() {
            *v = set.then_some(*range.start());
            changed = true;
        }
        match v.as_mut() {
            Some(x) => {
                changed |= ui.add(egui::DragValue::new(x).range(range)).changed();
            }
            None => {
                let mut dummy = *range.start();
                ui.add_enabled(false, egui::DragValue::new(&mut dummy).range(range));
            }
        }
    });
    changed
}

/// Optional u32: "set" checkbox + DragValue constrained to `range`.
/// The DragValue is enabled iff the value is `Some`. Typed convenience
/// wrapper over [`opt_num`].
pub fn opt_u32(
    ui: &mut egui::Ui,
    label: &str,
    v: &mut Option<u32>,
    range: std::ops::RangeInclusive<u32>,
) -> bool {
    opt_num(ui, label, v, range)
}

/// Optional i32: "set" checkbox + DragValue constrained to `range`.
/// The DragValue is enabled iff the value is `Some`. Typed convenience
/// wrapper over [`opt_num`].
pub fn opt_i32(
    ui: &mut egui::Ui,
    label: &str,
    v: &mut Option<i32>,
    range: std::ops::RangeInclusive<i32>,
) -> bool {
    opt_num(ui, label, v, range)
}

/// Applies `next` to `v`, reporting `false` when the value already holds
/// `next` — clicking the already-selected entry of a tri-state combo must
/// not count as an edit.
fn set_if_different(value: &mut Option<bool>, next: Option<bool>) -> bool {
    if *value == next {
        false
    } else {
        *value = next;
        true
    }
}

/// Shared popup body of the three-way optional-bool combos ([`opt_bool`],
/// [`opt_bool_tri`]): one selectable entry per `(value, label)` pair, in
/// the order the caller lists them.
fn opt_bool_menu(
    ui: &mut egui::Ui,
    label: &str,
    v: &mut Option<bool>,
    items: &[(Option<bool>, &str)],
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label(label);
        let selected = items
            .iter()
            .find(|(value, _)| *value == *v)
            .map_or(items[0].1, |(_, text)| text);
        egui::ComboBox::from_id_salt(ui.auto_id_with(label))
            .selected_text(selected)
            .show_ui(ui, |ui| {
                for (value, text) in items {
                    if ui.selectable_label(*v == *value, *text).clicked() {
                        changed |= set_if_different(v, *value);
                    }
                }
            });
    });
    changed
}

/// Optional bool as an "(unset)/true/false" combo: `None` is not "false",
/// it is the unset state. `none_label` supplies the entry (and selected
/// text) for `None`; callers pass their screen's translated label (e.g.
/// `t(lang, Key::SrvUnset)`).
pub fn opt_bool(ui: &mut egui::Ui, label: &str, v: &mut Option<bool>, none_label: &str) -> bool {
    opt_bool_menu(
        ui,
        label,
        v,
        &[
            (None, none_label),
            (Some(true), "true"),
            (Some(false), "false"),
        ],
    )
}

/// Optional bool as an "(inherit)/false/true" combo with translated entries:
/// `None` inherits the global default while explicit false and true stay
/// representable. The DNS screen's per-server override policy.
pub fn opt_bool_tri(ui: &mut egui::Ui, lang: Language, label: &str, v: &mut Option<bool>) -> bool {
    opt_bool_menu(
        ui,
        label,
        v,
        &[
            (None, t(lang, Key::Inherit)),
            (Some(false), t(lang, Key::BoolFalse)),
            (Some(true), t(lang, Key::BoolTrue)),
        ],
    )
}

/// Label + ComboBox writing a `String`, popup salted from the label: the
/// form for a screen with at most one combo per label per frame (the
/// servers screen's field editors). The empty value — and any empty entry
/// in `options` — renders as `empty_label`; callers pass the translated
/// text their screen uses for the empty meaning ("(default)", "(any)", …).
/// When `allow_empty` is set and `options` contains no empty entry, an
/// extra clear-to-empty entry appears. A change is reported only when the
/// value actually changed (re-clicking the current entry is not an edit).
pub fn combo_str_labeled<S: AsRef<str>>(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    options: &[S],
    empty_label: &str,
    allow_empty: bool,
) -> bool {
    combo_str(ui, label, label, value, options, empty_label, allow_empty)
}

/// Label + ComboBox writing a `String` over an explicit id salt: the form
/// for rows/loops where the same label repeats (routing/dns row editors
/// salt with the row's identity). The empty value — and any empty entry in
/// `options` — renders as `empty_label`; callers pass the translated text
/// their screen uses for the empty meaning ("(default)", "(any)", …).
/// When `allow_empty` is set and `options` contains no empty entry, an
/// extra clear-to-empty entry appears. A change is reported only when the
/// value actually changed (re-clicking the current entry is not an edit).
pub fn combo_str<S: AsRef<str>>(
    ui: &mut egui::Ui,
    label: &str,
    id: impl egui::AsIdSalt,
    value: &mut String,
    options: &[S],
    empty_label: &str,
    allow_empty: bool,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.label(label);
        egui::ComboBox::from_id_salt(id)
            .selected_text(if value.is_empty() {
                empty_label
            } else {
                value.as_str()
            })
            .show_ui(ui, |ui| {
                if allow_empty
                    && !options.iter().any(|opt| opt.as_ref().is_empty())
                    && !value.is_empty()
                    && ui.selectable_label(false, empty_label).clicked()
                {
                    value.clear();
                    changed = true;
                }
                for opt in options {
                    let opt = opt.as_ref();
                    let text = if opt.is_empty() { empty_label } else { opt };
                    if ui.selectable_label(value == opt, text).clicked() && value != opt {
                        *value = opt.to_string();
                        changed = true;
                    }
                }
            });
    });
    changed
}

/// Optional `Int32Range`: "set" checkbox + from/to DragValues ("N" when
/// equal, "from-to" on the wire). Enabling starts a single-value range at
/// the lower bound; the "to" half never drops below "from".
pub fn opt_range(
    ui: &mut egui::Ui,
    label: &str,
    v: &mut Option<Int32Range>,
    range: std::ops::RangeInclusive<i32>,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        let mut set = v.is_some();
        if ui.checkbox(&mut set, label).changed() {
            *v = if set {
                Some(Int32Range::single(*range.start()))
            } else {
                None
            };
            changed = true;
        }
        if let Some(r) = v.as_mut() {
            changed |= ui
                .add(egui::DragValue::new(&mut r.from).range(range.clone()))
                .changed();
            ui.label("–");
            changed |= ui
                .add(egui::DragValue::new(&mut r.to).range(range))
                .changed();
            if r.to < r.from {
                r.to = r.from;
                changed = true;
            }
        }
    });
    changed
}

/// Editable list of strings: one text field per row with a 🗑 remove button,
/// plus a "+ Add" button appending an empty entry.
pub fn string_list(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    items: &mut Vec<String>,
    hint: &str,
) -> bool {
    let mut changed = false;
    if !label.is_empty() {
        ui.label(label);
    }
    let mut remove = None;
    for (i, item) in items.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            // Right-to-left: the remove button pins to the row's right edge
            // and the field fills exactly the remaining width. An unbounded
            // field would claim the whole row and push the button past the
            // clip rect (invisible, unclickable).
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button(t(lang, Key::DeleteRow)).clicked() {
                    remove = Some(i);
                }
                changed |= ui
                    .add(
                        egui::TextEdit::singleline(item)
                            .hint_text(hint)
                            .desired_width(f32::INFINITY),
                    )
                    .changed();
            });
        });
    }
    if let Some(i) = remove {
        items.remove(i);
        changed = true;
    }
    if ui.button(t(lang, Key::AddRow)).clicked() {
        items.push(String::new());
        changed = true;
    }
    changed
}

/// Editable key→value table: a key column, a value field filling the rest of
/// the row, a 🗑 per row, and an add-row button.
///
/// Two columns only: egui grids size non-last columns from the previous
/// frame's width (first frame: `min_col_width`), and a `TextEdit` clamps its
/// desired width to the cell's available width — so fields in non-last
/// columns are frozen at the first frame's width forever. The key column gets
/// `min_col_width` and the value field lives in the last column (which egui
/// sizes to the remaining width); the 🗑 pins to the row's right edge via a
/// right-to-left layout, the same trick `string_list` uses.
pub fn kv_table(
    ui: &mut egui::Ui,
    lang: Language,
    entries: &mut Vec<(String, String)>,
    key_hint: &str,
    val_hint: &str,
) -> bool {
    let mut changed = false;
    let mut remove = None;
    egui::Grid::new(ui.auto_id_with("kv_table"))
        .num_columns(2)
        .min_col_width(150.0)
        .show(ui, |ui| {
            for (i, (k, v)) in entries.iter_mut().enumerate() {
                changed |= ui
                    .add(
                        egui::TextEdit::singleline(k)
                            .hint_text(key_hint)
                            .desired_width(150.0),
                    )
                    .changed();
                // Right-to-left: the remove button pins to the row's right
                // edge and the value field fills exactly the remaining
                // width. An unbounded field in a left-to-right row would
                // claim the whole row and push the button past the clip
                // rect (invisible, unclickable).
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button(t(lang, Key::DeleteRow)).clicked() {
                        remove = Some(i);
                    }
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(v)
                                .hint_text(val_hint)
                                .desired_width(f32::INFINITY),
                        )
                        .changed();
                });
                ui.end_row();
            }
        });
    if let Some(i) = remove {
        entries.remove(i);
        changed = true;
    }
    if ui.button(t(lang, Key::AddKvRow)).clicked() {
        entries.push((String::new(), String::new()));
        changed = true;
    }
    changed
}

/// Styled collapsing section, open by default.
pub fn section(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    egui::CollapsingHeader::new(RichText::new(title).strong())
        .default_open(true)
        .show(ui, |ui| {
            ui.add_space(2.0);
            add(ui);
            ui.add_space(4.0);
        });
}

/// Parse a Go-duration interval that must be greater than zero — the
/// observatory probe interval. Returns the inline message for an invalid
/// draft instead of a committed value.
pub(crate) fn parse_positive_probe_interval(
    lang: Language,
    value: &str,
) -> Result<DurationMs, String> {
    let duration =
        DurationMs::parse(value).ok_or_else(|| t(lang, Key::InvalidGoDuration).to_string())?;
    if duration.as_millis() == 0 {
        Err(t(lang, Key::ProbeIntervalPositive).to_string())
    } else {
        Ok(duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::{Harness, kittest::Queryable as _};

    #[test]
    fn parse_positive_probe_interval_rejects_zero_and_malformed() {
        let lang = Language::En;
        assert_eq!(
            parse_positive_probe_interval(lang, "30s")
                .expect("30s should parse")
                .as_millis(),
            30_000
        );
        assert_eq!(
            parse_positive_probe_interval(lang, "500ms")
                .expect("500ms should parse")
                .as_millis(),
            500
        );

        let malformed = t(lang, Key::InvalidGoDuration).to_string();
        let not_positive = t(lang, Key::ProbeIntervalPositive).to_string();
        for (value, expected) in [
            ("malformed", &malformed),
            ("0", &not_positive),
            ("0s", &not_positive),
            ("-1s", &malformed),
            ("1ns", &not_positive),
        ] {
            assert_eq!(
                parse_positive_probe_interval(lang, value),
                Err(expected.clone())
            );
        }
    }

    #[test]
    fn string_list_added_row_stays_in_viewport_and_removes() {
        // Regression: the row field used `desired_width(f32::INFINITY)`
        // inside `ui.horizontal`, claiming the entire row width and pushing
        // the remove button past the clip rect (invisible, unclickable).
        let items = vec!["10.255.0.1/30".to_owned()];
        let mut harness = Harness::builder()
            .with_size(egui::vec2(400.0, 200.0))
            .build_ui_state(
                |ui, items: &mut Vec<String>| {
                    let _ = string_list(ui, Language::En, "gateways", items, "10.255.0.1/30");
                },
                items,
            );
        harness.run();

        harness.get_by_label("+ Add").click();
        harness.run();
        assert_eq!(harness.state().len(), 2, "+ Add appends a row");

        let viewport = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(400.0, 200.0));
        let fields: Vec<_> = harness
            .query_all_by(|n| n.role() == egui::accesskit::Role::TextInput)
            .collect();
        let buttons: Vec<_> = harness.query_all_by_label("🗑").collect();
        assert_eq!(buttons.len(), 2, "every row keeps its remove button");
        assert!(
            fields
                .iter()
                .chain(buttons.iter())
                .all(|n| viewport.contains(n.rect().center())),
            "fields and remove buttons must stay inside the viewport; an unbounded \
             field pushes the button off-screen"
        );

        buttons[1].click();
        harness.run();
        assert_eq!(
            harness.state().len(),
            1,
            "the remove button deletes its row"
        );
    }

    #[test]
    fn kv_table_fields_have_usable_widths() {
        // Regression: egui grids size non-last columns from the previous
        // frame's width (first frame: `min_col_width`), and a `TextEdit`
        // clamps its desired width to the cell's available width — so text
        // fields in non-last columns froze at ~24 px forever. The key column
        // must reach its requested width and the value field must fill the
        // remaining row width.
        let entries = vec![("example.com".to_owned(), "1.2.3.4".to_owned())];
        let mut harness = Harness::builder()
            .with_size(egui::vec2(400.0, 200.0))
            .build_ui_state(
                |ui, entries: &mut Vec<(String, String)>| {
                    let _ = kv_table(ui, Language::En, entries, "domain", "ip");
                },
                entries,
            );
        // The grid's first frame is a sizing pass (invisible, discarded);
        // run until the widths stabilize.
        harness.run();
        harness.run();
        harness.run();

        let fields: Vec<_> = harness
            .query_all_by(|n| n.role() == egui::accesskit::Role::TextInput)
            .collect();
        assert_eq!(fields.len(), 2, "one key field and one value field");
        let key = fields[0].rect();
        let val = fields[1].rect();
        assert!(
            key.width() >= 100.0,
            "key field must reach its requested width, got {}",
            key.width()
        );
        assert!(
            val.width() >= 180.0,
            "value field must fill the remaining row width, got {}",
            val.width()
        );
        let viewport = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(400.0, 200.0));
        assert!(
            fields
                .into_iter()
                .chain(harness.query_all_by_label("🗑"))
                .all(|n| viewport.contains(n.rect().center())),
            "fields and the remove button must stay inside the viewport"
        );
    }

    #[test]
    fn tri_state_optional_bool_reports_only_real_changes() {
        // The tri-state optional-bool combos (opt_bool / opt_bool_tri) must
        // preserve explicit false, make None reachable again, and count only
        // actual value changes as edits.
        let mut value = None;
        assert!(set_if_different(&mut value, Some(false)));
        assert_eq!(value, Some(false));
        assert!(set_if_different(&mut value, Some(true)));
        assert_eq!(value, Some(true));
        assert!(set_if_different(&mut value, None));
        assert_eq!(value, None);
        assert!(!set_if_different(&mut value, None));
    }

    /// Validation is a pure parse of the buffer, so the
    /// verdict is memoized per widget id — idle frames with unchanged text
    /// must not re-run the validator. Assert through a validator side-effect
    /// counter: the validator runs on first display and on each text change,
    /// never on frames where the text stayed put.
    #[test]
    fn validated_field_runs_the_validator_only_when_the_text_changes() {
        use std::cell::Cell;

        let runs = Cell::new(0usize);
        let runs_ref = &runs;
        let mut harness = Harness::builder()
            .with_size(egui::vec2(320.0, 120.0))
            .build_ui_state(
                |ui, value: &mut String| {
                    let _ = validated_field(ui, "address", value, "", |text| {
                        runs_ref.set(runs_ref.get() + 1);
                        if text.parse::<std::net::IpAddr>().is_ok() {
                            None
                        } else {
                            Some("invalid address".to_owned())
                        }
                    });
                },
                "1.2.3.4".to_owned(),
            );

        // The seed frame validates once (first display); idle frames reuse
        // the memoized verdict.
        harness.run_steps(1);
        assert_eq!(runs.get(), 1, "first display validates exactly once");
        harness.run_steps(5);
        assert_eq!(
            runs.get(),
            1,
            "idle frames with unchanged text must not re-validate"
        );

        // One keystroke changes the buffer: exactly one revalidation, and
        // the following idle frames stay flat again.
        let input = harness
            .query_all_by(|node| node.role() == egui::accesskit::Role::TextInput)
            .next()
            .expect("the validated field's TextEdit must render");
        input.focus();
        harness.run_steps(2);
        assert_eq!(runs.get(), 1, "focus without text change must not validate");
        let input = harness
            .query_all_by(|node| node.role() == egui::accesskit::Role::TextInput)
            .next()
            .expect("the validated field's TextEdit must render");
        input.type_text("x");
        harness.run_steps(2);
        assert_eq!(
            runs.get(),
            2,
            "a text change revalidates exactly once on its frame"
        );
        harness.run_steps(5);
        assert_eq!(runs.get(), 2, "post-edit idle frames must not re-validate");

        // The rendered verdict follows the edit: the invalid buffer shows
        // the error text (the memoized verdict is what the row paints).
        assert!(
            harness
                .query_all_by_label("invalid address")
                .next()
                .is_some(),
            "the error message renders from the memoized verdict"
        );
    }
}
