//! Shared form widgets for broccoli screens.
//!
//! Every editor returns `true` iff the wrapped value changed this frame, so
//! screens can OR the results and call `UiCtx::mark_dirty()` once. The
//! commit-gated edit drafts ([`Draft`], [`Scratch`]) hold the uncommitted
//! text such an editor shows, and every labelled text field carries its own
//! label as the widget's accessible name, so a field is addressable by the
//! label it renders.

use egui::{RichText, Stroke, StrokeKind};

use crate::i18n::{Key, t};
use crate::model::DurationMs;
use crate::model::Int32Range;
use crate::model::settings::Language;
use crate::ui::status::status_colors_of;

/// A commit-gated edit draft: one buffer a screen's widget edits for the
/// frame, plus the identity the buffer was seeded from.
///
/// [`Self::begin_keyed`] seeds the buffer from the model when the field's
/// identity key changes and [`Self::begin`] seeds it once for a field with a
/// single identity, so two rows or profiles never share a draft. The widget
/// then edits the `&mut B` for the frame, and [`Self::commit_if`] writes the
/// model only for text the caller's own rule accepts: a rejected draft stays
/// in the buffer — with the inline error its field's widget renders — and
/// the model keeps its last good value.
///
/// `B` is the buffer shape the widget needs: the plain `String` of a text
/// field, a row list for the table widgets, or a small bundle of field
/// buffers.
#[derive(Default)]
pub struct Draft<B = String> {
    /// Identity the buffer was seeded for: the caller's key, or the empty key
    /// the seed-once form [`Self::begin`] records. `None` until the first
    /// seed; one draft uses one seeding form, never both.
    key: Option<String>,
    /// Whether the last seed call reset the buffer from the model.
    reseeded: bool,
    buf: B,
}

impl<B> Draft<B> {
    /// The buffer for this frame, seeded from the model once: the form for a
    /// field whose identity never changes, like a settings field loaded on
    /// first open.
    pub fn begin(&mut self, seed: impl FnOnce() -> B) -> &mut B {
        if self.key.is_none() {
            self.key = Some(String::new());
            self.reseeded = true;
            self.buf = seed();
        } else {
            self.reseeded = false;
        }
        &mut self.buf
    }

    /// The buffer for this frame, seeded from the model when the identity
    /// `key` changed — the edited rule's tag, a balancer's key. A steady key
    /// only compares: it neither allocates nor touches the buffer, so an
    /// uncommitted draft survives every idle frame.
    pub fn begin_keyed(&mut self, key: &str, seed: impl FnOnce() -> B) -> &mut B {
        self.reseeded = self.key.as_deref() != Some(key);
        if self.reseeded {
            self.key = Some(key.to_owned());
            self.buf = seed();
        }
        &mut self.buf
    }

    /// Whether the last seed call (re)loaded the buffer from the model, so a
    /// caller with seed-side work — starting the raw override's parse, say —
    /// runs it exactly on the seeding frame.
    pub fn reseeded(&self) -> bool {
        self.reseeded
    }

    /// Drop the seeded identity: the next seed call reloads the model even
    /// for the same key, the form an editor reopening must show the committed
    /// value again instead of the draft it was closed with.
    pub fn reset(&mut self) {
        self.key = None;
        self.reseeded = false;
    }

    /// Write the buffer into the model when `accept` accepts it, reporting
    /// whether the model changed. `accept` is the site's own rule and may
    /// read state beside the buffer (the raw override's parse verdict, the
    /// other rows of a table); a rejected draft stays in the buffer.
    pub fn commit_if(&self, accept: impl FnOnce(&B) -> bool, write: impl FnOnce(&B)) -> bool {
        if accept(&self.buf) {
            write(&self.buf);
            true
        } else {
            false
        }
    }
}

impl Draft<String> {
    /// The buffer text.
    pub fn text(&self) -> &str {
        &self.buf
    }

    /// A direct edit of the buffer, for a test that wants text the seeding
    /// flow would not produce.
    #[cfg(test)]
    pub fn text_mut(&mut self) -> &mut String {
        &mut self.buf
    }
}

/// A shared scratch buffer for a widget's row editors: [`Self::edit`] seeds
/// it from the row's own text — a key, or a non-string value's formatted
/// text — without dropping the buffer's capacity, and the row reads the
/// result back through [`Self::text`] only when its widget reports an edit.
/// One buffer thus serves every row of a table across every frame, where a
/// buffer per row would allocate per row per frame.
///
/// Unlike [`Draft`], a scratch carries no identity between frames: every call
/// seeds it explicitly, because the rows it serves share the one buffer.
#[derive(Default)]
pub struct Scratch {
    text: String,
}

impl Scratch {
    /// Seed from `text` and hand the buffer to this frame's widget. The seed
    /// is whatever the row shows (`Display` covers both a row's key and a
    /// non-string value's formatted text) and reuses the buffer's capacity.
    pub fn edit(&mut self, text: impl std::fmt::Display) -> &mut String {
        use std::fmt::Write as _;
        self.text.clear();
        // `fmt::Write` for `String` is infallible: the write cannot fail.
        let _ = write!(self.text, "{text}");
        &mut self.text
    }

    /// The text the last [`Self::edit`] seeded, plus any edit the widget
    /// wrote over it.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Write the edited text into the model when `accept` accepts it,
    /// reporting whether the model changed. `accept` is the site's own rule —
    /// a row's key must be non-empty and different from the committed one —
    /// and a rejected edit stays in the buffer.
    pub fn commit_if(&self, accept: impl FnOnce(&str) -> bool, write: impl FnOnce(&str)) -> bool {
        if accept(&self.text) {
            write(&self.text);
            true
        } else {
            false
        }
    }
}

/// One validated field's memoized verdict: the buffer text and the revision
/// value the validator saw beside it (see [`validated_field_with_revision`]),
/// plus the verdict itself. Validators are pure functions of that pair, so an
/// unchanged pair (idle repaint frames) reuses the memoized verdict —
/// validation runs only on the frame the text first appears or changed
/// (typed, or rewritten by the model) or the revision changed (a row added,
/// another row's value committed). Stored in egui temp data (never persisted)
/// keyed by the TextEdit's own id, the `timeout_editor` buffer precedent.
#[derive(Clone)]
struct ValidationMemo {
    value: String,
    revision: u64,
    error: Option<String>,
}

/// Revision value for [`validated_field_with_revision`]: a fixed-seed hash of
/// everything the validator reads beside the buffer text (the other rows'
/// values, the row's index, a length). Equal inputs hash equal; any change in
/// that state changes the revision, so the memoized verdict recomputes.
pub fn context_revision(value: impl std::hash::Hash) -> u64 {
    use std::hash::Hasher as _;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Label + single-line text field with a hint. Grows to fill the row.
pub fn text_field(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) -> bool {
    ui.horizontal(|ui| {
        let label = ui.label(label);
        ui.add(
            egui::TextEdit::singleline(value)
                .hint_text(hint)
                .desired_width(f32::INFINITY),
        )
        .labelled_by(label.id)
        .changed()
    })
    .inner
}

/// The state beside the buffer a validated field's verdict and its accessible
/// name read: the memo revision ([`context_revision`] of whatever the
/// validator reads beside the text) and the caption of the group the field
/// belongs to, when the caller rendered one.
#[derive(Clone, Copy, Default)]
struct FieldContext {
    revision: u64,
    caption: Option<egui::Id>,
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
    validated_field_impl(
        ui,
        label,
        value,
        hint,
        FieldContext::default(),
        validate,
        None,
    )
}

/// Label + validated single-line text field whose verdict also reads state
/// beside the buffer — the other rows of a table, a row's index, a length.
/// `revision` must change whenever that state changes: pass
/// [`context_revision`] of it. The memoized verdict recomputes when either
/// the text or the revision changes, so a verdict can never outlive the state
/// it was computed from. Rendering is identical to [`validated_field`].
pub fn validated_field_with_revision(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    revision: u64,
    validate: impl Fn(&str) -> Option<String>,
) -> bool {
    validated_field_impl(
        ui,
        label,
        value,
        hint,
        FieldContext {
            revision,
            ..FieldContext::default()
        },
        validate,
        None,
    )
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
    validated_field_impl(
        ui,
        label,
        value,
        hint,
        FieldContext::default(),
        validate,
        warning,
    )
}

/// [`validated_field`] whose field also carries the caption of the group it
/// belongs to: `caption` is the id of a label the caller has already rendered
/// (a fakeDNS pool's title), and the field's accessible name reads
/// `"{caption} {label}"`. The form for a field that repeats once per group —
/// every pool's CIDR field spells the same label — where the bare label names
/// every instance alike. Rendering is identical to [`validated_field`].
pub fn validated_field_captioned(
    ui: &mut egui::Ui,
    caption: egui::Id,
    label: &str,
    value: &mut String,
    hint: &str,
    validate: impl Fn(&str) -> Option<String>,
) -> bool {
    validated_field_impl(
        ui,
        label,
        value,
        hint,
        FieldContext {
            caption: Some(caption),
            ..FieldContext::default()
        },
        validate,
        None,
    )
}

/// The verdict cache behind every validated field: the validator is a pure
/// function of the field's text and its revision ([`context_revision`] of
/// whatever else it reads, `0` for a text-only field, the list length for a
/// list row) — every call site's contract — so the verdict is memoized per
/// widget id and recomputed only when either input no longer matches the
/// memo: the frame the user typed, the field's first display, an external
/// rewrite of the buffer, or a change in the state the revision covers. Temp
/// data (the `timeout_editor` buffer precedent) keys off the TextEdit's own
/// id, so the memo follows egui focus semantics for free; a stale memo from a
/// recycled widget slot self-heals through the input comparison.
fn validation_verdict(
    ui: &mut egui::Ui,
    response: &egui::Response,
    value: &str,
    revision: u64,
    validate: &impl Fn(&str) -> Option<String>,
) -> Option<String> {
    ui.data_mut(|data| {
        match data
            .get_temp_raw_mut(egui::util::id_type_map::RawKey::new::<ValidationMemo>(
                response.id,
            ))
            .and_then(|slot| slot.downcast_mut::<ValidationMemo>())
        {
            Some(memo) if memo.value == *value && memo.revision == revision => memo.error.clone(),
            Some(memo) => {
                *memo = ValidationMemo {
                    value: value.to_owned(),
                    revision,
                    error: validate(value),
                };
                memo.error.clone()
            }
            None => {
                let error = validate(value);
                data.insert_temp(
                    response.id,
                    ValidationMemo {
                        value: value.to_owned(),
                        revision,
                        error: error.clone(),
                    },
                );
                error
            }
        }
    })
}

/// Paint the verdict channels shared by [`validated_field`] and
/// [`validated_string_list`]: the border stroke on the field's rect, then the
/// message lines under it. Precedence: an error wins the border color, but
/// the warning text still renders beneath the error text.
fn paint_validation(
    ui: &mut egui::Ui,
    rect: egui::Rect,
    error: Option<&str>,
    warning: Option<&str>,
) {
    // The border is the error's channel; a warning only tints it while no
    // error is present.
    let stroke = match (error, warning) {
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
    if let Some(msg) = error {
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
}

/// Shared body of the [`validated_field`] family: renders the labelled field,
/// then the error/warning lines.
fn validated_field_impl(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    context: FieldContext,
    validate: impl Fn(&str) -> Option<String>,
    warning: Option<&str>,
) -> bool {
    let (changed, rect, error) = ui
        .horizontal(|ui| {
            let label = ui.label(label);
            let mut r = ui.add(
                egui::TextEdit::singleline(value)
                    .hint_text(hint)
                    .desired_width(f32::INFINITY),
            );
            // The group caption (when the caller rendered one) reads before
            // the field's own label, so the name of a field that repeats once
            // per group distinguishes the instances: "Pool 1 IP pool".
            if let Some(caption) = context.caption {
                r = r.labelled_by(caption);
            }
            let r = r.labelled_by(label.id);
            let error = validation_verdict(ui, &r, value, context.revision, &validate);
            let r = match error.as_deref().or(warning) {
                Some(message) => r.on_hover_text(message),
                None => r,
            };
            (r.changed(), r.rect, error)
        })
        .inner;
    paint_validation(ui, rect, error.as_deref(), warning);
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
    let label_id = (!label.is_empty()).then(|| ui.label(label).id);
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
                let field = ui.add(
                    egui::TextEdit::singleline(item)
                        .hint_text(hint)
                        .desired_width(f32::INFINITY),
                );
                let field = match label_id {
                    Some(label_id) => field.labelled_by(label_id),
                    None => field,
                };
                changed |= field.changed();
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

/// [`string_list`] with the [`validated_field`] verdict channel per row: when
/// `validate` returns `Some(message)` the row's field gets the red border, the
/// hover tooltip, and the message line under the row. Layout is otherwise the
/// same list shape — a label above, a 🗑 pinning each row's right edge, and a
/// "+ Add" button appending an empty entry. Only row edits count as
/// "changed"; a verdict never does.
///
/// `validate` receives the row's text plus the list length, and the memo keys
/// on the text and the length: a rule that reads the list (say, one entry is
/// valid only as the sole entry) must not keep the verdict it computed for a
/// longer list after a row is added or removed, even though the surviving
/// row's text never changed.
pub fn validated_string_list(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    items: &mut Vec<String>,
    hint: &str,
    validate: impl Fn(&str, usize) -> Option<String>,
) -> bool {
    let mut changed = false;
    let label_id = (!label.is_empty()).then(|| ui.label(label).id);
    // Read before the rows borrow the list: this frame's length is both the
    // verdict's context and the rows' memo revision.
    let list_len = items.len();
    let mut remove = None;
    for (i, item) in items.iter_mut().enumerate() {
        let (row_changed, rect, error) = ui
            .horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button(t(lang, Key::DeleteRow)).clicked() {
                        remove = Some(i);
                    }
                    let r = ui.add(
                        egui::TextEdit::singleline(item)
                            .hint_text(hint)
                            .desired_width(f32::INFINITY),
                    );
                    let r = match label_id {
                        Some(label_id) => r.labelled_by(label_id),
                        None => r,
                    };
                    let error = validation_verdict(ui, &r, item, list_len as u64, &|text: &str| {
                        validate(text, list_len)
                    });
                    let r = match error.as_deref() {
                        Some(message) => r.on_hover_text(message),
                        None => r,
                    };
                    (r.changed(), r.rect, error)
                })
                .inner
            })
            .inner;
        changed |= row_changed;
        // The message line renders in the list's own vertical layout, under
        // the row that carries the verdict.
        paint_validation(ui, rect, error.as_deref(), None);
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

    /// The draft shapes carry the contract the screens' edit buffers rely on:
    /// a buffer seeds per identity (not per frame), a steady identity keeps
    /// the uncommitted text, and only text the site's own rule accepts
    /// reaches the model. A regression here would silently drop a user's
    /// half-typed value or write an unvalidated one into the config.
    #[test]
    fn draft_seeds_per_identity_and_commits_only_accepted_text() {
        // Seed-once form: the first call loads the model, later frames keep
        // the draft even though the model could have moved on.
        let mut once = Draft::default();
        once.begin(|| "model".to_owned());
        assert!(once.reseeded(), "the first seed must report itself");
        once.begin(|| "model-moved".to_owned()).push('!');
        assert!(!once.reseeded(), "a seeded draft must not reload");
        assert_eq!(once.text(), "model!");

        // Commit gate: rejected text stays in the buffer, accepted text
        // reaches the model.
        let mut model = String::from("model");
        assert!(!once.commit_if(|text| text.len() < 6, |text| model = text.to_owned()));
        assert_eq!(model, "model", "a rejected draft must not reach the model");
        assert_eq!(once.text(), "model!");
        assert!(once.commit_if(|text| text.len() >= 6, |text| model = text.to_owned()));
        assert_eq!(model, "model!");

        // Keyed form: a new key reseeds, the same key keeps the draft, and
        // reset forces the reload a reopened editor needs.
        let mut keyed: Draft<Vec<(String, String)>> = Draft::default();
        keyed
            .begin_keyed("a", || vec![("a".to_owned(), "1".to_owned())])
            .push(("edited".to_owned(), "2".to_owned()));
        assert_eq!(keyed.begin_keyed("a", Vec::new).len(), 2);
        assert!(!keyed.reseeded(), "a steady key must keep the draft");
        assert_eq!(keyed.begin_keyed("b", Vec::new).len(), 0);
        assert!(keyed.reseeded(), "a new key must reseed");
        keyed.reset();
        assert!(
            keyed
                .begin_keyed("b", || vec![("b".to_owned(), "1".to_owned())])
                .len()
                == 1,
            "reset must force the same key to reseed"
        );
    }

    /// A scratch serves every row of its table from one buffer: each call
    /// reseeds it explicitly, and its own commit gate decides whether the
    /// edited text reaches the model.
    #[test]
    fn scratch_reseeds_per_row_and_gates_its_commit() {
        let mut scratch = Scratch::default();
        scratch.edit("row-key");
        assert_eq!(scratch.text(), "row-key");

        let mut model = String::new();
        assert!(
            !scratch.commit_if(
                |text| !text.is_empty() && text != "row-key",
                |text| model = text.to_owned()
            ),
            "a rename equal to the committed key must be rejected"
        );
        assert!(model.is_empty(), "a rejected edit must not reach the model");

        scratch.edit("row-key").push('2');
        assert!(scratch.commit_if(
            |text| !text.is_empty() && text != "row-key",
            |text| model = text.to_owned()
        ));
        assert_eq!(model, "row-key2");
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

    /// A verdict that reads state beside the buffer must not outlive that
    /// state: the memo keys on the caller's revision too, so a rule whose
    /// other input changes — while the buffer text stays put — recomputes in
    /// both directions.
    #[test]
    fn validated_field_with_revision_follows_the_context_both_ways() {
        let mut harness = Harness::builder()
            .with_size(egui::vec2(360.0, 160.0))
            .build_ui_state(
                |ui, state: &mut (String, Vec<String>)| {
                    let (value, others) = state;
                    let revision = context_revision(&*others);
                    let _ = validated_field_with_revision(
                        ui,
                        "tag",
                        value,
                        "",
                        revision,
                        |candidate| {
                            others
                                .iter()
                                .any(|other| other == candidate)
                                .then(|| "already used".to_owned())
                        },
                    );
                },
                ("mine".to_owned(), Vec::<String>::new()),
            );

        harness.run();
        assert!(
            harness.query_by_label("already used").is_none(),
            "a value no other row holds must stay clean"
        );

        // Another row takes the same value: the verdict appears although the
        // buffer text never changed.
        harness.state_mut().1.push("mine".to_owned());
        harness.run();
        assert!(
            harness.query_by_label("already used").is_some(),
            "the verdict must follow the context that changed, not just the text"
        );

        // The other row is renamed away: the verdict clears the same way.
        harness.state_mut().1.clear();
        harness.run();
        assert!(
            harness.query_by_label("already used").is_none(),
            "clearing the context must clear the verdict"
        );
    }
}
