//! Shared form widgets for broccoli screens.
//!
//! Every editor returns `true` iff the wrapped value changed this frame, so
//! screens can OR the results and call `UiCtx::mark_dirty()` once. The
//! commit-gated edit drafts ([`Draft`], [`Scratch`]) hold the uncommitted
//! text such an editor shows, and every labelled text field carries its own
//! label as the widget's accessible name, so a field is addressable by the
//! label it renders.

use egui::{RichText, Stroke, StrokeKind};

use crate::i18n::{Key, t, validation_message};
use crate::model::DurationMs;
use crate::model::Int32Range;
use crate::model::settings::Language;
use crate::model::validation::{ValidationCode, lua_script_path_issue};
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

/// One rebuild-on-key-change memo: the value an expensive derivation
/// produced for a key, kept whole while that key holds.
///
/// Every screen that formats or derives per-generation data — a plot series,
/// a latency grid, a caption set — held its own key field beside its payload
/// and its own staleness comparison. The comparison is the same everywhere:
/// equal key, reuse the value untouched; changed key, rebuild once. This is
/// that comparison and its slot.
///
/// The key is compared by reference, so an idle frame neither clones the key
/// nor re-derives the value; only a rebuild clones the live key into the
/// slot. The value must not contain the key — screens that need that shape
/// keep a plain struct (the dashboard's header cache keys on a
/// payload-carrying phase, the settings screen's on a name list, and both
/// compare those in place).
pub struct Memo<K, V> {
    slot: Option<(K, V)>,
}

impl<K, V> Default for Memo<K, V> {
    fn default() -> Self {
        Self { slot: None }
    }
}

impl<K: Clone + PartialEq, V> Memo<K, V> {
    /// The value for `key`: the stored one when the key still matches, and
    /// otherwise the result of `build` — run exactly once per key change, so
    /// a rebuild is one frame's work and idle frames do none.
    pub fn get(&mut self, key: &K, build: impl FnOnce() -> V) -> &V {
        if self.slot.as_ref().is_none_or(|(held, _)| held != key) {
            self.slot = Some((key.clone(), build()));
        }
        match &self.slot {
            Some((_, value)) => value,
            // `get` fills the slot on a miss, so a miss cannot reach here.
            None => unreachable!("a Memo fills its slot before it is read"),
        }
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

/// One validated field's memoized verdict: the field's label (its identity —
/// see [`validation_verdict`]), the buffer text, and the revision value the
/// validator saw beside it (see [`validated_field_with_revision`]), plus the
/// verdict itself. Validators are pure functions of that triple, so an
/// unchanged triple (idle repaint frames) reuses the memoized verdict —
/// validation runs only on the frame the text first appears or changed
/// (typed, or rewritten by the model), the revision changed (a row added,
/// another row's value committed), or another field's buffer landed on this
/// slot. Stored in egui temp data (never persisted) keyed by the TextEdit's
/// own id, the `timeout_editor` buffer precedent.
#[derive(Clone)]
struct ValidationMemo {
    label: String,
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

/// The two visibility classes one screen can mask this frame. A screen derives
/// it once from its own reveal control and passes the class a field belongs to,
/// so a field cannot disagree with the control about what it hides.
#[derive(Clone, Copy)]
pub struct Mask {
    /// Secret field values: the credentials a profile dials with.
    pub secrets: bool,
    /// Server information: a profile's address, its port, and a WireGuard peer
    /// endpoint.
    pub server_info: bool,
}

/// The per-screen reveal control: one toggle that shows what the screen hides —
/// its secret fields, and its server information while the setting asks for it
/// — and hides it again. `revealed` is the screen's own transient state, so the
/// caller decides when it dies.
pub fn reveal_toggle(ui: &mut egui::Ui, lang: Language, revealed: &mut bool) {
    let (label, note) = if *revealed {
        (Key::SrvHideSecrets, Key::SrvHideSecretsNote)
    } else {
        (Key::SrvRevealSecrets, Key::SrvRevealSecretsNote)
    };
    if ui
        .button(t(lang, label))
        .on_hover_text(t(lang, note))
        .clicked()
    {
        *revealed = !*revealed;
    }
}

/// The run that stands in for a masked value. Fixed width: the run never
/// reports the hidden value's length.
const MASKED_RUN: &str = "••••••••";

/// The stand-in a masked field renders in place of its control: the masked run
/// when a value stands behind the field, the field's own hint in the weak style
/// when none does. The stand-in is a label, so the value stays out of reach —
/// not editable, not focusable, not copyable, and absent from the
/// accessibility tree.
pub fn masked_stand_in(ui: &mut egui::Ui, has_value: bool, hint: &str) -> egui::Response {
    let text = if has_value {
        RichText::new(MASKED_RUN).monospace()
    } else {
        RichText::new(hint).weak()
    };
    ui.add(egui::Label::new(text).selectable(false))
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

/// The one control a validated field's row renders after its text box: it
/// draws itself into the row and returns the text it wants the field to hold
/// — a browse button handing over the folder the user picked — or `None` to
/// leave the field alone, the user having cancelled the control's dialog.
/// The control receives the row's `Ui` and not the field's buffer, because
/// the buffer belongs to the widget that renders the text box; the text it
/// yields is how a control writes to the field.
pub type Trailing<'a> = &'a mut dyn FnMut(&mut egui::Ui) -> Option<String>;

/// [`text_field`] whose value is masked while `masked` is set: the row renders
/// the label and the masked stand-in instead of an editable box, and reports no
/// change.
pub fn masked_text_field(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    masked: bool,
) -> bool {
    if !masked {
        return text_field(ui, label, value, hint);
    }
    ui.horizontal(|ui| {
        let label_response = ui.label(label);
        masked_stand_in(ui, !value.is_empty(), hint).labelled_by(label_response.id);
    });
    false
}

/// Label + validated single-line text field. When `validate` returns
/// `Some(msg)` the field gets a red border, a hover tooltip, and the message
/// in red under the field. `validate` is a pure parse of the text and runs
/// only when the text changed (or on first display); only an actual edit
/// (not the error state) counts as "changed".
///
/// [`validated_field_with_trailing`] with no trailing control.
pub fn validated_field(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    validate: impl Fn(&str) -> Option<String>,
) -> bool {
    validated_field_with_trailing(ui, label, value, hint, validate, None)
}

/// [`validated_field`] whose value is masked while `masked` is set. The verdict
/// renders unchanged: masking hides the value, never the field's verdict, so a
/// hidden field still shows the red border and the message under it.
pub fn masked_validated_field(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    validate: impl Fn(&str) -> Option<String>,
    masked: bool,
) -> bool {
    validated_field_impl(
        ui,
        label,
        value,
        hint,
        FieldContext::default(),
        validate,
        FieldExtras {
            masked,
            ..FieldExtras::default()
        },
    )
}

/// [`validated_field`] whose row also carries one [`Trailing`] control after
/// the text box: the form for a field a small button supplies the value to,
/// a folder picker beside a folder path. The control renders at the row's
/// right edge and the text box takes what it leaves, so the field's fill
/// width never pushes the control out of the clip rect. The hint, the
/// verdict and the required rule are the plain field's.
///
/// The control serves the field: the text it yields becomes the field's text
/// and counts as this field's change, while `None` leaves the field alone.
/// The verdict follows the yielded text on the next frame, like any other
/// rewrite of the buffer.
pub fn validated_field_with_trailing(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    validate: impl Fn(&str) -> Option<String>,
    trailing: Option<Trailing<'_>>,
) -> bool {
    validated_field_impl(
        ui,
        label,
        value,
        hint,
        FieldContext::default(),
        validate,
        FieldExtras {
            trailing,
            ..FieldExtras::default()
        },
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
        FieldExtras::default(),
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
        FieldExtras {
            warning,
            ..FieldExtras::default()
        },
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
        FieldExtras::default(),
    )
}

/// The three labels one optional Lua script row renders: the switch that
/// enables it, the path field that follows, and the field's hint. One value
/// keeps the row's call sites readable — the switch and the field are two
/// controls of the one surface, and every user of this widget supplies all
/// three.
pub struct LuaScriptLabels<'a> {
    pub toggle: &'a str,
    pub path: &'a str,
    pub hint: &'a str,
}

/// Label + checkbox for an optional Lua script and, once it is on, the
/// script's path field with a Browse button that only offers `.lua` files.
///
/// `value` is the script the model stores: `None` = no script,
/// `Some(path)` = the file the core resolves and compiles at load. Turning the
/// switch on seeds an empty path, which the field's own verdict refuses (the
/// core cannot resolve an empty path); turning it off clears the path. The
/// picker hands over the file dialog's path, which is always absolute.
///
/// The verdict combines the shared structural rule ([`lua_script_path_issue`])
/// with `conflict`, the surface's own cross-field rule, so a script row
/// reports exactly what the apply gate refuses. `revision` must change
/// whenever the state `conflict` reads changes — pass [`context_revision`] of
/// it. The app stores the path verbatim and never reads or runs the file.
pub fn lua_script_field(
    ui: &mut egui::Ui,
    lang: Language,
    labels: LuaScriptLabels<'_>,
    value: &mut Option<String>,
    revision: u64,
    conflict: impl Fn(&str) -> Option<ValidationCode>,
) -> bool {
    let mut enabled = value.is_some();
    let mut changed = false;
    if ui.checkbox(&mut enabled, labels.toggle).changed() {
        *value = enabled.then(String::new);
        changed = true;
    }
    let Some(script) = value.as_mut() else {
        return changed;
    };
    let validate = |path: &str| {
        lua_script_path_issue(path)
            .or_else(|| conflict(path))
            .map(|code| validation_message(&code, lang))
    };
    let mut browse = |ui: &mut egui::Ui| -> Option<String> {
        if !ui.small_button(t(lang, Key::SrvBrowse)).clicked() {
            return None;
        }
        rfd::FileDialog::new()
            .add_filter(t(lang, Key::ShellLuaScriptFilter), &["lua"])
            .pick_file()
            .map(|path| path.to_string_lossy().into_owned())
    };
    changed |= validated_field_impl(
        ui,
        labels.path,
        script,
        labels.hint,
        FieldContext {
            revision,
            ..FieldContext::default()
        },
        validate,
        FieldExtras {
            trailing: Some(&mut browse),
            ..FieldExtras::default()
        },
    );
    changed
}

/// The verdict cache behind every validated field: the validator is a pure
/// function of the field's text and its revision ([`context_revision`] of
/// whatever else it reads, `0` for a text-only field, the list length for a
/// list row) — every call site's contract — so the verdict is memoized per
/// field and recomputed only when an input no longer matches the memo: the
/// frame the user typed, the field's first display, an external rewrite of
/// the buffer, a change in the state the revision covers, or another field
/// landing on the slot. Temp data (the `timeout_editor` buffer precedent)
/// keys off the TextEdit's own id, so the memo follows egui focus semantics
/// for free.
///
/// The memo also carries the field's label, because the widget id is not the
/// field's identity: [`paint_validation`] renders the verdict rows
/// conditionally, so a verdict appearing or disappearing above a field shifts
/// the auto ids of every field below it — a field can land on the slot
/// another field used last frame, and a verdict keyed on the slot alone would
/// follow the slot (an empty pre-shared key showing the endpoint's "required"
/// line until the user edited it). A field's label names what the field is,
/// so the memo follows the field: it is reused only by a call site that
/// renders the same label, and every call site renders one validator per
/// label — the field's meaning is the validator's ([`validated_string_list`]
/// rows share their list's label and its one validator, keyed on the row's
/// own text and the list length).
fn validation_verdict(
    ui: &mut egui::Ui,
    response: &egui::Response,
    label: &str,
    value: &str,
    revision: u64,
    validate: &impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let matches_memo = |memo: &ValidationMemo| {
        memo.label == *label && memo.value == *value && memo.revision == revision
    };
    ui.data_mut(|data| {
        match data
            .get_temp_raw_mut(egui::util::id_type_map::RawKey::new::<ValidationMemo>(
                response.id,
            ))
            .and_then(|slot| slot.downcast_mut::<ValidationMemo>())
        {
            Some(memo) if matches_memo(memo) => memo.error.clone(),
            Some(memo) => {
                *memo = ValidationMemo {
                    label: label.to_owned(),
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
                        label: label.to_owned(),
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

/// The optional adornments of a validated row: the amber `warning` line
/// ([`validated_field_with_warning`]) and the one `trailing` control after the
/// text box ([`validated_field_with_trailing`]). A plain [`validated_field`]
/// row carries neither.
#[derive(Default)]
struct FieldExtras<'a> {
    warning: Option<&'a str>,
    trailing: Option<Trailing<'a>>,
    /// Whether the field's value renders as the masked stand-in
    /// ([`masked_validated_field`]).
    masked: bool,
}

/// Shared body of the [`validated_field`] family: renders the labelled field,
/// then the error/warning lines. When the extras carry a trailing control the
/// row is a [`Sides`](egui::containers::Sides) whose right side is that
/// control: the control is measured first and the text box is given what is
/// left of the row, so an unbounded field cannot claim the row and push the
/// control past the clip rect (invisible, unclickable).
fn validated_field_impl(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    hint: &str,
    context: FieldContext,
    validate: impl Fn(&str) -> Option<String>,
    extras: FieldExtras<'_>,
) -> bool {
    let FieldExtras {
        warning,
        trailing,
        masked,
    } = extras;
    let (changed, rect, error) = ui
        .horizontal(|ui| {
            // One row body for both shapes: the label, the text box, and the
            // verdict. Without a trailing control the row body *is* the row;
            // with one it is the row's left side.
            let mut row = |ui: &mut egui::Ui| {
                let label_response = ui.label(label);
                // A masked field renders the stand-in where the text box would
                // be: the row still adds exactly one widget for the field, so
                // revealing it moves no auto id below.
                let mut r = if masked {
                    masked_stand_in(ui, !value.is_empty(), hint)
                } else {
                    ui.add(
                        egui::TextEdit::singleline(value)
                            .hint_text(hint)
                            .desired_width(f32::INFINITY),
                    )
                };
                // The group caption (when the caller rendered one) reads before
                // the field's own label, so the name of a field that repeats once
                // per group distinguishes the instances: "Pool 1 IP pool".
                if let Some(caption) = context.caption {
                    r = r.labelled_by(caption);
                }
                let r = r.labelled_by(label_response.id);
                let error = validation_verdict(ui, &r, label, value, context.revision, &validate);
                let r = match error.as_deref().or(warning) {
                    Some(message) => r.on_hover_text(message),
                    None => r,
                };
                (r.changed(), r.rect, error)
            };
            match trailing {
                Some(trailing) => {
                    let ((row_changed, rect, error), yielded) = egui::containers::Sides::new()
                        .shrink_left()
                        .show(ui, |ui| row(ui), trailing);
                    let changed = match yielded {
                        Some(text) => {
                            *value = text;
                            true
                        }
                        None => row_changed,
                    };
                    (changed, rect, error)
                }
                None => row(ui),
            }
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

/// [`port_field`] whose number is masked while `masked` is set.
pub fn masked_port_field(ui: &mut egui::Ui, label: &str, value: &mut u16, masked: bool) -> bool {
    if !masked {
        return port_field(ui, label, value);
    }
    ui.horizontal(|ui| {
        ui.label(label);
        masked_stand_in(ui, true, "");
    });
    false
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
    let set_to = *range.start();
    opt_num_with(ui, label, v, range, set_to, None, 1.0)
}

/// The one optional-number editor: [`opt_num`] and every site whose "set"
/// state seeds a value other than the range start (a port's 53) or whose
/// unset state names its fallback instead of showing the disabled box.
///
/// `set_to` is what checking the box writes. `unset` renders in place of the
/// disabled box when the value is `None` — a caller inside a grid row with a
/// meaningful inherited default ("(default)") passes its text, and every
/// other caller passes `None` to keep the row's width stable. `speed` is the
/// drag step: integers and counts keep `1.0`, a fractional range passes the
/// step its granularity needs.
pub fn opt_num_with<Num: egui::emath::Numeric>(
    ui: &mut egui::Ui,
    label: &str,
    v: &mut Option<Num>,
    range: std::ops::RangeInclusive<Num>,
    set_to: Num,
    unset: Option<&str>,
    speed: f32,
) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        let mut set = v.is_some();
        if ui.checkbox(&mut set, label).changed() {
            *v = set.then_some(set_to);
            changed = true;
        }
        match v.as_mut() {
            Some(x) => {
                changed |= ui
                    .add(egui::DragValue::new(x).range(range).speed(speed))
                    .changed();
            }
            None => match unset {
                Some(text) => {
                    ui.label(RichText::new(text).weak());
                }
                None => {
                    let mut dummy = *range.start();
                    ui.add_enabled(false, egui::DragValue::new(&mut dummy).range(range));
                }
            },
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

/// Optional bool as a checkbox whose unchecked state is the absent one: for
/// the core flags where absent and false mean the same thing, so the model
/// stores `Some(true)` or nothing. Distinct from [`opt_bool`], which keeps
/// all three states apart — the two are never interchangeable.
pub fn opt_bool_flag(ui: &mut egui::Ui, label: &str, v: &mut Option<bool>) -> bool {
    let mut on = v.unwrap_or(false);
    if ui.checkbox(&mut on, label).changed() {
        *v = if on { Some(true) } else { None };
        true
    } else {
        false
    }
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

/// The captions of one row's reorder pair, and the tooltips they carry.
///
/// The pair is the same control on every ordered list — the DNS server
/// priorities, the routing rules, the finalmask rows — and only its wording
/// differs, so the wording is this value rather than a per-screen copy of the
/// two buttons.
#[derive(Clone, Copy)]
pub struct MoveLabels<'a> {
    /// Caption of the move-up button.
    pub up: &'a str,
    /// Caption of the move-down button.
    pub down: &'a str,
    /// Tooltip of the move-up button, when the screen explains the order.
    pub up_hint: Option<&'a str>,
    /// Tooltip of the move-down button, when the screen explains the order.
    pub down_hint: Option<&'a str>,
    /// Whether the pair renders at the compact (small) button size.
    pub small: bool,
}

impl<'a> MoveLabels<'a> {
    /// The compact ▲/▼ pair with a per-direction tooltip: the list rows whose
    /// order carries a meaning the arrows do not spell out.
    pub fn glyphs(up_hint: &'a str, down_hint: &'a str) -> Self {
        Self {
            up: "▲",
            down: "▼",
            up_hint: Some(up_hint),
            down_hint: Some(down_hint),
            small: true,
        }
    }

    /// Worded captions at the default button size, with no tooltip.
    pub fn words(up: &'a str, down: &'a str) -> Self {
        Self {
            up,
            down,
            up_hint: None,
            down_hint: None,
            small: false,
        }
    }
}

/// The reorder pair of one row in an ordered list: each button is enabled
/// only when the row can move that way, and a click reports the `(from, to)`
/// swap into `move_to` for the caller to apply after the loop — mutating the
/// list under the loop's iterator would skip the shifted row.
pub fn move_buttons(
    ui: &mut egui::Ui,
    index: usize,
    len: usize,
    labels: MoveLabels<'_>,
    move_to: &mut Option<(usize, usize)>,
) {
    let button = |text: &str| {
        let button = egui::Button::new(text);
        if labels.small { button.small() } else { button }
    };
    let up = ui.add_enabled(index > 0, button(labels.up));
    let up = match labels.up_hint {
        Some(hint) => up.on_hover_text(hint),
        None => up,
    };
    if up.clicked() {
        *move_to = Some((index, index.saturating_sub(1)));
    }
    let down = ui.add_enabled(index + 1 < len, button(labels.down));
    let down = match labels.down_hint {
        Some(hint) => down.on_hover_text(hint),
        None => down,
    };
    if down.clicked() {
        *move_to = Some((index, index + 1));
    }
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

/// [`string_list`] whose rows render masked while `masked` is set: each row
/// shows the masked stand-in in place of its text box, so the values stay out
/// of the frame, while the remove and Add buttons keep their meaning — a
/// masked list still says how many entries it holds.
pub fn masked_string_list(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    items: &mut Vec<String>,
    hint: &str,
    masked: bool,
) -> bool {
    if !masked {
        return string_list(ui, lang, label, items, hint);
    }
    let mut changed = false;
    let label_id = (!label.is_empty()).then(|| ui.label(label).id);
    let mut remove = None;
    for (i, item) in items.iter().enumerate() {
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button(t(lang, Key::DeleteRow)).clicked() {
                    remove = Some(i);
                }
                let row = masked_stand_in(ui, !item.is_empty(), hint);
                if let Some(label_id) = label_id {
                    row.labelled_by(label_id);
                }
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
                    let error =
                        validation_verdict(ui, &r, label, item, list_len as u64, &|text: &str| {
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
/// the row, a delete button per row, and an add-row button captioned
/// `add_label` (each screen names the kind of row it adds).
///
/// Two columns only: egui grids size non-last columns from the previous
/// frame's width (first frame: `min_col_width`), and a `TextEdit` clamps its
/// desired width to the cell's available width — so fields in non-last
/// columns are frozen at the first frame's width forever. The key column gets
/// `min_col_width` and the row itself is [`kv_row`], shared with the tables
/// over JSON objects.
pub fn kv_table(
    ui: &mut egui::Ui,
    lang: Language,
    entries: &mut Vec<(String, String)>,
    key_hint: &str,
    val_hint: &str,
    add_label: &str,
) -> bool {
    let mut changed = false;
    let mut remove = None;
    egui::Grid::new(ui.auto_id_with("kv_table"))
        .num_columns(2)
        .min_col_width(150.0)
        .show(ui, |ui| {
            for (i, (k, v)) in entries.iter_mut().enumerate() {
                let edit = kv_row(ui, k, key_hint, v, val_hint, t(lang, Key::DeleteRow));
                changed |= edit.key || edit.value;
                if edit.removed {
                    remove = Some(i);
                }
                ui.end_row();
            }
        });
    if let Some(i) = remove {
        entries.remove(i);
        changed = true;
    }
    if ui.button(add_label).clicked() {
        entries.push((String::new(), String::new()));
        changed = true;
    }
    changed
}

/// What one [`kv_row`]'s widgets reported this frame.
#[derive(Clone, Copy, Default)]
pub struct KvRowEdit {
    /// The key buffer was edited.
    pub key: bool,
    /// The value buffer was edited.
    pub value: bool,
    /// The row's delete button was clicked; the caller removes the row after
    /// its loop, when the iteration no longer borrows the table.
    pub removed: bool,
}

/// One row of a two-column key→value table: the key box at the fixed key
/// width, the delete button pinned to the row's right edge, and the value box
/// filling exactly what the button leaves.
///
/// Both buffers belong to the caller: a plain `Vec<(String, String)>` table
/// lends its own fields, and a table over a JSON object seeds a scratch for
/// the row it renders (its key is a map key and a non-string value has no
/// `String` of its own). Splitting the layout from the buffers is what keeps
/// the two tables one row.
///
/// The value box must be the last widget: egui grids size non-last columns
/// from the previous frame's width, and a `TextEdit` clamps its desired width
/// to its cell's available width — a box in the key column is frozen at the
/// first frame's width forever. The delete button pins right through a
/// right-to-left layout, so the value box takes the width it leaves, and a
/// left-to-right row would let an unbounded box claim the whole row and push
/// the button past the clip rect (invisible, unclickable).
pub fn kv_row(
    ui: &mut egui::Ui,
    key: &mut String,
    key_hint: &str,
    value: &mut String,
    val_hint: &str,
    delete_label: &str,
) -> KvRowEdit {
    let mut edit = KvRowEdit {
        key: ui
            .add(
                egui::TextEdit::singleline(key)
                    .hint_text(key_hint)
                    .desired_width(150.0),
            )
            .changed(),
        ..KvRowEdit::default()
    };
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        if ui.small_button(delete_label).clicked() {
            edit.removed = true;
        }
        edit.value = ui
            .add(
                egui::TextEdit::singleline(value)
                    .hint_text(val_hint)
                    .desired_width(f32::INFINITY),
            )
            .changed();
    });
    edit
}

/// A JSON object as the rows a [`kv_table`] edits: a string value renders
/// verbatim, a string array as its comma-joined items (the form both table
/// screens show a list in), and any other value as its JSON text.
pub fn kv_rows_from_json(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Vec<(String, String)> {
    map.iter()
        .map(|(k, v)| {
            let text = match v {
                serde_json::Value::String(text) => text.clone(),
                serde_json::Value::Array(items) => items
                    .iter()
                    .filter_map(|item| item.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                other => other.to_string(),
            };
            (k.clone(), text)
        })
        .collect()
}

/// The committed `(key, value)` pairs of an edited table, in row order: blank
/// keys drop and both sides trim. Every table-to-model write starts from this
/// shape, so the rows the widget refuses to commit are refused once.
pub fn kv_rows_trimmed(rows: &[(String, String)]) -> impl Iterator<Item = (String, String)> + '_ {
    rows.iter()
        .filter(|(k, _)| !k.trim().is_empty())
        .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
}

/// Width of a ledger row's label column, so the columns line up from row to
/// row and from screen to screen. Only [`ledger_label`] reads it: every screen
/// reaches the width through the two row functions below.
const LEDGER_LABEL_WIDTH: f32 = 128.0;

/// A ledger row whose body takes one line: the label shares that line, so
/// both sit against the same baseline. A body that stacks lines or wraps onto
/// several lines takes [`ledger_row_multiline`] instead.
pub fn ledger_row(
    ui: &mut egui::Ui,
    label: impl Into<egui::WidgetText>,
    body: impl FnOnce(&mut egui::Ui),
) {
    ui.horizontal(|ui| {
        ledger_label(ui, label);
        body(ui);
    });
}

/// A ledger row whose body stacks lines or wraps: the label stays on the
/// body's first line, where the row's subject belongs, instead of drifting to
/// the middle of the stack.
pub fn ledger_row_multiline(
    ui: &mut egui::Ui,
    label: impl Into<egui::WidgetText>,
    body: impl FnOnce(&mut egui::Ui),
) {
    ui.horizontal_top(|ui| {
        ledger_label(ui, label);
        body(ui);
    });
}

/// The label column both ledger rows share: the label with the column's width
/// reserved, so the body starts at the same x on every row.
fn ledger_label(ui: &mut egui::Ui, label: impl Into<egui::WidgetText>) {
    ui.vertical(|ui| {
        ui.set_width(LEDGER_LABEL_WIDTH);
        ui.label(label);
    });
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

/// Styled collapsing section, open by default, whose header row also carries
/// the reveal control at its right edge. The header keeps every part the plain
/// [`section`] header has — the disclosure arrow, the title, and the section's
/// own node for assistive technology — and adds the control beside them: a
/// click on the title or the arrow collapses the section, a click on the
/// control never does. `add` receives the mask the header left behind, so a
/// click applies to the body in the same frame. The section's id is derived
/// from the title exactly as [`section`] derives it, so its open state survives
/// the change.
pub fn section_with_reveal(
    ui: &mut egui::Ui,
    title: &str,
    lang: Language,
    revealed: &mut bool,
    add: impl FnOnce(&mut egui::Ui, bool),
) {
    let id = ui.make_persistent_id(egui::IdSalt::new(title));
    let mut shown = *revealed;
    let mut title_clicked = false;
    let mut header =
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, true)
            .show_header(ui, |ui| {
                // The title keeps the header's click target: a click on the
                // words collapses the section, as it does under [`section`].
                let title_response = ui.add(
                    egui::Label::new(RichText::new(title).strong())
                        .selectable(false)
                        .sense(egui::Sense::click()),
                );
                title_clicked = title_response.clicked();
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    reveal_toggle(ui, lang, &mut shown);
                });
            });
    if title_clicked {
        // Before the body runs, so the collapse lands on this frame.
        header.toggle();
    }
    let (collapser, _, _) = header.body(|ui| {
        ui.add_space(2.0);
        add(ui, !shown);
        ui.add_space(4.0);
    });
    // The arrow carries the section's own node, exactly as the plain header
    // does, so assistive technology reads the section and toggles it here.
    collapser.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::CollapsingHeader, ui.is_enabled(), title)
    });
    *revealed = shown;
}

/// Draw one control row whose explanation rides its hover: `add` renders the
/// control, and the row's rect carries `note` as a tooltip, so a note the
/// user does not need for the decision at hand costs no permanent line. The
/// scope keeps the caller's layout; the hover widget is created after the
/// row, because a child `Ui`'s own rect is registered at creation — before
/// its contents — and egui only hovers a non-interactive widget that sits
/// above the interactive one it covers. A control in the row keeps its own
/// tooltip: egui stacks the two while both are hovered. A row inside disabled
/// UI keeps its tooltip through the disabled channel.
pub fn noted<'a, R>(
    ui: &mut egui::Ui,
    note: impl Into<Option<&'a str>>,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    let row = ui.scope(|ui| add(ui));
    if let Some(note) = note.into() {
        let hover = ui.interact(
            row.response.rect,
            row.response.id.with("note"),
            egui::Sense::hover(),
        );
        if hover.enabled() {
            hover.on_hover_text(note);
        } else {
            hover.on_disabled_hover_text(note);
        }
    }
    row.inner
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

/// One editable text buffer's layout generation: the counter a
/// [`TrackedBuffer`] bumps on every mutation, and the value the memoized
/// [`TextLayoutMemo`] keys its cached galley on.
///
/// A generation is what tells an unchanged frame apart from one whose text
/// was replaced in place: a same-length replacement keeps the buffer's
/// allocation and length, so only a counter the mutation itself advances can
/// invalidate the cached layout.
#[derive(Default)]
pub struct TextRevision(std::cell::Cell<u64>);

impl TextRevision {
    /// Mark the text as changed.
    pub fn bump(&self) {
        self.0.set(self.0.get().wrapping_add(1));
    }

    /// The current generation.
    pub fn get(&self) -> u64 {
        self.0.get()
    }
}

/// A `TextEdit` buffer over a `String` that bumps its [`TextRevision`] on
/// every mutation, so a memoized layouter sees an edit as a new generation
/// even when the edit kept the string's length (and allocation) unchanged.
/// Everything else is the `String` implementation.
pub struct TrackedBuffer<'a> {
    text: &'a mut String,
    revision: &'a TextRevision,
}

impl<'a> TrackedBuffer<'a> {
    pub fn new(text: &'a mut String, revision: &'a TextRevision) -> Self {
        Self { text, revision }
    }
}

impl egui::TextBuffer for TrackedBuffer<'_> {
    fn is_mutable(&self) -> bool {
        true
    }

    fn as_str(&self) -> &str {
        self.text
    }

    fn insert_text(&mut self, text: &str, char_index: egui::text::CharIndex) -> usize {
        self.revision.bump();
        egui::TextBuffer::insert_text(&mut *self.text, text, char_index)
    }

    fn delete_char_range(&mut self, char_range: std::ops::Range<egui::text::CharIndex>) {
        self.revision.bump();
        egui::TextBuffer::delete_char_range(&mut *self.text, char_range);
    }

    fn type_id(&self) -> std::any::TypeId {
        // The buffer is lifetime-parameterized, so `Self` need not be
        // `'static`; the marker instantiation names the same type for
        // `TypeId` (lifetimes do not participate).
        std::any::TypeId::of::<TrackedBuffer<'static>>()
    }
}

/// The style-dependent half of a [`TextLayoutMemo`]'s key: the resolved font
/// and paint color, the line height and the wrap width. Equal components mean
/// the cached galley is still the layout this frame's `TextEdit` would
/// produce.
#[derive(Clone, PartialEq)]
struct TextLayoutStyle {
    font_id: egui::FontId,
    color: egui::Color32,
    line_height: f32,
    wrap_width: f32,
}

/// The memoized layouter for a large `TextEdit` buffer: an unchanged text at
/// an unchanged width and style reuses the cached galley instead of copying
/// the whole buffer into a fresh `LayoutJob` and laying it out again.
///
/// The default layouter does that copy and layout on every call — a plain
/// [`egui::Label`] builds the same job — so a preview of a large config or a
/// multi-megabyte raw override paid for its full text on every idle frame.
/// The key is the buffer's [`TextRevision`] (never the buffer's pointer and
/// length: a same-length in-place edit keeps both) plus the wrap width and
/// the style the `TextEdit` resolves, all cheap to compare. The layout runs
/// only when the key changes.
#[derive(Default)]
pub struct TextLayoutMemo {
    layout: Memo<(u64, TextLayoutStyle), std::sync::Arc<egui::text::Galley>>,
}

impl TextLayoutMemo {
    /// The layouter for this frame over a multiline `TextEdit` using `font`.
    /// `revision` must change whenever the buffer's text does, and the caller
    /// must pass the same [`egui::TextStyle`] the widget renders with (both
    /// the font and the resulting line height depend on it).
    pub fn layouter<'a>(
        &'a mut self,
        revision: &'a TextRevision,
        font: egui::TextStyle,
    ) -> impl FnMut(&egui::Ui, &dyn egui::TextBuffer, f32) -> std::sync::Arc<egui::text::Galley> + 'a
    {
        move |ui, text, wrap_width| {
            let font_id = font.resolve(ui.style());
            // The color the default layouter resolves for an unstyled
            // `TextEdit`: an explicit override, else the inactive widget
            // color.
            let color = ui
                .visuals()
                .override_text_color
                .unwrap_or_else(|| ui.visuals().widgets.inactive.text_color());
            let line_height = ui.fonts_mut(|fonts| fonts.row_height(&font_id))
                + ui.spacing().extra_text_line_spacing;
            let key = (
                revision.get(),
                TextLayoutStyle {
                    font_id,
                    color,
                    line_height,
                    wrap_width,
                },
            );
            let layout = self.layout.get(&key, || {
                let style = &key.1;
                let mut job = egui::text::LayoutJob::simple(
                    text.as_str().to_owned(),
                    style.font_id.clone(),
                    style.color,
                    style.wrap_width,
                );
                // The default layouter's two adjustments: trailing
                // whitespace stays visible, and every section uses the
                // resolved line height.
                job.keep_trailing_whitespace = true;
                for section in &mut job.sections {
                    section.format.line_height = Some(style.line_height);
                }
                ui.fonts_mut(|fonts| fonts.layout_job(job))
            });
            std::sync::Arc::clone(layout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::{Harness, kittest::Queryable as _};

    /// The one comparison every memoized screen row relies on: an unchanged
    /// key rebuilds nothing (an idle frame does no work), and a changed key
    /// rebuilds exactly once.
    #[test]
    fn memo_builds_once_per_key_change() {
        let mut memo: Memo<u64, String> = Memo::default();
        let mut builds = 0u32;

        {
            let held = memo.get(&1, || {
                builds += 1;
                "first".to_owned()
            });
            assert_eq!(held, "first");
        }
        assert_eq!(builds, 1, "the first frame seeds the value");

        {
            let held = memo.get(&1, || {
                builds += 1;
                "ignored".to_owned()
            });
            assert_eq!(held, "first");
        }
        assert_eq!(builds, 1, "an unchanged key rebuilds nothing");

        {
            let held = memo.get(&2, || {
                builds += 1;
                "second".to_owned()
            });
            assert_eq!(held, "second");
        }
        assert_eq!(builds, 2, "a changed key rebuilds exactly once");
    }

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
    fn a_noted_row_carries_its_note_on_hover_and_no_line() {
        // The note rides the row's hover instead of a permanent line: the
        // text is absent from the tree until the pointer is over the row,
        // and present once it is.
        let note = "The core downloads on first use.";
        let mut harness = Harness::builder()
            .with_size(egui::vec2(400.0, 200.0))
            .build_ui_state(
                |ui, value: &mut String| {
                    let _ = noted(ui, note, |ui| text_field(ui, "core", value, ""));
                },
                String::new(),
            );
        harness.run();
        assert!(
            harness.query_by_label(note).is_none(),
            "a noted row must render no permanent line for its note"
        );

        harness.get_by_label("core").hover();
        harness.run();
        harness.run();
        assert!(
            harness.query_all_by_label(note).next().is_some(),
            "the row's hover must carry the note"
        );
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
                    let _ = kv_table(ui, Language::En, entries, "domain", "ip", "+ Add row");
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

    /// A validated field's trailing control is how a browse button feeds the
    /// field it sits beside: the text the control yields becomes the field's
    /// text and counts as the field's change, while a control that yields
    /// nothing — a dialog the user cancelled — leaves the field alone. The
    /// control renders after the text box and stays inside the row: the
    /// field's fill width must not claim the control's own space.
    #[test]
    fn validated_field_trailing_control_feeds_the_field_it_sits_beside() {
        /// The row's inputs and what its last frame reported.
        #[derive(Default)]
        struct Row {
            folder: String,
            /// What the control yields on the next frame, one shot — the
            /// shape a dialog has: it opens, it yields, the frame runs on.
            yielded: Option<String>,
            changed: bool,
        }

        let mut harness = Harness::builder()
            .with_size(egui::vec2(400.0, 160.0))
            .build_ui_state(
                |ui, row: &mut Row| {
                    let Row {
                        folder,
                        yielded,
                        changed,
                    } = row;
                    let mut control = |ui: &mut egui::Ui| {
                        let _ = ui.small_button("Pick");
                        yielded.take()
                    };
                    *changed = validated_field_with_trailing(
                        ui,
                        "folder",
                        folder,
                        "",
                        |_| None,
                        Some(&mut control),
                    );
                },
                Row::default(),
            );
        harness.run();

        // The row renders both parts, the control after the text box, and the
        // control sits inside the viewport — a field that claimed the whole
        // row would leave it clipped and unclickable.
        let field = harness
            .get_by_role_and_label(egui::accesskit::Role::TextInput, "folder")
            .rect();
        let control = harness.get_by_label("Pick").rect();
        assert!(
            control.left() >= field.right(),
            "the control renders after the text box (field {field:?}, control {control:?})"
        );
        let viewport = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(400.0, 160.0));
        assert!(
            viewport.contains(control.center()),
            "the field's fill width must leave the control its own row space \
             (control {control:?}, viewport {viewport:?})"
        );

        // A control that yields nothing — a cancelled dialog — leaves the
        // field alone and reports no change.
        assert!(!harness.state().changed, "an idle row reports no change");
        assert!(harness.state().folder.is_empty());

        // The text the control yields is the field's new text, and the row
        // reports it as the field's change (one frame, so the report is the
        // yielding frame's).
        harness.state_mut().yielded = Some("C:\\xdrive".to_owned());
        harness.run_steps(1);
        assert_eq!(
            harness.state().folder,
            "C:\\xdrive",
            "the control's yielded text must land in the field's own buffer"
        );
        assert!(
            harness.state().changed,
            "the control's text counts as the field's change"
        );

        // The text box shows the yielded text on the following frame.
        harness.run_steps(1);
        assert_eq!(
            harness
                .get_by_role_and_label(egui::accesskit::Role::TextInput, "folder")
                .value()
                .as_deref(),
            Some("C:\\xdrive"),
            "the field must render the text the control yielded"
        );
    }

    /// The Lua script control: a switch that seeds and clears the optional
    /// path, a path row that appears only while the script is on, a Browse
    /// button that belongs to that row, and — under the field — the same
    /// verdict the apply gate renders: the structural path rule first, then
    /// the surface's conflict rule, recomputed when the revision moves.
    #[test]
    fn lua_script_field_toggles_the_path_and_renders_the_gate_verdict() {
        #[derive(Default)]
        struct Row {
            script: Option<String>,
            /// The surface's own conflict, driven through the revision.
            conflict: bool,
            revision: u64,
            changed: bool,
        }

        let browse = t(Language::En, Key::SrvBrowse).to_string();
        let required = validation_message(&ValidationCode::LuaScriptPathRequired, Language::En);
        let not_lua = validation_message(&ValidationCode::LuaScriptPathNotLua, Language::En);
        let conflict = validation_message(&ValidationCode::DnsScriptFallbackConflict, Language::En);

        let mut harness = Harness::builder()
            .with_size(egui::vec2(600.0, 220.0))
            .build_ui_state(
                |ui, row: &mut Row| {
                    let Row {
                        script,
                        conflict,
                        revision,
                        changed,
                    } = row;
                    *changed = lua_script_field(
                        ui,
                        Language::En,
                        LuaScriptLabels {
                            toggle: "Use a DNS script",
                            path: "Script path",
                            hint: "absolute path to a .lua file",
                        },
                        script,
                        *revision,
                        |_| conflict.then_some(ValidationCode::DnsScriptFallbackConflict),
                    );
                },
                Row::default(),
            );
        harness.run();

        // Off: no path row, and the picker belongs to the path row.
        assert!(harness.state().script.is_none());
        assert!(harness.query_by_label("Script path").is_none());
        assert!(harness.query_by_label(&browse).is_none());

        // The switch seeds an empty path, which the shared structural rule
        // refuses: the row reports the gate's own message immediately.
        harness.get_by_label("Use a DNS script").click();
        harness.run();
        assert_eq!(harness.state().script.as_deref(), Some(""));
        assert!(
            harness.query_by_label("Script path").is_some(),
            "the path row appears with the switch"
        );
        assert!(
            harness.query_by_label(&browse).is_some(),
            "the picker belongs to the enabled script's path row"
        );
        assert!(
            harness.query_by_label(&required).is_some(),
            "an enabled script with no path must show the required error"
        );

        // A non-`.lua` path is refused by the same structural rule.
        let field = harness.get_by_role_and_label(egui::accesskit::Role::TextInput, "Script path");
        field.click();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::TextInput, "Script path")
            .type_text("notes.txt");
        harness.run_steps(3);
        assert_eq!(harness.state().script.as_deref(), Some("notes.txt"));
        assert!(
            harness.query_by_label(&not_lua).is_some(),
            "a non-.lua path must show the extension error"
        );

        // The surface's conflict rule joins the verdict, and follows the
        // revision that reports the state beside the path changing. A
        // well-formed path clears the structural error, leaving the conflict
        // as the row's refusal.
        harness.state_mut().script = Some("dns.lua".into());
        harness.state_mut().conflict = true;
        harness.state_mut().revision += 1;
        harness.run();
        assert!(
            harness.query_by_label(&not_lua).is_none(),
            "a .lua path clears the structural error"
        );
        assert!(
            harness.query_by_label(&conflict).is_some(),
            "the surface's conflict must render through the same verdict"
        );

        // Switching the script off clears the stored path and the row.
        harness.get_by_label("Use a DNS script").click();
        harness.run();
        assert!(harness.state().script.is_none());
        assert!(harness.query_by_label("Script path").is_none());
        assert!(harness.query_by_label(&conflict).is_none());
    }
}
