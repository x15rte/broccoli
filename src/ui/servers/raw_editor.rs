//! Seeded text-buffer machinery behind the raw-JSON and PEM editors of the
//! servers screen: one store of per-field text buffers that survive across
//! frames while their text is temporarily invalid. Each buffer is seeded once
//! per field identity (an [`egui::Id`] derived from the editor path, which
//! includes the owning profile id) and is evicted with its owning profile.
//! Private to the screen.

use egui::{RichText, Stroke, StrokeKind};

use crate::i18n::{Key, t_fmt};
use crate::model::settings::Language;
use crate::ui::status::status_colors_of;

pub(super) fn pem_lines_editor(
    ui: &mut egui::Ui,
    label: &str,
    profile: &str,
    lines: &mut Vec<String>,
    hint: &str,
    buffers: &mut SeededBuffers,
) -> bool {
    ui.label(label);
    // Seed the joined text once per field identity (the key derives from
    // the ui id chain, which includes the profile id, so a profile switch
    // re-seeds) instead of joining the whole PEM on every repaint.
    let key = ui.auto_id_with(("pem-lines", label));
    let buf = buffers.pem_entry(key, profile, lines);
    let changed = ui
        .add(
            egui::TextEdit::multiline(&mut buf.text)
                .font(egui::TextStyle::Monospace)
                .hint_text(hint)
                .desired_rows(4)
                .desired_width(f32::INFINITY),
        )
        .changed();
    if changed {
        *lines = if buf.text.is_empty() {
            Vec::new()
        } else {
            buf.text.split('\n').map(str::to_owned).collect()
        };
    }
    changed
}

/// One PEM editor's text buffer (certificate/key line lists): the multiline
/// [`egui::TextEdit`] needs a contiguous string, so the joined text is seeded
/// once per field identity and re-joined only on an edit — never on idle
/// repaints. [`pem_lines_editor`] writes every edit straight back to the line
/// list it renders, so the text here is never uncommitted.
#[derive(Default)]
pub(super) struct PemBuf {
    key: Option<egui::Id>,
    text: String,
    /// Owning profile id, recorded on seed so eviction is one retain pass.
    profile: String,
}

/// One raw-JSON editor's text buffer (survives across frames while the text
/// is temporarily invalid; re-seeded when the field identity `key` changes).
/// The key is the field's egui [`egui::Id`] — derived from the editor path
/// without allocating, so the same field maps to the same buffer across
/// frames, and a different field (profile switch, mask re-index) re-seeds it.
#[derive(Default)]
pub(super) struct JsonBuf {
    pub(super) key: Option<egui::Id>,
    pub(super) text: String,
    /// Display text of the last parse failure; `None` while `text` parses.
    /// Persisted so the validation error keeps rendering on idle frames
    /// without re-parsing.
    pub(super) error: Option<String>,
    /// True while `text` holds an edit that never reached the draft (any
    /// edit is set, cleared when the text parses and commits, on re-seed,
    /// and by buffer eviction). Invalid JSON never commits, so without this
    /// flag the draft-vs-baseline comparison alone would leave Discard
    /// disabled while a buffer holds uncommitted text.
    pub(super) dirty: bool,
    /// Owning profile id, recorded on seed. Profile ids are
    /// immutable — a rename changes only the display name — so an entry
    /// stays valid across renames; deleting the profile evicts its entries
    /// with one retain pass over this field.
    pub(super) profile: String,
}

/// The servers screen's seeded text buffers: one entry per rendered field,
/// keyed by the field's egui `Id` (stable across frames without allocating a
/// key), in the shape the editor that renders it needs.
///
/// The two halves commit differently and their "uncommitted" states differ
/// with them. A raw-JSON entry parses on an edit or a seed and commits only
/// the text that parses, so it carries its last parse error and the dirty
/// flag for the text that never reached the draft (see [`JsonBuf`]). A PEM
/// entry's editor writes each edit straight through to the line list it
/// renders, so its text is always committed and it carries no such state
/// (see [`PemBuf`]). Everything else is shared: both halves are seeded per
/// field identity, keyed by the same id scheme, held across idle frames, and
/// dropped together when their owning profile goes away.
#[derive(Default)]
pub(super) struct SeededBuffers {
    json: std::collections::HashMap<egui::Id, JsonBuf>,
    pem: std::collections::HashMap<egui::Id, PemBuf>,
}

impl SeededBuffers {
    /// The raw-JSON half's per-field entry: the editors create it on first
    /// sight and reuse whatever it holds afterwards.
    pub(super) fn json_entry(
        &mut self,
        key: egui::Id,
    ) -> std::collections::hash_map::Entry<'_, egui::Id, JsonBuf> {
        self.json.entry(key)
    }

    /// The PEM half's buffer for `key`, seeded from `lines` when this field
    /// identity has no buffer yet.
    pub(super) fn pem_entry(
        &mut self,
        key: egui::Id,
        profile: &str,
        lines: &[String],
    ) -> &mut PemBuf {
        let buffer = self.pem.entry(key).or_default();
        if buffer.key != Some(key) {
            buffer.key = Some(key);
            buffer.profile = profile.to_owned();
            buffer.text = lines.join("\n");
        }
        buffer
    }

    /// Drop every buffer of both halves, so no editor keeps showing text of
    /// a draft that reverted to its persisted profile. Click-time only.
    pub(super) fn clear(&mut self) {
        self.json.clear();
        self.pem.clear();
    }

    /// Drop every buffer of `profile_id`: the owning profile is gone, so its
    /// buffers are dead weight. Both halves record their owner's immutable id
    /// on seed, so one retain pass each is exact and needs no reverse index.
    /// Renames never reach here: profile ids are immutable, so a renamed
    /// profile keeps its buffers (their keys stay valid, and clearing would
    /// only force one re-parse).
    pub(super) fn evict_owned(&mut self, profile_id: &str) {
        self.json.retain(|_, buffer| buffer.profile != profile_id);
        self.pem.retain(|_, buffer| buffer.profile != profile_id);
    }

    /// True when a raw-JSON buffer of `profile_id` holds text that never
    /// reached the draft: invalid JSON never commits, so the draft stays
    /// clean while the editor shows the unparsed text (the state that keeps
    /// Discard reachable). Only the raw-JSON half can qualify — a PEM
    /// buffer's editor writes through on every edit. Entries exist only
    /// while a profile has an open raw editor, and the scan short-circuits
    /// on the first dirty buffer.
    pub(super) fn holds_uncommitted(&self, profile_id: &str) -> bool {
        self.json
            .values()
            .any(|buffer| buffer.profile == profile_id && buffer.dirty)
    }

    /// The raw-JSON half, for the tests that assert seeding, reuse and
    /// per-owner eviction.
    #[cfg(test)]
    pub(super) fn json(&self) -> &std::collections::HashMap<egui::Id, JsonBuf> {
        &self.json
    }

    #[cfg(test)]
    pub(super) fn json_mut(&mut self) -> &mut std::collections::HashMap<egui::Id, JsonBuf> {
        &mut self.json
    }
}

/// Presentation of the multiline JSON editor: placeholder and height.
pub(super) struct JsonEditorSpec<'a> {
    pub(super) hint: &'a str,
    pub(super) rows: usize,
}

/// Identity of one raw-JSON editor field: its seeded-buffer cache key and
/// the owning profile (used for cache eviction). Bundled so the editor chain
/// passes one handle instead of two distinct arguments (same role as
/// [`JsonEditorSpec`]).
#[derive(Clone, Copy)]
pub(super) struct FieldKey<'a> {
    pub(super) key: egui::Id,
    pub(super) profile: &'a str,
}

/// [`FieldKey`] plus the shared seeded-buffer store the raw-editor chain
/// mutates through.
pub(super) struct RawField<'a> {
    pub(super) id: FieldKey<'a>,
    pub(super) buffers: &'a mut SeededBuffers,
}

/// Outcome of one buffered edit pass: whether the committed value changed.
struct EditPass {
    changed: bool,
}

impl JsonBuf {
    fn edit<T>(
        &mut self,
        ui: &mut egui::Ui,
        lang: Language,
        id: FieldKey<'_>,
        value: &mut T,
        spec: &JsonEditorSpec<'_>,
    ) -> EditPass
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone,
    {
        let seeded = self.key != Some(id.key);
        if seeded {
            self.key = Some(id.key);
            self.profile = id.profile.to_owned();
            self.text = serde_json::to_string_pretty(value).unwrap_or_default();
            // Re-seeded from the committed value: nothing is left uncommitted.
            self.dirty = false;
        }
        let mut pass = EditPass { changed: false };
        let resp = ui.add(
            egui::TextEdit::multiline(&mut self.text)
                .font(egui::TextStyle::Monospace)
                .hint_text(spec.hint)
                .desired_rows(spec.rows)
                .desired_width(f32::INFINITY),
        );
        // Any edit leaves text that never reached the draft until the next
        // successful parse commits it — invalid JSON never does, so mark the
        // buffer dirty on every edit and let the commit below clear it.
        if resp.changed() {
            self.dirty = true;
        }
        // Parse only on a real event — a text edit this frame or a re-seed —
        // never on idle frames. The result is persisted so validation errors
        // render identically until the next edit.
        if seeded || resp.changed() {
            match serde_json::from_str::<T>(&self.text) {
                Ok(v) => {
                    self.error = None;
                    if resp.changed() {
                        *value = v;
                        pass.changed = true;
                        // Committed into the draft: nothing is left uncommitted
                        // for Discard to clear.
                        self.dirty = false;
                    }
                }
                Err(e) => self.error = Some(e.to_string()),
            }
        }
        if let Some(error) = &self.error {
            ui.painter().rect_stroke(
                resp.rect,
                ui.style().visuals.widgets.inactive.corner_radius,
                Stroke::new(1.5, status_colors_of(ui).err),
                StrokeKind::Inside,
            );
            ui.colored_label(
                status_colors_of(ui).err,
                RichText::new(t_fmt(lang, Key::SrvInvalidJson, &[error])).small(),
            );
        }
        pass
    }
}

/// Present one raw-JSON editor buffer, creating the per-field entry on first
/// sight. A fresh entry is a cache mutation, so the live entry count is the
/// store's own raw-JSON map; eviction happens through
/// [`SeededBuffers::evict_owned`] when the owning profile is deleted.
pub(super) fn raw_buffer_edit<T>(
    ui: &mut egui::Ui,
    lang: Language,
    label: &str,
    field: RawField<'_>,
    value: &mut T,
    spec: &JsonEditorSpec<'_>,
) -> bool
where
    T: serde::Serialize + serde::de::DeserializeOwned + Clone,
{
    ui.label(label);
    // One lookup per field per frame: re-use the existing buffer, or create
    // the entry and seed it.
    match field.buffers.json_entry(field.id.key) {
        std::collections::hash_map::Entry::Occupied(mut occupied) => {
            occupied.get_mut().edit(ui, lang, field.id, value, spec)
        }
        std::collections::hash_map::Entry::Vacant(vacant) => {
            let mut buffer = JsonBuf::default();
            let pass = buffer.edit(ui, lang, field.id, value, spec);
            vacant.insert(buffer);
            pass
        }
    }
    .changed
}
