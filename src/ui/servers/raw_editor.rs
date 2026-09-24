//! Seeded text-buffer machinery behind the raw-JSON and PEM editors of the
//! servers screen: per-field text buffers survive across frames while their
//! text is temporarily invalid. Each buffer is seeded once per field
//! identity (an [`egui::Id`] derived from the editor path, which includes
//! the owning profile id), tracks its last parse error and whether it holds
//! an edit that never reached the draft, and is evicted with its owning
//! profile by the shared retain rule. Private to the screen.

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
    pem_buffers: &mut std::collections::HashMap<egui::Id, PemBuf>,
) -> bool {
    ui.label(label);
    // Seed the joined text once per field identity (the key derives from
    // the ui id chain, which includes the profile id, so a profile switch
    // re-seeds) instead of joining the whole PEM on every repaint.
    let key = ui.auto_id_with(("pem-lines", label));
    let buf = pem_buffers.entry(key).or_default();
    if buf.key != Some(key) {
        buf.key = Some(key);
        buf.profile = profile.to_owned();
        buf.text = lines.join("\n");
    }
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

/// Text buffer for PEM editors (certificate/key line lists): the multiline
/// [`egui::TextEdit`] needs a contiguous string, so the joined text is
/// seeded once per field identity (keyed like [`JsonBuf`] — the field's
/// [`egui::Id`] derived from the ui id chain, which includes the owning
/// profile id) and re-joined only when the identity changes (profile
/// switch, cert re-index) or on edits — never on idle repaints.
#[derive(Default)]
pub(super) struct PemBuf {
    key: Option<egui::Id>,
    text: String,
    /// Owning profile id, recorded on seed so eviction is one retain pass
    /// (mirrors [`JsonBuf`]).
    profile: String,
}

/// Text buffer for raw-JSON editors (survives across frames while the text
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
    /// flag the draft-vs-source comparison alone would leave Discard
    /// disabled while a buffer holds uncommitted text.
    pub(super) dirty: bool,
    /// Owning profile id, recorded on seed. Profile ids are
    /// immutable — a rename changes only the display name — so an entry
    /// stays valid across renames; deleting the profile evicts its entries
    /// with one retain pass over this field.
    pub(super) profile: String,
}

/// The raw-JSON editor buffer cache and the parse count kept beside it: one
/// entry per rendered field, keyed by the field's egui `Id`. The cache parses
/// only on a seed or an edit (see [`JsonBuf::edit`]) — an idle re-render of
/// unchanged text reuses both the buffer and its parse result. That parse is
/// the counted quantity because it leaves no other trace: a needless reparse
/// rewrites the same error string and never touches the committed value, so
/// the count is what fails when the parse gate is dropped. Read only by the
/// servers screen's idle-frame parse test.
#[derive(Default)]
pub(super) struct RawBuffers {
    entries: std::collections::HashMap<egui::Id, JsonBuf>,
    /// JSON parses this cache has performed since the screen was created:
    /// one per buffer seed plus one per edit that re-parses.
    pub(super) parses: u64,
}

impl std::ops::Deref for RawBuffers {
    type Target = std::collections::HashMap<egui::Id, JsonBuf>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl std::ops::DerefMut for RawBuffers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entries
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

/// [`FieldKey`] plus the shared seeded-buffer cache the raw-editor chain
/// mutates through.
pub(super) struct RawField<'a> {
    pub(super) id: FieldKey<'a>,
    pub(super) buffers: &'a mut RawBuffers,
}

/// Outcome of one buffered edit pass: whether the committed value changed,
/// and whether the pass parsed the buffer's text (a re-seed or a text edit) —
/// the parse [`RawBuffers::parses`] counts.
struct EditPass {
    changed: bool,
    parsed: bool,
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
        let mut pass = EditPass {
            changed: false,
            parsed: false,
        };
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
            pass.parsed = true;
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
/// map's own `len`; eviction happens through [`evict_owned_buffers`] when the
/// owning profile is deleted. Each parse the pass ran is counted on the
/// cache ([`RawBuffers::parses`]).
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
    let RawBuffers { entries, parses } = field.buffers;
    // One lookup per field per frame: re-use the existing buffer, or create
    // the entry and count the parse it ran.
    let pass = match entries.entry(field.id.key) {
        std::collections::hash_map::Entry::Occupied(mut occupied) => {
            occupied.get_mut().edit(ui, lang, field.id, value, spec)
        }
        std::collections::hash_map::Entry::Vacant(vacant) => {
            let mut buffer = JsonBuf::default();
            let pass = buffer.edit(ui, lang, field.id, value, spec);
            vacant.insert(buffer);
            pass
        }
    };
    if pass.parsed {
        *parses += 1;
    }
    pass.changed
}

/// Owner-eviction rule shared by the raw-JSON and PEM buffer caches:
/// the owning profile is gone, so its buffers are dead weight.
/// Entries record their immutable owner id on seed, so one retain pass over
/// each map is exact and needs no reverse index. Renames never reach here:
/// profile ids are immutable, so a renamed profile keeps its buffers (their
/// keys stay valid, and clearing would only force one re-parse).
pub(super) fn evict_owned_buffers(
    finalmask_raw: &mut RawBuffers,
    pem_buffers: &mut std::collections::HashMap<egui::Id, PemBuf>,
    profile_id: &str,
) {
    finalmask_raw.retain(|_, buffer| buffer.profile != profile_id);
    pem_buffers.retain(|_, buffer| buffer.profile != profile_id);
}
