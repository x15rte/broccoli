//! Logs screen: merged GUI + core log viewer with level/text
//! filtering, stick-to-bottom autoscroll, and clipboard/folder escapes.
//!
//! The buffer itself lives in the app (`UiCtx::logs`, already ring-capped);
//! this screen only filters and renders it — "Clear view" hides lines locally
//! and never touches the underlying buffer.

use std::collections::VecDeque;

use egui::{Color32, RichText, ScrollArea, TextEdit, TextStyle, Ui};

use super::UiCtx;
use crate::diag::DiagError;
use crate::i18n::{Key, t, t_fmt};
use crate::model::settings::Language;
use crate::rt::{CoreCmd, CorePhase, JobKind};
use crate::sys;
use crate::ui::gate::{Rung, verdict};
use crate::ui::request::{Request, Terminal};
use crate::ui::routing::contains_ascii_case_insensitive;
use crate::ui::status::{status_colors, status_colors_of};

/// Level threshold chosen in the filter combo.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LevelFilter {
    All,
    InfoPlus,
    WarningPlus,
    ErrorPlus,
}

impl LevelFilter {
    const ALL: [LevelFilter; 4] = [
        Self::All,
        Self::InfoPlus,
        Self::WarningPlus,
        Self::ErrorPlus,
    ];

    fn label(self, lang: Language) -> &'static str {
        match self {
            Self::All => t(lang, Key::LogsLevelAll),
            Self::InfoPlus => t(lang, Key::LogsLevelInfoPlus),
            Self::WarningPlus => t(lang, Key::LogsLevelWarningPlus),
            Self::ErrorPlus => t(lang, Key::LogsLevelErrorPlus),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Debug,
    Info,
    Warning,
    Error,
}

/// Best-effort level sniffing. Core console lines look like
/// `2026/08/10 12:00:00.123 [Warning] ...`; tracing lines carry a padded
/// ` WARN`-style token. Anything unrecognized returns `None`.
fn line_level(line: &str) -> Option<Level> {
    if line.contains("[Error]") || line.contains(" ERROR") {
        Some(Level::Error)
    } else if line.contains("[Warning]") || line.contains("[Warn]") || line.contains(" WARN") {
        Some(Level::Warning)
    } else if line.contains("[Info]") || line.contains(" INFO") {
        Some(Level::Info)
    } else if line.contains("[Debug]") || line.contains(" DEBUG") || line.contains(" TRACE") {
        Some(Level::Debug)
    } else {
        None
    }
}

fn passes(filter: LevelFilter, level: Option<Level>) -> bool {
    match filter {
        LevelFilter::All => true,
        // Unparseable lines (core banner, continuation output) stay visible
        // until the user narrows to warnings/errors on purpose.
        LevelFilter::InfoPlus => level.is_none_or(|l| l >= Level::Info),
        LevelFilter::WarningPlus => level.is_some_and(|l| l >= Level::Warning),
        LevelFilter::ErrorPlus => level == Some(Level::Error),
    }
}

fn line_color(from_core: bool, level: Option<Level>, dark: bool) -> Color32 {
    let status = status_colors(dark);
    match level {
        Some(Level::Error) => status.err,
        Some(Level::Warning) => status.warn,
        // Origin tint: core stdout/stderr greenish, app (tracing) bluish.
        // Darker on the Light theme so the tint stays legible on white.
        _ if from_core => {
            if dark {
                Color32::from_rgb(0x7f, 0xb5, 0x7f)
            } else {
                Color32::from_rgb(0x3f, 0x7d, 0x3f)
            }
        }
        _ => {
            if dark {
                Color32::from_rgb(0x9a, 0xb8, 0xd8)
            } else {
                Color32::from_rgb(0x3a, 0x5c, 0x8a)
            }
        }
    }
}

/// Identity of the log ring's contents. The ring mutates only
/// through `LogBuffer::push`, which bumps the buffer's monotonic insertion
/// counter once per push; eviction happens only inside `push` when a cap
/// binds. `(len, generation)` therefore changes exactly when the ring's
/// content changes: a push that evicts nothing moves both by one, a push at
/// the cap moves only the generation, and identical pairs mean identical
/// retained content (eviction is oldest-first and deterministic). The
/// previous fingerprint — `(len, front/back `String::as_ptr`)` — could
/// false-equal when capacity-0 empty lines rotated through a full ring:
/// every empty `String` reports the same dangling aligned pointer, so a
/// rotation could leave all three fields bit-identical while one evicted
/// line and one fresh line swapped places, silently keeping a stale
/// filtered view.
#[derive(Clone, Copy, PartialEq, Eq)]
struct RingId {
    len: usize,
    generation: u64,
}

impl RingId {
    fn of(logs: &VecDeque<(bool, String)>, generation: u64) -> Self {
        Self {
            len: logs.len(),
            generation,
        }
    }

    /// Whether the ring moved from `prev` forward by pushes alone — the shape
    /// every production refresh has, because `LogBuffer::push` is the ring's
    /// only mutation: it bumps the counter once and evicts oldest-first until
    /// both caps hold, so one push can drop one entry (the line cap, or a line
    /// exactly filling the byte cap's slack) or several (a long line pushing
    /// the byte cap past a run of short ones). The cached view can then be
    /// extended in place: drop the rows whose lines rotated out and admit the
    /// new tail. Two conditions make that derivation sound — the push counter
    /// never rewinds, and the retained window's front, which [`Self::front`]
    /// reads off the counter and the length, never moves backwards. Both
    /// follow from the ring's documented invariant that eviction happens only
    /// inside `push`, oldest-first; a ring mutated any other way (a test-side
    /// back pop, which would move the derived front without moving the real
    /// one) rebuilds instead.
    fn extends_from(&self, prev: RingId) -> bool {
        self.generation >= prev.generation && self.front() >= prev.front()
    }

    /// Absolute push index of the oldest retained entry: the counter is
    /// bumped once per push and eviction only ever drops from the front, so
    /// `generation - len` is that entry's sequence number.
    fn front(&self) -> u64 {
        self.generation.saturating_sub(self.len as u64)
    }
}

/// A character cursor in the filtered view's row space.
#[derive(Clone, Copy, PartialEq, Debug)]
struct RowCursor {
    row: usize,
    ccursor: egui::text::CCursor,
}

/// One row of the memoized filtered view. The view owns its text: the ring
/// can evict or rotate entries between rebuilds, so it cannot borrow from
/// the buffer.
/// `PartialEq` backs the selection-survival check in
/// [`LogsScreen::refresh_view`]: on the full-rebuild path, whether the
/// rebuilt rows keep the cached ones as a strict prefix (only possible when
/// evicted lines were unadmitted).
#[derive(PartialEq)]
struct FilteredRow {
    /// Absolute push index of the line this row was admitted from (the ring's
    /// front sequence plus the line's offset in it). It is what lets a
    /// refresh drop exactly the rows whose lines rotated out of the ring —
    /// the ring's current front is the watermark — instead of rebuilding the
    /// whole view whenever a cap evicts.
    seq: u64,
    from_core: bool,
    /// Sniffed level, computed once at rebuild instead of per painted row.
    level: Option<Level>,
    line: String,
}

/// Custom selection state for log rows. egui's native label selection
/// collapses on ANY press — including the secondary one — and owns private
/// state, so rows cannot use it (the TextEdit snapshot/restore trick needs
/// public state). This mirrors the drag selection instead, and right-clicks
/// deliberately leave it untouched: the row context menu
/// ([`Key::LogsCopySelection`]) opens with the selection intact, and the
/// platform copy chord copies the same slice.
#[derive(Clone, Copy, Default, Debug)]
struct RowSelection {
    anchor: Option<RowCursor>,
    active: Option<RowCursor>,
}

/// The exact inputs a [`FilteredView`] was built from. Current inputs are
/// compared against the key's fields in place — allocation-free (string
/// comparisons only) — so no per-frame key is constructed on idle frames.
struct ViewKey {
    ring: RingId,
    level: LevelFilter,
    needle: String,
    clear_after_generation: Option<u64>,
}

/// Memoized filtered view plus its layout bookkeeping:
/// only rows intersecting the scroll viewport are laid out per frame; row
/// heights are measured once per rebuild and re-fitted when the wrap width
/// changes (window resize, scrollbar appearance). A re-fit is a layout pass,
/// not a filter rebuild: it re-measures inside the retained view, so only the
/// screen's own layout-pass counts ([`LogsScreen::show_rows`]) move. A forward
/// refresh (pushes, with or without eviction) extends `rows` in place (see
/// [`LogsScreen::refresh_view`]); the measured vectors then cover a prefix of
/// `rows` — the retained prefix stays valid, and eviction truncates it — and
/// [`LogsScreen::show_rows`] extends them with the admitted tail only.
struct FilteredView {
    key: ViewKey,
    rows: Vec<FilteredRow>,
    /// Wrapped text height per row, measured at `measured_width` with the
    /// same fonts and width the render pass uses, so painted rows always
    /// fit their slots exactly.
    heights: Vec<f32>,
    /// The galleys measured into `heights`, kept for the custom row
    /// selection's cursor math (`cursor_from_pos` / `pos_from_cursor`).
    /// Rebuilt only on a re-fit, never per frame.
    galleys: Vec<std::sync::Arc<egui::text::Galley>>,
    /// Content width the heights were measured at.
    measured_width: f32,
    /// Item spacing baked into the prefix sums.
    spacing_y: f32,
    /// Prefix sums of row slot heights (row height + item spacing):
    /// `prefix[i]` is the y-offset of row `i`, `prefix[n]` the total
    /// content height including the trailing spacing.
    prefix: Vec<f32>,
}

impl FilteredView {
    /// Drop the rows whose lines left the ring, keeping the measured layout
    /// index-aligned with the survivors: each dropped row takes its height,
    /// galley and prefix-sum entry with it, and the retained prefix sums are
    /// rebased on the new front (`prefix[i] - prefix[k]` is the y-offset of
    /// the first survivor in the shortened view). The measured prefix is what
    /// `heights` covers — it may be shorter than `rows` when a refresh landed
    /// before the next layout pass — so only that prefix is drained.
    /// Returns how many rows moved, which is what invalidates an index-keyed
    /// selection.
    fn drop_departed_rows(&mut self, front: u64) -> usize {
        let keep = self.rows.partition_point(|row| row.seq < front);
        if keep == 0 {
            return 0;
        }
        self.rows.drain(..keep);
        let measured = keep.min(self.heights.len());
        self.heights.drain(..measured);
        self.galleys.drain(..measured);
        if measured > 0 && self.prefix.len() > measured {
            let base = self.prefix[measured];
            self.prefix.drain(..measured);
            for offset in &mut self.prefix {
                *offset -= base;
            }
        }
        keep
    }
}

pub struct LogsScreen {
    level: LevelFilter,
    text: String,
    autoscroll: bool,
    /// The ring's monotonic push count when [Clear view] was pressed. Lines
    /// pushed at or before this generation stay hidden; later lines never
    /// are. The anchor is positional (a generation), not textual: a line
    /// whose text recurs — before or after the clear point — can never
    /// misplace it, because the retained lines pushed after Clear are
    /// always the ring's tail (`start = len - (generation - clear)`
    /// follows from oldest-first eviction). Once every pre-clear line has
    /// rotated out, the anchor self-corrects to "show everything".
    clear_after_generation: Option<u64>,
    last_error: Option<String>,
    /// In-flight logger-restart request: the reply channel the runtime
    /// answers, polled per frame. Only one request at a time (idle while
    /// none is in flight).
    pending_logger_request: Request<Result<(), DiagError>>,
    logger_restart_feedback: Option<(bool, String)>,
    /// Memoized filtered view: rebuilt only when the ring identity, level,
    /// needle, or clear generation change — never per frame; a forward
    /// refresh extends it in place.
    view: Option<FilteredView>,
    /// Custom log-row selection (see [`RowSelection`]); cleared when the
    /// filtered view rebuilds, because the row indices shift.
    rows_selection: RowSelection,
    /// Memoized "N of M lines" caption: `t_fmt` runs only when
    /// the visible/total counts or the language moved — never per painted
    /// frame.
    line_count: Option<LineCountCaption>,
    /// Width-settle tracker for full re-layouts: a window drag
    /// streams the available width at frame rate, and re-fitting on every
    /// frame re-measures every filtered row (up to the full ring cap).
    /// A full re-fit runs only once the width holds still within
    /// [`REFIT_EPSILON`] for [`REFIT_SETTLE_SECS`], so a drag settles with
    /// at most one re-layout (at the drag's final width).
    pending_refit: Option<PendingRefit>,
    /// What the last view refresh decided (idle frames replace it with
    /// [`RefreshOutcome::Reused`]).
    last_refresh: RefreshOutcome,
    /// What the last layout pass measured: a fresh build or a re-fit
    /// measures every row, a forward refresh measures only its admitted tail,
    /// and an unchanged-width frame measures nothing.
    last_layout: LayoutPass,
}

/// What one refresh of the memoized view decided. The decision is a value the
/// caller can assert — the screen keeps the last one — instead of a layout
/// counter standing in for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefreshOutcome {
    /// The filter inputs and the ring are unchanged: the cached view stands.
    Reused,
    /// A forward refresh kept the cached rows and admitted `admitted` lines,
    /// dropping `dropped` rows whose lines left the ring. `selection_survives`
    /// is false when a dropped row shifted the indices the selection is keyed
    /// on.
    Extended {
        admitted: usize,
        dropped: usize,
        selection_survives: bool,
    },
    /// A full rebuild admitted `rows` rows. `selection_survives` is true only
    /// when the rebuilt rows keep the cached ones as a strict prefix (an
    /// append, which leaves the row indices alone).
    Rebuilt {
        rows: usize,
        selection_survives: bool,
    },
}

impl RefreshOutcome {
    /// Whether the refresh did any work (rebuilt or extended). Idle frames
    /// answer false. The screen renders whatever the view holds either way,
    /// so only the tests ask — they read "the view changed" off the decision
    /// instead of a private counter.
    #[cfg(test)]
    fn changed(&self) -> bool {
        !matches!(self, Self::Reused)
    }
}

/// What one layout pass measured. A fresh build or a re-fit measures every
/// row (`Full`); a forward refresh measures only the rows it admitted
/// (`Tail`); a frame whose width and spacing are unchanged measures nothing
/// (`None`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LayoutPass {
    None,
    Full { rows: usize },
    Tail { rows: usize },
}

/// Memoized "visible of total lines" caption text, keyed on its inputs.
struct LineCountCaption {
    visible: usize,
    total: usize,
    lang: Language,
    text: String,
}

/// A full re-layout deferred until the content width holds still: the
/// candidate width and the egui-clock time its current epsilon band was
/// entered. Any frame whose width leaves the band resets the candidate, so
/// a streaming drag never re-fits.
struct PendingRefit {
    width: f32,
    since: f64,
}

/// Width drift below this (px) does not trigger a re-layout: sub-pixel
/// scrollbar/rounding jitter must not re-measure the ring.
const REFIT_EPSILON: f32 = 1.0;
/// A width must hold still this long (egui-clock seconds) before a full
/// re-layout runs — at 60 fps one settle window is ~9 frames.
const REFIT_SETTLE_SECS: f64 = 0.15;

// Manual impl (rather than `#[derive(Default)]`) because autoscroll must
// default to ON.
impl Default for LogsScreen {
    fn default() -> Self {
        Self {
            level: LevelFilter::All,
            text: String::new(),
            autoscroll: true,
            clear_after_generation: None,
            last_error: None,
            pending_logger_request: Request::default(),
            logger_restart_feedback: None,
            view: None,
            rows_selection: RowSelection::default(),
            line_count: None,
            pending_refit: None,
            last_refresh: RefreshOutcome::Reused,
            last_layout: LayoutPass::None,
        }
    }
}

impl LogsScreen {
    pub fn show(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        // Consume the logger-restart reply for the in-flight request, if it
        // has landed. A send failure leaves the request idle, so a pending
        // request here always has a runtime job behind it.
        match self.pending_logger_request.poll() {
            Some(Terminal::Answered(result)) => {
                self.logger_restart_feedback =
                    Some(logger_restart_feedback(ctx.settings.language, result));
            }
            // Defensive: the runtime's reply guard always sends a terminal
            // before the sender drops.
            Some(Terminal::Exited) | None => {}
        }
        let logger_cmd = ctx.cmd.clone();
        let logs: &VecDeque<(bool, String)> = ctx.logs;
        let logger_gate = verdict(
            matches!(ctx.phase, CorePhase::Running),
            // The window rung is the logger restart kind's declared rule: the
            // runtime rejects the request while an exclusive job holds the
            // window, so the control is refused on exactly the same fact.
            ctx.busy.blocks(JobKind::LoggerRestart),
            self.pending_logger_request.is_pending(),
        );
        // The filtered view is memoized on
        // (ring identity, level, needle, clear generation); idle frames
        // never rebuild it, and forward refreshes extend the cached view —
        // rows and layout vectors — with the admitted tail instead of
        // rebuilding.
        // The ring identity is the app's monotonic push count (see
        // [`RingId`]), so empty-line rotations at the cap still invalidate.
        self.refresh_view(logs, ctx.logs_generation);

        ui.horizontal_wrapped(|ui| {
            let lang = ctx.settings.language;
            ui.label(t(lang, Key::LogsLevelLabel));
            egui::ComboBox::from_id_salt("logs_level_filter")
                .selected_text(self.level.label(lang))
                .show_ui(ui, |ui| {
                    for f in LevelFilter::ALL {
                        ui.selectable_value(&mut self.level, f, f.label(lang));
                    }
                });
            ui.separator();
            ui.label(t(lang, Key::LogsFilterLabel));
            ui.add(
                TextEdit::singleline(&mut self.text)
                    .hint_text(t(lang, Key::LogsFilterHint))
                    .desired_width(180.0),
            );
            ui.separator();
            ui.checkbox(&mut self.autoscroll, t(lang, Key::LogsAutoscroll));
            ui.separator();
            if ui.button(t(lang, Key::LogsCopyAll)).clicked() {
                let mut joined = String::new();
                for row in self.view.iter().flat_map(|view| &view.rows) {
                    if !joined.is_empty() {
                        joined.push('\n');
                    }
                    joined.push_str(&row.line);
                }
                ui.ctx().copy_text(joined);
            }
            if ui
                .button(t(lang, Key::LogsClearView))
                .on_hover_text(t(lang, Key::LogsClearViewHint))
                .clicked()
            {
                self.clear_after_generation = Some(ctx.logs_generation);
            }
            if ui.button(t(lang, Key::LogsOpenFolder)).clicked() {
                match sys::hidden_command("explorer")
                    .arg(sys::paths::logs_dir())
                    .spawn()
                {
                    Ok(_) => self.last_error = None,
                    Err(e) => self.last_error = Some(t_fmt(lang, Key::LogsOpenFolderFailed, &[&e])),
                }
            }
            let mut restart = ui
                .add_enabled(
                    logger_gate.enabled,
                    egui::Button::new(t(lang, Key::LogsRestartLogger)),
                )
                .on_hover_text(t(lang, Key::LogsRestartLoggerHint));
            // The disabled reason is attached only while the rung refuses the
            // button: hover-text arguments evaluate eagerly every frame.
            let disabled_reason = match logger_gate.rung {
                Rung::Ready => None,
                Rung::NotRunning => Some(t(lang, Key::LogsRestartDisabledNotRunning)),
                Rung::Busy => Some(t(lang, Key::LogsRestartDisabledBusy)),
                Rung::Pending => Some(t(lang, Key::WaitingForXray)),
            };
            if let Some(reason) = disabled_reason {
                restart = restart.on_disabled_hover_text(reason);
            }
            if restart.clicked() {
                let (reply, receiver) = tokio::sync::oneshot::channel();
                self.logger_restart_feedback = None;
                if logger_cmd.send(CoreCmd::RestartLogger { reply }).is_err() {
                    self.logger_restart_feedback =
                        Some((false, t(lang, Key::RuntimeChannelClosed).into()));
                } else {
                    self.pending_logger_request = Request::reply(receiver);
                }
            }
        });
        if let Some(err) = &self.last_error {
            ui.label(RichText::new(err.as_str()).color(status_colors_of(ui).err));
        }
        if let Some((ok, message)) = &self.logger_restart_feedback {
            ui.label(
                RichText::new(message)
                    .color(if *ok {
                        ui.visuals().strong_text_color()
                    } else {
                        ui.visuals().error_fg_color
                    })
                    .small(),
            );
        } else if self.pending_logger_request.is_pending() {
            ui.label(
                RichText::new(t(ctx.settings.language, Key::LogsRestarting))
                    .weak()
                    .small(),
            );
        }

        let visible_count = self.view.as_ref().map_or(0, |view| view.rows.len());
        // Memoized "N of M lines" caption: formatted only when
        // the visible/total counts or the language moved, never per painted
        // frame. The label borrows the cached text.
        let lang = ctx.settings.language;
        if !self.line_count.as_ref().is_some_and(|caption| {
            caption.visible == visible_count && caption.total == logs.len() && caption.lang == lang
        }) {
            self.line_count = Some(LineCountCaption {
                visible: visible_count,
                total: logs.len(),
                lang,
                text: t_fmt(lang, Key::LogsLineCount, &[&visible_count, &logs.len()]),
            });
        }
        let caption = self
            .line_count
            .as_ref()
            .expect("caption set above")
            .text
            .as_str();
        ui.label(RichText::new(caption).weak().small());
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .stick_to_bottom(self.autoscroll)
            .show_viewport(ui, |ui, viewport| self.show_rows(ui, viewport, lang));
    }

    /// Refresh the memoized filtered view when its inputs — ring identity,
    /// level, needle, clear generation — changed. A forward refresh (the ring
    /// only took pushes, filter inputs unchanged) extends the cached rows in
    /// place: the rows whose lines rotated out are dropped with their measured
    /// layout, and the admitted tail is appended — so a push at a cap costs
    /// the tail, not the ring. Anything else — a backwards or shrinking ring,
    /// filter/level changes, clears, first build — rebuilds the rows from
    /// scratch. The returned flag is exactly the refresh decision: false on an
    /// idle frame (the cached view stands), true on a rebuild or extension.
    /// Refresh the memoized view from the ring and report what it decided.
    /// The outcome is the observable the tests assert: "reused",
    /// "extended by N, dropped M" or "rebuilt with N rows", plus whether the
    /// index-keyed selection survived.
    fn refresh_view(
        &mut self,
        logs: &VecDeque<(bool, String)>,
        logs_generation: u64,
    ) -> RefreshOutcome {
        let ring = RingId::of(logs, logs_generation);
        let needle = self.text.trim();
        // Idle frames — nothing about the filter inputs changed — reuse the
        // cached view and keep the index-keyed custom selection intact. The
        // key fields are compared in place, so no key is allocated per
        // frame.
        if self.view.as_ref().is_some_and(|view| {
            view.key.ring == ring
                && view.key.level == self.level
                && view.key.needle == needle
                && view.key.clear_after_generation == self.clear_after_generation
        }) {
            self.last_refresh = RefreshOutcome::Reused;
            return self.last_refresh;
        }
        // Forward refresh: the ring's push counter advanced and the
        // level/needle/clear inputs are unchanged, so the cached rows are
        // still the new view's rows minus the ones whose lines left the
        // ring, followed by the unexamined tail. Drop the departed rows
        // (their measured heights, galleys and prefix sums with them, so the
        // retained layout stays index-aligned) and admit the tail; the
        // clear anchor is positional and unchanged, so no tail line can be
        // hidden by it. The push counter is the watermark: every line with a
        // sequence below the ring's front is gone, and the cached key's
        // counter is the first line this view has not examined.
        if let Some(view) = self.view.as_mut()
            && ring.extends_from(view.key.ring)
            && view.key.level == self.level
            && view.key.needle == needle
            && view.key.clear_after_generation == self.clear_after_generation
        {
            let front = ring.front();
            let dropped = view.drop_departed_rows(front);
            let mut admitted = 0;
            if dropped > 0 {
                // Evicted lines the view had admitted shift every later
                // row's index, so the index-keyed selection (and the copy
                // action it drives) must go. A refresh that dropped only
                // unadmitted lines leaves the indices alone and keeps it.
                self.rows_selection = RowSelection::default();
            }
            // `max` covers the ring having rotated past the view's watermark
            // (the Logs screen was not painted while lines streamed): those
            // lines are gone, so the walk starts at the oldest survivor.
            let from = view.key.ring.generation.max(front);
            for (offset, (from_core, line)) in logs.iter().enumerate().skip((from - front) as usize)
            {
                let seq = front + offset as u64;
                if seq >= ring.generation {
                    break;
                }
                let level = line_level(line);
                if passes(self.level, level) && contains_ascii_case_insensitive(line, needle) {
                    view.rows.push(FilteredRow {
                        seq,
                        from_core: *from_core,
                        level,
                        line: line.clone(),
                    });
                    admitted += 1;
                }
            }
            view.key.ring = ring;
            self.last_refresh = RefreshOutcome::Extended {
                admitted,
                dropped,
                selection_survives: dropped == 0,
            };
            return self.last_refresh;
        }
        // Full rebuild. The clear anchor only matters here: it is positional,
        // and idle frames never reach this point. Lines pushed at or before
        // the clear generation are "old" and sit at the ring's front; the
        // retained lines pushed after Clear are exactly the tail of length
        // `generation - clear` (eviction is oldest-first, so a retained new
        // line can never be preceded by an evicted old one). Hiding that
        // front prefix hides every old line and nothing new.
        let mut start = 0;
        if let Some(clear_gen) = self.clear_after_generation {
            let pushed = logs_generation.saturating_sub(clear_gen) as usize;
            start = start.max(logs.len().saturating_sub(pushed));
        }
        let mut rows = Vec::new();
        for (offset, (from_core, line)) in logs.iter().enumerate().skip(start) {
            let level = line_level(line);
            if passes(self.level, level) && contains_ascii_case_insensitive(line, needle) {
                rows.push(FilteredRow {
                    seq: ring.front() + offset as u64,
                    from_core: *from_core,
                    level,
                    line: line.clone(),
                });
            }
        }
        // A pure append (new lines only) keeps the old rows as a strict
        // prefix, so index-keyed selection stays valid — a line arriving
        // mid-drag in a live session must not silently move the selection
        // (and the copy action) onto other rows. Rotation, filter changes
        // and clears shift indices and drop the selection. (The append-only
        // case itself is handled above; this prefix check only decides
        // whether an eviction of unadmitted lines left the indices alone.)
        let selection_survives = self.view.as_ref().is_some_and(|view| {
            view.rows.len() < rows.len() && view.rows.iter().zip(&rows).all(|(old, new)| old == new)
        });
        if !selection_survives {
            self.rows_selection = RowSelection::default();
        }
        // A rebuild replaces every measured row: a width re-fit pending
        // from before the rebuild is stale (the fresh view starts
        // unmeasured and is laid out at the current width immediately).
        self.pending_refit = None;
        self.view = Some(FilteredView {
            key: ViewKey {
                ring,
                level: self.level,
                needle: needle.to_owned(),
                clear_after_generation: self.clear_after_generation,
            },
            rows,
            heights: Vec::new(),
            galleys: Vec::new(),
            measured_width: 0.0,
            spacing_y: 0.0,
            prefix: Vec::new(),
        });
        self.last_refresh = RefreshOutcome::Rebuilt {
            rows: self.view.as_ref().map_or(0, |view| view.rows.len()),
            selection_survives,
        };
        self.last_refresh
    }

    /// Virtualized rendering: only the rows intersecting `viewport` (content
    /// coordinates) are laid out per frame, positioned by the memoized
    /// prefix sums — O(log n) lookup, then the visible band only. Heights
    /// are measured once per rebuild and re-fitted when the wrap width or
    /// spacing changes; a forward refresh lays out only its admitted tail.
    /// Both are layout passes, not filter rebuilds.
    fn show_rows(&mut self, ui: &mut Ui, viewport: egui::Rect, lang: Language) {
        // The re-fit decision and its settle tracker must run before `view`
        // is borrowed mutably below: `pending_refit` updates
        // are field-local, so they compose with the shared `view` read.
        let Some(view_snapshot) = self.view.as_ref() else {
            return;
        };
        if view_snapshot.rows.is_empty() {
            return;
        }
        let available_width = ui.available_width();
        let spacing_y = ui.spacing().item_spacing.y;
        // One layout pass serves both the row heights and the galleys the
        // custom row selection does its cursor math on. Laid out with the
        // placeholder color: they are never painted — the label paints the
        // text with the per-frame color. A full re-measure runs only when
        // the measured width/spacing changed (a re-fit) or no rows have
        // been measured yet (a fresh rebuild); a forward refresh leaves the
        // cached vectors as a measured prefix of `rows`, so only the newly
        // admitted tail is laid out here.
        //
        // Width re-fits are coalesced: a window drag streams
        // the available width at frame rate, and a full re-measure lays
        // out every filtered row (up to the full ring cap) — re-fitting
        // per frame turned a drag into several full-ring re-layouts. An
        // already-measured layout re-fits only once the width has held
        // still within [`REFIT_EPSILON`] for [`REFIT_SETTLE_SECS`], so a
        // drag performs at most one full re-layout, at its final width. A
        // fresh rebuild's layout is never deferred (nothing would paint),
        // and spacing changes (style-level, never streaming) re-fit
        // immediately.
        let refit = if view_snapshot.heights.is_empty() || view_snapshot.spacing_y != spacing_y {
            true
        } else if (view_snapshot.measured_width - available_width).abs() > REFIT_EPSILON {
            // The layout is stale and the width may still be streaming:
            // run the settle tracker (field-local updates).
            let now = ui.input(|i| i.time);
            let settled = self.pending_refit.as_ref().is_some_and(|pending| {
                (pending.width - available_width).abs() <= REFIT_EPSILON
                    && now - pending.since >= REFIT_SETTLE_SECS
            });
            if settled {
                self.pending_refit = None;
                true
            } else {
                if self
                    .pending_refit
                    .as_ref()
                    .is_none_or(|pending| (pending.width - available_width).abs() > REFIT_EPSILON)
                {
                    self.pending_refit = Some(PendingRefit {
                        width: available_width,
                        since: now,
                    });
                }
                // Arm a frame at the settle deadline so the re-fit is not
                // starved in reactive repaint mode.
                if let Some(pending) = &self.pending_refit {
                    let remaining = REFIT_SETTLE_SECS - (now - pending.since);
                    if remaining > 0.0 {
                        ui.ctx()
                            .request_repaint_after(std::time::Duration::from_secs_f64(remaining));
                    }
                }
                false
            }
        } else {
            // The layout is current (sub-epsilon drift): drop any stale
            // settle candidate.
            self.pending_refit = None;
            false
        };
        let Some(view) = &mut self.view else { return };
        let mut pass = LayoutPass::None;
        if refit || view.heights.len() != view.rows.len() {
            let font_id = TextStyle::Monospace.resolve(ui.style());
            let first_unmeasured = if refit || view.heights.is_empty() {
                0
            } else {
                view.heights.len()
            };
            let mut heights = Vec::with_capacity(view.rows.len() - first_unmeasured);
            let mut galleys = Vec::with_capacity(view.rows.len() - first_unmeasured);
            for row in &view.rows[first_unmeasured..] {
                let galley = ui.ctx().fonts_mut(|fonts| {
                    fonts.layout(
                        row.line.clone(),
                        font_id.clone(),
                        Color32::PLACEHOLDER,
                        available_width,
                    )
                });
                let height = galley.rect.height();
                heights.push(height);
                galleys.push(galley);
            }
            if first_unmeasured == 0 {
                view.heights = heights;
                view.galleys = galleys;
                pass = LayoutPass::Full {
                    rows: view.rows.len(),
                };
            } else {
                view.heights.extend(heights);
                view.galleys.extend(galleys);
                pass = LayoutPass::Tail {
                    rows: view.rows.len() - first_unmeasured,
                };
            }
            view.measured_width = available_width;
            view.spacing_y = spacing_y;
            if first_unmeasured == 0 {
                let mut prefix = Vec::with_capacity(view.heights.len() + 1);
                let mut y = 0.0;
                prefix.push(0.0);
                for &height in &view.heights {
                    y += height + spacing_y;
                    prefix.push(y);
                }
                view.prefix = prefix;
            } else {
                // Extend the retained prefix sums past the measured tail.
                let mut y = view.prefix[view.prefix.len() - 1];
                for &height in &view.heights[first_unmeasured..] {
                    y += height + spacing_y;
                    view.prefix.push(y);
                }
            }
        }
        self.last_layout = pass;
        let rows = view.rows.len();
        // Content height for the scrollbar range and stick-to-bottom; the
        // trailing slot's spacing is trimmed, matching egui's own layout.
        ui.set_height((view.prefix[rows] - view.spacing_y).max(0.0));
        let band = visible_band(&view.prefix, &view.heights, viewport.min.y, viewport.max.y);
        if band.start >= band.end {
            return;
        }
        // Row slots are content coordinates; painting positions are screen
        // coordinates with the content origin at the scroll area's inner
        // top (`ui.max_rect().top()`, which already includes the scroll
        // offset) — mirroring `ScrollArea::show_rows`. Anchoring at the raw
        // prefix would paint rows at fixed screen positions regardless of
        // the offset and inflate the measured content height.
        let band_rect = egui::Rect::from_x_y_ranges(
            ui.max_rect().x_range(),
            ui.max_rect().top() + view.prefix[band.start]
                ..=ui.max_rect().top() + view.prefix[band.end],
        );
        // Screen rect per visible row, for the selection widget and the
        // press-elsewhere deselect.
        let rects: Vec<egui::Rect> = band
            .clone()
            .map(|index| {
                egui::Rect::from_min_size(
                    egui::pos2(
                        band_rect.left(),
                        band_rect.top() + view.prefix[index] - view.prefix[band.start],
                    ),
                    egui::vec2(band_rect.width(), view.heights[index]),
                )
            })
            .collect();
        ui.scope_builder(egui::UiBuilder::new().max_rect(band_rect), |ui| {
            ui.skip_ahead_auto_ids(2 * band.start);
            let dark = ui.visuals().dark_mode;
            // The closure owns the selection for this frame; persisting to
            // the field at the end keeps the updates visible to later
            // frames (a plain local captured by value would be a dead copy).
            let mut selection = self.rows_selection;
            // A primary press that lands on no row clears the selection —
            // but not while a popup is open: the copy menu's own click must
            // preserve the selection it is about to copy. Secondary presses
            // never clear (a right-click must not deselect, whether it
            // lands on a row or on empty pane space).
            if ui.input(|i| i.pointer.primary_pressed())
                && !ui.ctx().any_popup_open()
                && let Some(pointer) = ui.input(|i| i.pointer.interact_pos())
                && !rects.iter().any(|r| r.contains(pointer))
            {
                selection = RowSelection::default();
            }
            // Copy funnel for the two triggers below: the row context menu
            // ("Copy selection") and the platform copy chord. The menu
            // resolves per row; the chord is the screen's own action, so it
            // copies the selection from anywhere on the Logs screen unless a
            // focused text edit keeps its own copy behavior. The chord
            // arrives as egui's Copy event (the backend maps Ctrl+C there,
            // not to a key press) and is looked up once per frame. Both
            // triggers act on the whole selection, copied after the row loop
            // from the full view's rows.
            let mut copy_requested = !ui.ctx().text_edit_focused()
                && ui.input(|i| {
                    i.events
                        .iter()
                        .any(|event| matches!(event, egui::Event::Copy))
                });
            for (slot, index) in band.enumerate() {
                let row = &view.rows[index];
                let row_rect = rects[slot];
                let galley = &view.galleys[index];
                let color = line_color(row.from_core, row.level, dark);
                // Selection highlight, painted under the label.
                if let Some((start, end)) = Self::selection_range(selection, index, &row.line) {
                    let a = galley.pos_from_cursor(start);
                    let b = galley.pos_from_cursor(end);
                    ui.painter().rect_filled(
                        egui::Rect::from_min_max(
                            row_rect.min + a.min.to_vec2(),
                            row_rect.min + b.max.to_vec2(),
                        ),
                        0.0,
                        ui.visuals().selection.bg_fill,
                    );
                }
                // Non-selectable label: egui's label-selection machinery —
                // which collapses on any press and owns private state —
                // must never run on rows. The label still paints the text
                // with the per-frame color and keeps the row in the
                // accesskit tree; the selection widget sits on top and
                // claims all presses.
                let response = ui
                    .interact(row_rect, ui.next_auto_id(), egui::Sense::click_and_drag())
                    .on_hover_cursor(egui::CursorIcon::Text);
                ui.add(
                    egui::Label::new(
                        RichText::new(row.line.as_str())
                            .text_style(TextStyle::Monospace)
                            .color(color),
                    )
                    .selectable(false),
                );
                // The row context menu: the mouse-only copy trigger, which
                // right-clicks leave the selection intact for.
                response.context_menu(|ui| {
                    if ui.button(t(lang, Key::LogsCopySelection)).clicked() {
                        copy_requested = true;
                        ui.close();
                    }
                });
                // Mirror egui's label selection in custom state, which
                // right-clicks deliberately leave untouched.
                if response.double_clicked() {
                    if let Some(pointer) = response.interact_pointer_pos() {
                        let ccursor = galley.cursor_from_pos(pointer - row_rect.min);
                        let (lo, hi) = Self::word_bounds_at(&row.line, ccursor.index.0);
                        selection = RowSelection {
                            anchor: Some(RowCursor {
                                row: index,
                                ccursor: egui::text::CCursor::new(lo),
                            }),
                            active: Some(RowCursor {
                                row: index,
                                ccursor: egui::text::CCursor::new(hi),
                            }),
                        };
                    }
                } else if ui.input(|i| i.pointer.primary_pressed()) && response.hovered() {
                    // The press makes the row the keyboard-focus owner: the
                    // copy chord must reach the row selection rather than a
                    // text field focused earlier (egui surrenders that focus
                    // on clicks only, and a drag-select is not a click).
                    response.request_focus();
                    if let Some(pointer) = response.interact_pointer_pos() {
                        let cursor = RowCursor {
                            row: index,
                            ccursor: galley.cursor_from_pos(pointer - row_rect.min),
                        };
                        selection = RowSelection {
                            anchor: Some(cursor),
                            active: Some(cursor),
                        };
                    }
                } else if response.dragged_by(egui::PointerButton::Primary)
                    || (ui.input(|i| i.pointer.primary_down())
                        && selection.anchor.is_some()
                        && response.hovered())
                {
                    // Drag within the anchor row, or over another row while
                    // the primary button is down: extend the active end.
                    if let Some(pointer) = response.interact_pointer_pos() {
                        selection.active = Some(RowCursor {
                            row: index,
                            ccursor: galley.cursor_from_pos(pointer - row_rect.min),
                        });
                    }
                }
            }
            self.rows_selection = selection;
            if copy_requested {
                let text = Self::selection_text(selection, &view.rows);
                if !text.is_empty() {
                    ui.ctx().copy_text(text);
                }
            }
        });
    }

    /// The row's slice of the custom selection, sorted, or `None` when the
    /// row does not intersect it (or the slice is empty).
    fn selection_range(
        selection: RowSelection,
        index: usize,
        line: &str,
    ) -> Option<(egui::text::CCursor, egui::text::CCursor)> {
        let anchor = selection.anchor?;
        let active = selection.active?;
        let (lo, hi) = if (anchor.row, anchor.ccursor.index) <= (active.row, active.ccursor.index) {
            (anchor, active)
        } else {
            (active, anchor)
        };
        if lo.row > index || index > hi.row {
            return None;
        }
        let start = if index == lo.row {
            lo.ccursor
        } else {
            egui::text::CCursor::new(0)
        };
        let end = if index == hi.row {
            hi.ccursor
        } else {
            egui::text::CCursor::new(line.chars().count())
        };
        (start != end).then_some((start, end))
    }

    /// Clipboard text for `selection` over the whole memoized view: the
    /// first row from the lower cursor, every row in between in full, and
    /// the last row up to the upper cursor. Cursors sit on character
    /// boundaries — the character under the upper cursor stays out, the
    /// same boundary the highlight paints to — and the text comes from
    /// `rows` rather than the painted band, so a selection spanning past
    /// the viewport copies in full. Reversed anchors select the same slice
    /// (the ends are ordered by row, then cursor); rows are joined with one
    /// newline. Cursors clamp to their row, and an empty, collapsed, or
    /// out-of-range selection yields the empty string, which callers test
    /// before touching the clipboard.
    fn selection_text(selection: RowSelection, rows: &[FilteredRow]) -> String {
        let (Some(anchor), Some(active)) = (selection.anchor, selection.active) else {
            return String::new();
        };
        let (lo, hi) = if (anchor.row, anchor.ccursor.index) <= (active.row, active.ccursor.index) {
            (anchor, active)
        } else {
            (active, anchor)
        };
        if lo.row >= rows.len() {
            return String::new();
        }
        let last_row = hi.row.min(rows.len() - 1);
        let mut text = String::new();
        for (offset, row) in rows[lo.row..=last_row].iter().enumerate() {
            if offset > 0 {
                text.push('\n');
            }
            let line = row.line.as_str();
            let len = line.chars().count();
            let cursor_start = if offset == 0 { lo.ccursor.index.0 } else { 0 };
            let cursor_end = if offset == last_row - lo.row {
                hi.ccursor.index.0
            } else {
                len
            };
            let start = cursor_start.min(len);
            let end = cursor_end.clamp(start, len);
            text.push_str(&line[char_byte_offset(line, start)..char_byte_offset(line, end)]);
        }
        text
    }

    /// Character range of the whitespace-delimited word containing `index`
    /// (clamped to the text). On a space the range is empty — nothing is
    /// selected, mirroring egui's own word-select behavior.
    fn word_bounds_at(text: &str, index: usize) -> (usize, usize) {
        let len = text.chars().count();
        let index = index.min(len);
        let mut lo = index;
        while lo > 0 && text.chars().nth(lo - 1).is_some_and(|c| !c.is_whitespace()) {
            lo -= 1;
        }
        let mut hi = index;
        while hi < len && text.chars().nth(hi).is_some_and(|c| !c.is_whitespace()) {
            hi += 1;
        }
        (lo, hi)
    }
}

/// Byte offset of character index `index` in `line`; one past the last
/// character (the string's byte length) once the index reaches the
/// character count. The custom row selection carries character cursors
/// ([`egui::text::CCursor`]), while the clipboard slice needs byte bounds.
fn char_byte_offset(line: &str, index: usize) -> usize {
    line.char_indices()
        .nth(index)
        .map_or(line.len(), |(byte, _)| byte)
}

/// Rows of a virtualized list whose slots (prefix sums) intersect the given
/// viewport band, in content coordinates. Row `i` occupies
/// `[prefix[i], prefix[i + 1])`.
fn visible_band(
    prefix: &[f32],
    heights: &[f32],
    viewport_min_y: f32,
    viewport_max_y: f32,
) -> std::ops::Range<usize> {
    let n = heights.len();
    if n == 0 {
        return 0..0;
    }
    let first = prefix[1..].partition_point(|&p| p <= viewport_min_y);
    let last = prefix.partition_point(|&p| p < viewport_max_y).min(n);
    first..last.max(first)
}

fn logger_restart_feedback(lang: Language, result: Result<(), DiagError>) -> (bool, String) {
    match result {
        Ok(()) => (true, t(lang, Key::LogsRestartFeedbackOk).into()),
        Err(error) => (false, error.text(lang)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::settings::Language;
    use crate::ui::test_rig::{UiTestRig, screen_harness};
    use egui_kittest::{Harness, kittest::Queryable as _};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Push one line exactly like the app's `LogBuffer::push`:
    /// every push advances the ring's monotonic generation — the identity
    /// the memoized filtered view is keyed on. Direct-ring tests below must
    /// route their pushes through this helper, or `refresh_view` would see
    /// an unchanged ring and keep a stale view.
    fn push_line(
        logs: &mut VecDeque<(bool, String)>,
        generation: &mut u64,
        from_core: bool,
        line: &str,
    ) {
        *generation += 1;
        logs.push_back((from_core, line.to_string()));
    }

    /// User report: after [Clear view], newly arrived log lines were hidden
    /// again as soon as the (recurring) marker line re-appeared, making the
    /// tab unusable. The clear anchor must never advance past the lines that
    /// existed when Clear was pressed.
    #[test]
    fn clear_view_keeps_new_lines_visible_when_the_marker_line_recurs() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut r = rig.borrow_mut();
            for i in 0..40 {
                let line = if i % 4 == 3 {
                    "[Info] recurring heartbeat".to_string()
                } else {
                    format!("2026/08/10 12:00:{i:02}.000 [Info] line {i}")
                };
                r.push_log(false, line);
            }
        }
        let rig_handle = rig.clone();
        let mut harness = Harness::builder()
            .with_size(egui::vec2(700.0, 400.0))
            .build_ui_state(
                move |ui, screen: &mut LogsScreen| {
                    let mut rig = rig_handle.borrow_mut();
                    screen.show(ui, &mut rig.ctx())
                },
                LogsScreen::default(),
            );
        harness.run();

        harness.get_by_label("Clear view").click();
        harness.run();

        // New lines arrive; the last line at Clear time ("recurring
        // heartbeat") appears again between two fresh lines. Pushed through
        // `push_log` so the ring's generation advances with each line —
        // a bare `logs.push_back` would leave the memoized
        // view stale.
        {
            let mut r = rig.borrow_mut();
            r.push_log(
                false,
                "2026/08/10 12:01:00.000 [Info] fresh line A".to_string(),
            );
            r.push_log(false, "[Info] recurring heartbeat".to_string());
            r.push_log(
                false,
                "2026/08/10 12:01:01.000 [Info] fresh line B".to_string(),
            );
        }
        // The ring grew, so the view re-filters; forced steps let the
        // stick-to-bottom offset settle on the new content height.
        harness.run_steps(4);

        // Rows count as visible only when actually painted inside the scroll
        // area's viewport (the band is anchored at the content origin).
        let viewport = egui::Rect::from_min_max(egui::pos2(0.0, 60.0), egui::pos2(700.0, 400.0));
        for needle in ["fresh line A", "fresh line B"] {
            assert!(
                harness
                    .query_all_by(|n| n.value().is_some_and(|v| v.contains(needle)))
                    .next()
                    .is_some_and(|n| n.rect().intersects(viewport)),
                "a line logged after Clear view must stay visible: {needle}"
            );
        }
    }

    /// User report: [Clear view] sometimes left old log lines visible. The
    /// clear anchor is the last line's *text*; when that text had appeared
    /// earlier in the ring (a recurring line), the anchor sat at its first
    /// occurrence and every line after it — including lines logged before
    /// Clear — stayed visible. Clearing must hide every line present at
    /// press time.
    #[test]
    fn clear_view_hides_every_line_present_at_press_time() {
        let mut logs = VecDeque::new();
        let mut generation = 0u64;
        // A recurring line ("status ok") appears early, and again as the
        // buffer's last line at the moment Clear view is pressed — the
        // duplicate is textually identical, so a text anchor cannot tell
        // the two apart.
        push_line(&mut logs, &mut generation, false, "[Info] status ok");
        push_line(&mut logs, &mut generation, false, "[Info] connect");
        push_line(&mut logs, &mut generation, false, "[Info] status ok");
        let mut screen = LogsScreen::default();
        assert!(screen.refresh_view(&logs, generation).changed());
        screen.clear_after_generation = Some(generation);
        assert!(screen.refresh_view(&logs, generation).changed());
        assert!(
            screen.view.as_ref().unwrap().rows.is_empty(),
            "Clear view must hide every line present at press time"
        );
    }

    /// The positional clear anchor satisfies both halves the textual anchor
    /// had to trade off: lines present at press time stay hidden even when
    /// their text recurs *earlier*, and lines pushed after Clear stay
    /// visible even when the same text recurs *later*. Neither `position`
    /// nor `rposition` on a text marker can do both.
    #[test]
    fn clear_view_hides_old_and_keeps_new_lines_when_text_recurs_on_both_sides() {
        let mut logs = VecDeque::new();
        let mut generation = 0u64;
        push_line(&mut logs, &mut generation, false, "[Info] status ok");
        push_line(&mut logs, &mut generation, false, "[Info] connect");
        push_line(&mut logs, &mut generation, false, "[Info] status ok");
        let mut screen = LogsScreen::default();
        assert!(screen.refresh_view(&logs, generation).changed());
        // Clear pressed now, generation 3.
        screen.clear_after_generation = Some(generation);
        assert!(screen.refresh_view(&logs, generation).changed());
        assert!(screen.view.as_ref().unwrap().rows.is_empty());
        // New lines arrive, including another textually identical
        // "status ok".
        push_line(&mut logs, &mut generation, false, "[Info] fresh A");
        push_line(&mut logs, &mut generation, false, "[Info] status ok");
        push_line(&mut logs, &mut generation, false, "[Info] fresh B");
        assert!(screen.refresh_view(&logs, generation).changed());
        let rows = &screen.view.as_ref().unwrap().rows;
        assert_eq!(
            rows.iter().map(|row| row.line.as_str()).collect::<Vec<_>>(),
            ["[Info] fresh A", "[Info] status ok", "[Info] fresh B"]
        );
    }

    /// User report: on first open the tab showed only a portion of the log
    /// content and would not scroll. The view must cover the entire ring
    /// (the app bounds the ring itself), and wheel scrolling must reach the
    /// oldest buffered line.
    #[test]
    fn logs_tab_scrolls_back_to_the_first_buffered_line() {
        let rig = Rc::new(RefCell::new(UiTestRig::default()));
        {
            let mut r = rig.borrow_mut();
            for i in 0..4500 {
                r.push_log(false, format!("line {i:04}"));
            }
        }
        let rig_handle = rig.clone();
        let mut harness = Harness::builder()
            .with_size(egui::vec2(700.0, 400.0))
            .build_ui_state(
                move |ui, screen: &mut LogsScreen| {
                    let mut rig = rig_handle.borrow_mut();
                    screen.show(ui, &mut rig.ctx())
                },
                LogsScreen::default(),
            );
        harness.run();

        // A row counts as visible only when actually painted inside the
        // scroll area's viewport (the band is anchored at the content
        // origin, so off-viewport rows would be laid out off-screen).
        let viewport = egui::Rect::from_min_max(egui::pos2(0.0, 60.0), egui::pos2(700.0, 400.0));
        let row_on_screen = |harness: &egui_kittest::Harness<LogsScreen>, needle| {
            harness
                .query_all_by(|n| n.value().is_some_and(|v| v.contains(needle)))
                .next()
                .is_some_and(|n| n.rect().intersects(viewport))
        };

        // Stick-to-bottom: the newest line is on screen.
        assert!(
            row_on_screen(&harness, "line 4499"),
            "the newest line must be visible on first open"
        );

        // Wheel-scroll up past the whole content (100 px per step; 4500
        // rows are ~75 000 px tall) and verify the first buffered line
        // becomes reachable — the ring tail must not be cut off. The wheel
        // is only honored while the pointer hovers the scroll area.
        harness
            .input_mut()
            .events
            .push(egui::Event::PointerMoved(egui::pos2(350.0, 300.0)));
        for _ in 0..1200 {
            harness.input_mut().events.push(egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, 100.0),
                phase: egui::TouchPhase::Move,
                modifiers: egui::Modifiers::NONE,
            });
            harness.step();
        }
        assert!(
            row_on_screen(&harness, "line 0000"),
            "scrolling must reach the first buffered line"
        );
    }

    #[test]
    fn logger_result_describes_reopened_outputs_not_cleared_logs() {
        let (ok, message) = logger_restart_feedback(Language::En, Ok(()));
        assert!(ok);
        assert!(message.contains("reopened"));
        assert!(!message.contains("cleared"));
    }

    /// The restart button opens a per-request reply channel. The
    /// screen captures the sender from the emitted command and sends the
    /// terminal on it; the feedback text must render from that reply — no
    /// bus, no event.
    #[test]
    fn restart_click_captures_reply_channel_and_renders_feedback() {
        let rig = UiTestRig {
            phase: CorePhase::Running,
            ..UiTestRig::default()
        };
        let mut harness = screen_harness(rig, LogsScreen::default());
        harness.run();
        harness
            .get_by_label(t(Language::En, Key::LogsRestartLogger))
            .click();
        harness.run();

        // The click must send exactly one RestartLogger command carrying
        // the request channel; tests hold the sender and reply as the
        // runtime would.
        let reply = {
            let cmd = harness
                .state_mut()
                .1
                ._cmd_rx
                .try_recv()
                .expect("the restart click must send a command");
            if let CoreCmd::RestartLogger { reply } = cmd {
                reply
            } else {
                panic!("expected RestartLogger, got a different command");
            }
        };
        assert!(
            harness.state().0.pending_logger_request.is_pending(),
            "the pending slot must hold the request"
        );

        reply
            .send(Ok(()))
            .expect("the screen must listen for the reply");
        harness.run();

        assert!(
            !harness.state().0.pending_logger_request.is_pending(),
            "a landed reply must clear the pending slot"
        );
        let feedback = t(Language::En, Key::LogsRestartFeedbackOk);
        assert!(
            harness
                .query_all_by(|n| n.value().is_some_and(|v| v.contains(feedback)))
                .next()
                .is_some(),
            "the Ok terminal must render as feedback text"
        );
    }

    /// Memoization contract: the filtered view rebuilds exactly once per
    /// real input change — first build, log push, filter text change, level
    /// change, clear-marker change — and never on idle frames. The
    /// `refresh_view` return value is the seam: `true` on the frame that
    /// changed, `false` on every frame that reuses the memo.
    #[test]
    fn refresh_view_rebuilds_only_when_an_input_changes() {
        let mut logs = VecDeque::new();
        let mut generation = 0u64;
        let mut screen = LogsScreen::default();

        // First frame on the screen builds the view once.
        assert!(screen.refresh_view(&logs, generation).changed());

        // Idle frames never rebuild.
        for _ in 0..10 {
            assert!(!screen.refresh_view(&logs, generation).changed());
        }

        // One pushed line → exactly one rebuild.
        push_line(
            &mut logs,
            &mut generation,
            false,
            "2026/08/10 12:00:00.123 [Info] connected",
        );
        assert!(screen.refresh_view(&logs, generation).changed());
        assert_eq!(screen.view.as_ref().unwrap().rows.len(), 1);
        assert!(!screen.refresh_view(&logs, generation).changed());

        // Filter text change → exactly one rebuild, then stable.
        screen.text = "CONNECTED".to_string();
        assert!(screen.refresh_view(&logs, generation).changed());
        assert!(!screen.refresh_view(&logs, generation).changed());

        // Level change → one rebuild; the Info line is hidden.
        screen.text.clear();
        screen.level = LevelFilter::WarningPlus;
        assert!(screen.refresh_view(&logs, generation).changed());
        assert!(screen.view.as_ref().unwrap().rows.is_empty());

        // Clear-view generation → one rebuild; rows through the clear point
        // hidden.
        screen.level = LevelFilter::All;
        push_line(
            &mut logs,
            &mut generation,
            true,
            "2026/08/10 12:00:01.000 [Warning] retry",
        );
        assert!(screen.refresh_view(&logs, generation).changed());
        screen.clear_after_generation = Some(generation);
        assert!(screen.refresh_view(&logs, generation).changed());
        assert!(screen.view.as_ref().unwrap().rows.is_empty());
        // The pre-clear lines rotate out entirely; the positional anchor
        // survives the rotation and self-corrects to "show everything" —
        // no old line remains to hide. One rebuild per ring change.
        push_line(
            &mut logs,
            &mut generation,
            true,
            "2026/08/10 12:00:02.000 [Error] fail",
        );
        assert!(screen.refresh_view(&logs, generation).changed());
        logs.pop_front();
        logs.pop_front();
        assert!(screen.refresh_view(&logs, generation).changed());
        assert_eq!(
            screen.clear_after_generation,
            Some(2),
            "the clear anchor survives full rotation"
        );
        assert_eq!(screen.view.as_ref().unwrap().rows.len(), 1);
        assert_eq!(
            screen.view.as_ref().unwrap().rows[0].line,
            "2026/08/10 12:00:02.000 [Error] fail"
        );
    }

    /// The index-keyed custom selection survives pure-append rebuilds (a
    /// line arriving mid-drag in a live session must not silently degrade
    /// the copy menu to the whole-row fallback), but drops when indices
    /// actually shift: front eviction, filter change, level change.
    #[test]
    fn refresh_view_keeps_selection_on_pure_append_only() {
        let mut logs = VecDeque::new();
        let mut generation = 0u64;
        push_line(
            &mut logs,
            &mut generation,
            false,
            "2026/08/10 12:00:00.123 [Info] first",
        );
        let mut screen = LogsScreen::default();
        screen.refresh_view(&logs, generation);
        screen.rows_selection = RowSelection {
            anchor: Some(RowCursor {
                row: 0,
                ccursor: egui::text::CCursor::new(2),
            }),
            active: Some(RowCursor {
                row: 0,
                ccursor: egui::text::CCursor::new(5),
            }),
        };
        // Pure append: the old rows are a strict prefix, indices stay valid.
        push_line(
            &mut logs,
            &mut generation,
            false,
            "2026/08/10 12:00:01.000 [Info] second",
        );
        assert!(screen.refresh_view(&logs, generation).changed());
        assert!(
            screen.rows_selection.anchor.is_some(),
            "an append-only rebuild must keep the selection"
        );
        // Front eviction shifts indices → selection must go.
        logs.pop_front();
        assert!(screen.refresh_view(&logs, generation).changed());
        assert_eq!(screen.rows_selection.anchor, None);
        // Filter change → selection must go.
        screen.rows_selection = RowSelection {
            anchor: Some(RowCursor {
                row: 0,
                ccursor: egui::text::CCursor::new(1),
            }),
            active: Some(RowCursor {
                row: 0,
                ccursor: egui::text::CCursor::new(2),
            }),
        };
        screen.text = "FIRST".to_string();
        assert!(screen.refresh_view(&logs, generation).changed());
        assert_eq!(screen.rows_selection.anchor, None);
    }

    /// Push one line into a ring that evicts at `cap`, the shape
    /// `LogBuffer::push` gives the screen once either cap binds: the counter
    /// advances by one and the oldest entry drops.
    fn push_capped(
        logs: &mut VecDeque<(bool, String)>,
        generation: &mut u64,
        cap: usize,
        line: &str,
    ) {
        push_line(logs, generation, false, line);
        while logs.len() > cap {
            logs.pop_front();
        }
    }

    /// A capped ring rotates: each push evicts the oldest line. The memoized
    /// view must refresh incrementally — dropping the rows whose lines left
    /// the ring (with their measured layout, rebased on the survivor front)
    /// and admitting the new tail — and it must agree row for row with a
    /// view built from scratch at the same ring state.
    #[test]
    fn rotation_at_the_cap_drops_and_admits_rows_and_matches_a_rebuild() {
        const CAP: usize = 4;
        let mut logs = VecDeque::new();
        let mut generation = 0u64;
        for index in 0..CAP {
            push_capped(
                &mut logs,
                &mut generation,
                CAP,
                &format!("2026/08/10 12:00:0{index}.000 [Info] line {index}"),
            );
        }
        let mut screen = LogsScreen::default();
        assert!(screen.refresh_view(&logs, generation).changed());
        // Simulate a measured frame over the four admitted rows: heights,
        // galleys and prefix sums cover the same prefix, as `show_rows`
        // leaves them.
        let ctx = egui::Context::default();
        ctx.set_fonts(egui::FontDefinitions::default());
        // Fonts are only usable after a pass has run, and the seam test needs
        // galleys to hand the view as its measured prefix.
        let mut output = ctx.run_ui(egui::RawInput::default(), |_| {});
        output.textures_delta.clear();
        let galley = |text: &str| {
            ctx.fonts_mut(|fonts| {
                fonts.layout(
                    text.to_owned(),
                    egui::FontId::default(),
                    egui::Color32::PLACEHOLDER,
                    100.0,
                )
            })
        };
        {
            let view = screen.view.as_mut().unwrap();
            view.heights = vec![10.0; CAP];
            view.galleys = (0..CAP)
                .map(|index| galley(&format!("line {index}")))
                .collect();
            view.prefix = vec![0.0, 10.0, 20.0, 30.0, 40.0];
        }

        // Two arrivals, two evictions: the ring stays at its cap.
        push_capped(
            &mut logs,
            &mut generation,
            CAP,
            "2026/08/10 12:00:04.000 [Info] line 4",
        );
        push_capped(
            &mut logs,
            &mut generation,
            CAP,
            "2026/08/10 12:00:05.000 [Info] line 5",
        );
        assert!(screen.refresh_view(&logs, generation).changed());
        let view = screen.view.as_ref().unwrap();
        let lines: Vec<&str> = view.rows.iter().map(|row| row.line.as_str()).collect();
        assert_eq!(
            lines,
            [
                "2026/08/10 12:00:02.000 [Info] line 2",
                "2026/08/10 12:00:03.000 [Info] line 3",
                "2026/08/10 12:00:04.000 [Info] line 4",
                "2026/08/10 12:00:05.000 [Info] line 5",
            ],
            "the two evicted rows are gone and both arrivals are admitted"
        );
        assert_eq!(
            view.rows.iter().map(|row| row.seq).collect::<Vec<_>>(),
            [2, 3, 4, 5],
            "each row carries the ring position of its line"
        );
        assert_eq!(
            view.heights,
            [10.0, 10.0],
            "the survivors keep their measurements; the tail is left to the layout pass"
        );
        assert_eq!(
            view.prefix,
            [0.0, 10.0, 20.0],
            "the prefix sums are rebased on the survivor front"
        );

        // The same ring state through a view with no history: the incremental
        // refresh must agree with the rebuild row for row.
        let mut fresh = LogsScreen::default();
        assert!(fresh.refresh_view(&logs, generation).changed());
        let rebuilt = fresh.view.as_ref().unwrap();
        assert_eq!(
            rebuilt
                .rows
                .iter()
                .map(|row| (row.seq, row.line.as_str()))
                .collect::<Vec<_>>(),
            view.rows
                .iter()
                .map(|row| (row.seq, row.line.as_str()))
                .collect::<Vec<_>>(),
        );
        assert!(
            !screen.refresh_view(&logs, generation).changed(),
            "the refreshed key still makes the next idle frame a no-op"
        );
    }

    /// One push can evict several lines at once: the byte cap binds against a
    /// run of short lines when a long one arrives, so the length shrinks while
    /// the counter advances. That refresh is still a forward one — the view
    /// drops every departed row and admits only the arrival — and the frames
    /// that follow stay incremental.
    #[test]
    fn a_push_that_evicts_a_run_of_lines_still_refreshes_incrementally() {
        const CAP: usize = 4;
        let mut rig = UiTestRig::default();
        for index in 0..CAP {
            push_capped_rig(&mut rig, CAP, index);
        }
        let mut screen = LogsScreen::default();
        let ctx = egui::Context::default();
        ctx.set_fonts(egui::FontDefinitions::default());
        run_frame(&ctx, &mut screen, &mut rig);
        assert!(matches!(screen.last_layout, LayoutPass::Full { .. }));

        // One arrival that pushes three short lines out of the ring.
        rig.push_log(
            false,
            "2026/08/10 12:01:00.000 [Info] a much longer line than the rest".to_string(),
        );
        for _ in 0..CAP - 1 {
            rig.logs.pop_front();
        }
        assert_eq!(rig.logs.len(), CAP - 2);
        run_frame(&ctx, &mut screen, &mut rig);

        let view = screen.view.as_ref().unwrap();
        assert_eq!(
            view.rows.iter().map(|row| row.seq).collect::<Vec<_>>(),
            [3, 4],
            "the survivors keep their positions and the arrival is admitted"
        );
        assert_eq!(view.rows.len(), view.heights.len());
        assert_eq!(view.prefix.len(), view.rows.len() + 1);
        assert!(
            matches!(screen.last_layout, LayoutPass::Tail { .. }),
            "a multi-line eviction must not re-measure the ring: {:?}",
            screen.last_layout
        );

        // The next arrival is a plain one-line rotation at the same length.
        push_capped_rig(&mut rig, 2, 5);
        run_frame(&ctx, &mut screen, &mut rig);
        assert_eq!(
            screen
                .view
                .as_ref()
                .unwrap()
                .rows
                .iter()
                .map(|row| row.seq)
                .collect::<Vec<_>>(),
            [4, 5]
        );
        assert_eq!(
            screen.last_layout,
            LayoutPass::Tail { rows: 1 },
            "the rotation measured exactly its admitted row"
        );
    }

    /// Rotation that evicts lines the filter never admitted leaves the row
    /// indices alone, so the index-keyed selection survives; a rotation that
    /// evicts an admitted line shifts them and must drop it.
    #[test]
    fn rotation_keeps_the_selection_only_when_no_admitted_row_moved() {
        const CAP: usize = 4;
        let mut logs = VecDeque::new();
        let mut generation = 0u64;
        // The ring's oldest line is one the filter drops, so the first
        // rotation evicts an unadmitted line.
        push_capped(
            &mut logs,
            &mut generation,
            CAP,
            "2026/08/10 12:00:00.000 [Info] noise",
        );
        for index in 1..CAP {
            push_capped(
                &mut logs,
                &mut generation,
                CAP,
                &format!("2026/08/10 12:00:0{index}.000 [Info] keep {index}"),
            );
        }
        let mut screen = LogsScreen {
            text: "keep".to_string(),
            ..Default::default()
        };
        assert!(screen.refresh_view(&logs, generation).changed());
        let selection = RowSelection {
            anchor: Some(RowCursor {
                row: 1,
                ccursor: egui::text::CCursor::new(2),
            }),
            active: Some(RowCursor {
                row: 2,
                ccursor: egui::text::CCursor::new(3),
            }),
        };
        screen.rows_selection = selection;
        // The evicted line is the one the filter dropped: no admitted row
        // moved, and the admitted arrival only extends the tail.
        push_capped(
            &mut logs,
            &mut generation,
            CAP,
            "2026/08/10 12:00:04.000 [Info] keep 4",
        );
        assert!(screen.refresh_view(&logs, generation).changed());
        assert_eq!(
            screen.rows_selection.anchor, selection.anchor,
            "an eviction of unadmitted lines leaves every row index alone"
        );
        // The next arrival evicts an admitted line: every later row shifts.
        push_capped(
            &mut logs,
            &mut generation,
            CAP,
            "2026/08/10 12:00:05.000 [Info] keep 5",
        );
        assert!(screen.refresh_view(&logs, generation).changed());
        assert_eq!(
            screen.rows_selection.anchor, None,
            "an eviction of an admitted line must drop the index-keyed selection"
        );
    }

    /// Push one line into the rig's ring, evicting the oldest entries so the
    /// ring stays at `cap` — the shape `LogBuffer::push` gives the screen once
    /// either cap binds.
    fn push_capped_rig(rig: &mut UiTestRig, cap: usize, index: usize) {
        rig.push_log(
            false,
            format!("2026/08/10 12:00:{index:02}.000 [Info] line {index}"),
        );
        while rig.logs.len() > cap {
            rig.logs.pop_front();
        }
    }

    /// At a cap, an arriving line refreshes through the incremental path: the
    /// frame extends the retained measurements with the admitted tail instead
    /// of re-measuring the whole ring, so a streaming session at the cap does
    /// not pay a full-ring re-layout per line.
    #[test]
    fn rotation_at_the_cap_extends_the_measured_layout() {
        const CAP: usize = 4;
        let mut rig = UiTestRig::default();
        for index in 0..CAP {
            push_capped_rig(&mut rig, CAP, index);
        }
        let mut screen = LogsScreen::default();
        let ctx = egui::Context::default();
        ctx.set_fonts(egui::FontDefinitions::default());
        run_frame(&ctx, &mut screen, &mut rig);
        assert_eq!(
            screen.last_layout,
            LayoutPass::Full { rows: CAP },
            "the fresh view measures every row"
        );

        for index in CAP..CAP + 2 {
            push_capped_rig(&mut rig, CAP, index);
        }
        run_frame(&ctx, &mut screen, &mut rig);
        assert!(
            matches!(screen.last_layout, LayoutPass::Tail { .. }),
            "a rotation at the cap must not re-measure the ring: {:?}",
            screen.last_layout
        );
        let view = screen.view.as_ref().unwrap();
        assert_eq!(
            view.rows.iter().map(|row| row.seq).collect::<Vec<_>>(),
            [2, 3, 4, 5]
        );
        assert_eq!(view.rows.len(), CAP);
        assert_eq!(view.heights.len(), CAP, "survivors plus the admitted tail");
        assert_eq!(view.galleys.len(), CAP);
        assert_eq!(view.prefix.len(), CAP + 1);
        assert_eq!(view.prefix[0], 0.0);
    }

    /// Build one filtered row the way the view does, so the copy-text
    /// helper is exercised against the row shape the render path hands it.
    /// The sequence is irrelevant here: the copy helpers address rows by
    /// index, never by the ring position a row came from.
    fn filtered_row(line: &str) -> FilteredRow {
        FilteredRow {
            seq: 0,
            from_core: false,
            level: line_level(line),
            line: line.to_string(),
        }
    }

    fn row_cursor(row: usize, index: usize) -> RowCursor {
        RowCursor {
            row,
            ccursor: egui::text::CCursor::new(index),
        }
    }

    /// The copy text spans the selection across rows: the first row from
    /// the lower cursor, every row between in full, the last row up to the
    /// upper cursor — and a drag upward copies the same slice as the same
    /// drag downward.
    #[test]
    fn selection_text_spans_the_selected_rows_in_both_drag_directions() {
        let rows: Vec<FilteredRow> = ["alpha", "bravo", "charlie", "delta"]
            .iter()
            .map(|line| filtered_row(line))
            .collect();
        let forward = RowSelection {
            anchor: Some(row_cursor(0, 2)),
            active: Some(row_cursor(2, 3)),
        };
        assert_eq!(
            LogsScreen::selection_text(forward, &rows),
            "pha\nbravo\ncha",
            "the copy must run from the anchor row's cursor, through every \
             row in between, to the active row's cursor"
        );
        let reversed = RowSelection {
            anchor: Some(row_cursor(2, 3)),
            active: Some(row_cursor(0, 2)),
        };
        assert_eq!(
            LogsScreen::selection_text(reversed, &rows),
            "pha\nbravo\ncha",
            "a reversed anchor must copy the same slice"
        );
        // Whole rows: the range covers every row, so each one copies in
        // full — no trailing newline.
        assert_eq!(
            LogsScreen::selection_text(
                RowSelection {
                    anchor: Some(row_cursor(0, 0)),
                    active: Some(row_cursor(3, 5)),
                },
                &rows
            ),
            "alpha\nbravo\ncharlie\ndelta"
        );
    }

    /// Single-row, collapsed, absent, and stale selections all yield a
    /// bounded string: the single row copies cursor-to-cursor, the others
    /// nothing (the copy actions test the empty string before touching the
    /// clipboard).
    #[test]
    fn selection_text_handles_single_collapsed_and_stale_selections() {
        let rows: Vec<FilteredRow> = ["alpha", "bravo"]
            .iter()
            .map(|line| filtered_row(line))
            .collect();
        assert_eq!(
            LogsScreen::selection_text(
                RowSelection {
                    anchor: Some(row_cursor(1, 1)),
                    active: Some(row_cursor(1, 4)),
                },
                &rows
            ),
            "rav"
        );
        assert_eq!(
            LogsScreen::selection_text(
                RowSelection {
                    anchor: Some(row_cursor(0, 3)),
                    active: Some(row_cursor(0, 3)),
                },
                &rows
            ),
            ""
        );
        assert_eq!(
            LogsScreen::selection_text(RowSelection::default(), &rows),
            ""
        );
        // An index the view no longer covers is defended against (the
        // selection is dropped on any rebuild that shifts indices).
        assert_eq!(
            LogsScreen::selection_text(
                RowSelection {
                    anchor: Some(row_cursor(4, 0)),
                    active: Some(row_cursor(4, 2)),
                },
                &rows
            ),
            ""
        );
        // A cursor past a row's end clamps to it instead of panicking: the
        // first row contributes its (empty) tail, the last row its whole
        // text.
        assert_eq!(
            LogsScreen::selection_text(
                RowSelection {
                    anchor: Some(row_cursor(0, 90)),
                    active: Some(row_cursor(1, 90)),
                },
                &rows
            ),
            "\nbravo"
        );
    }

    /// Run one headless frame carrying the platform copy chord and return
    /// the clipboard texts it emitted.
    fn run_frame_copy_texts(
        ctx: &egui::Context,
        screen: &mut LogsScreen,
        rig: &mut UiTestRig,
    ) -> Vec<String> {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(700.0, 400.0),
                )),
                time: Some(2.0),
                events: vec![egui::Event::Copy],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| screen.show(ui, &mut rig.ctx()));
            },
        );
        // A headless run has no renderer to apply texture deltas to; drop
        // them explicitly instead of panicking in the TexturesDelta guard.
        output.textures_delta.clear();
        output
            .platform_output
            .commands
            .into_iter()
            .filter_map(|command| match command {
                egui::OutputCommand::CopyText(text) => Some(text),
                _ => None,
            })
            .collect()
    }

    /// The platform copy chord (egui's `Copy` event) hands the selected
    /// slice of the view's rows to the clipboard command the backend
    /// drains, and a frame with nothing selected leaves the clipboard
    /// untouched.
    #[test]
    fn copy_chord_hands_the_selected_rows_to_the_clipboard() {
        let mut rig = UiTestRig::default();
        for line in ["[Info] alpha", "[Info] bravo", "[Info] charlie"] {
            rig.push_log(false, line.to_string());
        }
        let mut screen = LogsScreen::default();
        let ctx = egui::Context::default();
        ctx.set_fonts(egui::FontDefinitions::default());
        // Warm-up frame: builds the filtered view the selection indexes
        // into.
        run_frame_at(&ctx, &mut screen, &mut rig, 700.0, 1.0);
        assert_eq!(screen.view.as_ref().unwrap().rows.len(), 3);

        // A selection whose active cursor sits on the boundary past the
        // first "charlie" character (cursors are character boundaries, so
        // index 8 means "[Info] c"): the middle row copies in full, the
        // last one up to the active cursor.
        screen.rows_selection = RowSelection {
            anchor: Some(row_cursor(1, 0)),
            active: Some(row_cursor(2, 8)),
        };
        assert_eq!(
            run_frame_copy_texts(&ctx, &mut screen, &mut rig),
            ["[Info] bravo\n[Info] c"]
        );

        // Nothing selected: the chord must not touch the clipboard.
        screen.rows_selection = RowSelection::default();
        assert!(
            run_frame_copy_texts(&ctx, &mut screen, &mut rig).is_empty(),
            "an empty selection must not emit a clipboard command"
        );
    }

    /// Behavior pin: the memoized view keeps the exact
    /// filtering semantics of the previous per-frame pass — unparseable
    /// lines stay visible at All, level thresholds, ASCII-case-insensitive
    /// trimmed text filter, clear marker, display cap.
    #[test]
    fn filtered_view_preserves_level_text_and_clear_marker_semantics() {
        let mut logs = VecDeque::new();
        let mut generation = 0u64;
        for (from_core, line) in [
            (true, "core banner (unparseable)"),
            (false, "2026/08/10 12:00:00.000 [Debug] trace detail"),
            (false, "2026/08/10 12:00:01.000 [Info] connected"),
            (false, "2026/08/10 12:00:02.000 [Warning] retrying"),
            (true, "2026/08/10 12:00:03.000 [Error] dns failed"),
            (false, "app WARN token line"),
        ] {
            push_line(&mut logs, &mut generation, from_core, line);
        }
        let mut screen = LogsScreen::default();
        fn rows(screen: &LogsScreen) -> &[FilteredRow] {
            &screen.view.as_ref().unwrap().rows
        }

        // All: every line, including the unparseable ones.
        assert!(screen.refresh_view(&logs, generation).changed());
        assert_eq!(rows(&screen).len(), 6);

        // InfoPlus: unparseable + Info + Warning + Error + WARN-token line.
        screen.level = LevelFilter::InfoPlus;
        assert!(screen.refresh_view(&logs, generation).changed());
        assert_eq!(rows(&screen).len(), 5);

        // WarningPlus: the two warning-or-above lines plus the WARN-token
        // line; unparseable and below-threshold lines are hidden.
        screen.level = LevelFilter::WarningPlus;
        assert!(screen.refresh_view(&logs, generation).changed());
        let warning_plus = rows(&screen);
        assert_eq!(warning_plus.len(), 3);
        assert_eq!(
            warning_plus[0].line,
            "2026/08/10 12:00:02.000 [Warning] retrying"
        );
        assert_eq!(
            warning_plus[1].line,
            "2026/08/10 12:00:03.000 [Error] dns failed"
        );
        assert_eq!(warning_plus[2].line, "app WARN token line");
        assert!(
            warning_plus
                .iter()
                .all(|row| row.level == Some(Level::Warning) || row.level == Some(Level::Error))
        );

        // ErrorPlus: only the Error line, from_core preserved.
        screen.level = LevelFilter::ErrorPlus;
        assert!(screen.refresh_view(&logs, generation).changed());
        assert_eq!(rows(&screen).len(), 1);
        assert!(rows(&screen)[0].from_core);

        // Text filter: ASCII-case-insensitive, whitespace trimmed.
        screen.level = LevelFilter::All;
        screen.text = "  DNS ".to_string();
        assert!(screen.refresh_view(&logs, generation).changed());
        assert_eq!(rows(&screen).len(), 1);
        assert_eq!(
            rows(&screen)[0].line,
            "2026/08/10 12:00:03.000 [Error] dns failed"
        );

        // Clear anchor: lines pushed at or before the clear generation are
        // hidden — a clear pressed after the third push hides the ring's
        // first three lines.
        screen.text.clear();
        screen.clear_after_generation = Some(3);
        assert!(screen.refresh_view(&logs, generation).changed());
        let after_marker = rows(&screen);
        assert_eq!(after_marker.len(), 3);
        assert_eq!(
            after_marker[0].line,
            "2026/08/10 12:00:02.000 [Warning] retrying"
        );
    }

    /// The view covers the entire ring — the app bounds the ring itself at
    /// `LOG_CAP` lines and `LOG_BYTE_CAP` bytes, so the screen must not cut
    /// off an unreachable tail: 2500 buffered lines render as 2500 rows,
    /// oldest first.
    #[test]
    fn filtered_view_covers_the_entire_ring() {
        let mut logs = VecDeque::new();
        let mut generation = 0u64;
        for i in 0..2500 {
            push_line(&mut logs, &mut generation, false, &format!("line {i:04}"));
        }
        let mut screen = LogsScreen::default();
        assert!(screen.refresh_view(&logs, generation).changed());
        let rows = &screen.view.as_ref().unwrap().rows;
        assert_eq!(rows.len(), 2500);
        assert_eq!(rows[0].line, "line 0000");
        assert_eq!(rows[2499].line, "line 2499");
    }

    /// Virtualized band math: the prefix-sum lookup returns exactly the rows
    /// intersecting the viewport band.
    #[test]
    fn visible_band_covers_exactly_the_rows_intersecting_the_viewport() {
        // Three rows of height 10 spaced by 2 → slots [0,12) [12,24) [24,36).
        let heights = [10.0, 10.0, 10.0];
        let prefix = [0.0, 12.0, 24.0, 36.0];
        // Viewport fully inside the middle slot.
        assert_eq!(visible_band(&prefix, &heights, 13.0, 23.0), 1..2);
        // Viewport straddling slot boundaries.
        assert_eq!(visible_band(&prefix, &heights, 10.0, 26.0), 0..3);
        // Viewport above the content: the first row still intersects.
        assert_eq!(visible_band(&prefix, &heights, 0.0, 0.1), 0..1);
        // Viewport below the content: nothing.
        assert_eq!(visible_band(&prefix, &heights, 40.0, 50.0), 3..3);
        // Empty list.
        assert_eq!(visible_band(&[0.0], &[], 0.0, 100.0), 0..0);
    }

    /// Render smoke: `show` builds the view once, measures the virtualized
    /// layout, and an idle second frame neither rebuilds nor re-measures —
    /// the screen's own layout-pass counter stays put and the measured
    /// layout is untouched.
    #[test]
    fn show_renders_the_memoized_rows_and_idle_frames_stay_pure() {
        let mut rig = UiTestRig::default();
        for i in 0..40 {
            rig.push_log(
                i % 3 == 0,
                format!("2026/08/10 12:00:{i:02}.000 [Info] line {i}"),
            );
        }
        let mut screen = LogsScreen::default();

        let ctx = egui::Context::default();
        ctx.set_fonts(egui::FontDefinitions::default());
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                screen.show(ui, &mut rig.ctx());

                // First frame: the view is built and the virtualized layout
                // was measured.
                let view = screen.view.as_ref().unwrap();
                assert_eq!(view.rows.len(), 40);
                assert_eq!(view.heights.len(), 40);
                assert_eq!(view.prefix.len(), 41);
                assert!(view.measured_width > 0.0);

                // Idle second frame: no rebuild, no re-measure. A frame that
                // re-laid the ring out would advance the screen's own
                // layout-pass counter (a rebuild empties `heights`, which
                // forces the full re-measure); the measured layout is
                // untouched on top of that.
                let (width_before, heights_before) = (view.measured_width, view.heights.len());
                screen.show(ui, &mut rig.ctx());
                assert_eq!(
                    screen.last_layout,
                    LayoutPass::None,
                    "an idle frame must not re-lay-out the memoized view"
                );
                let view = screen.view.as_ref().unwrap();
                assert_eq!(view.measured_width, width_before);
                assert_eq!(view.heights.len(), heights_before);
            });
        });
        // A headless run has no renderer to apply texture deltas to; drop
        // them explicitly instead of panicking in the TexturesDelta guard.
        output.textures_delta.clear();
    }

    /// Run one headless full frame of the Logs screen.
    fn run_frame(ctx: &egui::Context, screen: &mut LogsScreen, rig: &mut UiTestRig) {
        let mut output = ctx.run_ui(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| screen.show(ui, &mut rig.ctx()));
        });
        // A headless run has no renderer to apply texture deltas to; drop
        // them explicitly instead of panicking in the TexturesDelta guard.
        output.textures_delta.clear();
    }

    /// On a pure-append frame the retained layout vectors
    /// (heights/galleys/prefix) are extended with exactly the admitted tail
    /// rows — nothing is re-measured from scratch, regardless of the batch
    /// size. A filter change still triggers a full rebuild and a
    /// from-scratch layout pass. The layout-work counters bump only when a
    /// pass actually runs, never on idle frames.
    #[test]
    fn pure_append_extends_retained_layout_by_admitted_tail_only() {
        let mut rig = UiTestRig::default();
        for i in 0..4 {
            rig.push_log(
                false,
                format!("2026/08/10 12:00:{i:02}.000 [Info] keep line {i}"),
            );
        }
        let mut screen = LogsScreen {
            text: "keep".to_string(),
            ..Default::default()
        };
        let ctx = egui::Context::default();
        ctx.set_fonts(egui::FontDefinitions::default());

        // First frame: one full rebuild, one full layout pass over the four
        // admitted rows.
        run_frame(&ctx, &mut screen, &mut rig);
        {
            let view = screen.view.as_ref().unwrap();
            assert_eq!(view.rows.len(), 4);
            assert_eq!(view.heights.len(), 4);
            assert_eq!(view.galleys.len(), 4);
            assert_eq!(view.prefix.len(), 5);
        }
        assert_eq!(
            screen.last_layout,
            LayoutPass::Full { rows: 4 },
            "the fresh view measures every row"
        );

        // One arrival batch of three lines, of which only two pass the
        // filter: the refresh admits exactly the tail, and the layout pass
        // measures exactly the two admitted rows — the retained vectors
        // grow, nothing is re-measured from scratch. Each push advances the
        // ring's generation.
        rig.push_log(false, "2026/08/10 12:01:00.000 [Info] noise".to_string());
        rig.push_log(
            false,
            "2026/08/10 12:01:01.000 [Info] keep line 4".to_string(),
        );
        rig.push_log(
            false,
            "2026/08/10 12:01:02.000 [Info] keep line 5".to_string(),
        );
        run_frame(&ctx, &mut screen, &mut rig);
        {
            let view = screen.view.as_ref().unwrap();
            assert_eq!(view.rows.len(), 6);
            assert_eq!(view.heights.len(), 6);
            assert_eq!(view.galleys.len(), 6);
            assert_eq!(view.prefix.len(), 7);
            assert_eq!(
                view.rows[4].line,
                "2026/08/10 12:01:01.000 [Info] keep line 4"
            );
            assert_eq!(
                view.rows[5].line,
                "2026/08/10 12:01:02.000 [Info] keep line 5"
            );
            // Layout vectors stay index-aligned with the filtered rows: one
            // prefix entry per row plus the total, strictly increasing.
            assert_eq!(view.prefix.len(), view.heights.len() + 1);
            assert_eq!(view.prefix[0], 0.0);
            assert!(
                view.prefix
                    .windows(2)
                    .all(|slot| slot[1] > slot[0] && slot[1] - slot[0] > 0.0)
            );
            assert!(
                view.heights.iter().all(|&height| height > 0.0),
                "the tail rows must be measured"
            );
        }
        assert_eq!(
            screen.last_layout,
            LayoutPass::Tail { rows: 2 },
            "only the two admitted rows are measured"
        );

        // Idle frame: no refresh, no layout pass.
        run_frame(&ctx, &mut screen, &mut rig);
        assert_eq!(
            screen.last_layout,
            LayoutPass::None,
            "an idle frame measures nothing"
        );

        // Filter change: the full rebuild discards the stale vectors and
        // the frame re-measures the single admitted row from scratch (a
        // full layout pass, beside the tail passes the appends logged).
        screen.text = "noise".to_string();
        run_frame(&ctx, &mut screen, &mut rig);
        {
            let view = screen.view.as_ref().unwrap();
            assert_eq!(view.rows.len(), 1);
            assert_eq!(view.rows[0].line, "2026/08/10 12:01:00.000 [Info] noise");
            assert_eq!(view.heights.len(), 1);
            assert_eq!(view.galleys.len(), 1);
            assert_eq!(view.prefix.len(), 2);
        }
        assert_eq!(
            screen.last_layout,
            LayoutPass::Full { rows: 1 },
            "the rebuild discards the stale vectors and re-measures from scratch"
        );
    }

    /// The full-rebuild paths (filter/level/clear changes,
    /// rotation, first build) discard the measured layout vectors for a
    /// fresh measure; only a pure append keeps them index-aligned with the
    /// extended rows. Asserted at the refresh seam, so no UI frame is
    /// needed.
    #[test]
    fn full_rebuild_resets_layout_vectors_but_pure_append_keeps_them() {
        let mut logs = VecDeque::new();
        let mut generation = 0u64;
        push_line(
            &mut logs,
            &mut generation,
            false,
            "2026/08/10 12:00:00.000 [Info] line A",
        );
        push_line(
            &mut logs,
            &mut generation,
            false,
            "2026/08/10 12:00:01.000 [Info] line B",
        );
        let mut screen = LogsScreen::default();
        assert!(screen.refresh_view(&logs, generation).changed());
        // Simulate a measured frame: the layout vectors cover the two rows.
        let view = screen.view.as_mut().unwrap();
        view.heights = vec![10.0, 20.0];
        view.prefix = vec![0.0, 10.0, 30.0];

        // Pure append: the cached rows are extended in place and the layout
        // vectors are left untouched for show_rows to extend.
        push_line(
            &mut logs,
            &mut generation,
            false,
            "2026/08/10 12:00:02.000 [Info] line C",
        );
        assert!(screen.refresh_view(&logs, generation).changed());
        let view = screen.view.as_ref().unwrap();
        assert_eq!(view.rows.len(), 3);
        assert_eq!(view.heights, [10.0, 20.0]);
        assert_eq!(view.prefix, [0.0, 10.0, 30.0]);
        // The refreshed key keeps the following idle frame pure.
        assert!(!screen.refresh_view(&logs, generation).changed());

        // Level switch: rows rebuilt from scratch, stale layout discarded.
        screen.level = LevelFilter::ErrorPlus;
        assert!(screen.refresh_view(&logs, generation).changed());
        let view = screen.view.as_ref().unwrap();
        assert!(view.rows.is_empty());
        assert!(
            view.heights.is_empty() && view.galleys.is_empty() && view.prefix.is_empty(),
            "a level change must drop the measured vectors"
        );

        // Needle change after another append: same reset contract.
        screen.level = LevelFilter::All;
        push_line(
            &mut logs,
            &mut generation,
            false,
            "2026/08/10 12:00:03.000 [Error] fatal boom",
        );
        screen.text = "fatal".to_string();
        assert!(screen.refresh_view(&logs, generation).changed());
        let view = screen.view.as_ref().unwrap();
        assert_eq!(view.rows.len(), 1);
        assert_eq!(
            view.rows[0].line,
            "2026/08/10 12:00:03.000 [Error] fatal boom"
        );
        assert!(
            view.heights.is_empty() && view.galleys.is_empty() && view.prefix.is_empty(),
            "a needle change must drop the measured vectors"
        );
    }

    /// The index-keyed selection must survive a pure append even when the
    /// filter admits none of the new lines — the row content is untouched,
    /// so a mid-drag arrival must not silently drop the selection the copy
    /// actions work on.
    #[test]
    fn pure_append_that_admits_nothing_keeps_the_selection() {
        let mut logs = VecDeque::new();
        let mut generation = 0u64;
        push_line(
            &mut logs,
            &mut generation,
            false,
            "2026/08/10 12:00:00.000 [Info] keep line",
        );
        let mut screen = LogsScreen {
            text: "KEEP".to_string(),
            ..Default::default()
        };
        assert!(screen.refresh_view(&logs, generation).changed());
        screen.rows_selection = RowSelection {
            anchor: Some(RowCursor {
                row: 0,
                ccursor: egui::text::CCursor::new(2),
            }),
            active: Some(RowCursor {
                row: 0,
                ccursor: egui::text::CCursor::new(5),
            }),
        };

        // An arrival that passes nothing: the view keeps its single row and
        // the selection with it.
        push_line(
            &mut logs,
            &mut generation,
            false,
            "2026/08/10 12:00:01.000 [Info] filtered noise",
        );
        assert!(screen.refresh_view(&logs, generation).changed());
        assert_eq!(screen.view.as_ref().unwrap().rows.len(), 1);
        assert!(
            screen.rows_selection.anchor.is_some(),
            "a pure append that admits nothing must keep the selection"
        );

        // The next idle frame changes nothing.
        assert!(!screen.refresh_view(&logs, generation).changed());
        assert!(screen.rows_selection.anchor.is_some());
    }

    /// The view identity must change whenever the
    /// ring's content changes, even when every moved line is a capacity-0
    /// empty string. The old `(len, front/back String::as_ptr)` fingerprint
    /// aliased exactly this rotation — every empty `String` reports the
    /// same dangling aligned pointer, so a push at the cap left the
    /// fingerprint bit-identical while one line was evicted and a fresh one
    /// appended — silently keeping the stale view. The monotonic push
    /// generation cannot false-equal.
    #[test]
    fn empty_line_rotation_at_the_cap_invalidates_the_view() {
        let mut logs = VecDeque::new();
        let mut generation = 0u64;
        // Small stand-in for the app's ring with `LogBuffer`'s eviction
        // rule: push, then drop the front once the cap is exceeded.
        const CAP: usize = 3;
        let push = |logs: &mut VecDeque<(bool, String)>, generation: &mut u64| {
            *generation += 1;
            logs.push_back((false, String::new()));
            if logs.len() > CAP {
                logs.pop_front();
            }
        };

        // A full ring of empty lines: the front and back entries both hold
        // the dangling capacity-0 pointer — the aliasing state the old
        // fingerprint could not tell apart.
        push(&mut logs, &mut generation);
        push(&mut logs, &mut generation);
        push(&mut logs, &mut generation);
        let mut screen = LogsScreen::default();
        assert!(screen.refresh_view(&logs, generation).changed());
        assert_eq!(screen.view.as_ref().unwrap().rows.len(), CAP);

        // Rotate at the cap with another empty line. Ring length, front and
        // back pointers are all unchanged by the rotation — only the
        // monotonic generation moved.
        push(&mut logs, &mut generation);
        assert!(
            screen.refresh_view(&logs, generation).changed(),
            "an empty-line push at the cap must invalidate the memoized view"
        );
        assert_eq!(screen.view.as_ref().unwrap().rows.len(), CAP);

        // The refresh consumed the rotation: idle frames stay pure again.
        assert!(!screen.refresh_view(&logs, generation).changed());
    }

    /// The "N of M lines" caption is re-formatted
    /// only when its inputs — visible/total counts or language — change; an
    /// idle frame reuses the cached text allocation (same buffer).
    #[test]
    fn line_count_caption_is_memoized_on_its_counts() {
        let mut rig = UiTestRig::default();
        for i in 0..40 {
            rig.push_log(
                false,
                format!("2026/08/10 12:00:{i:02}.000 [Info] line {i}"),
            );
        }
        let mut screen = LogsScreen::default();
        let ctx = egui::Context::default();
        ctx.set_fonts(egui::FontDefinitions::default());

        run_frame(&ctx, &mut screen, &mut rig);
        let first = screen
            .line_count
            .as_ref()
            .expect("caption set on first frame");
        assert_eq!(
            first.text,
            t_fmt(
                rig.settings.language,
                Key::LogsLineCount,
                &[&40usize, &40usize]
            ),
            "the caption must show the memoized view's counts"
        );
        let first_ptr = first.text.as_ptr();

        // Idle frame: same counts, same cached allocation.
        run_frame(&ctx, &mut screen, &mut rig);
        let second = screen.line_count.as_ref().expect("caption kept");
        assert_eq!(
            second.text.as_ptr(),
            first_ptr,
            "an idle frame must not re-format the caption"
        );

        // One push moves both counts: the caption is re-formatted once and
        // reflects the new view.
        rig.push_log(false, "2026/08/10 12:00:40.000 [Info] line 40".to_string());
        run_frame(&ctx, &mut screen, &mut rig);
        let third_ptr = screen
            .line_count
            .as_ref()
            .expect("caption refreshed")
            .text
            .as_ptr();
        assert_eq!(
            screen.line_count.as_ref().expect("caption refreshed").text,
            t_fmt(
                rig.settings.language,
                Key::LogsLineCount,
                &[&41usize, &41usize]
            ),
            "a count change must re-format the caption"
        );

        // Another idle frame keeps the newest allocation.
        run_frame(&ctx, &mut screen, &mut rig);
        let fourth = screen.line_count.as_ref().expect("caption kept");
        assert_eq!(fourth.text.as_ptr(), third_ptr);
    }

    /// Run one headless frame at an explicit content width and egui-clock
    /// time: the resize-coalescing test drives drags this way,
    /// deterministically, without counting frames.
    fn run_frame_at(
        ctx: &egui::Context,
        screen: &mut LogsScreen,
        rig: &mut UiTestRig,
        width: f32,
        time: f64,
    ) {
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(width, 400.0),
                )),
                time: Some(time),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| screen.show(ui, &mut rig.ctx()));
            },
        );
        // A headless run has no renderer to apply texture deltas to; drop
        // them explicitly instead of panicking in the TexturesDelta guard.
        output.textures_delta.clear();
    }

    /// A drag streams the available width at frame
    /// rate, and a full re-layout re-measures every filtered row — so the
    /// re-fit must not run per streaming frame. The layout re-fits only
    /// once the width holds still for the settle window: one full re-layout
    /// per drag, at the drag's final width.
    #[test]
    fn drag_resize_runs_one_full_relayout_at_the_settled_width() {
        let mut rig = UiTestRig::default();
        for i in 0..40 {
            rig.push_log(
                false,
                format!("2026/08/10 12:00:{i:02}.000 [Info] line {i}"),
            );
        }
        let mut screen = LogsScreen::default();
        let ctx = egui::Context::default();
        ctx.set_fonts(egui::FontDefinitions::default());

        // First frame at 700 px: one full rebuild + one full layout pass.
        run_frame_at(&ctx, &mut screen, &mut rig, 700.0, 1.0);
        assert!(
            matches!(screen.last_layout, LayoutPass::Full { .. }),
            "the fresh view measures every row: {:?}",
            screen.last_layout
        );
        let initial_width = screen.view.as_ref().unwrap().measured_width;
        assert!(initial_width > 0.0);

        // An idle frame at the same width re-measures nothing.
        run_frame_at(&ctx, &mut screen, &mut rig, 700.0, 1.016);
        assert_eq!(
            screen.last_layout,
            LayoutPass::None,
            "an idle frame measures nothing"
        );

        // Drag: the width streams 30 px per frame. No full re-layout may
        // run on any streaming frame.
        run_frame_at(&ctx, &mut screen, &mut rig, 650.0, 1.1);
        run_frame_at(&ctx, &mut screen, &mut rig, 620.0, 1.116);
        run_frame_at(&ctx, &mut screen, &mut rig, 590.0, 1.132);
        assert_eq!(
            screen.last_layout,
            LayoutPass::None,
            "streaming drag frames must not re-layout the ring"
        );
        assert_eq!(screen.view.as_ref().unwrap().measured_width, initial_width);

        // The drag pauses at 590 px, still inside the settle window: no
        // re-layout yet...
        run_frame_at(&ctx, &mut screen, &mut rig, 590.0, 1.2);
        assert_eq!(
            screen.last_layout,
            LayoutPass::None,
            "a pause inside the settle window still measures nothing"
        );
        assert_eq!(screen.view.as_ref().unwrap().measured_width, initial_width);

        // ...once the width has held still past the settle window, exactly
        // one full re-layout runs at the settled width.
        run_frame_at(&ctx, &mut screen, &mut rig, 590.0, 1.32);
        assert!(
            matches!(screen.last_layout, LayoutPass::Full { .. }),
            "the settled width re-measures every row once: {:?}",
            screen.last_layout
        );
        let settled = screen.view.as_ref().unwrap().measured_width;
        assert!(
            (settled - (initial_width - 110.0)).abs() <= 2.0,
            "the re-layout must measure at the settled width: {settled} vs {}",
            initial_width - 110.0
        );

        // The settled layout stays put on idle frames.
        run_frame_at(&ctx, &mut screen, &mut rig, 590.0, 1.34);
        assert_eq!(
            screen.last_layout,
            LayoutPass::None,
            "an idle frame measures nothing"
        );
        assert_eq!(screen.view.as_ref().unwrap().measured_width, settled);
    }
}
