//! Top-bar status surface: the version caption at the row's right edge, and
//! the dynamic status/error chip zone whose width is capped so the chips can
//! never cover it — the "dynamic status covers the version info" bug.
//!
//! [`show_row`] is the row's whole interface: the shell fills
//! [`TopbarRowState`] with the frame's facts and dispatches the clicks it
//! gets back. The row owns its own caption memo ([`TopbarMemos`]) and lays
//! the zones out with [`egui::containers::Sides`], which measures the caption
//! first and hands the chips only what it leaves — the "chips yield, never
//! cover" invariant is the layout's, not a reserved number's. Everything is a free function or a plain data struct because the
//! app shell itself is not constructible in tests (it needs
//! `eframe::CreationContext` + profile I/O).

use crate::i18n::{Key, t, t_fmt};
use crate::model::Mode;
use crate::model::settings::Language;
use crate::rt::CorePhase;
use crate::ui::PhaseAction;
use crate::ui::status::{PhaseBadgeWording, phase_badge_color, phase_badge_text, status_colors_of};

/// The top bar's per-frame facts, supplied by the shell: the model and
/// runtime reads the row paints, plus the chip texts the shell already
/// memoizes for its other readers (the tray item, the Apply-now gate).
/// Everything else is the row's: the caption memoization, the width budget,
/// the clip that keeps the chips off the version caption, and the click
/// outcomes.
pub(crate) struct TopbarRowState<'a> {
    pub(crate) lang: Language,
    pub(crate) phase: &'a CorePhase,
    /// The mode as the caption's key: the caption text itself is derived in
    /// the memo, from this value and `lang`.
    pub(crate) mode: Mode,
    /// The active server's name (`None` while the list is empty).
    pub(crate) active_name: Option<&'a str>,
    pub(crate) core_version: Option<&'a str>,
    /// The model's edit generation: a rename, an added profile, a mode
    /// change or a core install moves the captions, and the memo re-derives
    /// on the generation it was built for.
    pub(crate) model_generation: u64,
    /// The shell's memoized Connect-refusal reason (`None` = Connect lives).
    pub(crate) blocked_reason: Option<&'a str>,
    // ---- chip zone ----
    pub(crate) unsaved_changes: bool,
    pub(crate) trial_rule_count: usize,
    pub(crate) core_available: bool,
    pub(crate) config_dirty: bool,
    /// The Apply-now refusal text (persistence or generation failure), or
    /// the shell's in-flight-operation caption.
    pub(crate) apply_block: Option<&'a str>,
    pub(crate) apply_result: Option<(&'a bool, &'a str)>,
    pub(crate) terminal_error: Option<&'a str>,
    pub(crate) config_error: Option<&'a str>,
    pub(crate) state_error: Option<&'a str>,
    pub(crate) persistence_error: Option<&'a str>,
}

/// The row's memo state: the caption generation, rebuilt only when its own
/// inputs move. One value the shell owns and hands back each frame — the
/// layout that reads it (and the keys it is stale on) lives with the row.
#[derive(Default)]
pub(crate) struct TopbarMemos {
    labels: Option<TopbarLabels>,
}

/// One generation of the row's captions: the phase badge, the mode caption,
/// the active-server caption and the version caption, rebuilt only when the
/// model generation, the phase, the mode, the active server, the core
/// version or the language moved — never on repaint frames.
struct TopbarLabels {
    phase: CorePhase,
    model_generation: u64,
    mode: Mode,
    active_name: Option<String>,
    core_version: Option<String>,
    lang: Language,
    badge: String,
    mode_caption: String,
    active_caption: Option<String>,
    version_caption: String,
}

impl TopbarLabels {
    fn is_current(&self, state: &TopbarRowState<'_>) -> bool {
        self.model_generation == state.model_generation
            && self.mode == state.mode
            && self.active_name.as_deref() == state.active_name
            && self.core_version.as_deref() == state.core_version
            && self.lang == state.lang
            && self.phase == *state.phase
    }
}

/// The click outcomes of one row frame: what the shell dispatches after
/// [`show_row`] returns.
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TopbarRowClicks {
    pub connect: bool,
    pub stop: bool,
    pub apply: bool,
    pub retry: bool,
    pub open_folder: bool,
    /// The terminal-error chip: jump to the message in the content area.
    pub jump_to_error: bool,
}

impl TopbarRowClicks {
    /// Merge one frame's outcomes into an accumulator. The shell dispatches
    /// the clicks of the frame it painted; a test that runs several frames
    /// past a click (kittest's `run` may frame again) needs the union of what
    /// the row asked for, never just the last frame's empty set.
    #[cfg(test)]
    pub(crate) fn latch(&mut self, other: TopbarRowClicks) {
        self.connect |= other.connect;
        self.stop |= other.stop;
        self.apply |= other.apply;
        self.retry |= other.retry;
        self.open_folder |= other.open_folder;
        self.jump_to_error |= other.jump_to_error;
    }
}

/// Render the whole top bar row — phase badge, lifecycle action, the
/// capped-and-clipped chip zone, and the right-edge version cluster —
/// refreshing the row's own memos, and return the clicks the shell must
/// dispatch. The one place the row's layout lives, so the "chips yield,
/// never cover the version info" invariant cannot be forgotten by a
/// caller that builds the row by hand.
pub(crate) fn show_row(
    ui: &mut egui::Ui,
    state: &TopbarRowState<'_>,
    memos: &mut TopbarMemos,
) -> TopbarRowClicks {
    let TopbarMemos { labels } = memos;
    ui.horizontal(|ui| {
        let labels = refresh_labels(labels, state);
        // `Sides::shrink_left` measures the caption first and hands this
        // side only the width the row has left, so no clip or reserved
        // number has to reproduce the measurement.
        let (clicks, ()) = egui::containers::Sides::new().shrink_left().show(
            ui,
            |ui| row_left(ui, labels, state),
            |ui| {
                // The right-edge cluster: the caption anchored at the row's
                // far right (the side's layout flows right-to-left, so the
                // first widget lands rightmost).
                ui.weak(&labels.version_caption);
            },
        );
        clicks
    })
    .inner
}

/// The row's left block: the phase badge, the lifecycle action, and the chip
/// zone, laid out in the width [`egui::containers::Sides`] leaves after the
/// version caption. Every chip truncates to its budget instead of pushing
/// under the cluster.
fn row_left(
    ui: &mut egui::Ui,
    labels: &TopbarLabels,
    state: &TopbarRowState<'_>,
) -> TopbarRowClicks {
    let mut clicks = TopbarRowClicks::default();
    ui.colored_label(phase_badge_color(state.phase, status_colors_of(ui)), "●");
    ui.label(&labels.badge);
    ui.separator();
    match PhaseAction::for_phase(state.phase) {
        PhaseAction::Connect => {
            let response = match state.blocked_reason {
                Some(reason) => ui
                    .add_enabled(
                        false,
                        egui::Button::new(PhaseAction::Connect.label(state.lang)),
                    )
                    .on_disabled_hover_text(reason),
                None => ui.button(PhaseAction::Connect.label(state.lang)),
            };
            clicks.connect = response.clicked();
        }
        PhaseAction::Disconnect | PhaseAction::CancelRetry => {
            clicks.stop = ui
                .button(PhaseAction::for_phase(state.phase).label(state.lang))
                .clicked();
        }
    }

    // The chip zone, capped to the row remainder and clipped, so every
    // chip truncates to its budget instead of pushing under the cluster.
    let can_apply = matches!(state.phase, CorePhase::Running) && state.apply_block.is_none();
    let status = TopbarStatus {
        lang: state.lang,
        mode_caption: &labels.mode_caption,
        active_caption: labels.active_caption.as_deref(),
        unsaved_changes: state.unsaved_changes,
        trial_rule_count: state.trial_rule_count,
        core_available: state.core_available,
        config_dirty: state.config_dirty,
        can_apply,
        apply_block: state.apply_block,
        apply_result: state.apply_result,
        terminal_error: state.terminal_error,
        config_error: state.config_error,
        state_error: state.state_error,
        persistence_error: state.persistence_error,
    };
    // The zone's budget is the width `Sides` left for this side: its
    // child `Ui` stops where the caption's block starts, and the clip
    // keeps a chip that ignores it from painting across.
    let zone_start_x = ui.cursor().min.x;
    let zone_w = ui.available_width().max(0.0);
    let zone_clicks = ui
        .scope(|ui| {
            ui.set_max_width(zone_w);
            ui.set_clip_rect(egui::Rect::from_min_max(
                egui::pos2(zone_start_x, ui.max_rect().min.y),
                egui::pos2(
                    zone_start_x + zone_w + ui.spacing().item_spacing.x,
                    ui.max_rect().max.y,
                ),
            ));
            topbar_status_zone(ui, &status)
        })
        .inner;
    clicks.apply = zone_clicks.apply;
    clicks.retry = zone_clicks.retry;
    clicks.open_folder = zone_clicks.open_folder;
    clicks.jump_to_error = zone_clicks.jump_to_error;
    clicks
}

/// Refresh the caption memo when any of its inputs moved, and hand back the
/// captions this frame renders. Everything the captions are built from —
/// including the wording of the phase badge — is decided here, so no render
/// site formats a caption.
fn refresh_labels<'a>(
    labels: &'a mut Option<TopbarLabels>,
    state: &TopbarRowState<'_>,
) -> &'a TopbarLabels {
    let current = labels
        .as_ref()
        .is_some_and(|labels| labels.is_current(state));
    if !current {
        let lang = state.lang;
        let active_caption = state
            .active_name
            .map(|name| t_fmt(lang, Key::TopbarActiveServer, &[&name]));
        let version_caption = match state.core_version {
            // `&v` is `&&str` — `&str` implements Display, so the element
            // coerces to `&dyn Display` (same double-reference shape as the
            // other t_fmt call sites).
            Some(v) => t_fmt(
                lang,
                Key::TopbarXrayAppVersions,
                &[&v, &env!("CARGO_PKG_VERSION")],
            ),
            None => t_fmt(lang, Key::TopbarAppVersion, &[&env!("CARGO_PKG_VERSION")]),
        };
        let mode_caption = t_fmt(lang, Key::TopbarMode, &[&mode_label(state.mode, lang)]);
        *labels = Some(TopbarLabels {
            phase: state.phase.clone(),
            model_generation: state.model_generation,
            mode: state.mode,
            active_name: state.active_name.map(str::to_owned),
            core_version: state.core_version.map(str::to_owned),
            lang,
            badge: phase_badge_text(state.phase, lang, PhaseBadgeWording::Topbar),
            mode_caption,
            active_caption,
            version_caption,
        });
    }
    labels.as_ref().expect("topbar labels refreshed above")
}

/// The mode caption's own word: "off" / "TUN".
fn mode_label(mode: Mode, lang: Language) -> &'static str {
    match mode {
        Mode::Off => t(lang, Key::ModeOff),
        Mode::Tun => t(lang, Key::ModeTun),
    }
}

/// The dynamic top-bar status inputs the chip zone renders; bundled so the
/// rendering fn stays under clippy's argument-count ceiling (the same
/// pattern as the servers editor's `AdvancedTabContext`).
struct TopbarStatus<'a> {
    pub(crate) lang: Language,
    pub(crate) mode_caption: &'a str,
    pub(crate) active_caption: Option<&'a str>,
    pub(crate) unsaved_changes: bool,
    pub(crate) trial_rule_count: usize,
    pub(crate) core_available: bool,
    pub(crate) config_dirty: bool,
    pub(crate) can_apply: bool,
    pub(crate) apply_block: Option<&'a str>,
    pub(crate) apply_result: Option<(&'a bool, &'a str)>,
    /// The terminal message standing right now: the chip's compact label is
    /// fixed, this is the message the hover shows and the click leads to.
    pub(crate) terminal_error: Option<&'a str>,
    pub(crate) config_error: Option<&'a str>,
    pub(crate) state_error: Option<&'a str>,
    pub(crate) persistence_error: Option<&'a str>,
}

/// The click outcomes of one chip-zone frame.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
struct TopbarClicks {
    pub apply: bool,
    pub retry: bool,
    pub open_folder: bool,
    /// The terminal-error chip: jump to the message in the content area.
    pub jump_to_error: bool,
}

/// One truncated chip in the dynamic zone: a `Label` capped to its
/// available width with the full text on hover when it was actually elided.
///
/// Takes `WidgetText` so a caption the caller already materialized (a
/// `String` from `t_fmt`) moves in without a second copy, and a caption the
/// caller built as a styled `WidgetText` keeps that styling. The chip's tint
/// rides a scoped `override_text_color` rather than a wrapping `RichText`:
/// that colours plain `WidgetText::Text` too, dropping the per-frame
/// `RichText` wrapper (and its `Arc` allocation) the old signature forced.
fn chip(ui: &mut egui::Ui, color: egui::Color32, text: impl Into<egui::WidgetText>) {
    let restore = ui.visuals().override_text_color;
    ui.visuals_mut().override_text_color = Some(color);
    ui.add(
        egui::Label::new(text.into())
            .truncate()
            .show_tooltip_when_elided(true),
    );
    ui.visuals_mut().override_text_color = restore;
}

/// Render the dynamic status/error zone. The caller lays this out inside a
/// child capped to the row remainder and clipped that child, so the chips can
/// never cover the right cluster; every piece of text truncates to its
/// remaining budget instead of overflowing.
///
/// The zone's order is a precedence: the controls (the Apply-now button, the
/// retry/open-folder pair, the error chip that jumps to the message) paint
/// before the informational chips, because the cap can clip the tail — a
/// clipped control is invisible *and* unreachable, while a clipped informational
/// chip only loses its text (its hover still carries the full value). Returns
/// the click outcomes (the row's caller dispatches them).
fn topbar_status_zone(ui: &mut egui::Ui, status: &TopbarStatus<'_>) -> TopbarClicks {
    let lang = status.lang;
    let colors = status_colors_of(ui);
    let mut clicks = TopbarClicks::default();

    ui.separator();
    ui.add(
        egui::Label::new(egui::RichText::new(status.mode_caption))
            .truncate()
            .show_tooltip_when_elided(true),
    );

    // ---- controls -------------------------------------------------------
    // The dirty-config pair: the pending change and the one control that
    // applies it.
    if status.config_dirty {
        ui.separator();
        chip(ui, colors.warn, t(lang, Key::TopbarChangesPending));
        let response = ui.add_enabled(
            status.can_apply,
            egui::Button::new(t(lang, Key::TopbarApplyNow)),
        );
        let response = if let Some(reason) = status.apply_block {
            response.on_disabled_hover_text(reason)
        } else {
            response
        };
        clicks.apply = response.clicked();
    }
    // The unwritable state's pair: both controls sit here, before the error
    // text that explains them.
    if let Some(error) = status.persistence_error {
        ui.separator();
        clicks.retry = ui.small_button(t(lang, Key::TopbarRetrySave)).clicked();
        clicks.open_folder = ui
            .small_button(t(lang, Key::TopbarOpenStateFolder))
            .clicked();
        ui.add(
            egui::Label::new(
                egui::RichText::new(t(lang, Key::TopbarSettingsNotSaved)).color(colors.err),
            )
            .truncate(),
        )
        .on_hover_text(error);
    }
    // The terminal error chip: the phase badge above keeps the phase readout
    // (an error never replaces it), so this is the status zone's pointer at
    // the message — a compact fixed label, the hover carrying the message's
    // own headline, and a click that jumps to the wrapped block. A truncating
    // label like every other chip, so the zone keeps yielding to the right
    // cluster whatever combination of chips is live.
    if let Some(error) = status.terminal_error {
        ui.separator();
        clicks.jump_to_error = ui
            .add(
                egui::Label::new(
                    egui::RichText::new(t(lang, Key::TopbarErrorChip)).color(colors.err),
                )
                .truncate()
                .sense(egui::Sense::click()),
            )
            .on_hover_text(error)
            .clicked();
    }

    // ---- informational chips -------------------------------------------
    if let Some(active) = status.active_caption {
        ui.separator();
        ui.add(
            egui::Label::new(egui::RichText::new(active))
                .truncate()
                .show_tooltip_when_elided(true),
        );
    }
    if status.unsaved_changes {
        ui.separator();
        chip(ui, colors.warn, t(lang, Key::TopbarServerEditsUnsaved));
    }
    if status.trial_rule_count > 0 {
        ui.separator();
        chip(
            ui,
            colors.warn,
            t_fmt(lang, Key::TopbarTrialRules, &[&status.trial_rule_count]),
        );
    }
    if !status.core_available {
        ui.separator();
        chip(ui, colors.warn, t(lang, Key::TopbarCoreNotInstalled));
    }
    if let Some((ok, output)) = status.apply_result {
        ui.separator();
        let summary = output
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or(if *ok {
                t(lang, Key::ApplyResultOk)
            } else {
                t(lang, Key::ApplyResultFailed)
            });
        ui.add(
            egui::Label::new(egui::RichText::new(summary).color(if *ok {
                colors.ok
            } else {
                colors.err
            }))
            .truncate(),
        )
        .on_hover_text(output);
    }
    if let Some(error) = status.config_error {
        ui.separator();
        ui.add(
            egui::Label::new(
                egui::RichText::new(t(lang, Key::TopbarConfigInvalid)).color(colors.err),
            )
            .truncate(),
        )
        .on_hover_text(error);
    }
    if let Some(error) = status.state_error {
        ui.separator();
        ui.add(
            egui::Label::new(
                egui::RichText::new(t(lang, Key::TopbarStateLoadFailed)).color(colors.err),
            )
            .truncate(),
        )
        .on_hover_text(error);
    }

    clicks
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::{Harness, kittest::Queryable as _};

    /// A status exercising every chip: all errors set, a long server name,
    /// a dirty config with an apply block and a stored apply result.
    fn heavy_status() -> TopbarStatus<'static> {
        TopbarStatus {
            lang: Language::En,
            mode_caption: "mode: TUN",
            active_caption: Some("server: very-long-server-name.example-01.com"),
            unsaved_changes: true,
            trial_rule_count: 2,
            core_available: false,
            config_dirty: true,
            can_apply: false,
            apply_block: Some("a lifecycle operation is running"),
            apply_result: Some((&true, "Configuration applied")),
            terminal_error: Some("the core exited before it answered"),
            config_error: Some("generation failure detail"),
            state_error: Some("load failure detail"),
            persistence_error: Some("save failure detail"),
        }
    }

    /// The three rows the tests drive: the all-chips-live worst case for the
    /// width budget, a row whose Apply-now button is enabled and on screen,
    /// and a row carrying only the unwritable-state chips (which are what the
    /// click test needs, since a chip clipped out of the budget is also
    /// outside hit-testing).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RowCase {
        Heavy,
        ApplyReady,
        PersistenceOnly,
    }

    /// One frame's row facts, built from the case and the row's own memos.
    struct RowFixture {
        phase: CorePhase,
        /// The model's edit generation, which the caption memo rebuilds on.
        generation: u64,
        /// The row width this frame lays the bar out in. kittest's harness
        /// floors the window width, so the budget under test is imposed on
        /// the `Ui` itself — the same thing the top panel does in the app.
        width: f32,
        case: RowCase,
        memos: TopbarMemos,
        clicks: TopbarRowClicks,
    }

    impl RowFixture {
        fn new(width: f32, case: RowCase) -> Self {
            Self {
                phase: CorePhase::Running,
                generation: 1,
                width,
                case,
                memos: TopbarMemos::default(),
                clicks: TopbarRowClicks::default(),
            }
        }
    }

    /// The version caption the row formats for the fixture's core version:
    /// the locale template over the committed pins, never a literal, so a
    /// wording or version bump cannot red the row's tests.
    fn version_caption() -> String {
        t_fmt(
            Language::En,
            Key::TopbarXrayAppVersions,
            &[&"v26.7.28", &env!("CARGO_PKG_VERSION")],
        )
    }

    /// Drive the real row through kittest. The state is built per frame from
    /// the fixture's owned fields, exactly as the shell builds it.
    fn row_harness(width: f32, case: RowCase) -> Harness<'static, RowFixture> {
        Harness::builder()
            .with_size(egui::Vec2::new(width, 60.0))
            .build_ui_state(
                |ui, fixture: &mut RowFixture| {
                    ui.set_max_width(fixture.width);
                    let heavy = fixture.case == RowCase::Heavy;
                    let apply_ready = fixture.case == RowCase::ApplyReady;
                    let row_clicks = show_row(
                        ui,
                        &TopbarRowState {
                            lang: Language::En,
                            phase: &fixture.phase,
                            mode: Mode::Tun,
                            // The long caption is the heavy row's point; the
                            // click cases keep the chips inside the budget so
                            // the widgets under test are hit-testable at all.
                            active_name: Some(if heavy {
                                "very-long-server-name.example-01.com"
                            } else {
                                "alpha"
                            }),
                            core_version: Some("v26.7.28"),
                            model_generation: fixture.generation,
                            blocked_reason: None,
                            unsaved_changes: heavy,
                            trial_rule_count: if heavy { 2 } else { 0 },
                            core_available: !heavy,
                            config_dirty: heavy || apply_ready,
                            apply_block: heavy.then_some("a lifecycle operation is running"),
                            apply_result: heavy.then_some((&true, "Configuration applied")),
                            terminal_error: heavy.then_some("the core exited before it answered"),
                            config_error: heavy.then_some("generation failure detail"),
                            state_error: heavy.then_some("load failure detail"),
                            persistence_error: (fixture.case == RowCase::PersistenceOnly)
                                .then_some("save failure detail"),
                        },
                        &mut fixture.memos,
                    );
                    fixture.clicks.latch(row_clicks);
                },
                RowFixture::new(width, case),
            )
    }

    /// The Apply-now control's enablement, at the row's own seam: the button
    /// exists whenever the config is dirty, and is enabled exactly while the
    /// core runs and nothing blocks the apply — the predicate the shell used
    /// to compute before handing the zone a flag.
    #[test]
    fn the_apply_button_is_enabled_only_for_a_running_core_without_a_block() {
        use egui_kittest::kittest::NodeT as _;

        let mut h = row_harness(1400.0, RowCase::Heavy);
        h.run();
        let blocked = h.get_by_label(t(Language::En, Key::TopbarApplyNow));
        assert!(
            blocked.accesskit_node().is_disabled(),
            "an operation in flight must disable the apply button"
        );

        let mut h = row_harness(1400.0, RowCase::ApplyReady);
        h.run();
        let ready = h.get_by_label(t(Language::En, Key::TopbarApplyNow));
        assert!(
            !ready.accesskit_node().is_disabled(),
            "a dirty config over a running core applies"
        );
    }

    #[test]
    fn the_row_memoizes_its_captions_on_the_model_generation() {
        let mut h = row_harness(900.0, RowCase::Heavy);
        h.run();
        let caption = version_caption();
        let version = h
            .get_all_by_label(caption.as_str())
            .next()
            .expect("the version caption renders from the memo");
        assert!(version.rect().width() > 1.5);

        // A model edit moves the generation: the caption memo re-derives and
        // the new core version reaches the row.
        h.state_mut().generation = 2;
        h.state_mut().memos = TopbarMemos::default();
        h.run();
        assert!(
            h.get_all_by_label(version_caption().as_str())
                .next()
                .is_some(),
            "the rebuilt memo still renders the same caption for the same facts"
        );
    }

    #[test]
    fn the_row_carries_every_chip_and_the_right_cluster() {
        // Every chip of the all-chips-live row, plus the right cluster.
        let mut h = row_harness(900.0, RowCase::Heavy);
        h.run();
        h.get_all_by_label("Disconnect")
            .next()
            .expect("the phase action renders");
        h.get_all_by_label("●")
            .next()
            .expect("the phase badge renders");
        for label in [
            "mode: TUN",
            "server: very-long-server-name.example-01.com",
            "View error",
            "Server edits not saved",
            "trial rules: 2 active",
            "Xray core not installed",
            "changes pending",
            "Apply now",
            "Configuration applied",
            "configuration invalid",
            "the app could not load the state file",
        ] {
            h.get_all_by_label(label)
                .next()
                .unwrap_or_else(|| panic!("chip {label:?} must render"));
        }
        h.get_all_by_label(version_caption().as_str())
            .next()
            .expect("the version caption renders");

        // An unwritable state adds its own chips and the two buttons.
        let mut h = row_harness(1400.0, RowCase::PersistenceOnly);
        h.run();
        for label in ["settings not saved", "Retry save", "Open state folder"] {
            h.get_all_by_label(label)
                .next()
                .unwrap_or_else(|| panic!("chip {label:?} must render"));
        }
        // The row's own click outcomes start clean.
        assert_eq!(h.state().clicks, TopbarRowClicks::default());
    }

    #[test]
    fn the_row_dispatches_the_clicks() {
        // The row reports what the shell must do; a click must not be
        // swallowed by the composition that now owns it.
        let mut h = row_harness(900.0, RowCase::Heavy);
        h.run();
        h.get_by_label(t(Language::En, Key::TopbarErrorChip))
            .click();
        h.run();
        assert!(
            h.state().clicks.jump_to_error,
            "the error chip must report the jump to the message"
        );

        // A row whose Apply-now button is enabled (no operation holding the
        // window) reports the apply request — at the app's minimum window
        // width, with the worst-case caption live: the zone paints its
        // controls before its informational chips, so the cap can clip the
        // latter and never the button.
        let mut h = row_harness(900.0, RowCase::ApplyReady);
        h.run();
        h.get_by_label(t(Language::En, Key::TopbarApplyNow)).click();
        h.run();
        assert!(h.state().clicks.apply, "Apply now must ask for an apply");

        // The unwritable state's pair is a control too, and equally out of the
        // cap's reach.
        let mut h = row_harness(900.0, RowCase::PersistenceOnly);
        h.run();
        h.get_by_label(t(Language::En, Key::TopbarRetrySave))
            .click();
        h.run();
        assert!(
            h.state().clicks.retry,
            "Retry save must report a retry request"
        );
        h.get_by_label(t(Language::En, Key::TopbarOpenStateFolder))
            .click();
        h.run();
        assert!(
            h.state().clicks.open_folder,
            "Open state folder must report the folder request"
        );
    }

    #[test]
    fn status_zone_renders_every_chip_state() {
        let mut h = Harness::new_ui(|ui| {
            topbar_status_zone(ui, &heavy_status());
        });
        h.run();
        for label in [
            "mode: TUN",
            "server: very-long-server-name.example-01.com",
            "View error",
            "Server edits not saved",
            "trial rules: 2 active",
            "Xray core not installed",
            "changes pending",
            "Apply now",
            "Configuration applied",
            "configuration invalid",
            "the app could not load the state file",
            "settings not saved",
            "Retry save",
            "Open state folder",
        ] {
            h.get_all_by_label(label)
                .next()
                .unwrap_or_else(|| panic!("chip {label:?} must render"));
        }
    }

    #[test]
    fn terminal_error_chip_reports_the_jump_to_the_message() {
        let mut h = Harness::builder().build_ui_state(
            move |ui, clicks: &mut TopbarClicks| {
                // Latched: `run` may frame past the click's frame.
                if topbar_status_zone(ui, &heavy_status()).jump_to_error {
                    clicks.jump_to_error = true;
                }
            },
            TopbarClicks::default(),
        );
        h.run();
        h.get_by_label(t(Language::En, Key::TopbarErrorChip))
            .click();
        h.run();
        assert!(
            h.state().jump_to_error,
            "the error chip must ask the shell to jump to the message"
        );
    }

    /// The x the chip zone may paint up to: the version cluster's own left
    /// edge, which the row's `Sides` layout hands the chips as their width
    /// budget.
    fn cluster_edge(h: &Harness<'_, RowFixture>) -> f32 {
        h.get_all_by_label(version_caption().as_str())
            .next()
            .expect("the row paints the version caption")
            .rect()
            .min
            .x
    }

    /// A chip past the row's budget is clipped to a degenerate ellipsis: it
    /// can never carry a word of text into the cluster's reservation, which
    /// is the whole point of the cap.
    fn assert_chips_yield_to_the_cluster(h: &Harness<'_, RowFixture>) {
        let budget_edge = cluster_edge(h);
        for label in [
            "mode: TUN",
            "Server edits not saved",
            "configuration invalid",
        ] {
            let node = h
                .get_all_by_label(label)
                .next()
                .unwrap_or_else(|| panic!("chip {label:?} must render"));
            let rect = node.rect();
            if rect.max.x > budget_edge {
                assert!(
                    rect.width() < 30.0,
                    "chip {label:?} carries text past the cluster's left edge \
                     ({budget_edge}): {:?}",
                    rect
                );
            }
        }
    }

    #[test]
    fn full_row_keeps_the_right_cluster_visible_and_uncovered() {
        // The coverage invariant, through the row's own interface: the
        // version caption anchors at the row's far right and the chip zone
        // yields to the width the caption reserved — with every error chip
        // live.
        let width = 900.0f32;
        let mut h = row_harness(width, RowCase::Heavy);
        h.run();
        let caption = version_caption();
        let version = h
            .get_all_by_label(caption.as_str())
            .next()
            .expect("version caption renders");
        assert!(
            version.rect().max.x >= 8.0 + width - 20.0,
            "version must anchor at the row's right edge, rect {:?}",
            version.rect()
        );
        assert!(
            cluster_edge(&h) < 8.0 + width,
            "the caption must leave the row's left part to the chips"
        );
        assert_chips_yield_to_the_cluster(&h);
    }

    #[test]
    fn status_zone_stays_inside_a_narrow_budget() {
        // The coverage bug: an unbounded chip zone overflowed the row and
        // painted over the version cluster. At a width where the chips
        // cannot all fit, the zone still yields — no chip carries text past
        // the reservation — and the caption itself still renders.
        let width = 620.0f32;
        let mut h = row_harness(width, RowCase::Heavy);
        h.run();
        assert!(
            h.get_all_by_label(version_caption().as_str())
                .next()
                .is_some(),
            "the cluster must render at a tight width"
        );
        assert!(
            cluster_edge(&h) > 8.0,
            "the caption must keep the row's right edge for itself"
        );
        assert_chips_yield_to_the_cluster(&h);
    }
}
