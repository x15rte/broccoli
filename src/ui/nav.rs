//! The nav rail: the screen selectors, with the live speed readout at its
//! foot.
//!
//! [`show_nav_panel`] is the nav rail's whole interface. The shell fills
//! [`NavRailState`] with the frame's facts, hands the nav rail the screen it
//! owns and the nav rail's own memos each frame, and dispatches nothing
//! afterwards — the selectors write the screen in place, so unlike the top
//! bar's row there is no click outcome to hand back.
//!
//! The readout is a memo over the stats tick, keyed on the same generation the
//! rest of the UI keys on, so no rate is ever formatted on the repaint path.
//! The nav rail measures no width: nothing yields to it, unlike the top bar's
//! version cluster.
//!
//! Everything here is a free function or a plain data struct because the app
//! shell itself is not constructible in tests (it needs `eframe::CreationContext`
//! + profile I/O).

use crate::i18n::{Key, t_fmt};
use crate::model::settings::{Language, TrafficUnit};
use crate::rt::StatsTick;
use crate::ui::Screen;
use crate::ui::dashboard::format_bytes;

/// The nav rail's per-frame facts, supplied by the shell: the readout's inputs
/// and the language the selectors render in.
pub(crate) struct NavRailState<'a> {
    pub(crate) lang: Language,
    /// The latest stats tick, `None` while no core session has produced one.
    pub(crate) stats: Option<&'a StatsTick>,
    /// The shell's stats generation, moving whenever a tick arrives or a
    /// session ends — what the readout memo rebuilds on.
    pub(crate) stats_generation: u64,
    pub(crate) unit: TrafficUnit,
}

/// The nav rail's memo state: one readout generation, rebuilt only when its own
/// inputs move. Owned by the shell and handed back each frame, like the top
/// bar's `TopbarMemos`.
#[derive(Default)]
pub(crate) struct NavRailMemos {
    readout: Option<NavReadout>,
}

/// The nav rail's width: a fixed column, narrow enough to leave the screens
/// the window's room.
const NAV_RAIL_WIDTH: f32 = 140.0;

/// One generation of the readout: the two lines (up first) for the stats tick
/// the key names. `lines` is `None` while no tick exists — the nav rail then
/// shows no readout at all rather than a zeroed one.
struct NavReadout {
    key: (u64, TrafficUnit, Language),
    lines: Option<(String, String)>,
}

/// Render the nav rail in its own panel. The one place the nav rail's panel is
/// built, so the shell's frame and the nav rail's tests lay out the same
/// column — the readout's pinned foot is a property of the panel's height.
pub(crate) fn show_nav_panel(
    ui: &mut egui::Ui,
    state: &NavRailState<'_>,
    screen: &mut Screen,
    memos: &mut NavRailMemos,
) {
    egui::Panel::left("nav")
        .resizable(false)
        .default_size(NAV_RAIL_WIDTH)
        .show(ui, |ui| show_rail(ui, state, screen, memos));
}

/// Render the nav rail's contents: one selector per screen, and the speed
/// readout pinned at the nav rail's foot. The selectors write `screen` in
/// place.
fn show_rail(
    ui: &mut egui::Ui,
    state: &NavRailState<'_>,
    screen: &mut Screen,
    memos: &mut NavRailMemos,
) {
    ui.add_space(8.0);
    for s in Screen::ALL {
        ui.selectable_value(screen, s, s.label(state.lang));
        ui.add_space(2.0);
    }
    // The readout is pinned to the nav rail's foot: the child layout stacks
    // from the bottom up, so the selectors above never move when the readout
    // appears or goes away. The first widget added lands lowest, so the down
    // line goes in first and the up line sits above it.
    let lines = refresh_readout(memos, state);
    ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
        if let Some((up, down)) = lines {
            ui.add(egui::Label::new(egui::RichText::new(down).small()));
            ui.add(egui::Label::new(egui::RichText::new(up).small()));
        }
    });
}

/// Refresh the readout memo when its inputs moved, and hand back this frame's
/// two lines, up first. Never formats on the repaint path: the key compares by
/// value, and only a new stats tick, a unit change or a language change
/// rebuilds the strings.
fn refresh_readout<'a>(
    memos: &'a mut NavRailMemos,
    state: &NavRailState<'_>,
) -> Option<(&'a str, &'a str)> {
    let key = (state.stats_generation, state.unit, state.lang);
    if memos
        .readout
        .as_ref()
        .is_none_or(|readout| readout.key != key)
    {
        let lines = state.stats.map(|stats| {
            (
                t_fmt(
                    state.lang,
                    Key::NavSpeedUp,
                    &[&format_bytes(stats.up, state.unit)],
                ),
                t_fmt(
                    state.lang,
                    Key::NavSpeedDown,
                    &[&format_bytes(stats.down, state.unit)],
                ),
            )
        });
        memos.readout = Some(NavReadout { key, lines });
    }
    memos
        .readout
        .as_ref()
        .and_then(|readout| readout.lines.as_ref())
        .map(|(up, down)| (up.as_str(), down.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_rig::DEFAULT_TEST_VIEWPORT;
    use egui_kittest::{Harness, kittest::Queryable as _};

    /// A 1 Hz sample with distinctive rates: 1 MiB/s up, 2 MiB/s down under
    /// the Auto unit.
    fn tick() -> StatsTick {
        StatsTick {
            up: 1_048_576,
            down: 2_097_152,
            ..Default::default()
        }
    }

    /// One frame's nav rail facts plus the screen and memos the shell owns.
    struct NavRailFixture {
        stats: Option<StatsTick>,
        generation: u64,
        unit: TrafficUnit,
        lang: Language,
        screen: Screen,
        memos: NavRailMemos,
    }

    impl Default for NavRailFixture {
        fn default() -> Self {
            Self {
                stats: Some(tick()),
                generation: 1,
                unit: TrafficUnit::Auto,
                lang: Language::En,
                screen: Screen::Dashboard,
                memos: NavRailMemos::default(),
            }
        }
    }

    /// Drive the real nav rail through the panel the shell builds, at the
    /// app's minimum window size — the layout a user's window can actually
    /// have.
    fn nav_rail_harness(fixture: NavRailFixture) -> Harness<'static, NavRailFixture> {
        Harness::builder()
            .with_size(DEFAULT_TEST_VIEWPORT)
            .build_ui_state(
                |ui, fixture: &mut NavRailFixture| {
                    show_nav_panel(
                        ui,
                        &NavRailState {
                            lang: fixture.lang,
                            stats: fixture.stats.as_ref(),
                            stats_generation: fixture.generation,
                            unit: fixture.unit,
                        },
                        &mut fixture.screen,
                        &mut fixture.memos,
                    );
                },
                fixture,
            )
    }

    #[test]
    fn the_readout_renders_one_line_per_direction() {
        let mut h = nav_rail_harness(NavRailFixture::default());
        h.run();
        for label in ["↑ 1.0 MiB/s", "↓ 2.0 MiB/s"] {
            assert!(
                h.get_all_by_label(label).next().is_some(),
                "{label:?} must render in the nav rail"
            );
        }
    }

    #[test]
    fn the_readout_follows_the_global_unit_ladder() {
        for (unit, up, down) in [
            (TrafficUnit::Auto, "↑ 1.0 MiB/s", "↓ 2.0 MiB/s"),
            (TrafficUnit::KiBps, "↑ 1024.0 KiB/s", "↓ 2048.0 KiB/s"),
            (TrafficUnit::Bps, "↑ 1048576.0 B/s", "↓ 2097152.0 B/s"),
        ] {
            let mut h = nav_rail_harness(NavRailFixture {
                unit,
                ..Default::default()
            });
            h.run();
            for label in [up, down] {
                assert!(
                    h.get_all_by_label(label).next().is_some(),
                    "{label:?} must render under {unit:?}"
                );
            }
        }
    }

    #[test]
    fn an_ended_session_leaves_no_readout_behind() {
        // The rates are session facts: when the session ends the shell clears
        // the tick and bumps the generation, and the last tick's numbers must
        // not masquerade as live traffic.
        let mut h = nav_rail_harness(NavRailFixture::default());
        h.run();
        assert!(
            h.query_by_label("↑ 1.0 MiB/s").is_some(),
            "the live session must show its rates"
        );

        h.state_mut().stats = None;
        h.state_mut().generation = 2;
        h.step();
        assert!(
            h.query_all_by_label_contains("/s").next().is_none(),
            "a session that ended must leave no readout in the nav rail"
        );
    }

    #[test]
    fn the_readout_sits_at_the_nav_rail_foot_below_the_selectors() {
        let mut h = nav_rail_harness(NavRailFixture::default());
        h.run();
        let last_selector = h
            .get_all_by_label(Screen::About.label(Language::En))
            .next()
            .expect("the last screen selector renders");
        let up = h
            .get_all_by_label("↑ 1.0 MiB/s")
            .next()
            .expect("the up line renders");
        let down = h
            .get_all_by_label("↓ 2.0 MiB/s")
            .next()
            .expect("the down line renders");

        assert!(
            up.rect().min.y > last_selector.rect().max.y,
            "the readout must sit below the selectors, up {:?} vs About {:?}",
            up.rect(),
            last_selector.rect()
        );
        assert!(
            up.rect().max.y <= down.rect().min.y,
            "the up line must sit above the down line, up {:?} vs down {:?}",
            up.rect(),
            down.rect()
        );
        assert!(
            down.rect().max.y > DEFAULT_TEST_VIEWPORT.y - 40.0,
            "the readout must sit at the nav rail's foot, down {:?}",
            down.rect()
        );
    }

    #[test]
    fn an_idle_frame_does_not_rebuild_the_readout() {
        // The memoization rule keeps its guard, at the memoization: a frame
        // with unchanged inputs must keep the very strings it built, not
        // merely their values.
        let mut h = nav_rail_harness(NavRailFixture::default());
        h.run();
        let built = h
            .state()
            .memos
            .readout
            .as_ref()
            .and_then(|readout| readout.lines.as_ref())
            .expect("the first tick seeds the readout")
            .0
            .as_ptr();
        h.run_steps(5);
        assert_eq!(
            h.state()
                .memos
                .readout
                .as_ref()
                .and_then(|readout| readout.lines.as_ref())
                .expect("the readout stays while the tick does")
                .0
                .as_ptr(),
            built,
            "unchanged inputs must not rebuild the readout"
        );
    }

    #[test]
    fn a_selector_click_writes_the_screen() {
        let mut h = nav_rail_harness(NavRailFixture::default());
        h.run();
        h.get_by_label(Screen::About.label(Language::En)).click();
        h.run();
        assert!(
            h.state().screen == Screen::About,
            "the nav rail's selectors must still choose the screen"
        );
    }
}
