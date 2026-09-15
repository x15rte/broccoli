//! Top-bar status surface: the live speed readout (`↑ rate/s · ↓ rate/s`),
//! shown at the row's right edge immediately left of the version caption,
//! and the dynamic status/error chip zone whose width is capped so the
//! chips can never cover the right edge — the "dynamic status covers the
//! speed/version info" bug.
//!
//! Everything here is a free function or a data struct because the app
//! shell itself is not constructible in tests (it needs
//! `eframe::CreationContext` + profile I/O) — the same seam pattern as
//! `topbar_unsaved_chip` in the shell. The shell memoizes the speed text
//! and the reserved right-cluster width (rebuilt only when
//! the stats generation / traffic unit / language / core version / viewport
//! width moves, never per frame) and renders the chip zone inside a clipped
//! child sized to the row remainder.

use crate::i18n::{Key, t, t_fmt};
use crate::metrics::{MetricsHandle, WorkCounter};
use crate::model::settings::{Language, TrafficUnit};
use crate::rt::StatsTick;
use crate::ui::dashboard::format_bytes;
use crate::ui::status::status_colors_of;

/// The speed readout for one stats tick: one label with both directions,
/// each rate formatted in the global unit (the unit selection is
/// global). `↑ 1.0 MiB/s · ↓ 2.0 MiB/s`.
pub(crate) fn build_speed_label(stats: &StatsTick, unit: TrafficUnit, lang: Language) -> String {
    t_fmt(
        lang,
        Key::TopbarSpeed,
        &[
            &format_bytes(stats.up, unit),
            &format_bytes(stats.down, unit),
        ],
    )
}

/// Width the right-edge cluster reserves on the row: the version caption
/// (weak, body text) plus the speed readout (small) and the inter-item
/// spacing. The shell subtracts this from the row width before sizing the
/// chip zone, so the chips yield instead of ever covering the version/speed
/// info.
pub(crate) fn cluster_width(ui: &egui::Ui, version: &str, speed: Option<&str>) -> f32 {
    let text_width = |text: &str, style: egui::TextStyle| {
        let font_id = egui::FontId::proportional(ui.text_style_height(&style));
        ui.painter()
            .layout_no_wrap(text.to_owned(), font_id, egui::Color32::WHITE)
            .size()
            .x
    };
    let version_w = text_width(version, egui::TextStyle::Body);
    let speed_w = speed
        .map(|text| text_width(text, egui::TextStyle::Small))
        .unwrap_or(0.0);
    version_w + speed_w + ui.spacing().item_spacing.x
}

/// The app-shell memo for the right cluster: the speed
/// readout text and the width it plus the version caption reserve, keyed by
/// everything that moves them — stats tick, traffic unit, language, core
/// version (the version caption's other input), viewport width. `speed` is
/// empty while no stats tick exists (the cluster then reserves the version
/// caption only).
#[derive(Default)]
pub(crate) struct TopbarRightCache {
    key: (u64, TrafficUnit, Language, Option<String>, f32),
    /// The speed readout text; empty while no stats tick exists.
    pub(crate) speed: String,
    /// The width the cluster (version + speed) reserves on the row.
    pub(crate) width: f32,
}

/// The inputs the right cluster depends on, bundled so the refresh fn
/// stays under clippy's argument-count ceiling (the same pattern as the
/// servers editor's `AdvancedTabContext`).
pub(crate) struct TopbarRightInputs<'a> {
    pub stats_generation: u64,
    pub unit: TrafficUnit,
    pub lang: Language,
    pub stats: Option<&'a StatsTick>,
    pub version_caption: &'a str,
    pub core_version: Option<&'a str>,
}

/// Refresh the right-cluster memo and return the width it reserves. The
/// shell calls this with disjoint field borrows. Never allocates on the
/// repaint path: the staleness check compares by value, and only a key
/// change rebuilds the strings (bumping [`WorkCounter::TopbarSpeedRebuilds`]
/// when the cache was already warm).
pub(crate) fn refresh_topbar_right(
    ui: &egui::Ui,
    inputs: &TopbarRightInputs<'_>,
    cache: &mut Option<TopbarRightCache>,
    metrics: &MetricsHandle,
) -> f32 {
    let view_w = (ui.max_rect().width() * 2.0).round() / 2.0;
    let stale = cache.as_ref().is_none_or(|c| {
        c.key.0 != inputs.stats_generation
            || c.key.1 != inputs.unit
            || c.key.2 != inputs.lang
            || c.key.3.as_deref() != inputs.core_version
            || c.key.4 != view_w
    });
    if stale {
        let speed = inputs
            .stats
            .map(|s| build_speed_label(s, inputs.unit, inputs.lang));
        let width = cluster_width(ui, inputs.version_caption, speed.as_deref());
        let was_warm = cache.is_some();
        *cache = Some(TopbarRightCache {
            key: (
                inputs.stats_generation,
                inputs.unit,
                inputs.lang,
                inputs.core_version.map(str::to_owned),
                view_w,
            ),
            speed: speed.unwrap_or_default(),
            width,
        });
        if was_warm {
            metrics.bump_work(WorkCounter::TopbarSpeedRebuilds);
        }
    }
    cache
        .as_ref()
        .expect("topbar right cache populated above")
        .width
}

/// Render the right-edge cluster: version caption at the far right with the
/// speed readout immediately left of it (right-to-left flow — the first
/// widget lands rightmost). `speed` is `None` until the first stats tick.
pub(crate) fn show_right_cluster(ui: &mut egui::Ui, version: &str, speed: Option<&str>) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        ui.weak(version);
        if let Some(speed) = speed {
            ui.add(egui::Label::new(egui::RichText::new(speed).small()));
        }
    });
}

/// The dynamic top-bar status inputs the chip zone renders; bundled so the
/// rendering fn stays under clippy's argument-count ceiling (the same
/// pattern as the servers editor's `AdvancedTabContext`).
pub(crate) struct TopbarStatus<'a> {
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
    pub(crate) config_error: Option<&'a str>,
    pub(crate) state_error: Option<&'a str>,
    pub(crate) persistence_error: Option<&'a str>,
}

/// The click outcomes of one chip-zone frame.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TopbarClicks {
    pub apply: bool,
    pub retry: bool,
    pub open_folder: bool,
}

/// One truncated chip in the dynamic zone: a `Label` capped to its
/// available width with the full text on hover when it was actually elided.
fn chip(ui: &mut egui::Ui, color: egui::Color32, text: impl Into<String>) {
    ui.add(
        egui::Label::new(egui::RichText::new(text.into()).color(color))
            .truncate()
            .show_tooltip_when_elided(true),
    );
}

/// Render the dynamic status/error zone. The caller lays this out inside a
/// child capped to the row remainder and clips that child, so the chips can
/// never cover the right cluster; every piece of text truncates to its
/// remaining budget instead of overflowing. Returns the click outcomes (the
/// shell dispatches the actions).
pub(crate) fn topbar_status_zone(ui: &mut egui::Ui, status: &TopbarStatus<'_>) -> TopbarClicks {
    let lang = status.lang;
    let colors = status_colors_of(ui);
    let mut clicks = TopbarClicks::default();

    ui.separator();
    ui.add(
        egui::Label::new(egui::RichText::new(status.mode_caption))
            .truncate()
            .show_tooltip_when_elided(true),
    );
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
    if let Some(error) = status.persistence_error {
        ui.separator();
        ui.add(
            egui::Label::new(
                egui::RichText::new(t(lang, Key::TopbarSettingsNotSaved)).color(colors.err),
            )
            .truncate(),
        )
        .on_hover_text(error);
        clicks.retry = ui.small_button(t(lang, Key::TopbarRetrySave)).clicked();
        clicks.open_folder = ui
            .small_button(t(lang, Key::TopbarOpenStateFolder))
            .clicked();
    }

    clicks
}

#[cfg(test)]
mod tests {
    use super::*;
    use egui_kittest::{Harness, kittest::Queryable as _};

    /// A 1 Hz sample with distinctive rates.
    fn tick() -> StatsTick {
        StatsTick {
            up: 1_048_576,   // 1.0 MiB/s under Auto
            down: 2_097_152, // 2.0 MiB/s under Auto
            ..Default::default()
        }
    }

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
            config_error: Some("generation failure detail"),
            state_error: Some("load failure detail"),
            persistence_error: Some("save failure detail"),
        }
    }

    #[test]
    fn speed_label_follows_the_global_unit_ladder() {
        assert_eq!(
            build_speed_label(&tick(), TrafficUnit::Auto, Language::En),
            "↑ 1.0 MiB/s · ↓ 2.0 MiB/s"
        );
        assert_eq!(
            build_speed_label(&tick(), TrafficUnit::KiBps, Language::En),
            "↑ 1024.0 KiB/s · ↓ 2048.0 KiB/s"
        );
        assert_eq!(
            build_speed_label(&tick(), TrafficUnit::Bps, Language::En),
            "↑ 1048576.0 B/s · ↓ 2097152.0 B/s"
        );
    }

    #[test]
    fn speed_label_renders_the_idle_session_shape() {
        assert_eq!(
            build_speed_label(
                &StatsTick {
                    up: 0,
                    down: 0,
                    ..Default::default()
                },
                TrafficUnit::Auto,
                Language::En,
            ),
            "↑ 0.0 B/s · ↓ 0.0 B/s"
        );
    }

    #[test]
    fn right_cluster_refresh_memoizes_on_key_changes() {
        // The inputs the right cluster depends on — a state struct because
        // kittest drives the closure per frame and the app-shell pattern is
        // build_ui_state + state mutation.
        struct RightState {
            generation: u64,
            stats: Option<StatsTick>,
            unit: TrafficUnit,
            lang: Language,
            version: String,
            cache: Option<TopbarRightCache>,
            metrics: MetricsHandle,
        }
        let state = RightState {
            generation: 7,
            stats: Some(tick()),
            unit: TrafficUnit::Auto,
            lang: Language::En,
            version: "xray v1 · app 0.1".to_owned(),
            cache: None,
            metrics: MetricsHandle::new(),
        };
        let mut h = Harness::builder().build_ui_state(
            move |ui, state: &mut RightState| {
                let inputs = TopbarRightInputs {
                    stats_generation: state.generation,
                    unit: state.unit,
                    lang: state.lang,
                    stats: state.stats.as_ref(),
                    version_caption: &state.version,
                    core_version: Some("v1"),
                };
                refresh_topbar_right(ui, &inputs, &mut state.cache, &state.metrics);
            },
            state,
        );
        h.run();
        let speed = h
            .state()
            .cache
            .as_ref()
            .expect("the first call seeds the cache")
            .speed
            .clone();
        assert_eq!(speed, "↑ 1.0 MiB/s · ↓ 2.0 MiB/s");
        assert!(
            h.state().cache.as_ref().is_some_and(|c| c.width > 0.0),
            "the cluster must reserve row width for the version + speed"
        );

        // A stats tick (generation bump) rebuilds exactly once.
        h.state_mut().generation = 8;
        h.step();
        assert_eq!(
            h.state().metrics.snapshot().topbar_speed_rebuilds,
            1,
            "a generation bump rebuilds exactly once"
        );

        // Idle frames with unchanged inputs must not rebuild.
        h.run_steps(5);
        assert_eq!(
            h.state().metrics.snapshot().topbar_speed_rebuilds,
            1,
            "unchanged inputs must not rebuild the speed readout"
        );
        assert_eq!(
            h.state().cache.as_ref().expect("cache populated").speed,
            "↑ 1.0 MiB/s · ↓ 2.0 MiB/s"
        );
    }

    #[test]
    fn right_cluster_without_stats_reserves_only_the_version_caption() {
        let mut cache: Option<TopbarRightCache> = None;
        let metrics = MetricsHandle::new();
        {
            let mut h = Harness::new_ui(|ui| {
                let inputs = TopbarRightInputs {
                    stats_generation: 0,
                    unit: TrafficUnit::Auto,
                    lang: Language::En,
                    stats: None,
                    version_caption: "xray v1 · app 0.1",
                    core_version: Some("v1"),
                };
                refresh_topbar_right(ui, &inputs, &mut cache, &metrics);
                assert!(
                    cache.as_ref().is_some_and(|c| c.speed.is_empty()),
                    "no stats tick -> no speed text"
                );
            });
            h.run();
        } // drop the harness: the closure's `&mut cache` borrow ends here
        let (speed, width) = cache
            .as_ref()
            .map(|c| (c.speed.clone(), c.width))
            .expect("cache populated");
        assert_eq!(speed, "", "no stats tick -> no speed text");
        assert!(
            width > 0.0,
            "without stats the cluster still reserves the version caption"
        );
    }

    #[test]
    fn right_cluster_renders_version_with_speed_to_its_left() {
        let mut h = Harness::new_ui(|ui| {
            show_right_cluster(ui, "xray v1 · app 0.1", Some("↑ 1.0 MiB/s · ↓ 2.0 MiB/s"));
        });
        h.run();
        h.get_all_by_label("xray v1 · app 0.1")
            .next()
            .expect("version caption renders at the right edge");
        h.get_all_by_label("↑ 1.0 MiB/s · ↓ 2.0 MiB/s")
            .next()
            .expect("speed readout renders left of the version caption");
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
    fn full_row_keeps_the_right_cluster_visible_and_uncovered() {
        // The end-to-end shape of the top bar: a capped chip zone laid out
        // left-to-right followed by the right-to-left version+speed cluster.
        // The cluster must anchor at the row's far right and nothing the
        // zone paints may overlap it — even with every error chip live and
        // a narrow window.
        let mut h = Harness::builder()
            .with_size(egui::Vec2::new(360.0, 60.0))
            .build_ui_state(
                move |ui, clicks: &mut TopbarClicks| {
                    ui.horizontal(|ui| {
                        ui.label("●");
                        ui.label("Connecting");
                        ui.separator();
                        let budget = 120.0f32;
                        let start_x = ui.cursor().min.x;
                        let _ = ui.scope(|ui| {
                            ui.set_max_width(budget);
                            ui.set_clip_rect(egui::Rect::from_min_max(
                                egui::pos2(start_x, ui.max_rect().min.y),
                                egui::pos2(start_x + budget, ui.max_rect().max.y),
                            ));
                            topbar_status_zone(ui, &heavy_status())
                        });
                        show_right_cluster(
                            ui,
                            "xray v26.7.28 · app 0.1",
                            Some("↑ 1.0 MiB/s · ↓ 2.0 MiB/s"),
                        );
                        *clicks = TopbarClicks::default();
                    });
                },
                TopbarClicks::default(),
            );
        h.run();
        let version = h
            .get_all_by_label("xray v26.7.28 · app 0.1")
            .next()
            .expect("version caption renders");
        let speed = h
            .get_all_by_label("↑ 1.0 MiB/s · ↓ 2.0 MiB/s")
            .next()
            .expect("speed readout renders");
        // The cluster sits at the row's far right.
        assert!(
            version.rect().max.x >= 360.0 - 12.0,
            "version must anchor at the row's right edge, rect {:?}",
            version.rect()
        );
        // The speed sits immediately left of the version.
        assert!(
            speed.rect().max.x <= version.rect().min.x + 2.0,
            "speed must render left of the version, speed {:?} vs version {:?}",
            speed.rect(),
            version.rect()
        );
        // No chip node may overlap the version's rect with readable width
        // (a degenerate clipped node is width ~0 and does not paint there).
        for label in [
            "mode: TUN",
            "Server edits not saved",
            "configuration invalid",
        ] {
            let chip = h.get_all_by_label(label).next().expect("chip renders");
            let overlap = chip.rect().intersects(version.rect())
                && chip.rect().width() > 1.5
                && version.rect().width() > 1.5;
            assert!(
                !overlap,
                "chip {label:?} covers the version caption: chip {:?} vs version {:?}",
                chip.rect(),
                version.rect()
            );
        }
    }

    #[test]
    fn status_zone_stays_inside_a_narrow_budget() {
        // The coverage bug: an unbounded chip zone overflowed the row and
        // painted over the version/speed cluster. The zone must stay inside
        // its capped budget at a width where the chips cannot all fit —
        // truncating labels yield, buttons clip, nothing escapes.
        let mut h = Harness::builder()
            .with_size(egui::Vec2::new(240.0, 60.0))
            .build_ui_state(
                move |ui, clicks: &mut TopbarClicks| {
                    let budget = 150.0f32;
                    let start_x = ui.cursor().min.x;
                    let clip = egui::Rect::from_min_max(
                        egui::pos2(start_x, ui.max_rect().min.y),
                        egui::pos2(start_x + budget, ui.max_rect().max.y),
                    );
                    ui.set_max_width(budget);
                    ui.set_clip_rect(clip);
                    *clicks = topbar_status_zone(ui, &heavy_status());
                },
                TopbarClicks::default(),
            );
        h.run();
        // The zone's chip rows truncate inside the capped width; nodes
        // beyond the budget are degenerate (zero-width ellipsis) and only
        // exist off-clip — the painted row never crosses the budget edge.
        let budget_max_x = 8.0 + 150.0;
        for label in [
            "mode: TUN",
            "Server edits not saved",
            "configuration invalid",
            "settings not saved",
        ] {
            let node = h
                .get_all_by_label(label)
                .next()
                .unwrap_or_else(|| panic!("chip {label:?} must render"));
            // A clipped (degenerate, beyond-budget) chip has no readable
            // text — accesskit still publishes it, so only assert that any
            // *laid-out* chip either fits the budget or carries no width.
            if node.rect().max.x > budget_max_x + 0.5 {
                assert!(
                    node.rect().width() <= 1.5,
                    "chip {label:?} escaped the budget with readable width: \
                     rect {:?}, budget {budget_max_x}",
                    node.rect()
                );
            }
        }
    }
}
