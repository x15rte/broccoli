//! The dashboard throughput chart must always auto-fit its Y axis to the
//! traffic currently in the history window.
//!
//! egui_plot's automatic bounds are sticky: any pan/zoom/scroll interaction
//! on the plot flips `PlotMemory.auto_bounds` to false permanently (only a
//! double-click restores it), so one wheel scroll or drag over the chart
//! freezes the zoom at whatever scale was current — the reported "zoom level
//! fixed to the peak traffic volume" symptom. The chart's Y axis must follow
//! the data instead: after a peak scrolls out of the history ring, the axis
//! must shrink back, interaction or not.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! A temporary APPDATA still isolates persistence, downloaded assets, and
//! logs. Tests are serialized because changing a process environment
//! variable while another harness/runtime thread reads it is undefined
//! behavior.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::settings::Language;
use broccoli::rt::{CoreEvt, StatsTick};
use broccoli::ui::Screen;
use egui_kittest::{Harness, kittest::Queryable};

mod common;

/// The dashboard plot's explicit global id — the `PlotMemory` key under which
/// its bounds are observable. The screen owns the value, so a rename cannot
/// leave this test bound to a key nothing writes.
fn plot_id() -> egui::Id {
    broccoli::ui::dashboard::throughput_plot_id()
}

/// Push a synthetic stats tick through the real event-drain path.
fn inject_stats(h: &mut Harness<'static, BroccoliApp>, up: u64, down: u64) {
    h.state().inject_event(CoreEvt::Stats(StatsTick {
        up,
        down,
        ..Default::default()
    }));
}

/// The chart's persisted plot memory: bounds + auto-bounds state.
fn plot_memory(h: &Harness<'static, BroccoliApp>) -> egui_plot::PlotMemory {
    egui_plot::PlotMemory::load(&h.ctx, plot_id())
        .expect("the throughput plot must have rendered and stored its memory")
}

/// The current Y-axis upper bound of the throughput chart.
fn plot_y_max(h: &Harness<'static, BroccoliApp>) -> f64 {
    plot_memory(h).bounds().max()[1]
}

/// The chart's on-screen rect: the plot stores its frame in `PlotMemory`
/// every frame, so tests can aim at the chart's actual geometry instead of
/// window coordinates that a layout shift could move clear of the plot.
fn plot_frame(h: &Harness<'static, BroccoliApp>) -> egui::Rect {
    let frame = *plot_memory(h).transform().frame();
    assert!(
        frame.is_positive() && frame.is_finite(),
        "the throughput chart must have a laid-out frame to scroll over (got {frame:?})"
    );
    frame
}

/// A wheel scroll over the chart body, the way a user scrolling the
/// dashboard page does. Each scroll targets a point inside the chart's own
/// frame (resolved from `PlotMemory` at scroll time), spread across the
/// frame height so at least one lands on the plot whatever small layout
/// shifts occur — a scroll anywhere else in the dashboard is inert. The
/// chart must never lose its auto-bounds to such an interaction.
fn wheel_scroll_over_chart(h: &mut Harness<'static, BroccoliApp>) {
    let frame = plot_frame(h);
    for y in [
        frame.top() + frame.height() * 0.25,
        frame.center().y,
        frame.top() + frame.height() * 0.75,
    ] {
        h.hover_at(egui::Pos2::new(frame.center().x, y));
        h.event(egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Point,
            delta: egui::Vec2::new(0.0, 60.0),
            modifiers: egui::Modifiers::NONE,
            phase: egui::TouchPhase::Move,
        });
        h.run();
    }
}

/// The chart's Y axis follows the current traffic: a peak expands it, and
/// once the peak scrolls out of the history ring the axis shrinks back —
/// even after a wheel scroll over the chart (which would otherwise freeze
/// the zoom at the peak scale forever).
#[test]
fn chart_y_axis_auto_fits_and_releases_after_peak() {
    let (_lock, _tmp, mut h) = common::boot(|_| {}, None);
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    common::dismiss_wizard(&mut h);
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Dashboard.label(Language::En),
    )
    .click();
    h.run_steps(4);

    // Low traffic: the axis fits the low level.
    inject_stats(&mut h, 1_000, 2_000);
    h.run_steps(2);
    let low = plot_y_max(&h);
    assert!(
        low < 10_000.0,
        "the Y axis must fit low traffic (got max {low} for 2_000 B/s)"
    );

    // A peak expands the axis.
    inject_stats(&mut h, 50_000_000, 40_000_000);
    h.run_steps(2);
    let peak = plot_y_max(&h);
    assert!(
        peak > 40_000_000.0,
        "the Y axis must expand to the peak (got max {peak})"
    );

    // A wheel scroll over the chart — the interaction that, on a plot with
    // default interaction settings, disabled auto-bounds permanently and
    // froze the zoom at the peak scale.
    wheel_scroll_over_chart(&mut h);
    assert!(
        plot_memory(&h).auto_bounds.y,
        "a wheel scroll over the chart must not disable its auto-bounds"
    );

    // The peak leaves the history ring (HISTORY_CAP ticks), traffic drops.
    for _ in 0..120 {
        inject_stats(&mut h, 1_000, 2_000);
    }
    h.run_steps(2);
    let back = plot_y_max(&h);
    assert!(
        back < 10_000.0,
        "the Y axis must shrink back to the low level once the peak leaves the \
         window (got max {back}, peak was {peak})"
    );
}

/// Without any interaction, the axis already follows the data — the
/// no-scroll baseline the scroll case builds on.
#[test]
fn chart_y_axis_auto_fits_without_interaction() {
    let (_lock, _tmp, mut h) = common::boot(|_| {}, None);
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    common::dismiss_wizard(&mut h);
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Dashboard.label(Language::En),
    )
    .click();
    h.run_steps(4);

    inject_stats(&mut h, 1_000, 2_000);
    h.run_steps(2);
    assert!(plot_y_max(&h) < 10_000.0, "the Y axis must fit low traffic");

    inject_stats(&mut h, 50_000_000, 40_000_000);
    h.run_steps(2);
    assert!(
        plot_y_max(&h) > 40_000_000.0,
        "the Y axis must expand to the peak"
    );

    for _ in 0..120 {
        inject_stats(&mut h, 1_000, 2_000);
    }
    h.run_steps(2);
    assert!(
        plot_y_max(&h) < 10_000.0,
        "the Y axis must shrink back once the peak leaves the window"
    );
}

/// Smoke: the chart still renders its evidence labels with the explicit id
/// (navigation proof, the `ui_smoke` convention).
#[test]
fn chart_still_renders_on_the_dashboard() {
    let (_lock, _tmp, mut h) = common::boot(|_| {}, None);
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    common::dismiss_wizard(&mut h);
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Dashboard.label(Language::En),
    )
    .click();
    h.run_steps(4);
    assert!(
        h.query_all_by_label(
            t(Language::En, Key::DashboardNoServers)
                .to_string()
                .as_str()
        )
        .next()
        .is_some(),
        "the dashboard must render"
    );
    assert!(
        plot_memory(&h).bounds().is_valid(),
        "the throughput chart must be laid out with valid bounds"
    );
}
