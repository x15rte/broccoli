//! The Logs screen's filtered view is memoized
//! on (log ring identity, filter state, clear marker) and only the rows
//! visible in the scroll area are laid out per frame. This file pins the
//! counter contract through the metrics snapshot (the `ui_smoke`
//! convention): N idle frames never rebuild the filtered view, a filter
//! keystroke reapplies it exactly once, and the memoized view still drives
//! the rendered screen.
//!
//! The app's log push path (`BroccoliApp::push_log`) is private and only fed
//! by runtime events, which a fresh temp-APPDATA harness never produces, so
//! line-append rebuild counts are pinned by the memoized-view unit tests in
//! `src/ui/logs.rs` instead (the acceptance allows either route).

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::settings::Language;
use broccoli::ui::Screen;
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::{Mutex, MutexGuard};

static APPDATA_LOCK: Mutex<()> = Mutex::new(());

/// Fresh temp APPDATA + harness, exactly like tests/ui_smoke.rs (the process
/// lock serializes env mutation; each test binary has its own process, so no
/// cross-binary lock is needed).
fn harness() -> (
    MutexGuard<'static, ()>,
    tempfile::TempDir,
    Harness<'static, BroccoliApp>,
) {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: APPDATA_LOCK excludes every test in this process that changes
    // or reads APPDATA through a BroccoliApp harness.
    unsafe { std::env::set_var("APPDATA", tmp.path()) };
    let h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    (lock, tmp, h)
}

/// The Logs screen's filter input — the only text input on that screen.
fn logs_filter<'a>(h: &'a Harness<'a, BroccoliApp>) -> egui_kittest::Node<'a> {
    h.get_all_by_role(egui::accesskit::Role::TextInput)
        .next()
        .expect("logs filter input")
}

/// Boot, dismiss the first-run wizard, navigate to Logs, and settle.
fn open_logs(h: &mut Harness<'static, BroccoliApp>) {
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    assert!(
        h.query_all_by_label("Welcome to broccoli").next().is_none(),
        "the first-run wizard must be dismissed before navigating"
    );
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Logs.label(Language::En),
    )
    .click();
    h.run_steps(4);
    assert!(
        h.query_by_label(t(Language::En, Key::LogsCopyAll))
            .is_some(),
        "the Logs screen must render its toolbar"
    );
}

/// Acceptance (a): N consecutive idle frames on the Logs screen advance the
/// frame-time accumulator but never rebuild the filtered view.
#[test]
fn idle_frames_on_logs_never_rebuild_the_filtered_view() {
    let (_lock, _tmp, mut h) = harness();
    open_logs(&mut h);

    const IDLE_FRAMES: u64 = 120;
    let before = h.state().metrics_snapshot();
    h.run_steps(IDLE_FRAMES as usize);
    let after = h.state().metrics_snapshot();

    assert_eq!(
        after.frames - before.frames,
        IDLE_FRAMES,
        "the frame accumulator must count the idle window exactly"
    );
    assert_eq!(
        after.log_filter_rebuilds - before.log_filter_rebuilds,
        0,
        "N idle frames on the Logs screen must not rebuild the filtered view"
    );
}

/// Acceptance (b): typing in the filter input reapplies the filter exactly
/// once — one keystroke batch is one rebuild, settled frames add nothing.
#[test]
fn filter_keystroke_reapplies_the_view_exactly_once() {
    let (_lock, _tmp, mut h) = harness();
    open_logs(&mut h);

    let before = h.state().metrics_snapshot();
    logs_filter(&h).click();
    h.run();
    // The first build already happened during open_logs; focusing the field
    // must not rebuild anything.
    assert_eq!(
        h.state().metrics_snapshot().log_filter_rebuilds - before.log_filter_rebuilds,
        0,
        "focusing the filter input is not a filter change"
    );

    logs_filter(&h).type_text("z");
    h.run();
    h.run_steps(8);

    let after = h.state().metrics_snapshot();
    assert_eq!(
        after.log_filter_rebuilds - before.log_filter_rebuilds,
        1,
        "one keystroke batch must rebuild the filtered view exactly once"
    );
    // The filter stays applied: more idle frames must not rebuild again.
    h.run_steps(16);
    let settled = h.state().metrics_snapshot();
    assert_eq!(
        settled.log_filter_rebuilds - after.log_filter_rebuilds,
        0,
        "settled frames after the keystroke must not rebuild again"
    );
}

/// Acceptance (d), app level: the memoized view still drives the rendered
/// screen — the line-count label reflects the (empty) buffer through the
/// view, and the screen renders after a filter edit.
#[test]
fn logs_screen_renders_the_memoized_view() {
    let (_lock, _tmp, mut h) = harness();
    open_logs(&mut h);

    // The line-count label is built from the memoized view's row count:
    // with a fresh empty buffer it must read "0 of 0 lines".
    assert!(
        h.query_by_label("0 of 0 lines").is_some(),
        "the line-count label must reflect the memoized view over the empty buffer"
    );

    // A filter edit that matches nothing still renders the screen, and the
    // count label follows the view.
    logs_filter(&h).click();
    h.run();
    logs_filter(&h).type_text("zzz");
    h.run_steps(4);
    assert!(
        h.query_by_label("0 of 0 lines").is_some(),
        "the memoized view must keep rendering after a filter edit"
    );
    assert!(
        h.query_by_label(t(Language::En, Key::LogsCopyAll))
            .is_some(),
        "the Logs screen must still render its toolbar after a filter edit"
    );
}
