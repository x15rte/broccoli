//! The UI-context snapshot is generation-gated.
//!
//! The app rebuilds its owned `UiCtxSnapshot` only when a drained runtime
//! event changes the inputs (phase, stats, observatory, download) — never
//! per frame. These tests drive the real `BroccoliApp` through egui_kittest
//! and assert the `UiCtxRebuilds` work counter: zero over idle frames, one
//! per real input change, and no second build on the first-run wizard path.
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
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::{Mutex, MutexGuard};

static APPDATA_LOCK: Mutex<()> = Mutex::new(());
fn harness() -> (
    MutexGuard<'static, ()>,
    tempfile::TempDir,
    Harness<'static, BroccoliApp>,
) {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: APPDATA_LOCK excludes every test in this process that changes or
    // reads APPDATA through a BroccoliApp harness.
    unsafe { std::env::set_var("APPDATA", tmp.path()) };
    let h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    (lock, tmp, h)
}

/// Dismiss the first-run wizard ("Set up later") exactly like the sibling
/// tests, so nav clicks reach the real screens.
fn dismiss_wizard(h: &mut Harness<'static, BroccoliApp>) {
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    assert!(
        h.query_all_by_label("Welcome to broccoli").next().is_none(),
        "the first-run wizard must be dismissed before asserting idle behavior"
    );
}

const IDLE_FRAMES: usize = 120;

/// Acceptance (a): N consecutive idle frames must not rebuild the UI-context
/// snapshot — the work counter's delta across the window is zero — and the
/// screens still render afterwards (behavior unchanged).
#[test]
fn idle_frames_never_rebuild_the_ui_context_snapshot() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    dismiss_wizard(&mut h);

    let before = h.state().metrics_snapshot();
    h.run_steps(IDLE_FRAMES);
    let after = h.state().metrics_snapshot();
    assert_eq!(
        after.ui_ctx_rebuilds - before.ui_ctx_rebuilds,
        0,
        "idle frames must not rebuild the UI-context snapshot"
    );

    // The snapshot gating must not change rendering: the Dashboard still
    // renders its body after the idle window.
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Dashboard")
        .click();
    h.run();
    assert!(
        h.query_all_by_label(t(Language::En, Key::DashboardNoServers))
            .next()
            .is_some(),
        "Dashboard must still render after idle frames"
    );
}

/// Acceptance (b): a rebuild happens exactly when an input generation
/// changes. A synthetic stats tick pushed through the real event channel
/// drains on the next frame and rebuilds the snapshot exactly once; a
/// follow-up log event (which does not feed the snapshot) must not rebuild
/// it, and idle frames after the tick must stay at zero.
#[test]
fn a_stats_tick_rebuilds_the_snapshot_exactly_once() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    dismiss_wizard(&mut h);

    let before = h.state().metrics_snapshot();
    h.state().inject_event(CoreEvt::Stats(StatsTick {
        up: 42,
        down: 7,
        uptime_secs: 1,
        goroutines: 2,
        ..Default::default()
    }));
    h.run_steps(2);
    let after_tick = h.state().metrics_snapshot();
    assert_eq!(
        after_tick.ui_ctx_rebuilds - before.ui_ctx_rebuilds,
        1,
        "one stats tick must rebuild the snapshot exactly once"
    );

    // A log line is a real event but does not feed the snapshot: no rebuild.
    h.state().inject_event(CoreEvt::Log {
        line: "probe".to_string(),
        from_core: true,
    });
    h.run_steps(2);
    let after_log = h.state().metrics_snapshot();
    assert_eq!(
        after_log.ui_ctx_rebuilds - after_tick.ui_ctx_rebuilds,
        0,
        "a log event must not rebuild the snapshot"
    );

    // Idle frames after the tick keep the counter flat.
    h.run_steps(IDLE_FRAMES);
    let settled = h.state().metrics_snapshot();
    assert_eq!(
        settled.ui_ctx_rebuilds - after_log.ui_ctx_rebuilds,
        0,
        "idle frames after a rebuild must not rebuild again"
    );
}

/// Acceptance (c): the first-run wizard path (no core seeded) reuses the
/// same snapshot — while the wizard covers the screen, across dismissal,
/// and afterwards, the rebuild counter stays at zero.
#[test]
fn wizard_path_reuses_the_snapshot_without_a_second_build() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    // No core in the scratch APPDATA, so the first-run wizard is up.
    h.run();

    let with_wizard = h.state().metrics_snapshot();
    h.run_steps(IDLE_FRAMES);
    let still_wizard = h.state().metrics_snapshot();
    assert_eq!(
        still_wizard.ui_ctx_rebuilds - with_wizard.ui_ctx_rebuilds,
        0,
        "idle frames with the wizard covering the screen must not rebuild the snapshot"
    );

    // Dismissing the wizard is a UI event, not a runtime event: no rebuild.
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    let dismissed = h.state().metrics_snapshot();
    assert_eq!(
        dismissed.ui_ctx_rebuilds - still_wizard.ui_ctx_rebuilds,
        0,
        "dismissing the wizard must not build a second snapshot"
    );

    // And idle frames after dismissal stay flat too.
    h.run_steps(IDLE_FRAMES);
    let settled = h.state().metrics_snapshot();
    assert_eq!(
        settled.ui_ctx_rebuilds - dismissed.ui_ctx_rebuilds,
        0,
        "idle frames after wizard dismissal must not rebuild the snapshot"
    );
}
