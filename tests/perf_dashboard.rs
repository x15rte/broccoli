//! The dashboard must not rebuild its
//! throughput-plot series on idle frames, and must rebuild it exactly once
//! per stats-history change. The plot side is asserted through the always-on
//! `PlotRebuilds` work counter; the latency grid deliberately carries no
//! counter of its own, so its memoization is verified
//! structurally by `DashboardScreen`'s unit tests (generation gating) and
//! behaviorally here (labels render correctly and stay stable across idle
//! frames).
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! A temporary APPDATA still isolates persistence, downloaded assets, and
//! logs. Tests are serialized because changing a process environment
//! variable while another harness/runtime thread reads it is undefined
//! behavior.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::settings::Language;
use broccoli::model::{OutboundModel, Protocol, ServerProfile, ServersFile};
use broccoli::ui::Screen;
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::{Mutex, MutexGuard};
use serde_json::Map;

static APPDATA_LOCK: Mutex<()> = Mutex::new(());

/// `%APPDATA%` pointed at a fresh tempdir; the guard serializes every test
/// that mutates the process env vars (the `ui_smoke` convention — env
/// mutation while another thread reads it is undefined behavior).
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

/// Like [`harness`], but with a seeded `state/servers.json` (the real state
/// layout) so the dashboard's latency grid has rows to render.
fn harness_with_profiles() -> (
    MutexGuard<'static, ()>,
    tempfile::TempDir,
    Harness<'static, BroccoliApp>,
) {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: APPDATA_LOCK excludes every test in this process that changes
    // or reads APPDATA through a BroccoliApp harness.
    unsafe { std::env::set_var("APPDATA", tmp.path()) };
    let state = tmp.path().join("broccoli/state");
    std::fs::create_dir_all(&state).unwrap();
    let servers = seeded_servers();
    std::fs::write(
        state.join("servers.json"),
        serde_json::to_vec_pretty(&servers).unwrap(),
    )
    .unwrap();
    let h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    (lock, tmp, h)
}

/// Three seeded profiles for the latency grid. `latency_ms` is a runtime
/// cache (`#[serde(skip)]` — never persisted), so every seeded row renders
/// the unmeasured em dash; the measured/dead cells are driven by in-memory
/// values in the `DashboardScreen` unit tests (a live core would provide
/// observatory entries, which the headless harness cannot).
fn seeded_servers() -> ServersFile {
    let mk = |name: &str| ServerProfile::new(name, OutboundModel::new(Protocol::Trojan));
    ServersFile {
        version: 1,
        active: None,
        profiles: vec![mk("alpha"), mk("beta"), mk("gamma")],
        extra: Map::new(),
    }
}

/// Dismiss the first-run wizard ("Set up later") exactly like `ui_smoke` —
/// a fresh temp APPDATA has no core, so the modal covers the screen and
/// swallows nav clicks until it is dismissed.
fn dismiss_wizard(h: &mut Harness<'static, BroccoliApp>) {
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    assert!(
        h.query_all_by_label("Welcome to broccoli").next().is_none(),
        "the first-run wizard must be dismissed before navigating"
    );
}

/// The dashboard's latency grid renders the seeded profile rows: the profile
/// names plus the em dash for the (unmeasured, since `latency_ms` is a
/// runtime cache) latency cells.
fn assert_grid_evidence(h: &Harness<'static, BroccoliApp>) {
    for name in ["alpha", "beta", "gamma"] {
        assert!(
            h.query_all_by_label(name).next().is_some(),
            "the grid must render the seeded profile {name}"
        );
    }
    assert!(
        h.query_all_by_label("—").next().is_some(),
        "the grid must render the em dash for the unmeasured profiles"
    );
}

/// Acceptance (a): N idle frames on the dashboard advance the
/// frame-time accumulator by exactly N and rebuild neither the plot series
/// nor the grid. With no core the runtime never leaves Stopped, so no stats
/// or observatory tick can ever fire — the single plot rebuild from the
/// first render must be the only one, forever.
#[test]
fn dashboard_idle_frames_rebuild_nothing() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    dismiss_wizard(&mut h);

    // The dashboard is the default screen; clicking the nav item settles the
    // navigation the way the benchmark does.
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Dashboard.label(Language::En),
    )
    .click();
    h.run_steps(4);

    let after_nav = h.state().metrics_snapshot();
    assert_eq!(
        after_nav.plot_rebuilds, 0,
        "the first render seeds the plot cache without counting a rebuild"
    );
    assert_eq!(
        after_nav.stats_ticks, 0,
        "no stats arm can fire while the runtime is Stopped"
    );
    assert_eq!(
        after_nav.obs_ticks, 0,
        "no observatory arm can fire while the runtime is Stopped"
    );

    const IDLE_FRAMES: u64 = 120;
    let before = h.state().metrics_snapshot();
    h.run_steps(IDLE_FRAMES as usize);
    let after = h.state().metrics_snapshot();

    assert_eq!(
        after.frames - before.frames,
        IDLE_FRAMES,
        "the frame accumulator must count exactly the idle window"
    );
    assert_eq!(
        after.plot_rebuilds - before.plot_rebuilds,
        0,
        "idle frames must not rebuild the throughput plot series"
    );
}

/// Acceptance (b): with a seeded profile list the latency grid
/// renders the correct values (evidence labels) and idle frames produce no
/// observable work — the plot counter stays flat and the memoized grid keeps
/// rendering the same values.
#[test]
fn seeded_dashboard_grid_renders_values_and_idles_flat() {
    let (_lock, _tmp, mut h) = harness_with_profiles();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    dismiss_wizard(&mut h);
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Dashboard.label(Language::En),
    )
    .click();
    h.run_steps(4);

    assert_grid_evidence(&h);

    // The seeded dashboard still renders its body label (navigation proof,
    // the `ui_smoke` convention for the seeded case).
    assert!(
        h.query_all_by_label(
            t(Language::En, Key::DashboardActiveServer)
                .to_string()
                .as_str()
        )
        .next()
        .is_some(),
        "the seeded dashboard must render its active-server section"
    );

    const IDLE_FRAMES: u64 = 120;
    let before = h.state().metrics_snapshot();
    h.run_steps(IDLE_FRAMES as usize);
    let after = h.state().metrics_snapshot();

    assert_eq!(
        after.frames - before.frames,
        IDLE_FRAMES,
        "the frame accumulator must count exactly the idle window"
    );
    assert_eq!(
        after.plot_rebuilds - before.plot_rebuilds,
        0,
        "idle frames must not rebuild the throughput plot series"
    );
    // The grid has no counter by design; the observable contract is that its
    // memoized values keep rendering unchanged across idle frames.
    assert_grid_evidence(&h);
}
