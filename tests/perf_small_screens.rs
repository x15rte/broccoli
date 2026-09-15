//! Small-screen churn (inbounds, TUN).
//! Idle-frame purity for the two screens that used to touch OS or validation
//! state per frame:
//!
//! - Inbounds: validation references (cross-listener collisions, tag errors,
//!   routing reference counts, LAN-exposure posture) are rebuilt only when
//!   the model generation `(config_revision, dirty)` changes; idle frames
//!   keep rendering the cached verdicts.
//! - TUN: adapter enumeration runs on a worker thread at a 5 s cadence; idle
//!   frames must not bump `adapter_enumerations`, and the adapter list
//!   renders from the delivered worker result.
//!
//! Safety: the `tests/ui_smoke.rs` convention — `APPDATA_LOCK` + tempdir
//! isolation; every test that mutates or reads process env holds the lock.
//! Tests in this binary share one process, so the lock is process-local
//! (other test binaries have their own processes).

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::Settings;
use broccoli::model::settings::Language;
use broccoli::sys::netif;
use broccoli::ui::Screen;
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

static APPDATA_LOCK: Mutex<()> = Mutex::new(());

fn harness() -> (
    MutexGuard<'static, ()>,
    tempfile::TempDir,
    Harness<'static, BroccoliApp>,
) {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: APPDATA_LOCK serializes every test in this process that changes
    // or reads APPDATA through a BroccoliApp harness.
    unsafe { std::env::set_var("APPDATA", tmp.path()) };
    let h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    (lock, tmp, h)
}

/// Boot, dismiss the first-run wizard (fresh APPDATA has no core), and
/// navigate to `screen`.
fn navigate(h: &mut Harness<'static, BroccoliApp>, screen: Screen) {
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, screen.label(Language::En))
        .click();
    h.run();
}

// ---------------------------------------------------------------------------
// Inbounds: generation-gated validation references
// ---------------------------------------------------------------------------

/// The inbounds screen rebuilds its validation references only when the
/// model generation changes. Seed a SOCKS/HTTP port collision on a
/// non-loopback listen (posture banner + both collision verdicts), render,
/// and run an idle window: the cached verdicts must keep rendering.
#[test]
fn inbounds_idle_frames_keep_rendering_validation() {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: APPDATA_LOCK serializes all Broccoli state access in this test
    // process.
    unsafe { std::env::set_var("APPDATA", tmp.path()) };

    // The default list's SOCKS and HTTP entries on the same non-loopback
    // listen + port: the posture banner and the cross-listener
    // collisions all render.
    let mut settings = Settings::default();
    settings.local_inbounds[0].listen = "192.168.1.5".into();
    settings.local_inbounds[1].listen = "192.168.1.5".into();
    settings.local_inbounds[1].port = settings.local_inbounds[0].port;

    let broccoli_root = tmp.path().join("broccoli");
    std::fs::create_dir_all(broccoli_root.join("state")).unwrap();
    std::fs::write(
        broccoli_root.join("state/settings.json"),
        serde_json::to_vec_pretty(&settings).unwrap(),
    )
    .unwrap();

    let mut h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Inbounds.label(Language::En),
    )
    .click();
    h.run_steps(4);

    assert!(
        h.query_by_label_contains("conflicts with HTTP").is_some(),
        "the SOCKS collision verdict must render from the validation cache"
    );
    assert!(
        h.query_by_label_contains("conflicts with SOCKS").is_some(),
        "the HTTP collision verdict must render from the validation cache"
    );
    assert!(
        h.query_by_label_contains("non-loopback listeners off the public internet")
            .is_some(),
        "the LAN-exposure posture banner must render from the validation cache"
    );

    // Idle frames: the cached verdicts stay rendered (nothing is rebuilt).
    h.run_steps(12);
    assert!(
        h.query_by_label_contains("conflicts with HTTP").is_some(),
        "idle frames must keep rendering the cached collision verdict"
    );
    assert!(
        h.query_by_label_contains("non-loopback listeners off the public internet")
            .is_some(),
        "idle frames must keep rendering the cached posture banner"
    );

    drop(h);
    drop(tmp);
    drop(lock);
}

// ---------------------------------------------------------------------------
// TUN: worker-thread adapter enumeration
// ---------------------------------------------------------------------------

/// Wall-clock bound for a real-clock worker result to land: generous enough
/// that a loaded CI machine cannot fail the wait, finite so a dead worker
/// still fails the test.
const WORKER_DEADLINE: Duration = Duration::from_secs(30);

/// Wall-clock bound for a delivered result to reach the screen.
const RENDER_DEADLINE: Duration = Duration::from_secs(15);

/// The TUN worker's enumeration cadence: the screen refreshes adapters at
/// this interval (its `REFRESH_INTERVAL`).
const WORKER_CADENCE: Duration = Duration::from_secs(5);

/// The TUN screen enumerates adapters on a worker thread at a 5 s cadence.
/// The first show spawns one enumeration; the delivered result renders the
/// adapter grid; idle UI frames must not bump `adapter_enumerations` (the
/// worker cadence is the only source).
#[test]
fn tun_enumerates_off_thread_and_idle_frames_do_not_reenumerate() {
    let (_lock, _tmp, mut h) = harness();
    // The Dashboard renders a TUN mode selector next to the sidebar's TUN
    // nav item (two buttons with the same label), so route through Inbounds
    // first; the sidebar item is then the only "TUN" button.
    navigate(&mut h, Screen::Inbounds);
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Tun.label(Language::En),
    )
    .click();
    h.run();

    // The first show spawns the worker; poll until its enumeration lands
    // (the worker runs on the real clock, so poll with real sleeps). The
    // wait is bounded by wall-clock, not by an iteration budget, so a slow
    // machine only makes it longer.
    let deadline = Instant::now() + WORKER_DEADLINE;
    while h.state().metrics_snapshot().adapter_enumerations == 0 {
        assert!(
            Instant::now() < deadline,
            "the TUN worker must deliver one adapter enumeration within {WORKER_DEADLINE:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
        h.run();
    }

    // The adapter list renders: drain the delivered result into the UI and
    // prove the grid shows the same adapters a fresh local enumeration
    // reports (the worker enumerated on this machine moments earlier).
    h.run_steps(4);
    let expected = netif::list();
    if let Some(first) = expected.first() {
        let deadline = Instant::now() + RENDER_DEADLINE;
        while h.query_by_label_contains(&first.name).is_none() {
            assert!(
                Instant::now() < deadline,
                "the TUN screen must render the enumerated adapter list ({} missing) \
                 within {RENDER_DEADLINE:?}",
                first.name
            );
            std::thread::sleep(Duration::from_millis(20));
            h.run();
        }
    } else {
        // No adapters on this machine: the grid has no rows to name, but
        // the rendered section header is still adapter-independent evidence
        // that the delivered (empty) list did not blank the screen.
        assert!(
            h.query_by_label_contains(t(Language::En, Key::TunSectionIfaces))
                .is_some(),
            "the TUN interfaces section must render even with no adapters"
        );
    }

    // Idle UI frames: the worker is the only enumeration source and it
    // re-runs at a 5 s cadence, so the admissible number of new
    // enumerations scales with the wall-clock the frame window actually
    // took — under load the window (or a cadence already due when it opens)
    // can legally contain a scheduled worker run, and attributing that to
    // the frames would be a false failure. A per-frame enumeration adds one
    // per frame, far beyond the cadence's share, and still fails.
    const IDLE_FRAMES: usize = 8;
    let before = h.state().metrics_snapshot();
    let started = Instant::now();
    h.run_steps(IDLE_FRAMES);
    let window = started.elapsed();
    let after = h.state().metrics_snapshot();
    let enumerated = after.adapter_enumerations - before.adapter_enumerations;
    let permitted = window.as_secs() / WORKER_CADENCE.as_secs() + 1;
    assert!(
        enumerated <= permitted,
        "idle TUN frames must not enumerate adapters: {enumerated} enumerations in a \
         {window:?} window (the worker cadence permits at most {permitted})"
    );
}
