//! A completed latency probe must reach the dashboard's Servers latency
//! grid, not only the Servers screen's badges.
//!
//! The probe writes each profile's `latency_ms` (the dashboard grid's
//! fallback cell when no observatory entry covers the tag), so its result
//! must advance the grid's memoization key or the table keeps rendering the
//! pre-probe cells until an unrelated persist/revision change.
//!
//! Phase-2 minimisation record (diagnosing-bugs flow, 2026-09-11): the
//! smallest red-capable repro is the first test minus the wizard dismissal —
//! a seeded single profile, one injected probe status, one frame, one
//! assertion. The dismissal is retained per the repo's test contract
//! ("dismiss wizards before ... assert navigation/rendering"); the
//! dead-status test is retained because no other test drives a dead probe
//! status through the app's `apply_observatory_statuses` seam.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! A temporary APPDATA still isolates persistence, downloaded assets, and
//! logs. Tests are serialized because changing a process environment
//! variable while another harness/runtime thread reads it is undefined
//! behavior.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t, t_fmt};
use broccoli::model::settings::Language;
use broccoli::model::{OutboundModel, Protocol, ServerProfile, ServersFile};
use broccoli::rt::{CoreEvt, LatencyProbeResult, OutboundStatusView};
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::{Mutex, MutexGuard};
use serde_json::Map;

static APPDATA_LOCK: Mutex<()> = Mutex::new(());

/// The seeded profile's `srv-<id8>` tag, as the app derives it.
const ALPHA_TAG: &str = "srv-aaaaaaaa";

/// One seeded profile with a stable id, so the probe status can address it
/// by the same `srv-<id8>` tag the app derives.
fn seeded_servers() -> ServersFile {
    let mut alpha = ServerProfile::new("alpha", OutboundModel::new(Protocol::Trojan));
    alpha.id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
    ServersFile {
        version: 1,
        active: None,
        profiles: vec![alpha],
        extra: Map::new(),
    }
}

/// `%APPDATA%` pointed at a fresh tempdir with a seeded `state/servers.json`
/// (the real state layout); the guard serializes every test that mutates the
/// process env vars (the `ui_smoke` convention).
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
    let state = tmp.path().join("broccoli/state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(
        state.join("servers.json"),
        serde_json::to_vec_pretty(&seeded_servers()).unwrap(),
    )
    .unwrap();
    let h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    (lock, tmp, h)
}

/// Dismiss the first-run wizard ("Set up later") — a fresh temp APPDATA has
/// no core, so the modal swallows nav clicks until it is dismissed.
fn dismiss_wizard(h: &mut Harness<'static, BroccoliApp>) {
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    assert!(
        h.query_all_by_label("Welcome to broccoli").next().is_none(),
        "the first-run wizard must be dismissed before navigating"
    );
}

/// Push one probe result through the real event-drain path.
fn inject_probe(h: &Harness<'static, BroccoliApp>, alive: bool, delay_ms: i64) {
    h.state()
        .inject_event(CoreEvt::LatencyProbe(LatencyProbeResult {
            tags: vec![ALPHA_TAG.into()],
            result: Ok(vec![OutboundStatusView {
                health_ping: None,
                tag: ALPHA_TAG.into(),
                alive,
                delay_ms,
                last_error: Some("connection refused".into()),
                diagnostics: None,
            }]),
        }));
}

/// With no observatory emitted there are never observatory rows, so the
/// dashboard's latency cells resolve from `profile.latency_ms` alone — the
/// field a latency probe writes. The result must repaint the memoized grid.
#[test]
fn probe_result_refreshes_the_dashboard_latency_grid() {
    let (_lock, _tmp, mut h) = harness();
    dismiss_wizard(&mut h);

    let measured = t_fmt(Language::En, Key::LatencyMs, &[&120]);
    inject_probe(&h, true, 120);
    h.run();

    assert!(
        h.query_all_by_label(&measured).next().is_some(),
        "the dashboard grid must render the probe's measured latency"
    );
}

/// A dead probe status must paint the dead cell: the result maps to
/// `latency_ms = -1` and the grid's fallback cell renders it as dead.
#[test]
fn dead_probe_result_paints_the_dead_cell() {
    let (_lock, _tmp, mut h) = harness();
    dismiss_wizard(&mut h);

    inject_probe(&h, false, 0);
    h.run();

    assert!(
        h.query_all_by_label(t(Language::En, Key::Dead))
            .next()
            .is_some(),
        "the dashboard grid must render the probe's dead verdict"
    );
}
