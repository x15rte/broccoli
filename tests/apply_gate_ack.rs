//! Apply-gate hazard acknowledgment: end-to-end reachable
//! surface for the full app harness.
//!
//! The hazard gate itself sits behind the existing Connect/Apply blocked
//! checks (`connect_blocked_reason`), and the kittest harness boots without
//! a verified managed core — so `ConnectBlockedInstallCore` disables both
//! apply entry points BEFORE the hazard gate can fire. The harness therefore
//! cannot reach the modal state through real clicks; the dialog rendering
//! and its confirm/cancel flow are covered by the in-app kittest unit tests
//! in `src/app.rs::safety_ack_tests` (the Settings Cleanup modal precedent),
//! and the gate decision by `hazard_gate_findings` unit tests.
//!
//! What IS reachable end-to-end, and pinned here:
//! - Hazardous persisted settings load and boot normally.
//! - The acknowledgment dialog does not appear spontaneously — it is the
//!   response to a gated apply request, never an idle frame.
//! - Clicking Connect with hazards still hits the existing core-availability
//!   gate first (unchanged ordering), so neither the dialog nor a candidate
//!   config appears — the hazard gate only fires when the apply would
//!   otherwise proceed.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! A temporary APPDATA still isolates persistence, downloaded assets, and
//! logs. Tests are serialized because changing a process environment
//! variable while another harness/runtime thread reads it is undefined
//! behavior.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::ServersFile;
use broccoli::model::Settings;
use broccoli::model::inbound::{LocalInboundCfg, LocalInboundProtocol};
use broccoli::model::settings::Language;
use egui_kittest::{Harness, kittest::Queryable};

#[path = "common/screen.rs"]
mod screen;

mod common;

fn harness_with_hazardous_settings() -> (
    parking_lot::MutexGuard<'static, ()>,
    common::TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    // Unauthenticated SOCKS listener bound beyond loopback: an Exposure hazard
    // by every model rule (src/model/safety.rs).
    let settings = Settings {
        local_inbounds: vec![LocalInboundCfg {
            protocol: LocalInboundProtocol::Socks,
            listen: "0.0.0.0".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    screen::boot_state(screen::BootState {
        settings,
        servers: ServersFile::default(),
    })
}

#[test]
fn hazardous_settings_boot_without_a_dialog_and_existing_gates_still_block() {
    let (_lock, _tmp, mut h) = harness_with_hazardous_settings();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    // Fresh temp APPDATA -> no core -> the first-run wizard modal covers the
    // whole screen, so the top bar is only probeable once it is dismissed.
    common::dismiss_wizard(&mut h);

    // The hazard dialog is the response to a gated apply request — it must
    // not appear spontaneously, however hazardous the persisted settings.
    assert!(
        h.query_by_label(t(Language::En, Key::SafetyAckTitle))
            .is_none(),
        "no hazard dialog may appear without an apply request"
    );
    assert!(
        h.query_all_by_label(t(Language::En, Key::SafetyAckApplyAnyway))
            .next()
            .is_none(),
        "no hazard dialog may appear without an apply request"
    );

    // Click Connect: without a verified core the existing gate
    // (ConnectBlockedInstallCore) still runs first and wins, so the hazard
    // gate must not fire, no dialog may appear, and no candidate may be
    // produced. Both the top-bar and the dashboard Connect buttons funnel
    // into request_connect; clicking the first one found exercises the same
    // path.
    h.get_all_by_role_and_label(egui::accesskit::Role::Button, "Connect")
        .next()
        .expect("the Connect button must render")
        .click();
    h.run();

    assert!(
        h.query_by_label(t(Language::En, Key::SafetyAckTitle))
            .is_none(),
        "the hazard gate must not fire while the existing gates still block"
    );
    assert!(
        !broccoli::sys::paths::config_dir()
            .join("config.candidate.json")
            .exists(),
        "a blocked Connect must not produce a candidate config"
    );
    // The persisted hazardous settings survive untouched.
    let settings: serde_json::Value = serde_json::from_slice(
        &std::fs::read(broccoli::sys::paths::state_dir().join("settings.json")).unwrap(),
    )
    .expect("settings state must remain JSON");
    assert_eq!(settings["localInbounds"][0]["listen"], "0.0.0.0");
}
