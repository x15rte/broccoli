//! Regression: at the default 1100x720 window the server editor's
//! Validate and Discard buttons (and the validation-error block) must stay
//! visible and clickable on every editor tab.
//!
//! Before the fix the tab content's `ScrollArea` had no `max_height`, so on
//! tall tabs it expanded to fill the whole panel and laid the action row out
//! past the bottom edge, where egui never hit-tests it: pointer clicks at
//! the buttons' centers landed nowhere and the draft never reverted.
//!
//! Drives the real app through egui_kittest at the default window size: the
//! buttons' rects must lie fully inside the viewport on every tab, a real
//! pointer click on Discard must revert a name edit on every tab, and a real
//! pointer click on Validate must be received (the core-less harness fails
//! validation immediately and renders the failure report).
//!
//! Tallness: the Advanced tab is the tallest with a preserved-raw finalmask
//! (the ~45 KiB bulk seeded below), and the Basic tab is the tallest for a Wireguard
//! profile with several peers. The preserved-raw mask is deliberately
//! invalid (that is what keeps it raw), so Validate stays disabled there;
//! the clickability of an enabled Validate is exercised on the tall
//! Wireguard tab.

use broccoli::app::BroccoliApp;
use broccoli::model::{
    FinalmaskModel, FinalmaskTcpMask, OutboundModel, Protocol, ProtocolSettings, ServerProfile,
    ServersFile, Settings, WireguardPeer,
};
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::MutexGuard;
use serde_json::{Value, json};

#[path = "common/screen.rs"]
mod screen;

mod common;

/// The seeded profile name; Discard must restore it after an edit.
const SEEDED_NAME: &str = "editor-actions";

/// The editor's tabs, in UI order (the action row sits below the tab content
/// on every one of them).
const TABS: &[&str] = &["Basic", "Transport", "Security", "Mux", "Advanced"];

/// A deliberately large preserved-raw config (~45 KiB, structured): the bulk
/// the seeded profile needs so the Advanced tab is tall.
fn large_raw_value(seed: u64) -> Value {
    json!({
        "type": "future-mask",
        "seed": seed,
        "payload": {
            "entries": (0..1024)
                .map(|i| format!("{seed:04x}-{i:04x}-{}", "r".repeat(32)))
                .collect::<Vec<_>>(),
        },
    })
}

/// Boot the app through the shared fixture against a temp APPDATA seeded with
/// one active profile whose name is [`SEEDED_NAME`] and whose finalmask holds
/// an unknown (preserved-raw) TCP mask (name edits enable Discard without
/// touching any tab's own fields; the raw mask makes the Advanced tab the
/// tallest).
fn harness() -> (
    MutexGuard<'static, ()>,
    common::TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    let mut profile = ServerProfile::new(SEEDED_NAME, OutboundModel::new(Protocol::Freedom));
    profile.id = "0123456789abcdef".into();
    profile.outbound.stream.finalmask = Some(FinalmaskModel {
        tcp: vec![FinalmaskTcpMask::Unknown(large_raw_value(0x03))],
        udp: Vec::new(),
        quic_params: None,
        extra: Default::default(),
    });
    let servers = ServersFile {
        version: 1,
        active: Some(profile.id.clone()),
        profiles: vec![profile],
        extra: Default::default(),
    };
    let mut settings = Settings::default();
    settings.routing.observatory.enabled = false;
    settings.routing.burst_observatory.enabled = false;
    screen::boot_state(screen::BootState { settings, servers }, None)
}

/// A 32-byte Wireguard key in hex (64 hex digits — any 64-hex-digit value
/// passes the format validator; the validator is `pub(crate)`, so the test
/// does not call it).
const WG_KEY: &str = "abababababababababababababababababababababababababababababababab";

/// Boot the app like [`harness`] but with a VALID Wireguard profile whose
/// Basic tab is the tallest: six peer groups (~1.5k px of content) keep the
/// action row past the bottom edge at 720 px before the fix, while the
/// profile stays error-free so Validate is enabled.
fn harness_wg() -> (
    MutexGuard<'static, ()>,
    common::TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    let mut profile = ServerProfile::new(SEEDED_NAME, OutboundModel::new(Protocol::Wireguard));
    profile.id = "0123456789abcdef".into();
    if let ProtocolSettings::Wireguard(settings) = &mut profile.outbound.settings {
        settings.secret_key = WG_KEY.into();
        settings.address = vec!["10.0.0.2/32".into()];
        settings.peers = (0..6)
            .map(|_| WireguardPeer {
                public_key: WG_KEY.into(),
                endpoint: "1.2.3.4:51820".into(),
                allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
                ..Default::default()
            })
            .collect();
    }
    let servers = ServersFile {
        version: 1,
        active: Some(profile.id.clone()),
        profiles: vec![profile],
        extra: Default::default(),
    };
    let mut settings = Settings::default();
    settings.routing.observatory.enabled = false;
    settings.routing.burst_observatory.enabled = false;
    screen::boot_state(screen::BootState { settings, servers }, None)
}

/// Dismiss the first-run wizard and open the Servers screen at the DEFAULT
/// window size 1100x720 (the size where the regression occurred).
fn open_servers(h: &mut Harness<'static, BroccoliApp>) {
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    common::dismiss_wizard(h);
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Servers")
        .click();
    h.run();
}

/// The viewport rect at the default window size: `set_size` anchors the
/// harness window at the origin, so (0,0)-(1100,720) is exactly the egui
/// viewport.
fn viewport() -> egui::Rect {
    egui::Rect::from_min_size(egui::Pos2::ZERO, egui::Vec2::new(1100.0, 720.0))
}

/// The profile name field renders above the tab row on every tab; focus and
/// append `text` to it (a name edit marks the draft changed and enables
/// Discard regardless of the active tab).
fn append_to_name(h: &mut Harness<'static, BroccoliApp>, text: &str) {
    h.get_all_by_role(egui::accesskit::Role::TextInput)
        .next()
        .expect("profile name field")
        .focus();
    h.run();
    h.get_all_by_role(egui::accesskit::Role::TextInput)
        .next()
        .expect("profile name field")
        .type_text(text);
    h.run();
}

fn name_value(h: &Harness<'static, BroccoliApp>) -> String {
    h.get_all_by_role(egui::accesskit::Role::TextInput)
        .next()
        .expect("profile name field")
        .value()
        .expect("profile name value")
}

/// The action row must lie inside the viewport: egui never hit-tests widgets
/// beyond the panel clip, so an off-screen button silently swallows pointer
/// clicks.
fn assert_action_row_on_screen(h: &Harness<'static, BroccoliApp>, tab: &str) {
    let viewport = viewport();
    for label in ["Validate and save", "Discard changes"] {
        let rect = h
            .get_by_role_and_label(egui::accesskit::Role::Button, label)
            .rect();
        assert!(
            viewport.contains_rect(rect),
            "the {label:?} button must be fully visible on the {tab:?} tab \
             at 1100x720 (rect {rect:?} outside viewport {viewport:?})"
        );
    }
}

/// Every editor tab must keep its action row on screen at the default window
/// size — including the tallest (Advanced, with the ~45 KiB raw editor).
#[test]
fn action_row_is_visible_on_every_tab_at_default_window_size() {
    let (_lock, _tmp, mut h) = harness();
    open_servers(&mut h);
    assert_action_row_on_screen(&h, TABS[0]);
    for &tab in &TABS[1..] {
        h.get_by_role_and_label(egui::accesskit::Role::Button, tab)
            .click();
        h.run();
        assert_action_row_on_screen(&h, tab);
    }
}

/// A real pointer click on Discard must revert the draft on every editor tab
/// at the default window size (before the fix the button sat past the bottom
/// edge on the tall tabs and clicks landed nowhere).
#[test]
fn discard_click_reverts_on_every_tab_at_default_window_size() {
    let (_lock, _tmp, mut h) = harness();
    open_servers(&mut h);
    for (i, &tab) in TABS.iter().enumerate() {
        if i > 0 {
            h.get_by_role_and_label(egui::accesskit::Role::Button, tab)
                .click();
            h.run();
        }
        append_to_name(&mut h, "X");
        assert_eq!(
            name_value(&h),
            format!("{SEEDED_NAME}X"),
            "the name edit must register on the {tab:?} tab before Discard"
        );
        h.get_by_role_and_label(egui::accesskit::Role::Button, "Discard changes")
            .click();
        // The click's frame still renders the edited draft; the re-seeded
        // draft appears on a later frame.
        h.run();
        h.run_steps(4);
        assert_eq!(
            name_value(&h),
            SEEDED_NAME,
            "a pointer click on Discard must revert the name edit on the {tab:?} \
             tab at 1100x720"
        );
    }
}

/// A real pointer click on Validate must be received at the default window
/// size on a tall tab. The harness has no managed core, so validation fails
/// immediately and the failure report renders — observable proof the click
/// landed. (The Wireguard profile is error-free so Validate is enabled; the
/// Advanced tab's raw-editor tallness comes from a preserved-raw mask that
/// is deliberately invalid, which disables Validate by design.)
#[test]
fn validate_click_is_received_on_tall_tab_at_default_window_size() {
    let (_lock, _tmp, mut h) = harness_wg();
    open_servers(&mut h);
    append_to_name(&mut h, "X");
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Validate and save")
        .click();
    // The runtime's validation task fails fast (no managed core in the temp
    // APPDATA), but while it runs a spinner requests repaints each frame;
    // `run()` panics when frames do not settle within its step cap, so step
    // explicitly until the failure report renders.
    let mut steps = 0;
    while steps < 60
        && h.query_by_label_contains("Xray validation failed:")
            .is_none()
    {
        h.run_steps(4);
        steps += 1;
    }
    assert!(
        h.query_by_label_contains("Xray validation failed:")
            .is_some(),
        "a pointer click on Validate must be received at 1100x720 and render \
         the validation failure report"
    );
}
