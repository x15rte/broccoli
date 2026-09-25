//! UI smoke test: the full app boots headlessly and every screen renders
//! without panicking. Drives the real `BroccoliApp` through egui_kittest.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! A temporary APPDATA still isolates persistence, downloaded assets, and logs.
//! Tests are serialized because changing a process environment variable while
//! another harness/runtime thread reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::diag::Diag;
use broccoli::i18n::{Key, t, t_fmt};
use broccoli::model::settings::Language;
use broccoli::model::{OutboundModel, Protocol, ServerProfile, ServersFile, Settings};
use broccoli::rt::{CoreEvt, CorePhase, StatsTick};
use broccoli::sys::core_dl;
use broccoli::ui::Screen;
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::{Mutex, MutexGuard};
use std::ffi::OsString;
use std::time::Duration;

static APPDATA_LOCK: Mutex<()> = Mutex::new(());
struct TempDirectoryEnv {
    tmp: Option<OsString>,
    temp: Option<OsString>,
}

impl TempDirectoryEnv {
    fn set(path: &std::path::Path) -> Self {
        let previous = Self {
            tmp: std::env::var_os("TMP"),
            temp: std::env::var_os("TEMP"),
        };
        // SAFETY: APPDATA_LOCK serializes every test that changes process
        // environment variables used by Broccoli and tempfile.
        unsafe {
            std::env::set_var("TMP", path);
            std::env::set_var("TEMP", path);
        }
        previous
    }
}

impl Drop for TempDirectoryEnv {
    fn drop(&mut self) {
        // SAFETY: the guard restores values while APPDATA_LOCK is held.
        unsafe {
            match self.tmp.take() {
                Some(value) => std::env::set_var("TMP", value),
                None => std::env::remove_var("TMP"),
            }
            match self.temp.take() {
                Some(value) => std::env::set_var("TEMP", value),
                None => std::env::remove_var("TEMP"),
            }
        }
    }
}

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

/// The Logs screen's filter input — the only text input on that screen.
fn logs_filter<'a>(h: &'a Harness<'a, BroccoliApp>) -> egui_kittest::Node<'a> {
    h.get_all_by_role(egui::accesskit::Role::TextInput)
        .next()
        .expect("logs filter input")
}

/// Unique label rendered by the visited screen's own body, used to prove a
/// nav click actually switched screens. The sidebar always exposes every
/// screen's label, so the asserted label must never collide with a nav label:
/// headings that share text with the nav item (e.g. the Servers heading, which
/// the Dashboard also renders) are matched through their screen-specific
/// section/empty-state text instead.
fn screen_rendered_label(screen: Screen) -> String {
    match screen {
        Screen::Dashboard => t(Language::En, Key::DashboardNoServers).to_string(),
        Screen::Servers => t(Language::En, Key::NoServersYet).to_string(),
        Screen::ProfilePreview => t(Language::En, Key::PreviewNoLaunch).to_string(),
        Screen::Routing => t(Language::En, Key::RoutingRulesSection).to_string(),
        Screen::Dns => t(Language::En, Key::DnsSectionServers).to_string(),
        Screen::Inbounds => t(Language::En, Key::LocalListeners).to_string(),
        Screen::Tun => t(Language::En, Key::TunSectionIdentity).to_string(),
        Screen::Logs => t(Language::En, Key::LogsCopyAll).to_string(),
        Screen::Settings => t(Language::En, Key::SettingsAppearance).to_string(),
        Screen::About => t_fmt(
            Language::En,
            Key::AboutBroccoliVersion,
            &[&env!("CARGO_PKG_VERSION")],
        ),
    }
}

#[test]
fn app_boots_and_every_screen_renders() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    // Fresh temp APPDATA -> no core -> the first-run wizard modal covers the
    // whole screen and swallows nav clicks. Dismiss it exactly like the
    // sibling tests so the loop below actually reaches every screen.
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    assert!(
        h.query_all_by_label("Welcome to broccoli").next().is_none(),
        "the first-run wizard must be dismissed before navigating"
    );

    for screen in Screen::ALL {
        // Sidebar items are buttons; scope the click by role so a
        // same-labeled heading in the central panel is never clicked instead.
        h.get_by_role_and_label(egui::accesskit::Role::Button, screen.label(Language::En))
            .click();
        h.run();
        // Fail loudly when the click did not navigate or the screen failed to
        // render: the visited screen's own body label must be present.
        let rendered = screen_rendered_label(screen);
        assert!(
            h.query_all_by_label(rendered.as_str()).next().is_some(),
            "screen {} did not render: its body label {rendered:?} is missing after clicking the nav item",
            screen.label(Language::En),
        );
    }
}

#[test]
fn dashboard_shows_core_state_badge() {
    let (_lock, _tmp, mut h) = harness();
    h.run();
    // Stopped badge is always present on a fresh boot (top bar + dashboard).
    assert!(h.get_all_by_label("Stopped").next().is_some());
    assert!(h.get_all_by_label("TUN").next().is_some());
    assert!(
        h.query_by_label("Test latency now").is_none(),
        "Dashboard must not expose a redundant snapshot-read action"
    );
}

/// Session traffic is a session fact: the top bar carries the
/// live rate pair and the dashboard's inbound table the core's cumulative
/// session totals while a tick from the running core exists — and a phase
/// change (restart / config commit) drops both, because the last tick of a
/// dead session must not masquerade as live state. The sidebar rail this
/// contract used to be pinned on was emptied (nav only).
#[test]
fn dashboard_session_totals_drop_on_phase_change() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    // Fresh temp APPDATA -> the first-run wizard modal covers the dashboard.
    // Dismiss it (as the sibling tests do) so the asserted surfaces are the
    // real rendered ones, not widgets hidden under the modal.
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();

    // The exhibition shape: an idle-but-live core carrying session volume.
    h.state().inject_event(CoreEvt::Stats(StatsTick {
        up: 0,
        down: 0,
        per_inbound: vec![("socks".to_string(), 0, 0)],
        per_inbound_totals: vec![("socks".to_string(), 251_133_952, 1_073_741_824)],
        total_up: 251_133_952,     // 239.5 MiB
        total_down: 1_073_741_824, // 1.0 GiB
        ..Default::default()
    }));
    h.run();

    h.get_all_by_label("↑ 0.0 B/s · ↓ 0.0 B/s")
        .next()
        .expect("the top bar must pin the live rate pair once a stats tick lands");
    h.get_all_by_label("↑ 239.5 MiB")
        .next()
        .expect("the inbound table must carry the uplink session total");
    h.get_all_by_label("↓ 1.0 GiB")
        .next()
        .expect("the inbound table must carry the downlink session total");

    h.state().inject_event(CoreEvt::State(CorePhase::Stopped));
    h.run();
    assert!(
        h.query_all_by_label("↑ 239.5 MiB").next().is_none(),
        "a phase change must drop the uplink session total"
    );
    assert!(
        h.query_all_by_label("↓ 1.0 GiB").next().is_none(),
        "the downlink total must drop with the uplink total"
    );
    assert!(
        h.query_all_by_label("↑ 0.0 B/s · ↓ 0.0 B/s")
            .next()
            .is_none(),
        "the rate readout must drop with the dead session"
    );
}

#[test]
fn topbar_pins_app_version_on_the_right() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    // Fresh temp APPDATA has no core, so the right edge shows the app
    // version alone (the `xray {} · app {}` form appears once a core is
    // installed — `core_version` is read at boot from the verified core).
    let app_version = t_fmt(
        Language::En,
        Key::TopbarAppVersion,
        &[&env!("CARGO_PKG_VERSION")],
    );
    h.get_all_by_label(app_version.as_str())
        .next()
        .expect("the topbar must pin the app version at the right edge");
}

#[test]
fn first_run_wizard_exposes_anchored_release_controls_and_copies_link() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    assert!(
        h.query_all_by_label_contains("Pinned release")
            .next()
            .is_some(),
        "first-run modal must expose the compiled Xray version"
    );
    assert!(
        h.query_all_by_label_contains(core_dl::pinned_release_version())
            .next()
            .is_some()
    );
    assert!(
        h.query_all_by_label_contains(core_dl::pinned_release_archive())
            .next()
            .is_some()
    );
    assert!(
        h.query_all_by_label_contains(core_dl::pinned_release_url())
            .next()
            .is_some()
    );
    assert!(
        h.query_by_label("Download pinned release").is_some(),
        "first-run modal must expose the primary download action"
    );
    assert!(
        h.query_by_label("Import archive…").is_some(),
        "first-run modal must expose archive import"
    );

    h.get_by_role_and_label(egui::accesskit::Role::Button, "Copy link")
        .click();
    h.step();
    assert!(
        h.output()
            .platform_output
            .commands
            .iter()
            .any(|command| matches!(
                command,
                egui::OutputCommand::CopyText(text) if text == core_dl::pinned_release_url()
            ))
    );
}

#[test]
fn settings_exposes_same_core_setup_after_defer() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Settings")
        .click();
    h.run();

    assert!(
        h.query_all_by_label_contains("Pinned release")
            .next()
            .is_some(),
        "Settings must expose the same pinned version"
    );
    assert!(
        h.query_all_by_label_contains(core_dl::pinned_release_version())
            .next()
            .is_some()
    );
    assert!(
        h.query_all_by_label_contains(core_dl::pinned_release_archive())
            .next()
            .is_some()
    );
    assert!(
        h.query_all_by_label_contains(core_dl::pinned_release_url())
            .next()
            .is_some()
    );

    h.get_by_role_and_label(egui::accesskit::Role::Button, "Copy link")
        .click_accesskit();
    h.step();
    assert!(
        h.output()
            .platform_output
            .commands
            .iter()
            .any(|command| matches!(
                command,
                egui::OutputCommand::CopyText(text) if text == core_dl::pinned_release_url()
            ))
    );
}

#[test]
fn routing_exposes_probe_interval_and_one_health_engine() {
    let (_lock, tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Routing")
        .click();
    h.run();

    // Both engines start off: neither group renders its fields.
    assert!(h.query_by_label("Probe interval").is_none());
    assert!(h.query_by_label("Destination").is_none());

    let observatory = h.get_by_role_and_label(
        egui::accesskit::Role::CheckBox,
        "Observatory (latency probing)",
    );
    observatory.scroll_to_me();
    h.run();
    h.get_by_role_and_label(
        egui::accesskit::Role::CheckBox,
        "Observatory (latency probing)",
    )
    .click();
    h.run();

    let field = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("10s"))
        .expect("Probe interval text input should be accessible");
    field.scroll_to_me();
    h.run();

    let field = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("10s"))
        .expect("Probe interval text input should remain accessible");
    field.click();
    h.run();
    h.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    h.run();
    let field = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("10s"))
        .expect("Probe interval text input should remain accessible");
    field.type_text("30s");
    h.run_steps(4);

    let settings = persisted_settings(&tmp);
    assert_eq!(settings["routing"]["observatory"]["probeInterval"], "30s");
    assert_eq!(settings["routing"]["observatory"]["enabled"], true);

    // The second engine cannot be added beside the first: enabling the burst
    // observatory drops the ordinary one and swaps the rendered group.
    let burst = h.get_by_role_and_label(
        egui::accesskit::Role::CheckBox,
        "Burst observatory (health ping)",
    );
    burst.scroll_to_me();
    h.run();
    h.get_by_role_and_label(
        egui::accesskit::Role::CheckBox,
        "Burst observatory (health ping)",
    )
    .click();
    h.run_steps(4);

    assert!(
        h.query_by_label("Probe interval").is_none(),
        "the observatory group must be gone once burst is the engine"
    );
    assert!(
        h.query_by_label("Destination").is_some(),
        "the burst group must render its own fields"
    );
    let settings = persisted_settings(&tmp);
    assert_eq!(
        settings["routing"]["burstObservatory"]["enabled"], true,
        "the burst toggle must persist"
    );
    assert!(
        settings["routing"]["observatory"]["enabled"].is_null(),
        "enabling burst must clear the ordinary observatory"
    );
}

fn persisted_settings(tmp: &tempfile::TempDir) -> serde_json::Value {
    let settings_bytes =
        std::fs::read(tmp.path().join("broccoli/state/settings.json")).expect("settings state");
    serde_json::from_slice(&settings_bytes).expect("persisted settings must be JSON")
}

#[test]
fn delete_first_digit_of_non_loopback_listen_keeps_focus() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    if let Some(node) = h.get_all_by_label("Inbounds").next() {
        node.click();
    }
    h.run();

    // The first list row is the default SOCKS entry (in-socks):
    // start loopback, type a valid non-loopback IP so the unencrypted-listen
    // posture banner appears, then delete the first digit -> value becomes
    // invalid, banner hides, inline error shows. This mirrors the
    // user-reported focus loss while editing after a failed apply.
    let field = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("127.0.0.1"))
        .expect("SOCKS row listen address input");
    field.scroll_to_me();
    h.run();
    let field = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("127.0.0.1"))
        .expect("listen input should remain accessible");
    field.click();
    h.run();
    h.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    h.run();
    let field = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("127.0.0.1"))
        .expect("listen input should remain accessible");
    field.type_text("192.168.1.5");
    h.run_steps(4);
    assert!(
        h.query_by_label_contains("non-loopback listeners off the public internet")
            .is_some(),
        "a valid non-loopback listen must show the posture banner"
    );

    // Re-click, move to the start, delete chars until the value turns
    // invalid: "192.168.1.5" -> ".168.1.5". Valid -> invalid transitions the
    // posture banner and the inline error while the field is focused.
    let field = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("192.168.1.5"))
        .expect("listen input should keep the typed value");
    field.click();
    h.run();
    h.key_press(egui::Key::Home);
    h.run();
    for _ in 0..3 {
        h.key_press(egui::Key::Delete);
        h.run();
    }
    h.run_steps(4);
    assert!(
        h.query_by_label(
            "listen address must be an IP address, for example 127.0.0.1, 0.0.0.0, or ::1"
        )
        .is_some(),
        "deleting the leading digits must show the inline validation error"
    );

    // The user's report: focus is lost at this point. Typing must still land.
    let field = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some(".168.1.5"))
        .expect("listen input should show the truncated value");
    field.type_text("x");
    h.run_steps(4);
    assert!(
        h.get_all_by_role(egui::accesskit::Role::TextInput)
            .any(|node| node.value().is_some_and(|value| value.contains('x'))),
        "keystrokes after deleting the first digits must land in the field (focus must not drop)"
    );
}

#[test]
fn typing_partial_listen_address_keeps_input_focus() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    if let Some(node) = h.get_all_by_label("Inbounds").next() {
        node.click();
    }
    h.run();

    // The first list row's listen address field (default value; the HTTP row
    // shares it, so the first "127.0.0.1" input is the SOCKS entry's).
    let field = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("127.0.0.1"))
        .expect("SOCKS row listen address input");
    field.scroll_to_me();
    h.run();
    let field = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("127.0.0.1"))
        .expect("listen input should remain accessible");
    field.click();
    h.run();
    h.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    h.run();
    // Half-typed IP: every keystroke fails generation validation.
    h.get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("127.0.0.1"))
        .expect("listen input should remain accessible")
        .type_text("192.168");
    h.run_steps(4);

    assert!(
        h.query_by_label("configuration invalid").is_some(),
        "a partial listen address must flag the config as invalid in the top bar"
    );
    assert!(
        h.query_by_label(
            "listen address must be an IP address, for example 127.0.0.1, 0.0.0.0, or ::1"
        )
        .is_some(),
        "the listen field must show the validation error inline (top-bar summaries carry a \
         listener-name prefix, so this exact label can only come from the field)"
    );

    // Focus must survive the error frames: more typing lands in the field.
    h.get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("192.168"))
        .expect("listen input keeps the partial value")
        .type_text(".1.5");
    h.run_steps(4);

    let completed = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .any(|node| node.value().as_deref() == Some("192.168.1.5"));
    assert!(
        completed,
        "typed characters must keep landing while the field holds focus"
    );
    assert!(
        h.query_by_label("configuration invalid").is_none(),
        "a complete valid listen address must clear the config error"
    );
}

#[test]
fn settings_edits_persist_without_applying_the_runtime_candidate() {
    let (_lock, tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Settings")
        .click();
    h.run();
    // Edit: raise the log level — a persisted, Apply-gated setting (the
    // mode radios that used to live here were removed as a duplicate of the
    // dashboard toggle).
    h.get_all_by_role(egui::accesskit::Role::ComboBox)
        .find(|node| node.value().as_deref() == Some("warning"))
        .expect("the log-level combo must show warning initially")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "info")
        .click();
    h.run();

    // Outlive the removed deferred-apply window and drive more frames so an
    // accidental timer-based apply has an opportunity to enqueue its candidate.
    std::thread::sleep(std::time::Duration::from_secs(1));
    h.run_steps(4);

    let broccoli_root = tmp.path().join("broccoli");
    assert!(broccoli_root.join("state/settings.json").is_file());
    assert!(broccoli_root.join("state/servers.json").is_file());
    assert!(
        h.get_all_by_label("changes pending").next().is_some(),
        "an ordinary edit must remain pending until Apply now or Connect"
    );
    assert!(
        !broccoli_root.join("config/config.candidate.json").exists(),
        "an ordinary edit must not enqueue a runtime candidate"
    );
    assert!(
        !broccoli_root.join("config/config.json").exists(),
        "an ordinary edit must not replace the active runtime configuration"
    );
}

/// The changes-pending gate must drop when an edit is reverted to the state
/// that was last applied (or, before any apply, the state at startup).
/// Regression: the gate was a sticky latch that only a successful Apply
/// cleared, so reverting an edit left the yellow chip up until Connect.
#[test]
fn reverting_a_settings_edit_clears_the_changes_pending_chip() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Settings")
        .click();
    h.run();

    // Edit: raise the log level — a persisted, Apply-gated setting (the
    // mode radios that used to live here were removed as a duplicate of the
    // dashboard toggle).
    h.get_all_by_role(egui::accesskit::Role::ComboBox)
        .find(|node| node.value().as_deref() == Some("warning"))
        .expect("the log-level combo must show warning initially")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "info")
        .click();
    h.run();
    std::thread::sleep(std::time::Duration::from_secs(1));
    h.run_steps(4);
    assert!(
        h.get_all_by_label("changes pending").next().is_some(),
        "an edit must raise the changes-pending gate"
    );

    // Revert to the previous level: the gate must drop again.
    h.get_all_by_role(egui::accesskit::Role::ComboBox)
        .find(|node| node.value().as_deref() == Some("info"))
        .expect("the log-level combo must show info after the edit")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "warning")
        .click();
    h.run();
    std::thread::sleep(std::time::Duration::from_secs(1));
    h.run_steps(4);
    assert!(
        h.query_by_label("changes pending").is_none(),
        "reverting the edit must clear the changes-pending chip"
    );
}

/// A display preference (the traffic-unit dropdown) persists to settings.json
/// but never raises the Apply gate: no "changes pending" chip, no "Apply
/// now" button, no candidate — the running core's configuration cannot
/// depend on a unit choice.
#[test]
fn traffic_unit_change_persists_without_demanding_apply() {
    let (_lock, tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();

    // The dashboard's unit combo shows the current unit as its value.
    h.get_all_by_role(egui::accesskit::Role::ComboBox)
        .find(|node| node.value().as_deref() == Some("Auto"))
        .expect("the traffic-unit combo must show Auto initially")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "KiB/s")
        .click();
    h.run();

    // No apply affordance: the unit is a display preference.
    assert!(
        h.query_by_label("changes pending").is_none(),
        "a unit change must not raise the config-apply gate"
    );
    assert!(
        h.query_by_role_and_label(egui::accesskit::Role::Button, "Apply now")
            .is_none(),
        "a unit change must not offer Apply now"
    );

    // Outlive the persist throttle and drive frames so a late save (or an
    // accidental apply) has its chance.
    std::thread::sleep(std::time::Duration::from_secs(1));
    h.run_steps(4);

    let broccoli_root = tmp.path().join("broccoli");
    let settings_path = broccoli_root.join("state/settings.json");
    assert!(settings_path.is_file(), "settings must have been persisted");
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&settings_path).unwrap()).unwrap();
    assert_eq!(
        saved["trafficUnit"], "kiBps",
        "the chosen unit must be persisted in settings.json"
    );
    assert!(
        h.query_by_label("changes pending").is_none(),
        "still no config-apply gate after the throttle flush"
    );
    assert!(
        !broccoli_root.join("config/config.candidate.json").exists(),
        "a display preference must not enqueue a runtime candidate"
    );
}

/// Run `steps` frames with egui's clock pinned to `time` before each one: the
/// harness takes its raw input per frame, so a pinned clock must be re-applied
/// for every frame it should cover.
fn run_at(h: &mut Harness<'static, BroccoliApp>, time: f64, steps: usize) {
    for _ in 0..steps {
        h.input_mut().time = Some(time);
        h.run_steps(1);
    }
}

/// Pick a display unit through the dashboard's combo, which shows the current
/// unit as its value. Each click costs one batch of frames, so a caller that
/// pins the clock around two calls holds both edits inside one persist window.
fn choose_traffic_unit_at(
    h: &mut Harness<'static, BroccoliApp>,
    time: f64,
    current: &str,
    next: &str,
) {
    h.get_all_by_role(egui::accesskit::Role::ComboBox)
        .find(|node| node.value().as_deref() == Some(current))
        .expect("the traffic-unit combo must show the current unit")
        .click();
    run_at(h, time, 1);
    h.get_by_role_and_label(egui::accesskit::Role::Button, next)
        .click();
    run_at(h, time, 2);
}

fn saved_settings(path: &std::path::Path) -> serde_json::Value {
    serde_json::from_str(
        &std::fs::read_to_string(path).expect("the state file must have been written"),
    )
    .expect("the state file must be valid JSON")
}

/// An edit landing inside the persist throttle window is written when the
/// window closes, with no further edit to carry it: the deadline repaint's
/// frame has no widget change of its own, so the deferred save has to be
/// flushed by that frame — otherwise the last edit of a burst stays in memory
/// until the next edit, or until a clean exit.
#[test]
fn the_persist_deadline_flushes_the_last_edit_of_a_burst() {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: APPDATA_LOCK serializes every test in this process that changes
    // or reads APPDATA through a BroccoliApp harness.
    unsafe { std::env::set_var("APPDATA", tmp.path()) };
    // The harness's default frame step is a quarter second, which is longer
    // than the persist window this test reasons about; a 60 Hz step keeps
    // every frame a small, known distance from the pinned clock.
    let mut h = Harness::builder()
        .with_step_dt(1.0 / 60.0)
        .with_size(egui::Vec2::new(1100.0, 720.0))
        .build_eframe(|cc| BroccoliApp::new_headless(cc));
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    // Every pin below sits at least a window away from the save it must not
    // see, and inside one of the save it must: a click's own frames drift at
    // most a few 60 Hz steps from the frame it pinned.
    let settings_path = tmp.path().join("broccoli/state/settings.json");
    let first = h.ctx.input(|input| input.time) + 1.0;

    // The first edit opens the window, so it lands at once.
    choose_traffic_unit_at(&mut h, first, "Auto", "KiB/s");
    assert_eq!(saved_settings(&settings_path)["trafficUnit"], "kiBps");

    // The second edit lands 50 ms into that window: deferred to the deadline.
    choose_traffic_unit_at(&mut h, first + 0.05, "KiB/s", "MiB/s");
    assert_eq!(
        saved_settings(&settings_path)["trafficUnit"],
        "kiBps",
        "an edit inside the throttle window must not be written yet"
    );

    // The deadline frame, with nothing edited in between.
    run_at(&mut h, first + 1.0, 1);
    assert_eq!(
        saved_settings(&settings_path)["trafficUnit"],
        "miBps",
        "the deadline frame must flush the deferred edit"
    );
    drop(lock);
}

#[test]
fn settings_appearance_theme_radio_switches_preference() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Settings")
        .click();
    h.run();

    // Appearance section: locale list (English only) and accent row exist.
    assert!(h.query_by_label("Language").is_some());
    assert!(h.query_by_label("Accent color").is_some());

    h.get_all_by_label("Dark")
        .next()
        .expect("Dark theme radio")
        .click();
    h.run();
    assert_eq!(
        h.ctx.options(|options| options.theme_preference),
        egui::ThemePreference::Dark
    );
    assert_eq!(h.ctx.theme(), egui::Theme::Dark);

    h.get_all_by_label("Light")
        .next()
        .expect("Light theme radio")
        .click();
    h.run();
    assert_eq!(
        h.ctx.options(|options| options.theme_preference),
        egui::ThemePreference::Light
    );
    assert_eq!(h.ctx.theme(), egui::Theme::Light);
}

#[test]
fn settings_appearance_accent_reapplied_at_startup_and_reset() {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: APPDATA_LOCK serializes all Broccoli state access in this test
    // process.
    unsafe { std::env::set_var("APPDATA", tmp.path()) };

    let broccoli_root = tmp.path().join("broccoli");
    std::fs::create_dir_all(broccoli_root.join("state")).unwrap();
    let settings = Settings {
        accent_color: Some(0x4f_af_4f_ff),
        ..Default::default()
    };
    std::fs::write(
        broccoli_root.join("state/settings.json"),
        serde_json::to_vec_pretty(&settings).unwrap(),
    )
    .unwrap();

    let mut h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    // Startup re-apply: the persisted accent reaches both themes, so System
    // mode (which follows the Windows light/dark flag) carries it too.
    let expected = egui::Color32::from_rgba_unmultiplied(0x4f, 0xaf, 0x4f, 0xff);
    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        let visuals = &h.ctx.style_of(theme).visuals;
        assert_eq!(
            visuals.selection.bg_fill, expected,
            "{theme:?} accent at startup"
        );
    }

    // Live reset clears both themes and persists the cleared model.
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Settings")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Reset")
        .click();
    h.run_steps(4);

    for theme in [egui::Theme::Dark, egui::Theme::Light] {
        let visuals = &h.ctx.style_of(theme).visuals;
        let stock = theme.default_visuals();
        assert_eq!(
            visuals.selection.bg_fill, stock.selection.bg_fill,
            "{theme:?} reset must restore stock"
        );
    }
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(broccoli_root.join("state/settings.json")).unwrap())
            .expect("settings state must persist");
    assert!(
        persisted.get("accentColor").is_none(),
        "reset must clear the persisted accent"
    );

    drop(h);
    drop(tmp);
    drop(lock);
}

#[test]
fn window_close_request_hides_to_tray() {
    let (_lock, _tmp, mut h) = harness();
    h.run();

    h.input_mut()
        .viewports
        .get_mut(&egui::ViewportId::ROOT)
        .expect("root viewport input")
        .events
        .push(egui::ViewportEvent::Close);
    h.step();

    let commands = &h
        .output()
        .viewport_output
        .get(&egui::ViewportId::ROOT)
        .expect("root viewport output")
        .commands;
    assert!(
        commands
            .iter()
            .any(|command| matches!(command, egui::ViewportCommand::CancelClose)),
        "close request must be cancelled"
    );
    assert!(
        commands
            .iter()
            .any(|command| matches!(command, egui::ViewportCommand::Visible(false))),
        "close request must hide the window"
    );
}
#[test]
fn isolated_latency_probe_does_not_persist_or_create_a_candidate() {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: APPDATA_LOCK serializes all Broccoli state access in this test
    // process.
    unsafe { std::env::set_var("APPDATA", tmp.path()) };
    let probe_tmp = tmp.path().join("probe-tmp");
    std::fs::create_dir_all(&probe_tmp).unwrap();
    let _temp_env = TempDirectoryEnv::set(&probe_tmp);

    let broccoli_root = tmp.path().join("broccoli");
    std::fs::create_dir_all(broccoli_root.join("state")).unwrap();
    std::fs::create_dir_all(broccoli_root.join("config")).unwrap();
    let mut profile = ServerProfile::new("isolated", OutboundModel::new(Protocol::Freedom));
    profile.id = "0123456789abcdef".into();
    let servers = ServersFile {
        version: 1,
        active: Some(profile.id.clone()),
        profiles: vec![profile],
        extra: Default::default(),
    };
    let mut settings = Settings::default();
    settings.routing.observatory.enabled = false;
    settings.routing.burst_observatory.enabled = false;
    let servers_bytes = serde_json::to_vec_pretty(&servers).unwrap();
    let settings_bytes = serde_json::to_vec_pretty(&settings).unwrap();
    std::fs::write(broccoli_root.join("state/servers.json"), &servers_bytes).unwrap();
    std::fs::write(broccoli_root.join("state/settings.json"), &settings_bytes).unwrap();
    let config_path = broccoli_root.join("config/config.json");
    let config_before = std::fs::read(&config_path).ok();

    let mut h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Servers")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Test latency")
        .click();
    // The isolated probe child keeps the runtime repainting while it
    // starts, so a quiet-until-idle `run()` blows the step budget under
    // load (parallel test binaries). Step deterministically and poll for
    // the outcome below instead.
    h.run_steps(4);

    let mut settled = false;
    for _ in 0..100 {
        if h.query_all_by_label_contains("Latency test failed:")
            .next()
            .is_some()
        {
            settled = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
        h.run_steps(2);
    }
    assert!(settled, "isolated latency failure did not settle in the UI");

    assert_eq!(
        std::fs::read(broccoli_root.join("state/servers.json")).unwrap(),
        servers_bytes
    );
    assert_eq!(
        std::fs::read(broccoli_root.join("state/settings.json")).unwrap(),
        settings_bytes
    );
    assert_eq!(std::fs::read(&config_path).ok(), config_before);
    assert!(
        !broccoli_root.join("config/config.candidate.json").exists(),
        "one-shot probing must not write a candidate config"
    );
    assert!(
        h.query_by_label("changes pending").is_none(),
        "one-shot probing must not mark the model dirty"
    );
    let leftovers: Vec<_> = std::fs::read_dir(&probe_tmp)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("broccoli-latency-probe-")
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary latency probe directories leaked: {leftovers:?}"
    );

    drop(h);
    drop(_temp_env);
    drop(lock);
}

#[test]
fn visible_delete_button_removes_selected_server() {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: APPDATA_LOCK serializes all Broccoli state access in this test
    // process.
    unsafe { std::env::set_var("APPDATA", tmp.path()) };

    let broccoli_root = tmp.path().join("broccoli");
    std::fs::create_dir_all(broccoli_root.join("state")).unwrap();
    std::fs::create_dir_all(broccoli_root.join("config")).unwrap();
    let mut profile = ServerProfile::new("visible-delete", OutboundModel::new(Protocol::Freedom));
    profile.id = "0123456789abcdef".into();
    let servers = ServersFile {
        version: 1,
        active: Some(profile.id.clone()),
        profiles: vec![profile],
        extra: Default::default(),
    };
    let mut settings = Settings::default();
    settings.routing.observatory.enabled = false;
    settings.routing.burst_observatory.enabled = false;
    let servers_bytes = serde_json::to_vec_pretty(&servers).unwrap();
    std::fs::write(broccoli_root.join("state/servers.json"), &servers_bytes).unwrap();
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
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Servers")
        .click();
    h.run();

    assert!(
        h.query_by_role_and_label(egui::accesskit::Role::Button, "🗑")
            .is_some()
    );
    h.get_by_role_and_label(egui::accesskit::Role::Button, "🗑")
        .click();
    h.run();
    assert!(h.query_by_label("Delete server").is_some());
    assert!(
        h.get_all_by_label_contains("visible-delete")
            .next()
            .is_some()
    );
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Cancel")
        .click();
    h.run();
    assert!(h.query_by_label("Delete server").is_none());
    assert!(
        h.get_all_by_label_contains("visible-delete")
            .next()
            .is_some()
    );
    assert_eq!(
        std::fs::read(broccoli_root.join("state/servers.json")).unwrap(),
        servers_bytes
    );

    h.get_by_role_and_label(egui::accesskit::Role::Button, "🗑")
        .click();
    h.run();
    assert!(h.query_by_label("Delete server").is_some());
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Delete")
        .click();
    h.run_steps(4);
    assert!(h.query_by_label("No servers yet.").is_some());
    assert!(
        h.query_by_role_and_label(egui::accesskit::Role::Button, "🗑")
            .is_none()
    );

    drop(h);
    let persisted: ServersFile =
        serde_json::from_slice(&std::fs::read(broccoli_root.join("state/servers.json")).unwrap())
            .unwrap();
    assert!(persisted.profiles.is_empty());
    assert!(persisted.active.is_none());

    drop(tmp);
    drop(lock);
}

#[test]
fn settings_renders_geodata_section() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Settings")
        .click();
    h.run();

    assert!(
        h.get_all_by_label("Geodata").next().is_some(),
        "Settings must render the Geodata section"
    );
    assert!(
        h.get_all_by_label("geoip.dat").next().is_some()
            && h.get_all_by_label("geosite.dat").next().is_some(),
        "the Geodata section must bind both dat file URL fields"
    );
}

/// Right-clicking must no longer offer a Copy button on any surface: the
/// static-label menu, the log-row menu, and the text-field menu were all
/// removed (the logs toolbar's "Copy all" button remains).
#[test]
fn right_click_never_offers_copy() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();

    // A selectable static label.
    let badge = h
        .get_all_by_label("Stopped")
        .next()
        .expect("phase badge label");
    badge.click_secondary();
    h.step();
    assert!(
        h.query_by_role_and_label(egui::accesskit::Role::Button, "Copy")
            .is_none(),
        "right-clicking a static label must not offer a Copy button"
    );

    // A log row.
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Logs")
        .click();
    h.run();
    const LINE: &str = "no-copy probe line";
    h.state_mut().push_log(false, LINE.to_owned());
    h.run();
    let row_rect = h
        .query_all_by_label(LINE)
        .next()
        .expect("pushed log line must render as a row label")
        .rect();
    let pos = row_rect.center();
    h.event(egui::Event::PointerMoved(pos));
    h.event(egui::Event::PointerButton {
        pos,
        button: egui::PointerButton::Secondary,
        pressed: true,
        modifiers: egui::Modifiers::default(),
    });
    h.event(egui::Event::PointerButton {
        pos,
        button: egui::PointerButton::Secondary,
        pressed: false,
        modifiers: egui::Modifiers::default(),
    });
    h.step();
    assert!(
        h.query_by_role_and_label(egui::accesskit::Role::Button, "Copy")
            .is_none(),
        "right-clicking a log row must not offer a Copy button"
    );

    // A text field with a selection.
    logs_filter(&h).click();
    h.run();
    logs_filter(&h).type_text("select me");
    h.run_steps(4);
    h.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    h.run();
    logs_filter(&h).click_secondary();
    h.step();
    assert!(
        h.query_by_role_and_label(egui::accesskit::Role::Button, "Copy")
            .is_none(),
        "right-clicking a text field must not offer a Copy button"
    );
}

/// An idle window must leave the app alive and rendering: no idle frame may
/// drive a work side-effect (a teardown, a screen that stops painting), so
/// the shell's own body is still on screen after N idle frames. That no work
/// side-effect rides an idle frame is guarded where the work is decided: the
/// memoization gates per screen and the runtime arm gates.
#[test]
fn idle_frames_keep_the_app_rendering() {
    let (_lock, _tmp, mut h) = harness();
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();

    // Fresh temp APPDATA -> no core -> the first-run wizard modal covers the
    // whole screen; dismiss it so the render assertion below targets the
    // shell, exactly like the sibling tests.
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();

    const IDLE_FRAMES: u64 = 120;
    h.run_steps(IDLE_FRAMES as usize);

    // Idle frames must leave the app alive and rendering: the Dashboard body
    // (its no-servers empty state) is still on screen after the window.
    assert!(
        h.query_all_by_label(t(Language::En, Key::DashboardNoServers))
            .next()
            .is_some(),
        "the Dashboard must keep rendering its empty state across idle frames"
    );
}

/// Runtime-authored log lines travel as `CoreEvt::AppLog` and are rendered by
/// the app in the active language with the log prefix raw lines carry.
#[test]
fn app_log_events_render_in_the_active_language_with_the_prefix() {
    let (_lock, _tmp, mut h) = harness();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();

    h.state()
        .inject_event(CoreEvt::AppLog(Diag::new(Key::RtLogCoreReady).into()));
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Logs")
        .click();
    h.run_steps(2);

    let expected = format!("[broccoli] {}", t(Language::En, Key::RtLogCoreReady));
    assert!(
        h.query_all_by_label(expected.as_str()).next().is_some(),
        "the Logs screen must render the runtime line in the active language \
         with its prefix: {expected}"
    );
}
