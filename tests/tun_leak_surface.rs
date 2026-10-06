//! Coverage: the TUN screen's leak-block switches round-trip.
//!
//! The core's `autoSystemWfpBlockLeak` key is what keeps DNS and an unrouted
//! address family inside the tunnel, and it defaults on. The TUN screen
//! renders one switch per half; a toggle writes the folded value straight into
//! the model, so it survives a restart (the state file) and reaches the
//! generator (the emitted document). A hand-edited list is shown truthfully —
//! the folded read, not the raw entries. A switched-off family half also draws
//! the advisory the settings pass renders, right under its switch; the DNS
//! half's safety banner is unchanged.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! Tests are serialized because changing a process environment variable while
//! another harness reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::r#gen::generate_with_api_port;
use broccoli::i18n::{Key, safety_message, t, validation_message};
use broccoli::model::settings::{Language, Mode, Settings};
use broccoli::model::{SafetyCode, ServersFile, TunCfg, ValidationCode};
use broccoli::ui::Screen;
use egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT as _, Queryable as _};
use parking_lot::MutexGuard;

#[path = "common/nav.rs"]
mod nav;
#[path = "common/screen.rs"]
mod screen;

mod common;

/// TUN mode with the seeded DNS module and the seeded both-on leak block, so
/// the key reaches the wire and both switches start checked.
fn tun_settings() -> Settings {
    Settings {
        mode: Mode::Tun,
        ..Default::default()
    }
}

/// Boot at the TUN screen over `settings`, with a viewport tall enough that
/// every section lands in the AccessKit tree.
fn boot(
    settings: Settings,
) -> (
    MutexGuard<'static, ()>,
    common::TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    nav::boot_screen(
        screen::BootState {
            settings,
            servers: ServersFile::default(),
        },
        Some(Screen::Tun),
        egui::Vec2::new(1100.0, 2800.0),
    )
}

/// The toggled state of the leak switch the label names.
fn switch(harness: &Harness<'static, BroccoliApp>, label: &str) -> Option<bool> {
    harness
        .get_by_role_and_label(Role::CheckBox, label)
        .accesskit_node()
        .toggled()
        .map(|toggled| matches!(toggled, egui::accesskit::Toggled::True))
}

/// The emitted TUN inbound's settings object.
fn tun_wire(settings: &Settings) -> serde_json::Value {
    let config = generate_with_api_port(&ServersFile::default(), settings, 19999)
        .expect("the seeded TUN config must generate");
    config["inbounds"]
        .as_array()
        .expect("inbounds is an array")
        .iter()
        .find(|inbound| inbound["protocol"] == "tun")
        .expect("the TUN inbound must be emitted")["settings"]
        .clone()
}

#[test]
fn leak_switches_round_trip_into_the_state_file_and_the_generated_config() {
    let dns_label = t(Language::En, Key::TunLeakDnsLabel);
    let family_label = t(Language::En, Key::TunLeakMisconfigLabel);
    let (_lock, _tmp, mut h) = boot(tun_settings());

    // A fresh profile runs both halves: the switches read on, and the state
    // file the boot seeded carries both values.
    assert_eq!(switch(&h, dns_label), Some(true));
    assert_eq!(switch(&h, family_label), Some(true));
    assert_eq!(
        Settings::load()
            .expect("the seeded settings.json loads")
            .tun
            .auto_system_wfp_block_leak,
        vec!["dns".to_string(), "misconfigtun".to_string()]
    );

    // Switch the family half off: the change reaches the state file and the
    // generator emits exactly the folded value that is left.
    h.get_by_role_and_label(Role::CheckBox, family_label)
        .click();
    h.run_steps(4);
    let saved = Settings::load().expect("the persisted settings.json loads");
    assert_eq!(
        saved.tun.auto_system_wfp_block_leak,
        vec!["dns".to_string()],
        "the switch must persist the folded value"
    );
    assert_eq!(
        tun_wire(&saved)["autoSystemWfpBlockLeak"],
        serde_json::json!(["dns"])
    );

    // Switch the DNS half off too: both halves cleared, and the key still
    // reaches the wire as the core's accepted no-op.
    h.get_by_role_and_label(Role::CheckBox, dns_label).click();
    h.run_steps(4);
    let saved = Settings::load().expect("the persisted settings.json loads");
    assert!(
        saved.tun.auto_system_wfp_block_leak.is_empty(),
        "both halves off must persist an empty list"
    );
    assert_eq!(
        tun_wire(&saved)["autoSystemWfpBlockLeak"],
        serde_json::json!([])
    );
}

#[test]
fn leak_switches_show_a_hand_edited_list_truthfully() {
    // A hand-edited list: the DNS half in a mixed-case spelling, and no
    // family half. The switches must read the folded truth.
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = vec!["DNS".into()];
    let (_lock, _tmp, h) = boot(settings);

    assert_eq!(
        switch(&h, t(Language::En, Key::TunLeakDnsLabel)),
        Some(true)
    );
    assert_eq!(
        switch(&h, t(Language::En, Key::TunLeakMisconfigLabel)),
        Some(false)
    );
    // Guard: the seeded both-on profile really differs from this one, so the
    // assertions above cannot pass on a screen that ignores the list.
    assert_eq!(TunCfg::default().auto_system_wfp_block_leak.len(), 2);
}

/// The advisory message the settings pass renders for a switched-off family
/// half; the screen shows these same bytes under the switch.
fn family_warning() -> String {
    validation_message(&ValidationCode::TunLeakMisconfigTunOff, Language::En)
}

/// True when the AccessKit tree carries a node whose text contains `text`.
fn rendered(h: &Harness<'static, BroccoliApp>, text: &str) -> bool {
    h.query_all_by_label_contains(text).next().is_some()
}

#[test]
fn the_unrouted_family_warning_follows_its_switch() {
    let family_label = t(Language::En, Key::TunLeakMisconfigLabel);
    let message = family_warning();
    let (_lock, _tmp, mut h) = boot(tun_settings());

    // Both halves on: the advisory's text is absent.
    assert!(
        !rendered(&h, &message),
        "the warning must stay quiet while the family half is on"
    );

    // The family half off: the warning appears where the switch lives, and
    // the configuration still generates (an advisory, never a gate).
    h.get_by_role_and_label(Role::CheckBox, family_label)
        .click();
    h.run_steps(4);
    assert!(
        rendered(&h, &message),
        "a switched-off family half must warn"
    );
    let saved = Settings::load().expect("the persisted settings.json loads");
    generate_with_api_port(&ServersFile::default(), &saved, 19999)
        .expect("the advisory must not block generation");

    // Back on: the warning clears.
    h.get_by_role_and_label(Role::CheckBox, family_label)
        .click();
    h.run_steps(4);
    assert!(
        !rendered(&h, &message),
        "the warning must clear when the half comes back"
    );
}

#[test]
fn the_family_warning_and_the_dns_banner_stay_independent() {
    let dns_label = t(Language::En, Key::TunLeakDnsLabel);
    let family_label = t(Language::En, Key::TunLeakMisconfigLabel);
    let family_message = family_warning();
    let dns_message = safety_message(&SafetyCode::TunDnsUnprotected, Language::En);
    let (_lock, _tmp, mut h) = boot(tun_settings());

    // Only the DNS half off: its privacy banner appears and the family
    // warning stays quiet (that half is still on).
    h.get_by_role_and_label(Role::CheckBox, dns_label).click();
    h.run_steps(4);
    assert!(
        rendered(&h, &dns_message),
        "the DNS half's banner must keep rendering"
    );
    assert!(
        !rendered(&h, &family_message),
        "the family warning must track only its own half"
    );

    // Both halves off: the family warning joins the banner.
    h.get_by_role_and_label(Role::CheckBox, family_label)
        .click();
    h.run_steps(4);
    assert!(
        rendered(&h, &dns_message),
        "the DNS half's banner must stay"
    );
    assert!(
        rendered(&h, &family_message),
        "the family warning must join the banner"
    );
}
