//! Coverage: the TUN screen's leak-block entry list round-trips.
//!
//! The core's `autoSystemWfpBlockLeak` key is what keeps the system's DNS and
//! an unrouted address family inside the tunnel, and it defaults on with every
//! entry the core's `dns` alias stands for. The TUN screen renders one row per
//! entry; an edit writes the core's own spelling straight into the model, so it
//! survives a restart (the state file) and reaches the generator (the emitted
//! document). A list without the entries that block the system's DNS draws the
//! privacy banner, a list without the unrouted family draws the advisory the
//! settings pass renders, and a stored `dns` alias warns once for the session
//! that loaded it.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! Tests are serialized because changing a process environment variable while
//! another harness reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::r#gen::generate_with_api_port;
use broccoli::i18n::{Key, safety_message, t, validation_message};
use broccoli::model::inbound::{
    DNS_LEAK_ENTRIES, TUN_LEAK_MISCONFIG_TUN, TUN_LEAK_WINDNS_CLIENT, leak_port,
};
use broccoli::model::settings::{Language, Mode, Settings};
use broccoli::model::{SafetyCode, ServersFile, TunCfg, ValidationCode};
use broccoli::ui::Screen;
use egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable as _;
use parking_lot::MutexGuard;

#[path = "common/nav.rs"]
mod nav;
#[path = "common/screen.rs"]
mod screen;

mod common;

/// TUN mode with the seeded DNS module and the seeded leak list, so the key
/// reaches the wire and every seeded row renders.
fn tun_settings() -> Settings {
    Settings {
        mode: Mode::Tun,
        ..Default::default()
    }
}

/// The seeded leak list, read off [`TunCfg::default()`] so a re-default cannot
/// silently dodge these tests.
fn seeded_leak() -> Vec<String> {
    TunCfg::default().auto_system_wfp_block_leak
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

/// The leak list the persisted state file loads back to.
fn saved_leak() -> Vec<String> {
    Settings::load()
        .expect("the persisted settings.json loads")
        .tun
        .auto_system_wfp_block_leak
}

/// Click row `index`'s 🗑 among the leak block's port rows.
///
/// The two named entries render as checkboxes, so the delete buttons the leak
/// section contributes are its port rows only, and they come before every
/// other list's in the tree.
fn delete_leak_port_row(h: &mut Harness<'static, BroccoliApp>, index: usize) {
    h.query_all_by_label(t(Language::En, Key::DeleteRow))
        .nth(index)
        .expect("a leak row's delete button")
        .click();
    h.run_steps(4);
}

/// Tick or untick one named leak entry's checkbox.
fn toggle_leak_switch(h: &mut Harness<'static, BroccoliApp>, key: Key) {
    h.get_by_role_and_label(Role::CheckBox, t(Language::En, key))
        .click();
    h.run_steps(4);
}

/// Press the leak block's "add a port" button.
fn add_leak_port(h: &mut Harness<'static, BroccoliApp>) {
    h.get_by_role_and_label(Role::Button, t(Language::En, Key::TunLeakAddPort))
        .click();
    h.run_steps(4);
}

/// True when the AccessKit tree carries a node whose text contains `text`.
fn rendered(h: &Harness<'static, BroccoliApp>, text: &str) -> bool {
    h.query_all_by_label_contains(text).next().is_some()
}

/// The advisory message the settings pass renders for a list without the
/// unrouted family; the screen shows these same bytes under the list.
fn family_warning() -> String {
    validation_message(&ValidationCode::TunLeakMisconfigTunOff, Language::En)
}

#[test]
fn the_leak_rows_round_trip_into_the_state_file_and_the_generated_config() {
    let (_lock, _tmp, mut h) = boot(tun_settings());

    // A fresh profile runs the core's whole expansion of `dns`, then the
    // unrouted family: the seeded list, the state file the boot wrote, and
    // the emitted document all carry the same six entries.
    let seeded = seeded_leak();
    assert_eq!(seeded.len(), 6, "the seeded list is six entries");
    assert_eq!(saved_leak(), seeded);
    assert_eq!(
        tun_wire(&tun_settings())["autoSystemWfpBlockLeak"],
        serde_json::json!(seeded)
    );

    // One row per port: deleting the first row removes exactly the entry it
    // names, in the list's own order, until only the two checkboxes' entries
    // remain.
    let mut remaining = seeded;
    for _ in 0..4 {
        let first_port = remaining
            .iter()
            .position(|entry| leak_port(entry).is_some())
            .expect("a port row to delete");
        remaining.remove(first_port);
        delete_leak_port_row(&mut h, 0);
        assert_eq!(
            saved_leak(),
            remaining,
            "the first port row names {first_port}"
        );
    }
    assert_eq!(
        remaining,
        vec![
            TUN_LEAK_WINDNS_CLIENT.to_string(),
            TUN_LEAK_MISCONFIG_TUN.to_string(),
        ],
        "only the two named entries are left"
    );

    // The two checkboxes own the named entries: unticking both empties the
    // list.
    toggle_leak_switch(&mut h, Key::TunLeakWindnsClientLabel);
    toggle_leak_switch(&mut h, Key::TunLeakMisconfigLabel);
    assert!(
        saved_leak().is_empty(),
        "unticking both named entries must leave an empty list"
    );
    assert_eq!(
        tun_wire(&Settings::load().expect("the persisted settings.json loads"))["autoSystemWfpBlockLeak"],
        serde_json::json!([]),
        "an empty list stays a no-op the core accepts"
    );

    // The add button appends the lowest port the list does not hold, and the
    // next save and generation carry it.
    add_leak_port(&mut h);
    assert_eq!(saved_leak(), vec!["tcp/1".to_string()]);
    assert_eq!(
        tun_wire(&Settings::load().expect("the persisted settings.json loads"))["autoSystemWfpBlockLeak"],
        serde_json::json!(["tcp/1"])
    );
}

#[test]
fn a_stored_dns_alias_loads_expanded_and_warns_once() {
    // An old profile stores the alias. The load keeps the entries it stands
    // for and the save writes them, so the alias never reaches the state file
    // or the generated document again.
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = vec!["dns".into()];
    let (_lock, _tmp, h) = boot(settings);

    assert_eq!(
        saved_leak(),
        DNS_LEAK_ENTRIES.map(String::from).to_vec(),
        "the alias must load as the entries it stands for"
    );
    // The one session that saw the alias says so, under the list it migrated.
    let advisory = validation_message(&ValidationCode::TunLeakDnsAliasExpanded, Language::En);
    assert!(
        rendered(&h, &advisory),
        "the load-time expansion must warn: {advisory}"
    );
}

#[test]
fn the_family_advisory_follows_its_entry() {
    let message = family_warning();
    let (_lock, _tmp, mut h) = boot(tun_settings());

    // The seeded list carries the family entry: the advisory's text is absent.
    assert!(
        !rendered(&h, &message),
        "the advisory must stay quiet while the family entry is present"
    );

    // Untick the family checkbox: the advisory appears under the list, while
    // generation still succeeds (an advisory, never a gate).
    toggle_leak_switch(&mut h, Key::TunLeakMisconfigLabel);
    assert!(
        !saved_leak().contains(&TUN_LEAK_MISCONFIG_TUN.to_string()),
        "unticking the box must remove the family entry"
    );
    assert!(
        rendered(&h, &message),
        "a list without the family entry must warn"
    );
    generate_with_api_port(
        &ServersFile::default(),
        &Settings::load().expect("the persisted settings.json loads"),
        19999,
    )
    .expect("the advisory must not block generation");

    // Tick it back: the advisory clears.
    toggle_leak_switch(&mut h, Key::TunLeakMisconfigLabel);
    assert!(saved_leak().contains(&TUN_LEAK_MISCONFIG_TUN.to_string()));
    assert!(
        !rendered(&h, &message),
        "the advisory must clear when the family entry comes back"
    );
}

#[test]
fn the_privacy_banner_and_the_family_advisory_track_their_own_entries() {
    let banner = safety_message(&SafetyCode::TunDnsUnprotected, Language::En);
    let family = family_warning();
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = vec!["misconfigtun".into()];
    let (_lock, _tmp, mut h) = boot(settings);

    // The family entry alone: the system's DNS is unprotected, the family is
    // not.
    assert!(
        rendered(&h, &banner),
        "a list without port 53 or the DNS Client service must warn"
    );
    assert!(
        !rendered(&h, &family),
        "the family advisory must track only its own entry"
    );

    // Unticking the only entry leaves an empty block: both warnings render,
    // and the empty list still generates.
    toggle_leak_switch(&mut h, Key::TunLeakMisconfigLabel);
    assert!(saved_leak().is_empty());
    assert!(rendered(&h, &banner), "the banner must stay");
    assert!(rendered(&h, &family), "the family advisory must join it");

    // Ticking the DNS Client service blocks the system's DNS again: the banner
    // clears while the family advisory stays.
    toggle_leak_switch(&mut h, Key::TunLeakWindnsClientLabel);
    assert_eq!(saved_leak(), vec!["windnsclient".to_string()]);
    assert!(
        !rendered(&h, &banner),
        "the DNS Client service must clear the banner"
    );
    assert!(
        rendered(&h, &family),
        "the family advisory must keep tracking its own entry"
    );
}
