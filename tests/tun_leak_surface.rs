//! Coverage: the TUN screen's leak-block entry list round-trips.
//!
//! The core's `autoSystemWfpBlockLeak` key is what keeps the system's DNS and
//! an unrouted address family inside the tunnel, and it defaults on with every
//! entry the core's `dns` alias stands for. The TUN screen renders one control
//! per entry — a named value as a checkbox, a port as a protocol row, and any
//! other value as a raw row — and an edit writes the core's own spelling
//! straight into the model, so it survives a restart (the state file) and
//! reaches the generator (the emitted document). An entry an unprefixed `all`
//! or `allexceptlan` already covers renders disabled but stays in the list. A
//! list without the entries that block the system's DNS draws the privacy
//! banner, a list without the unrouted family draws the advisory the settings
//! pass renders, and a stored `dns` alias warns once for the session that
//! loaded it.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! Tests are serialized because changing a process environment variable while
//! another harness reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::r#gen::generate_with_api_port;
use broccoli::i18n::{Key, safety_message, t, t_fmt, validation_message};
use broccoli::model::inbound::{
    DNS_LEAK_ENTRIES, TUN_LEAK_ALL, TUN_LEAK_ALL_EXCEPT_LAN, TUN_LEAK_ICMP, TUN_LEAK_MISCONFIG_TUN,
    TUN_LEAK_WINDNS_CLIENT, leak_port,
};
use broccoli::model::settings::{Language, Mode, Settings};
use broccoli::model::{SafetyCode, ServersFile, TunCfg, ValidationCode};
use broccoli::ui::Screen;
use egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::NodeT as _;
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

/// Whether one leak entry renders as a checkbox (a named value) rather than a
/// row.
fn is_named_leak(entry: &str) -> bool {
    [
        TUN_LEAK_WINDNS_CLIENT,
        TUN_LEAK_MISCONFIG_TUN,
        TUN_LEAK_ALL,
        TUN_LEAK_ALL_EXCEPT_LAN,
        TUN_LEAK_ICMP,
    ]
    .iter()
    .any(|named| entry.eq_ignore_ascii_case(named))
}

/// The number of leak rows the editor renders: every stored entry that is not
/// one of the named checkboxes.
fn leak_row_count(entries: &[String]) -> usize {
    entries.iter().filter(|entry| !is_named_leak(entry)).count()
}

/// Whether the named value's checkbox renders disabled.
fn named_disabled(h: &Harness<'static, BroccoliApp>, key: Key) -> bool {
    h.get_by_role_and_label(Role::CheckBox, t(Language::En, key))
        .accesskit_node()
        .is_disabled()
}

/// Whether leak row `index`'s 🗑 renders disabled.
fn leak_row_delete_disabled(h: &Harness<'static, BroccoliApp>, index: usize) -> bool {
    h.query_all_by_label(t(Language::En, Key::DeleteRow))
        .nth(index)
        .expect("a leak row's delete button")
        .accesskit_node()
        .is_disabled()
}

/// Press a leak block button by its label key.
fn press_leak_button(h: &mut Harness<'static, BroccoliApp>, key: Key) {
    h.get_by_role_and_label(Role::Button, t(Language::En, key))
        .click();
    h.run_steps(4);
}

/// Type `text` into the leak block's raw entry row and press its add button.
fn add_raw_leak(h: &mut Harness<'static, BroccoliApp>, text: &str) {
    let label = t(Language::En, Key::TunLeakRawLabel);
    h.get_by_role_and_label(Role::TextInput, label).click();
    h.run();
    h.get_by_role_and_label(Role::TextInput, label)
        .type_text(text);
    h.run_steps(4);
    press_leak_button(h, Key::TunLeakAddEntry);
}

/// The covered-entry note naming `covering`.
fn covered_note(covering: &str) -> String {
    t_fmt(Language::En, Key::TunLeakCoveredNote, &[&covering])
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

#[test]
fn the_leak_controls_author_named_values_ports_ranges_and_prefixed_entries() {
    let (_lock, _tmp, mut h) = boot(tun_settings());
    let mut expected = seeded_leak();

    // A named value: the toggle adds the core's spelling and removes it
    // again, and the state file carries each change.
    toggle_leak_switch(&mut h, Key::TunLeakIcmpLabel);
    expected.push(TUN_LEAK_ICMP.to_string());
    assert_eq!(
        saved_leak(),
        expected,
        "the toggle must add its named value"
    );
    toggle_leak_switch(&mut h, Key::TunLeakIcmpLabel);
    expected.pop();
    assert_eq!(
        saved_leak(),
        expected,
        "the toggle must remove its named value"
    );

    // A port row: the button appends the lowest port the list lacks, and the
    // row's 🗑 removes exactly that entry.
    press_leak_button(&mut h, Key::TunLeakAddPort);
    expected.push("tcp/1".to_string());
    assert_eq!(
        saved_leak(),
        expected,
        "the port button appends a free port"
    );
    delete_leak_port_row(&mut h, leak_row_count(&expected) - 1);
    expected.pop();
    assert_eq!(
        saved_leak(),
        expected,
        "the row's remove button must remove the port"
    );

    // A range row: the button appends the lowest free two-port range.
    press_leak_button(&mut h, Key::TunLeakAddRange);
    expected.push("tcp/1-2".to_string());
    assert_eq!(
        saved_leak(),
        expected,
        "the range button appends a free range"
    );
    delete_leak_port_row(&mut h, leak_row_count(&expected) - 1);
    expected.pop();
    assert_eq!(
        saved_leak(),
        expected,
        "the row's remove button must remove the range"
    );

    // A CIDR-prefixed value: authored in the raw row and stored in the
    // model's canonical spelling.
    add_raw_leak(&mut h, "1.1.1.0/24:53");
    expected.push("1.1.1.0/24:53".to_string());
    assert_eq!(
        saved_leak(),
        expected,
        "the raw row must add the parsed value"
    );
    delete_leak_port_row(&mut h, leak_row_count(&expected) - 1);
    expected.pop();
    assert_eq!(
        saved_leak(),
        expected,
        "the raw row's remove button must remove it"
    );
}

#[test]
fn an_unprefixed_all_disables_the_other_entries_and_keeps_them_stored() {
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = vec![
        TUN_LEAK_ALL.to_string(),
        "udp/53".to_string(),
        TUN_LEAK_ICMP.to_string(),
        TUN_LEAK_MISCONFIG_TUN.to_string(),
    ];
    let (_lock, _tmp, mut h) = boot(settings);

    // The note names the entry that covers the others.
    assert!(
        rendered(&h, &covered_note(TUN_LEAK_ALL)),
        "the covered entries must name all"
    );

    // `all` itself and the unrouted-family entry stay editable, so the
    // covering entry can be removed and the family kept.
    assert!(!named_disabled(&h, Key::TunLeakAllLabel));
    assert!(!named_disabled(&h, Key::TunLeakMisconfigLabel));
    for key in [
        Key::TunLeakWindnsClientLabel,
        Key::TunLeakAllExceptLanLabel,
        Key::TunLeakIcmpLabel,
    ] {
        assert!(named_disabled(&h, key), "all covers the {key:?} entry");
    }
    assert!(leak_row_delete_disabled(&h, 0), "all covers the udp/53 row");

    // The state disables, never deletes: the list and the emitted document
    // keep every covered entry.
    let stored: Vec<String> = ["all", "udp/53", "icmp", "misconfigtun"]
        .map(String::from)
        .to_vec();
    assert_eq!(saved_leak(), stored);
    let loaded = Settings::load().expect("the persisted settings.json loads");
    assert_eq!(
        tun_wire(&loaded)["autoSystemWfpBlockLeak"],
        serde_json::json!(stored),
        "the emitted list must still carry every covered entry"
    );

    // Removing the covering entry restores the stored entries to editable.
    toggle_leak_switch(&mut h, Key::TunLeakAllLabel);
    assert!(
        !rendered(&h, &covered_note(TUN_LEAK_ALL)),
        "the note must clear with the covering entry"
    );
    assert_eq!(
        saved_leak(),
        vec!["udp/53", "icmp", "misconfigtun"],
        "removing all must keep the entries it covered"
    );
    assert!(!named_disabled(&h, Key::TunLeakIcmpLabel));
    assert!(!named_disabled(&h, Key::TunLeakWindnsClientLabel));
    assert!(!leak_row_delete_disabled(&h, 0));
}

#[test]
fn an_unprefixed_allexceptlan_disables_the_dns_entries_and_icmp_only() {
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = vec![
        TUN_LEAK_ALL_EXCEPT_LAN.to_string(),
        "udp/53".to_string(),
        "tcp/853".to_string(),
        "tcp/443".to_string(),
        TUN_LEAK_ICMP.to_string(),
        TUN_LEAK_MISCONFIG_TUN.to_string(),
    ];
    let (_lock, _tmp, mut h) = boot(settings);

    assert!(
        rendered(&h, &covered_note(TUN_LEAK_ALL_EXCEPT_LAN)),
        "the covered entries must name allexceptlan"
    );

    assert!(named_disabled(&h, Key::TunLeakWindnsClientLabel));
    assert!(named_disabled(&h, Key::TunLeakIcmpLabel));
    for key in [
        Key::TunLeakAllLabel,
        Key::TunLeakAllExceptLanLabel,
        Key::TunLeakMisconfigLabel,
    ] {
        assert!(
            !named_disabled(&h, key),
            "{key:?} is not a DNS entry the alias covers"
        );
    }
    // The DNS port rows are covered, while another port stays editable.
    assert!(leak_row_delete_disabled(&h, 0), "udp/53 is a DNS entry");
    assert!(leak_row_delete_disabled(&h, 1), "tcp/853 is a DNS entry");
    assert!(
        !leak_row_delete_disabled(&h, 2),
        "tcp/443 is not a DNS entry"
    );

    // Removing the covering entry restores every stored entry, and nothing
    // was deleted by the state.
    assert_eq!(saved_leak().len(), 6);
    toggle_leak_switch(&mut h, Key::TunLeakAllExceptLanLabel);
    assert_eq!(
        saved_leak(),
        vec!["udp/53", "tcp/853", "tcp/443", "icmp", "misconfigtun"],
        "removing allexceptlan must keep the entries it covered"
    );
    assert!(!named_disabled(&h, Key::TunLeakIcmpLabel));
    assert!(!leak_row_delete_disabled(&h, 0));
}

#[test]
fn a_prefixed_all_or_allexceptlan_covers_no_other_entry() {
    for covering in ["1.1.1.0/24:all", "[::/0]:allexceptlan"] {
        let mut settings = tun_settings();
        settings.tun.auto_system_wfp_block_leak = vec![
            covering.to_string(),
            "udp/53".to_string(),
            TUN_LEAK_ICMP.to_string(),
            TUN_LEAK_MISCONFIG_TUN.to_string(),
        ];
        let (_lock, _tmp, h) = boot(settings);

        for value in [TUN_LEAK_ALL, TUN_LEAK_ALL_EXCEPT_LAN] {
            assert!(
                !rendered(&h, &covered_note(value)),
                "{covering} must not cover other entries"
            );
        }
        for key in [
            Key::TunLeakAllLabel,
            Key::TunLeakAllExceptLanLabel,
            Key::TunLeakIcmpLabel,
        ] {
            assert!(
                !named_disabled(&h, key),
                "{covering} must leave {key:?} editable"
            );
        }
        assert!(
            !leak_row_delete_disabled(&h, 0),
            "{covering} must leave the port row editable"
        );
    }
}
