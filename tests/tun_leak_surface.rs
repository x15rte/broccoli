//! Coverage: the TUN screen's leak-block entry list round-trips.
//!
//! The core's `autoSystemWfpBlockLeak` key is what keeps the system's DNS and
//! an unrouted address family inside the tunnel, and a fresh profile seeds it
//! with `allexceptlan`: private destinations stay direct while the core follows
//! the alias with the DNS entries it stands for. The TUN screen reads the
//! stored list as a scope — an unprefixed `all` or `allexceptlan` selects one of
//! the two policy scopes, and every other list selects `Custom entries` — and
//! only the custom scope shows the detail editor. A scope switch rewrites the
//! scope values alone, so the detail entries stay stored, stay in the emitted
//! document, and come back under `Custom`. A list without the entries that
//! block the system's DNS draws the privacy banner, a list without the
//! unrouted family draws the advisory the settings pass renders, and a stored
//! `dns` alias warns once for the session that loaded it.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! Tests are serialized because changing a process environment variable while
//! another harness reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::r#gen::generate_with_api_port;
use broccoli::i18n::{Key, safety_message, t, t_fmt, validation_message};
use broccoli::model::inbound::{
    DNS_LEAK_ENTRIES, TUN_LEAK_ALL, TUN_LEAK_ALL_EXCEPT_LAN, TUN_LEAK_ICMP, TUN_LEAK_MISCONFIG_TUN,
    TUN_LEAK_WINDNS_CLIENT,
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

/// The emitted leak list of the persisted settings.
fn saved_wire_leak() -> serde_json::Value {
    let settings = Settings::load().expect("the persisted settings.json loads");
    tun_wire(&settings)["autoSystemWfpBlockLeak"].clone()
}

/// Whether one scope radio reads selected.
fn scope_checked(h: &Harness<'static, BroccoliApp>, key: Key) -> bool {
    h.get_by_role_and_label(Role::RadioButton, t(Language::En, key))
        .accesskit_node()
        .toggled()
        .is_some_and(|toggled| matches!(toggled, egui::accesskit::Toggled::True))
}

/// Click one scope radio.
fn select_scope(h: &mut Harness<'static, BroccoliApp>, key: Key) {
    h.get_by_role_and_label(Role::RadioButton, t(Language::En, key))
        .click();
    h.run_steps(4);
}

/// Click row `index`'s 🗑 among the leak block's detail rows.
///
/// The named values render as checkboxes and the scope as radios, so the
/// delete buttons the leak section contributes are its detail rows only, and
/// they come before every other list's in the tree.
fn delete_leak_row(h: &mut Harness<'static, BroccoliApp>, index: usize) {
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

/// The hidden-detail note naming `count` stored entries.
fn hidden_note(count: usize) -> String {
    let count = count.to_string();
    t_fmt(Language::En, Key::TunLeakHiddenNote, &[&count])
}

/// True when the AccessKit tree carries a node whose text contains `text`.
fn rendered(h: &Harness<'static, BroccoliApp>, text: &str) -> bool {
    h.query_all_by_label_contains(text).next().is_some()
}

/// Whether the detail editor renders: its ICMP checkbox is present under every
/// scope that keeps the list (the DNS controls are absent under the alias).
fn detail_visible(h: &Harness<'static, BroccoliApp>) -> bool {
    h.query_by_role_and_label(Role::CheckBox, t(Language::En, Key::TunLeakIcmpLabel))
        .is_some()
}

/// The number of detail rows the editor renders, counted inside the leak
/// section's body so every other list's delete buttons stay out of the count.
fn detail_rows(h: &Harness<'static, BroccoliApp>) -> usize {
    let hint = h.get_by_label(t(Language::En, Key::TunLeakEntriesHint));
    let body = hint.parent().expect("the hint sits in the section body");
    let delete = t(Language::En, Key::DeleteRow);
    body.children_recursive()
        .filter(|node| {
            node.accesskit_node()
                .label()
                .is_some_and(|label| label == delete)
        })
        .count()
}

/// The advisory message the settings pass renders for a list without the
/// unrouted family; the screen shows these same bytes under the list.
fn family_warning() -> String {
    validation_message(&ValidationCode::TunLeakMisconfigTunOff, Language::En)
}

#[test]
fn the_leak_rows_round_trip_into_the_state_file_and_the_generated_config() {
    let (_lock, _tmp, mut h) = boot(tun_settings());

    // A fresh profile states the scope its routing defaults need: everything
    // except the local network stays inside the tunnel, and an unrouted family
    // stays guarded even on that network.
    let seeded = seeded_leak();
    assert_eq!(
        seeded,
        vec![
            TUN_LEAK_ALL_EXCEPT_LAN.to_string(),
            TUN_LEAK_MISCONFIG_TUN.to_string()
        ],
        "the seed is the scope value plus the family guard"
    );
    assert_eq!(saved_leak(), seeded);
    assert_eq!(
        tun_wire(&tun_settings())["autoSystemWfpBlockLeak"],
        serde_json::json!(seeded)
    );

    // The scope radio reads the stored alias and the detail editor stays open:
    // a detail entry still blocks inside the local network, which the alias
    // leaves alone. The DNS controls are not repeated, and the empty list adds
    // no hidden note.
    assert!(scope_checked(&h, Key::TunLeakScopeAllExceptLanLabel));
    assert!(detail_visible(&h));
    assert_eq!(detail_rows(&h), 0);
    assert!(
        rendered(&h, t(Language::En, Key::TunLeakDnsIncludedNote)),
        "the alias already blocks DNS"
    );
    assert!(
        h.query_by_role_and_label(
            Role::CheckBox,
            t(Language::En, Key::TunLeakWindnsClientLabel)
        )
        .is_none(),
        "the DNS Client control would read off while the alias blocks it"
    );
    assert!(
        !rendered(&h, &hidden_note(0)),
        "an empty detail list needs no hidden note"
    );

    // The custom scope removes only the scope value: the family guard stays,
    // and it is the only detail the editor carries.
    select_scope(&mut h, Key::TunLeakScopeCustomLabel);
    assert_eq!(saved_leak(), vec![TUN_LEAK_MISCONFIG_TUN.to_string()]);
    assert!(detail_visible(&h));

    // Author a named value and a port through the detail editor; the family
    // guard is already stored, and the state file and the emitted document
    // carry each edit.
    toggle_leak_switch(&mut h, Key::TunLeakWindnsClientLabel);
    add_leak_port(&mut h);
    let details: Vec<String> = ["misconfigtun", "windnsclient", "tcp/1"]
        .map(String::from)
        .to_vec();
    assert_eq!(saved_leak(), details);
    assert_eq!(saved_wire_leak(), serde_json::json!(details));

    // Selecting a policy scope appends its spelling and hides the details,
    // while the state and the emitted document keep them.
    select_scope(&mut h, Key::TunLeakScopeAllLabel);
    let mut hidden = details.clone();
    hidden.push(TUN_LEAK_ALL.to_string());
    assert_eq!(saved_leak(), hidden);
    assert!(scope_checked(&h, Key::TunLeakScopeAllLabel));
    assert!(!detail_visible(&h));
    assert_eq!(detail_rows(&h), 0);
    assert!(
        rendered(&h, &hidden_note(details.len())),
        "the note must count the hidden detail entries"
    );
    assert_eq!(saved_wire_leak(), serde_json::json!(hidden));

    // Back to Custom: the scope value goes and every detail entry reappears.
    select_scope(&mut h, Key::TunLeakScopeCustomLabel);
    assert_eq!(saved_leak(), details);
    assert!(detail_visible(&h));
    assert!(!rendered(&h, &hidden_note(details.len())));
    assert_eq!(
        saved_wire_leak(),
        serde_json::json!(details),
        "the emitted document keeps every detail entry"
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
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = vec!["udp/53".into(), TUN_LEAK_MISCONFIG_TUN.into()];
    let (_lock, _tmp, mut h) = boot(settings);

    // The list carries the family entry: the advisory's text is absent.
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
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = Vec::new();
    let (_lock, _tmp, mut h) = boot(settings);
    select_scope(&mut h, Key::TunLeakScopeCustomLabel);
    assert!(saved_leak().is_empty());

    // A named value: the toggle adds the core's spelling and removes it
    // again, and the state file carries each change.
    toggle_leak_switch(&mut h, Key::TunLeakIcmpLabel);
    assert_eq!(saved_leak(), vec![TUN_LEAK_ICMP.to_string()]);
    toggle_leak_switch(&mut h, Key::TunLeakIcmpLabel);
    assert!(saved_leak().is_empty());

    // A port row: the button appends the lowest port the list lacks, and the
    // row's 🗑 removes exactly that entry.
    press_leak_button(&mut h, Key::TunLeakAddPort);
    assert_eq!(saved_leak(), vec!["tcp/1".to_string()]);
    delete_leak_row(&mut h, 0);
    assert!(saved_leak().is_empty());

    // A range row: the button appends the lowest free two-port range.
    press_leak_button(&mut h, Key::TunLeakAddRange);
    assert_eq!(saved_leak(), vec!["tcp/1-2".to_string()]);
    delete_leak_row(&mut h, 0);
    assert!(saved_leak().is_empty());

    // A CIDR-prefixed value: authored in the raw row and stored in the
    // model's canonical spelling, then removed by its own row.
    add_raw_leak(&mut h, "1.1.1.0/24:53");
    assert_eq!(saved_leak(), vec!["1.1.1.0/24:53".to_string()]);
    delete_leak_row(&mut h, 0);
    assert!(saved_leak().is_empty());
}

#[test]
fn selecting_all_hides_the_detail_and_keeps_the_stored_entries() {
    let details: Vec<String> = ["udp/53", "icmp", "misconfigtun"]
        .map(String::from)
        .to_vec();
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = details.clone();
    let (_lock, _tmp, mut h) = boot(settings);

    // The detail list selects the custom scope and renders its editor.
    assert!(scope_checked(&h, Key::TunLeakScopeCustomLabel));
    assert!(detail_visible(&h));
    assert_eq!(detail_rows(&h), 1, "only udp/53 is a detail row");

    // Selecting `all` appends its spelling and hides the whole editor.
    select_scope(&mut h, Key::TunLeakScopeAllLabel);
    let mut stored = details.clone();
    stored.push(TUN_LEAK_ALL.to_string());
    assert_eq!(saved_leak(), stored);
    assert!(scope_checked(&h, Key::TunLeakScopeAllLabel));
    assert!(!detail_visible(&h), "the whole detail editor must hide");
    assert_eq!(detail_rows(&h), 0);
    assert!(
        rendered(&h, &hidden_note(details.len())),
        "the note must count the entries the scope hides"
    );

    // The emitted document keeps every hidden entry.
    assert_eq!(
        saved_wire_leak(),
        serde_json::json!(stored),
        "the emitted list must still carry every hidden entry"
    );

    // Removing the scope restores the stored entries to the editor.
    select_scope(&mut h, Key::TunLeakScopeCustomLabel);
    assert_eq!(saved_leak(), details);
    assert!(detail_visible(&h));
    assert_eq!(detail_rows(&h), 1);
    assert!(!rendered(&h, &hidden_note(details.len())));
}

#[test]
fn the_alias_hides_every_dns_spelling_it_contains() {
    let details: Vec<String> = [
        TUN_LEAK_ALL_EXCEPT_LAN,
        "53",
        "1.1.1.0/24:tcp/53",
        TUN_LEAK_WINDNS_CLIENT,
        "tcp/443",
    ]
    .map(String::from)
    .to_vec();
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = details.clone();
    let (_lock, _tmp, mut h) = boot(settings);

    // Bare and prefixed DNS forms, and the DNS Client switch, are contained by
    // the alias; only the non-DNS port stays editable.
    assert!(scope_checked(&h, Key::TunLeakScopeAllExceptLanLabel));
    assert!(rendered(&h, t(Language::En, Key::TunLeakDnsIncludedNote)));
    assert_eq!(detail_rows(&h), 1);
    assert!(
        h.query_by_role_and_label(
            Role::CheckBox,
            t(Language::En, Key::TunLeakWindnsClientLabel)
        )
        .is_none()
    );
    assert_eq!(saved_leak(), details);

    // Custom shows every stored spelling again; nothing was deleted.
    select_scope(&mut h, Key::TunLeakScopeCustomLabel);
    assert_eq!(
        saved_leak(),
        vec![
            "53".to_string(),
            "1.1.1.0/24:tcp/53".to_string(),
            TUN_LEAK_WINDNS_CLIENT.to_string(),
            "tcp/443".to_string(),
        ]
    );
    assert_eq!(detail_rows(&h), 3);
    assert!(!rendered(&h, t(Language::En, Key::TunLeakDnsIncludedNote)));
}

#[test]
fn an_invalid_entry_stays_editable_under_every_scope() {
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak =
        vec![TUN_LEAK_ALL.to_string(), "bogus".into(), "udp/53".into()];
    let (_lock, _tmp, h) = boot(settings);

    // `all` contains the valid entries but not the broken one: the editor
    // renders that row for repair, while the contained entry is counted as
    // hidden and the add controls stay away (anything added would be hidden).
    assert!(scope_checked(&h, Key::TunLeakScopeAllLabel));
    assert_eq!(detail_rows(&h), 1);
    assert!(rendered(&h, &hidden_note(1)));
    assert!(saved_leak().contains(&"bogus".to_string()));
    assert!(
        h.query_by_role_and_label(Role::CheckBox, t(Language::En, Key::TunLeakIcmpLabel))
            .is_none(),
        "the named switches are contained by all"
    );
    assert!(
        h.query_by_role_and_label(Role::Button, t(Language::En, Key::TunLeakAddPort))
            .is_none(),
        "all offers no add control"
    );
}

#[test]
fn selecting_allexceptlan_keeps_the_detail_editable() {
    let details: Vec<String> = ["udp/53", "tcp/443"].map(String::from).to_vec();
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = details.clone();
    let (_lock, _tmp, mut h) = boot(settings);

    select_scope(&mut h, Key::TunLeakScopeAllExceptLanLabel);
    let mut stored = details.clone();
    stored.push(TUN_LEAK_ALL_EXCEPT_LAN.to_string());
    assert_eq!(saved_leak(), stored);
    assert!(scope_checked(&h, Key::TunLeakScopeAllExceptLanLabel));
    assert!(
        detail_visible(&h),
        "the alias leaves LAN blocking to the detail entries"
    );
    // The DNS port row is implied by the alias and omitted; the non-DNS port
    // row stays editable.
    assert_eq!(detail_rows(&h), 1);
    assert!(rendered(&h, t(Language::En, Key::TunLeakDnsIncludedNote)));
    assert!(
        h.query_by_role_and_label(
            Role::CheckBox,
            t(Language::En, Key::TunLeakWindnsClientLabel)
        )
        .is_none(),
        "the DNS Client control would read off while the alias blocks it"
    );
    assert!(
        !rendered(&h, &hidden_note(2)),
        "nothing is hidden under the alias"
    );

    // A detail entry still adds LAN-level blocking, so ICMP can join the alias.
    toggle_leak_switch(&mut h, Key::TunLeakIcmpLabel);
    let mut with_icmp = details.clone();
    with_icmp.push(TUN_LEAK_ALL_EXCEPT_LAN.to_string());
    with_icmp.push("icmp".to_string());
    assert_eq!(saved_leak(), with_icmp);
    assert_eq!(saved_wire_leak(), serde_json::json!(with_icmp));
    assert_eq!(detail_rows(&h), 1);

    // The custom scope drops only the alias; every detail stays.
    select_scope(&mut h, Key::TunLeakScopeCustomLabel);
    let mut custom = details;
    custom.push("icmp".to_string());
    assert_eq!(saved_leak(), custom);
    assert!(detail_visible(&h));
    assert_eq!(detail_rows(&h), 2);
    assert!(!rendered(&h, t(Language::En, Key::TunLeakDnsIncludedNote)));
}

#[test]
fn a_prefixed_scope_value_keeps_the_custom_scope() {
    let details: Vec<String> = ["1.1.1.0/24:all", "[::/0]:allexceptlan", "udp/53"]
        .map(String::from)
        .to_vec();
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = details.clone();
    let (_lock, _tmp, mut h) = boot(settings);

    // A prefixed form limits itself to its own addresses, so it is a detail
    // entry and the editor stays open.
    assert!(scope_checked(&h, Key::TunLeakScopeCustomLabel));
    assert!(detail_visible(&h));
    assert_eq!(detail_rows(&h), 3);

    // Selecting a scope leaves the prefixed values alone and adds the
    // unprefixed spelling; the note counts every detail entry, prefixed or
    // not.
    select_scope(&mut h, Key::TunLeakScopeAllLabel);
    let mut stored = details.clone();
    stored.push(TUN_LEAK_ALL.to_string());
    assert_eq!(saved_leak(), stored);
    assert!(rendered(&h, &hidden_note(3)));
    assert!(!detail_visible(&h));

    select_scope(&mut h, Key::TunLeakScopeCustomLabel);
    assert_eq!(saved_leak(), details);
    assert_eq!(detail_rows(&h), 3);
}

#[test]
fn the_scope_radio_reflects_the_stored_list() {
    for (leak, key) in [
        (vec![TUN_LEAK_ALL.to_string()], Key::TunLeakScopeAllLabel),
        (
            vec![TUN_LEAK_ALL_EXCEPT_LAN.to_string()],
            Key::TunLeakScopeAllExceptLanLabel,
        ),
        (Vec::new(), Key::TunLeakScopeCustomLabel),
        (
            vec![
                TUN_LEAK_ALL_EXCEPT_LAN.to_string(),
                TUN_LEAK_ALL.to_string(),
            ],
            Key::TunLeakScopeAllLabel,
        ),
    ] {
        let mut settings = tun_settings();
        settings.tun.auto_system_wfp_block_leak = leak.clone();
        let (_lock, _tmp, h) = boot(settings);
        assert!(scope_checked(&h, key), "{leak:?} must select {key:?}");
    }
}
