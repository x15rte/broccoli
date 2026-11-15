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
use broccoli::i18n::{Key, safety_message, t, validation_message};
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

/// Type `text` into the leak block's raw entry row.
fn type_raw_leak(h: &mut Harness<'static, BroccoliApp>, text: &str) {
    let label = t(Language::En, Key::TunLeakRawLabel);
    h.get_by_role_and_label(Role::TextInput, label).click();
    h.run();
    h.get_by_role_and_label(Role::TextInput, label)
        .type_text(text);
    h.run_steps(4);
}

/// Type `text` into the leak block's raw entry row and press its add button.
fn add_raw_leak(h: &mut Harness<'static, BroccoliApp>, text: &str) {
    type_raw_leak(h, text);
    press_leak_button(h, Key::TunLeakAddEntry);
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
        serde_json::json!([
            TUN_LEAK_ALL_EXCEPT_LAN,
            "53",
            "853",
            TUN_LEAK_WINDNS_CLIENT,
            TUN_LEAK_MISCONFIG_TUN
        ]),
        "the wire follows the alias with the DNS entries the core adds"
    );

    // The screen's rendered controls are the screen tests' meaning; a boot
    // proves the bytes only it can: the stored list and the emitted document.
    // The custom scope removes only the scope value: the family guard stays.
    select_scope(&mut h, Key::TunLeakScopeCustomLabel);
    assert_eq!(saved_leak(), vec![TUN_LEAK_MISCONFIG_TUN.to_string()]);

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

    // Selecting a policy scope appends its spelling while the state and the
    // emitted document keep every detail.
    select_scope(&mut h, Key::TunLeakScopeAllLabel);
    let mut hidden = details.clone();
    hidden.push(TUN_LEAK_ALL.to_string());
    assert_eq!(saved_leak(), hidden);
    assert_eq!(saved_wire_leak(), serde_json::json!(hidden));

    // Back to Custom: the scope value goes and every detail entry stays.
    select_scope(&mut h, Key::TunLeakScopeCustomLabel);
    assert_eq!(saved_leak(), details);
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

    // The row's own range control turns that port into a range: the core has
    // one port-or-range grammar, so the editor needs no separate button.
    press_leak_button(&mut h, Key::TunLeakAddPort);
    assert_eq!(saved_leak(), vec!["tcp/1".to_string()]);
    h.get_by_role_and_label(Role::CheckBox, t(Language::En, Key::TunLeakRangeLabel))
        .click();
    h.run_steps(4);
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
fn the_raw_add_control_appears_only_for_an_addable_entry() {
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = Vec::new();
    let (_lock, _tmp, mut h) = boot(settings);
    select_scope(&mut h, Key::TunLeakScopeCustomLabel);

    // An empty draft and a spelling the core refuses have nothing to add.
    let add = t(Language::En, Key::TunLeakAddEntry);
    assert!(h.query_by_role_and_label(Role::Button, add).is_none());
    type_raw_leak(&mut h, "bogus");
    assert!(h.query_by_role_and_label(Role::Button, add).is_none());
}

#[test]
fn a_raw_entry_the_alias_already_blocks_offers_no_control() {
    // The seeded alias already blocks port 53, so a CIDR-limited port-53
    // value adds nothing and gets no control.
    let (_lock, _tmp, mut h) = boot(tun_settings());
    type_raw_leak(&mut h, "1.1.1.0/24:53");
    assert!(
        h.query_by_role_and_label(Role::Button, t(Language::En, Key::TunLeakAddEntry))
            .is_none(),
        "the scope already produces the entry"
    );
}

#[test]
fn a_raw_entry_the_scope_leaves_open_is_added() {
    // The alias leaves the local network open, so a CIDR-limited port the
    // alias does not block still gets a control and is stored.
    let (_lock, _tmp, mut h) = boot(tun_settings());
    type_raw_leak(&mut h, "1.1.1.0/24:443");
    h.get_by_role_and_label(Role::Button, t(Language::En, Key::TunLeakAddEntry))
        .click();
    h.run_steps(4);
    assert!(saved_leak().contains(&"1.1.1.0/24:443".to_string()));
}

#[test]
fn selecting_all_keeps_the_stored_entries() {
    let details: Vec<String> = ["udp/53", "icmp", "misconfigtun"]
        .map(String::from)
        .to_vec();
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = details.clone();
    let (_lock, _tmp, mut h) = boot(settings);

    // Selecting `all` appends its spelling; the emitted document keeps every
    // detail the screen no longer offers. The screen tests own the hidden
    // rows and their note.
    select_scope(&mut h, Key::TunLeakScopeAllLabel);
    let mut stored = details.clone();
    stored.push(TUN_LEAK_ALL.to_string());
    assert_eq!(saved_leak(), stored);
    assert_eq!(
        saved_wire_leak(),
        serde_json::json!(stored),
        "the emitted list must still carry every hidden entry"
    );

    // Removing the scope keeps the stored entries intact.
    select_scope(&mut h, Key::TunLeakScopeCustomLabel);
    assert_eq!(saved_leak(), details);
}

#[test]
fn the_alias_scope_removal_keeps_every_stored_detail() {
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

    // The alias is stored beside the details; none of them is deleted while
    // it is selected. How each one renders is the screen tests' meaning.
    assert_eq!(saved_leak(), details);

    // Custom drops only the alias and keeps every stored spelling.
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
}

#[test]
fn an_invalid_entry_stays_stored_under_a_policy_scope() {
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak =
        vec![TUN_LEAK_ALL.to_string(), "bogus".into(), "udp/53".into()];
    let (_lock, _tmp, _h) = boot(settings);

    // The load keeps the value the core refuses so the user can repair it; a
    // save writes it back unchanged. The screen test owns the repair row, and
    // the settings pass's gate refuses to emit the list.
    let stored = vec![
        TUN_LEAK_ALL.to_string(),
        "bogus".to_string(),
        "udp/53".to_string(),
    ];
    assert_eq!(saved_leak(), stored);
}

#[test]
fn selecting_allexceptlan_keeps_the_stored_details() {
    let details: Vec<String> = ["udp/53", "tcp/443"].map(String::from).to_vec();
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = details.clone();
    let (_lock, _tmp, mut h) = boot(settings);

    select_scope(&mut h, Key::TunLeakScopeAllExceptLanLabel);
    let mut stored = details.clone();
    stored.push(TUN_LEAK_ALL_EXCEPT_LAN.to_string());
    assert_eq!(saved_leak(), stored);

    // A detail entry still adds LAN-level blocking, so ICMP can join the alias
    // and the emitted document keeps both. Which rows the editor hides is the
    // screen tests' meaning.
    toggle_leak_switch(&mut h, Key::TunLeakIcmpLabel);
    let mut with_icmp = details.clone();
    with_icmp.push(TUN_LEAK_ALL_EXCEPT_LAN.to_string());
    with_icmp.push("icmp".to_string());
    assert_eq!(saved_leak(), with_icmp);
    assert_eq!(
        saved_wire_leak(),
        serde_json::json!([
            "udp/53",
            "tcp/443",
            TUN_LEAK_ALL_EXCEPT_LAN,
            "53",
            "853",
            TUN_LEAK_WINDNS_CLIENT,
            "icmp"
        ]),
        "the wire follows the alias with the DNS entries the core adds"
    );

    // The custom scope drops only the alias; every detail stays.
    select_scope(&mut h, Key::TunLeakScopeCustomLabel);
    let mut custom = details;
    custom.push("icmp".to_string());
    assert_eq!(saved_leak(), custom);
}

#[test]
fn a_prefixed_scope_value_survives_a_scope_switch() {
    let details: Vec<String> = ["1.1.1.0/24:all", "[::/0]:allexceptlan", "udp/53"]
        .map(String::from)
        .to_vec();
    let mut settings = tun_settings();
    settings.tun.auto_system_wfp_block_leak = details.clone();
    let (_lock, _tmp, mut h) = boot(settings);

    // A prefixed form is a detail entry: selecting a scope leaves it alone
    // and adds the unprefixed spelling, and removing the scope restores the
    // stored list byte for byte.
    select_scope(&mut h, Key::TunLeakScopeAllLabel);
    let mut stored = details.clone();
    stored.push(TUN_LEAK_ALL.to_string());
    assert_eq!(saved_leak(), stored);

    select_scope(&mut h, Key::TunLeakScopeCustomLabel);
    assert_eq!(saved_leak(), details);
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
