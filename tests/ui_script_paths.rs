//! kittest coverage: both Lua script surfaces — the DNS screen and the routing
//! screen — are mounted, and editing through them writes the model. The
//! shared control's own switch/reveal/path-rule behaviour is pinned by its
//! unit test, and the gate conflicts by the validation pass, so this file
//! carries only the screen wiring.
//!
//! The harness boots the real `BroccoliApp` (the shared UI harness pattern:
//! temp APPDATA with the state written through the app's own writers, first-run
//! wizard dismissed) and navigates to the screen. Every expected string comes
//! from the i18n renderer the screen itself consumes — never hardcoded copy.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! Tests are serialized because changing a process environment variable while
//! another harness reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::settings::{Language, Settings};
use broccoli::model::{RoutingCfg, Rule, ServersFile};
use broccoli::ui::Screen;
use egui::Vec2;
use egui::accesskit::Role;
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::MutexGuard;

#[path = "common/nav.rs"]
mod nav;
#[path = "common/screen.rs"]
mod screen;

mod common;

/// Type `text` into the only text box labelled `label` and let the screen
/// settle: the field writes the model on every edit, and the persist pass
/// writes the state file on the next frames.
fn type_into(h: &mut Harness<'static, BroccoliApp>, label: &str, text: &str) {
    h.get_by_role_and_label(Role::TextInput, label).click();
    h.run();
    h.get_by_role_and_label(Role::TextInput, label)
        .type_text(text);
    h.run_steps(4);
}

/// The DNS screen mounts the shared script control and writes the path it
/// edits into the model.
#[test]
fn dns_script_row_mounts_and_writes_the_model() {
    let (_lock, _tmp, mut h): (
        MutexGuard<'static, ()>,
        common::TempEnvironment,
        Harness<'static, BroccoliApp>,
    ) = nav::boot_screen(
        screen::BootState::default(),
        Some(Screen::Dns),
        Vec2::new(1100.0, 2800.0),
    );

    let toggle = t(Language::En, Key::DnsScriptToggle);
    assert!(
        h.query_by_label(toggle).is_some(),
        "the DNS screen must mount the script control"
    );
    h.get_by_label(toggle).click();
    h.run();
    type_into(&mut h, t(Language::En, Key::DnsScriptPath), "dns.lua");
    assert_eq!(
        Settings::load()
            .expect("the persisted settings.json loads")
            .dns
            .script
            .as_deref(),
        Some("dns.lua"),
        "the DNS script row must write the model"
    );
}

/// The routing screen mounts the shared script control and writes the path it
/// edits into the model.
#[test]
fn routing_script_row_mounts_and_writes_the_model() {
    let settings = Settings {
        routing: RoutingCfg {
            rules: vec![Rule {
                rule_tag: "rule-one".into(),
                outbound_tag: "direct".into(),
                ..Rule::default()
            }],
            ..RoutingCfg::default()
        },
        ..Settings::default()
    };
    let (_lock, _tmp, mut h): (
        MutexGuard<'static, ()>,
        common::TempEnvironment,
        Harness<'static, BroccoliApp>,
    ) = nav::boot_screen(
        screen::BootState {
            settings,
            servers: ServersFile::default(),
        },
        Some(Screen::Routing),
        Vec2::new(1100.0, 2800.0),
    );

    let toggle = t(Language::En, Key::RoutingScriptToggle);
    assert!(
        h.query_by_label(toggle).is_some(),
        "the routing screen must mount the script control"
    );
    h.get_by_label(toggle).click();
    h.run();
    type_into(
        &mut h,
        t(Language::En, Key::RoutingScriptPath),
        "routing.lua",
    );
    assert_eq!(
        Settings::load()
            .expect("the persisted settings.json loads")
            .routing
            .script
            .as_deref(),
        Some("routing.lua"),
        "the routing script row must write the model"
    );
}
