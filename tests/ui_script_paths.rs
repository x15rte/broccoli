//! kittest coverage: both Lua script surfaces — the DNS screen and the routing
//! screen — render the shared path control (a switch, a validated path field,
//! and a Browse button that only offers `.lua` files), and an enabled script
//! reports the same blocking conflict the apply gate refuses.
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
use broccoli::i18n::{Key, t, validation_message};
use broccoli::model::settings::{Language, Settings};
use broccoli::model::validation::ValidationCode;
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

/// The browse button's text: the shared control's picker.
fn browse_label() -> String {
    t(Language::En, Key::SrvBrowse).to_string()
}

/// Type `text` into the only text box labelled `label` and let the screen
/// settle: the field writes the model on every edit, and the surface's
/// conflict verdict follows on the next frame.
fn type_into(h: &mut Harness<'static, BroccoliApp>, label: &str, text: &str) {
    h.get_by_role_and_label(Role::TextInput, label).click();
    h.run();
    h.get_by_role_and_label(Role::TextInput, label)
        .type_text(text);
    h.run_steps(3);
}

/// The DNS screen: the script row appears with its switch, seeds an empty path
/// (the shared structural error), and a well-formed path beside a server that
/// carries domains shows the apply gate's conflict.
#[test]
fn dns_script_row_renders_and_reports_the_gate_conflict() {
    let mut settings = Settings::default();
    settings.dns.servers[0].domains = vec!["geosite:cn".into()];
    let (_lock, _tmp, mut h): (
        MutexGuard<'static, ()>,
        common::TempEnvironment,
        Harness<'static, BroccoliApp>,
    ) = nav::boot_screen(
        screen::BootState {
            settings,
            servers: ServersFile::default(),
        },
        Some(Screen::Dns),
        Vec2::new(1100.0, 2800.0),
    );

    let toggle = t(Language::En, Key::DnsScriptToggle);
    let path_label = t(Language::En, Key::DnsScriptPath);
    let required = validation_message(&ValidationCode::LuaScriptPathRequired, Language::En);
    let conflict = validation_message(
        &ValidationCode::DnsScriptServerConflict(1, "domains".into()),
        Language::En,
    );

    assert!(
        h.query_by_label(&browse_label()).is_none(),
        "no script row before the switch is on"
    );

    h.get_by_label(toggle).click();
    h.run();
    assert!(
        h.query_by_label(path_label).is_some(),
        "the switch reveals the path field"
    );
    assert!(
        h.query_by_label(&browse_label()).is_some(),
        "the path field carries the file picker"
    );
    assert!(
        h.query_by_label(&required).is_some(),
        "an enabled script with no path shows the structural error"
    );

    type_into(&mut h, path_label, "dns.lua");
    assert!(
        h.query_by_label(&required).is_none(),
        "the structural error clears once the path names a .lua file"
    );
    assert!(
        h.query_by_label(&conflict).is_some(),
        "the row must show the same conflict the apply gate refuses"
    );
}

/// The routing screen: the switch reveals the path field, and the script
/// beside a rule shows the rules conflict while the rule itself stays in the
/// editor — the app never drops it to make the script fit.
#[test]
fn routing_script_row_reports_the_rules_conflict_without_dropping_rules() {
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
    let path_label = t(Language::En, Key::RoutingScriptPath);
    let required = validation_message(&ValidationCode::LuaScriptPathRequired, Language::En);
    let conflict = validation_message(&ValidationCode::RoutingScriptRulesConflict, Language::En);

    assert!(
        h.query_by_label(&browse_label()).is_none(),
        "no script row before the switch is on"
    );

    h.get_by_label(toggle).click();
    h.run();
    assert!(
        h.query_by_label(path_label).is_some(),
        "the switch reveals the path field"
    );
    assert!(
        h.query_by_label(&browse_label()).is_some(),
        "the path field carries the file picker"
    );
    assert!(
        h.query_by_label(&required).is_some(),
        "an enabled script with no path shows the structural error"
    );

    type_into(&mut h, path_label, "routing.lua");
    assert!(
        h.query_by_label(&conflict).is_some(),
        "the row must show the conflict the apply gate refuses"
    );
    assert!(
        h.query_by_label("rule-one").is_some(),
        "the user's rule must stay in the editor"
    );
}
