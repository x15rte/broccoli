//! kittest coverage: the routing editor renders the
//! model-layer balancer breakage warnings (`crate::model::safety::assess`)
//! inline per balancer row through the amber tier and clears them live; the
//! rule `network` field is a `tcp`/`udp`/`tcp,udp` combo that never rewrites
//! an off-list stored value; and the PortList fields gate invalid edits with
//! an inline grammar error while valid lists commit to the model.
//!
//! The harness boots the real `BroccoliApp` (the shared UI harness pattern:
//! temp APPDATA with a pre-seeded settings.json, first-run wizard dismissed)
//! and navigates to the Routing screen. Expected strings are derived by
//! calling the i18n renderers the UI itself consumes — never hardcoded copy.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! Tests are serialized because changing a process environment variable while
//! another harness reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, safety_finding_message, t};
use broccoli::model::safety::{HazardClass, SafetyCode, SafetyFinding};
use broccoli::model::settings::{Language, Settings};
use broccoli::model::{Balancer, OutboundModel, RoutingCfg, Rule, ServerProfile, ServersFile};
use broccoli::ui::Screen;
use egui::accesskit::Role;
use egui::{Key as EguiKey, Modifiers, Vec2};
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::MutexGuard;

#[path = "common/nav.rs"]
mod nav;
#[path = "common/screen.rs"]
mod screen;

mod common;

/// The expected inline message for one balancer breakage finding, rendered
/// through the i18n renderer the UI itself consumes.
fn breakage_message(tag: &str) -> String {
    let finding = SafetyFinding {
        path: String::new(),
        class: HazardClass::Breakage,
        code: SafetyCode::BalancerSelectorNoMatch(tag.into()),
    };
    safety_finding_message(&finding, Language::En)
}

/// The inline PortList grammar error text, as the field itself renders it.
fn port_list_error() -> String {
    t(Language::En, Key::RoutingPortListInvalid).to_string()
}

/// Boot through the shared fixture against `settings` (and optionally
/// `servers`) persisted into the temp APPDATA, dismiss the first-run wizard,
/// and navigate to the Routing screen. The window is tall so every section
/// renders into the AccessKit tree without scrolling.
fn boot_routing(
    settings: &Settings,
    servers: Option<&ServersFile>,
) -> (
    MutexGuard<'static, ()>,
    common::TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    let state = screen::BootState {
        settings: settings.clone(),
        servers: servers.cloned().unwrap_or_default(),
    };
    nav::boot_screen(state, Some(Screen::Routing), Vec2::new(1100.0, 2800.0))
}

/// A rule with a valid built-in target and a fixed tag.
fn rule_with(rule_tag: &str) -> Rule {
    Rule {
        rule_tag: rule_tag.into(),
        outbound_tag: "direct".into(),
        ..Rule::default()
    }
}

fn settings_with_rules(rules: Vec<Rule>) -> Settings {
    Settings {
        routing: RoutingCfg {
            rules,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn settings_with_balancer(tag: &str, selector: &str) -> Settings {
    Settings {
        routing: RoutingCfg {
            balancers: vec![Balancer::new(tag.into(), selector.into())],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Replace the text of the only TextInput currently holding `from` with `to`
/// (click, select all, type) — the shared smoke-test editing flow.
fn replace_text(h: &mut Harness<'static, BroccoliApp>, from: &str, to: &str) {
    let field = h
        .get_all_by_role(Role::TextInput)
        .find(|node| node.value().as_deref() == Some(from))
        .expect("field holding the current value");
    field.click();
    h.run();
    h.key_combination_modifiers(Modifiers::COMMAND, &[EguiKey::A]);
    h.run();
    h.get_all_by_role(Role::TextInput)
        .find(|node| node.value().as_deref() == Some(from))
        .expect("field should keep the typed value")
        .type_text(to);
    h.run_steps(4);
}

/// Open the inline editor of the first rule row.
fn open_rule_editor(h: &mut Harness<'static, BroccoliApp>) {
    h.get_by_role_and_label(Role::Button, "▸").click();
    h.run();
}

/// The value shown by the rule editor's network combo (the only combo that
/// can hold `value` in the seeded screens).
fn combo_value(h: &Harness<'static, BroccoliApp>, value: &str) -> bool {
    h.get_all_by_role(Role::ComboBox)
        .any(|node| node.value().as_deref() == Some(value))
}

#[test]
fn balancer_no_match_renders_inline_warning() {
    let (_lock, _tmp, h) = boot_routing(&settings_with_balancer("bal-a", "srv-"), None);

    let message = breakage_message("bal-a");
    assert!(
        h.query_by_label(&message).is_some(),
        "a balancer whose selector matches no outbound tag must warn inline: {message}"
    );
}

#[test]
fn balancer_matching_profile_renders_no_warning() {
    let mut servers = ServersFile::default();
    servers
        .profiles
        .push(ServerProfile::new("alpha", OutboundModel::default()));
    let selector = servers.profiles[0].tag();
    let (_lock, _tmp, h) =
        boot_routing(&settings_with_balancer("bal-a", &selector), Some(&servers));

    let message = breakage_message("bal-a");
    assert!(
        h.query_by_label(&message).is_none(),
        "a selector matching a seeded profile tag must not warn: {message}"
    );
}

#[test]
fn editing_selector_to_matching_tag_live_clears_warning() {
    let (_lock, _tmp, mut h) = boot_routing(&settings_with_balancer("bal-a", "srv-"), None);
    let message = breakage_message("bal-a");
    assert!(
        h.query_by_label(&message).is_some(),
        "the warning must render before the edit"
    );

    // Open the balancer editor and point the selector at the built-in
    // "direct" outbound; the warning must clear without a restart.
    h.get_by_role_and_label(Role::Button, "▸").click();
    h.run();
    replace_text(&mut h, "srv-", "direct");

    assert!(
        h.query_by_label(&message).is_none(),
        "a selector matching an outbound tag must clear the warning live"
    );
}

#[test]
fn network_combo_roundtrips_wire_values() {
    let mut rule = rule_with("r-1");
    rule.network = "tcp".into();
    let (_lock, _tmp, mut h) = boot_routing(&settings_with_rules(vec![rule]), None);
    open_rule_editor(&mut h);

    assert!(
        combo_value(&h, "tcp"),
        "the network combo must show the stored value"
    );
    let mut current = "tcp";
    for option in ["udp", "tcp,udp", "tcp"] {
        h.get_all_by_role(Role::ComboBox)
            .find(|node| node.value().as_deref() == Some(current))
            .expect("network combo")
            .click();
        h.run();
        h.get_by_role_and_label(Role::Button, option).click();
        h.run_steps(4);
        current = option;
        assert!(
            combo_value(&h, option),
            "picking {option} must commit it to the model"
        );
    }
}

#[test]
fn network_off_list_stored_value_displays_without_mutation() {
    // "unix" is not in the wire grammar combo, but a stored value must keep
    // displaying (graceful migration) and never be silently rewritten.
    let mut rule = rule_with("r-1");
    rule.network = "unix".into();
    let (_lock, _tmp, mut h) = boot_routing(&settings_with_rules(vec![rule]), None);
    open_rule_editor(&mut h);

    assert!(
        combo_value(&h, "unix"),
        "an off-list stored network must still display in the combo"
    );
    h.run_steps(8);
    assert!(
        combo_value(&h, "unix"),
        "idle frames must not rewrite the off-list stored value"
    );
}

#[test]
fn port_field_grammar_errors_block_commit_and_valid_list_passes() {
    let mut rule = rule_with("r-1");
    rule.port = "80".into();
    let (_lock, _tmp, mut h) = boot_routing(&settings_with_rules(vec![rule]), None);
    open_rule_editor(&mut h);

    let error = port_list_error();
    assert!(
        h.query_by_label(&error).is_none(),
        "the seeded valid port must not show an error"
    );

    let mut current = "80";
    for malformed in ["abc", "70,abc", "99999", "1-"] {
        replace_text(&mut h, current, malformed);
        current = malformed;
        assert!(
            h.query_by_label(&error).is_some(),
            "{malformed:?} must show the inline grammar error"
        );
        assert!(
            h.query_by_label("port: 80").is_some(),
            "the invalid list must not commit: the summary still shows the old port"
        );
    }

    replace_text(&mut h, current, "80,443,1000-2000");
    assert!(
        h.query_by_label(&error).is_none(),
        "a valid port list must clear the inline error"
    );
    assert!(
        h.query_by_label("port: 80,443,1000-2000").is_some(),
        "the valid list must commit to the model"
    );
}

/// The routing rule editor hides the inbound-user email list — the
/// GUI can set no inbound emails for it to match. The i18n keys were removed
/// with the widget, so the expected label is a literal.
#[test]
fn rule_editor_hides_users_email_list() {
    let (_lock, _tmp, mut h) = boot_routing(&settings_with_rules(vec![rule_with("r-1")]), None);
    open_rule_editor(&mut h);

    assert!(
        h.query_by_label("Users").is_none(),
        "the rule editor must not offer the inbound-user email list"
    );
}

/// The TestRoute dialog hides the inbound-user email field and
/// drops "unix" from its network combo. The dialog opens through the
/// TestRoute button; a combo's options render only while its popup is open.
#[test]
fn route_test_dialog_hides_user_field_and_unix_network() {
    let (_lock, _tmp, mut h) = boot_routing(&settings_with_rules(vec![rule_with("r-1")]), None);
    h.get_by_role_and_label(Role::Button, t(Language::En, Key::TestRoute))
        .click();
    h.run();

    assert!(
        h.query_by_label(t(Language::En, Key::TestRouteWindow))
            .is_some(),
        "the TestRoute dialog must be open"
    );
    assert!(
        h.query_by_label("User").is_none(),
        "the route-test dialog must not offer the inbound-user email field"
    );

    // Scan every combo of the open dialog (inbound tag, then network):
    // opening each popup in turn renders its options, and opening the next
    // combo closes the previous popup.
    let combo_count = h.get_all_by_role(Role::ComboBox).count();
    for index in 0..combo_count {
        h.get_all_by_role(Role::ComboBox)
            .nth(index)
            .expect("dialog combo")
            .click();
        h.run();
        assert!(
            h.query_by_label("unix").is_none(),
            "no route-test combo may offer the unix network"
        );
    }
}

/// Two balancers, both with a selector matching the built-in `direct` tag so
/// only the tag field's verdict can render.
fn settings_with_two_balancers(first: &str, second: &str) -> Settings {
    Settings {
        routing: RoutingCfg {
            balancers: vec![
                Balancer::new(first.into(), "direct".into()),
                Balancer::new(second.into(), "direct".into()),
            ],
            ..Default::default()
        },
        ..Default::default()
    }
}

/// The balancer tag verdict reads every other row's committed tag, so it must
/// follow the list: renaming the buffer to a sibling's tag reports the
/// duplicate, and removing that sibling clears the verdict — although the
/// buffer's text never changed after the rename.
#[test]
fn balancer_tag_duplicate_verdict_follows_the_other_rows() {
    let duplicate = t(Language::En, Key::TagDuplicate);
    let (_lock, _tmp, mut h) = boot_routing(&settings_with_two_balancers("bal-a", "bal-x"), None);

    // Open the first balancer's editor: its buffer holds its own tag, so no
    // duplicate verdict shows.
    h.get_all_by_role_and_label(Role::Button, "▸")
        .next()
        .expect("the first balancer row's editor button")
        .click();
    h.run();
    assert!(
        h.query_by_label(duplicate).is_none(),
        "a balancer's own tag must not report as a duplicate"
    );

    // Typing a sibling's tag reports the duplicate.
    replace_text(&mut h, "bal-a", "bal-x");
    assert!(
        h.query_by_label(duplicate).is_some(),
        "a tag another balancer already carries must report"
    );

    // Delete the sibling: the open editor's buffer still holds "bal-x", but
    // no other balancer carries it any more, so the verdict must clear. The
    // sibling's header tag locates its row; its delete button shares that
    // line (the open editor also renders its selector list's row button).
    let sibling_y = h
        .query_by_label("bal-x")
        .expect("the sibling balancer's row header")
        .rect()
        .center()
        .y;
    h.get_all_by_label("🗑")
        .find(|node| (node.rect().center().y - sibling_y).abs() < 12.0)
        .expect("the sibling row's delete button")
        .click();
    h.run_steps(2);
    assert!(
        h.get_all_by_role(Role::TextInput)
            .any(|node| node.value().as_deref() == Some("bal-x")),
        "the open editor's buffer must survive the sibling's removal"
    );
    assert!(
        h.query_by_label("bal-x").is_none(),
        "the sibling balancer row must be gone from the list"
    );
    assert!(
        h.query_by_label(duplicate).is_none(),
        "the duplicate verdict must clear with the row that carried the tag"
    );
}
