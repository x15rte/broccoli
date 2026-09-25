//! kittest coverage: the TUN editor renders the model-layer privacy warning
//! (`crate::model::safety::assess`) inline through the amber warning tier,
//! and clears it live as the user configures DNS; the DNS editor's
//! field-level inline errors are covered alongside.
//!
//! The harness boots the real `BroccoliApp` (the shared UI harness pattern:
//! temp APPDATA with a pre-seeded settings.json, first-run wizard dismissed)
//! and navigates to the DNS or TUN screen. Expected strings are derived by
//! calling the i18n renderer on model findings — never hardcoded copy.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! Tests are serialized because changing a process environment variable while
//! another harness reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::i18n::safety_finding_message;
use broccoli::i18n::{Key, t};
use broccoli::model::safety::{HazardClass, SafetyCode, SafetyFinding};
use broccoli::model::settings::{Language, Mode};
use broccoli::model::{DnsCfg, DnsServer, FakeDnsCfg, Settings};
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::MutexGuard;

mod common;

/// The expected inline message for one privacy finding, rendered through
/// the i18n renderer the UI itself consumes.
fn privacy_message(code: SafetyCode) -> String {
    let finding = SafetyFinding {
        path: String::new(),
        class: HazardClass::Privacy,
        code,
    };
    safety_finding_message(&finding, Language::En)
}

#[test]
fn invalid_pool_cidr_shows_inline_error() {
    // The pool editor must validate ip_pool as a real CIDR —
    // Xray's fakeip holder parses it with Go's net.ParseCIDR (a bare IP is
    // rejected), so the inline error must fire for non-CIDR input and the
    // model-level check must refuse generation (covered by
    // invalid_fakedns_pool_rejected_at_generation).
    let settings = Settings {
        dns: DnsCfg {
            fakedns: FakeDnsCfg {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let (_lock, _tmp, mut h) = boot(&settings, "DNS");

    // Replace the first pool's CIDR with a non-CIDR value, exactly like the
    // shared smoke-test editing flow.
    let field = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("198.18.0.0/15"))
        .expect("fakeDNS pool ip_pool input");
    field.click();
    h.run();
    h.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    h.run();
    h.get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("198.18.0.0/15"))
        .expect("pool input should keep the typed value")
        .type_text("300.1.1.1/8");
    h.run_steps(4);

    let expected = t(Language::En, Key::DnsPoolCidrInvalid);
    assert!(
        h.query_by_label(expected).is_some(),
        "an invalid pool CIDR must show the inline error: {expected}"
    );
}

/// Boot through the shared fixture against `settings` persisted into the temp
/// APPDATA, dismiss the first-run wizard, and navigate to the given screen
/// ("DNS" or "TUN"). The window is tall so every section renders into the
/// AccessKit tree without scrolling.
fn boot(
    settings: &Settings,
    screen: &str,
) -> (
    MutexGuard<'static, ()>,
    common::TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    let (lock, tmp, mut h) = common::boot(
        |root| {
            let state_dir = root.join("broccoli/state");
            std::fs::create_dir_all(&state_dir).unwrap();
            std::fs::write(
                state_dir.join("settings.json"),
                serde_json::to_vec_pretty(settings).unwrap(),
            )
            .unwrap();
        },
        None,
    );

    h.set_size(egui::Vec2::new(1100.0, 2800.0));
    h.run();
    common::dismiss_wizard(&mut h);
    // The dashboard's mode selector carries its own "TUN" selectable label
    // (same Button role in the AccessKit tree), so the sidebar item is
    // ambiguous while the dashboard is showing; stage through the DNS screen
    // (whose label is unique) so the final nav click has exactly one match.
    if screen != "DNS" {
        h.get_by_role_and_label(egui::accesskit::Role::Button, "DNS")
            .click();
        h.run();
    }
    h.get_by_role_and_label(egui::accesskit::Role::Button, screen)
        .click();
    h.run();
    (lock, tmp, h)
}

/// A `Settings` in the given mode, with a DNS server configured iff
/// `dns_configured`. The no-DNS branch must also clear
/// `enable_parallel_query`: the seeded default is `true`, and the parallel
/// flag alone serializes, keeping the config *effectively non-empty*
/// (`is_effectively_empty` follows `to_wire().is_none()`).
fn settings_with_mode(mode: Mode, dns_configured: bool) -> Settings {
    Settings {
        mode,
        dns: DnsCfg {
            servers: if dns_configured {
                vec![DnsServer {
                    address: "1.1.1.1".into(),
                    ..Default::default()
                }]
            } else {
                Vec::new()
            },
            enable_parallel_query: dns_configured,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn tun_without_dns_renders_tun_warning() {
    let (_lock, _tmp, h) = boot(&settings_with_mode(Mode::Tun, false), "TUN");

    let warning = privacy_message(SafetyCode::TunDnsUnprotected);
    assert!(
        h.query_by_label(&warning).is_some(),
        "TUN mode without a DNS configuration must warn inline on the TUN screen: {warning}"
    );
}

#[test]
fn tun_with_dns_renders_no_tun_warning() {
    let (_lock, _tmp, h) = boot(&settings_with_mode(Mode::Tun, true), "TUN");

    let warning = privacy_message(SafetyCode::TunDnsUnprotected);
    assert!(
        h.query_by_label(&warning).is_none(),
        "a configured DNS block must clear the TUN warning: {warning}"
    );
}

#[test]
fn mode_off_renders_no_tun_warning() {
    let (_lock, _tmp, h) = boot(&Settings::default(), "TUN");
    let tun_warning = privacy_message(SafetyCode::TunDnsUnprotected);
    assert!(
        h.query_by_label(&tun_warning).is_none(),
        "mode Off must not warn on the TUN screen: {tun_warning}"
    );
}

#[test]
fn enabling_tun_live_shows_warning_and_dns_config_clears_it() {
    // Default settings now carry the seeded DNS module, so the "no DNS"
    // state must be built explicitly (servers empty + parallel flag cleared).
    let (_lock, _tmp, mut h) = boot(&settings_with_mode(Mode::Off, false), "TUN");
    let warning = privacy_message(SafetyCode::TunDnsUnprotected);
    assert!(
        h.query_by_label(&warning).is_none(),
        "mode Off must not warn on the TUN screen before the toggle"
    );

    h.get_by_label("enable TUN inbound").click();
    h.run_steps(4);
    assert!(
        h.query_by_label(&warning).is_some(),
        "enabling TUN without a DNS configuration must warn live"
    );

    // Configure a DNS server on the DNS screen, then come back: the warning
    // must clear within the normal change flow, no restart.
    h.get_by_role_and_label(egui::accesskit::Role::Button, "DNS")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "+ Add DNS server")
        .click();
    h.run_steps(4);
    h.get_by_role_and_label(egui::accesskit::Role::Button, "TUN")
        .click();
    h.run_steps(4);

    assert!(
        h.query_by_label(&warning).is_none(),
        "configuring DNS must clear the TUN warning live"
    );
}
