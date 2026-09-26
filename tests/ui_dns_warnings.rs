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
use broccoli::i18n::{Key, t, t_fmt};
use broccoli::model::safety::{HazardClass, SafetyCode, SafetyFinding};
use broccoli::model::settings::{Language, Mode};
use broccoli::model::{DnsCfg, DnsServer, FakeDnsCfg, ServersFile, Settings};
use broccoli::ui::Screen;
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::MutexGuard;

#[path = "common/nav.rs"]
mod nav;
#[path = "common/screen.rs"]
mod screen;

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
    let (_lock, _tmp, mut h) = boot(&settings, Screen::Dns);

    // Replace the first pool's CIDR with a non-CIDR value, exactly like the
    // shared smoke-test editing flow. Every pool's CIDR field spells the same
    // "IP pool" label, so the first pool's field is addressed by the name its
    // own group title composes with that label ("Pool 1 IP pool").
    let pool_field_name = format!(
        "{} {}",
        t_fmt(Language::En, Key::DnsPoolTitle, &[&1_u32]),
        t(Language::En, Key::DnsIpPool)
    );
    h.get_by_role_and_label(egui::accesskit::Role::TextInput, pool_field_name.as_str())
        .click();
    h.run();
    h.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::TextInput, pool_field_name.as_str())
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
    screen: Screen,
) -> (
    MutexGuard<'static, ()>,
    common::TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    nav::boot_screen(
        screen::BootState {
            settings: settings.clone(),
            servers: ServersFile::default(),
        },
        Some(screen),
        egui::Vec2::new(1100.0, 2800.0),
    )
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
    let (_lock, _tmp, h) = boot(&settings_with_mode(Mode::Tun, false), Screen::Tun);

    let warning = privacy_message(SafetyCode::TunDnsUnprotected);
    assert!(
        h.query_by_label(&warning).is_some(),
        "TUN mode without a DNS configuration must warn inline on the TUN screen: {warning}"
    );
}

#[test]
fn tun_with_dns_renders_no_tun_warning() {
    let (_lock, _tmp, h) = boot(&settings_with_mode(Mode::Tun, true), Screen::Tun);

    let warning = privacy_message(SafetyCode::TunDnsUnprotected);
    assert!(
        h.query_by_label(&warning).is_none(),
        "a configured DNS block must clear the TUN warning: {warning}"
    );
}

#[test]
fn mode_off_renders_no_tun_warning() {
    let (_lock, _tmp, h) = boot(&Settings::default(), Screen::Tun);
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
    let (_lock, _tmp, mut h) = boot(&settings_with_mode(Mode::Off, false), Screen::Tun);
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
