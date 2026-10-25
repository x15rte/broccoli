//! kittest coverage: the inbounds editor renders the
//! model-layer exposure warnings (`crate::model::safety::assess`) inline
//! under the offending listen field, through the amber warning tier of the
//! shared validated-field widget, and clears them live as the user fixes the
//! field.
//!
//! The harness boots the real `BroccoliApp` (the shared UI harness pattern:
//! temp APPDATA with a pre-seeded settings.json, first-run wizard dismissed)
//! and navigates to the Inbounds screen. Expected strings are derived by
//! calling the i18n renderer on model findings — never hardcoded copy.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! Tests are serialized because changing a process environment variable while
//! another harness reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, safety_message, t, validation_issue_message};
use broccoli::model::safety::SafetyCode;
use broccoli::model::settings::{Language, Settings};
use broccoli::model::validation::{ValidationCode, validate_finalmask};
use broccoli::model::{
    DokodemoCfg, FinalmaskFilter, FinalmaskModel, FinalmaskTcpMask, LocalInboundCfg,
    LocalInboundProtocol, ServersFile,
};
use broccoli::ui::Screen;
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::MutexGuard;

#[path = "common/nav.rs"]
mod nav;
#[path = "common/screen.rs"]
mod screen;

mod common;

/// The expected inline message for one exposure finding, rendered through
/// the i18n renderer the UI itself consumes.
fn exposure_message(code: SafetyCode) -> String {
    safety_message(&code, Language::En)
}

/// Boot through the shared fixture against `settings` persisted into the temp
/// APPDATA, dismiss the first-run wizard, and navigate to the Inbounds screen.
/// The window is tall so every section (including dokodemo-door, which sits
/// below SOCKS/HTTP) renders into the AccessKit tree without scrolling.
fn boot_inbounds(
    settings: &Settings,
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
        Some(Screen::Inbounds),
        egui::Vec2::new(1100.0, 2800.0),
    )
}

fn settings_with_socks_listen(listen: &str) -> Settings {
    Settings {
        local_inbounds: vec![LocalInboundCfg {
            listen: listen.into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// One listener carrying a `filter` mask with a malformed rule: the core
/// refuses the whole configuration when the mask is built, and the settings
/// walk only builds the mask of an emitted listener.
fn settings_with_bad_filter(enabled: bool) -> Settings {
    Settings {
        local_inbounds: vec![LocalInboundCfg {
            enabled,
            finalmask: Some(FinalmaskModel {
                tcp: vec![FinalmaskTcpMask::Filter {
                    settings: FinalmaskFilter {
                        blocked_source_ips: vec!["nope".into()],
                        ..Default::default()
                    },
                    extra: Default::default(),
                }],
                ..Default::default()
            }),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// The row renders the same finding the mask pass produces, under the same
/// path: the filter editor feeds the verdict straight through.
fn bad_filter_message() -> String {
    let settings = settings_with_bad_filter(true);
    let finalmask = settings.local_inbounds[0]
        .finalmask
        .as_ref()
        .expect("the fixture carries a mask");
    let issue = validate_finalmask(finalmask)
        .into_iter()
        .find(|issue| matches!(issue.code, ValidationCode::FinalmaskFilterIpRuleInvalid(_)))
        .expect("the malformed rule must produce a finding");
    validation_issue_message(&issue, Language::En)
}

fn settings_with_dokodemo(enabled: bool) -> Settings {
    Settings {
        dokodemo: vec![DokodemoCfg {
            tag: "in-doko-a".into(),
            enabled,
            listen_port: 10810,
            listen: "0.0.0.0".into(),
            network: "tcp,udp".into(),
            address: "1.2.3.4".into(),
            port: 80,
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[test]
fn socks_exposed_listen_renders_inline_warning() {
    let (_lock, _tmp, h) = boot_inbounds(&settings_with_socks_listen("0.0.0.0"));

    let exposed = exposure_message(SafetyCode::SocksListenerExposed("0.0.0.0".into()));
    assert!(
        h.query_by_label(&exposed).is_some(),
        "the SOCKS exposure warning must render inline under the listen field: {exposed}"
    );
    let http_exposed = exposure_message(SafetyCode::HttpListenerExposed("0.0.0.0".into()));
    assert!(
        h.query_by_label(&http_exposed).is_none(),
        "only the offending field's finding may render; the HTTP listener still binds loopback"
    );
}

#[test]
fn loopback_listen_renders_no_warning() {
    let (_lock, _tmp, h) = boot_inbounds(&Settings::default());

    for code in [
        SafetyCode::SocksListenerExposed("0.0.0.0".into()),
        SafetyCode::SocksListenerExposed("127.0.0.1".into()),
    ] {
        let message = exposure_message(code);
        assert!(
            h.query_by_label(&message).is_none(),
            "a loopback SOCKS listen must not render an exposure warning: {message}"
        );
    }
}

#[test]
fn password_auth_exposed_listen_renders_no_warning() {
    let settings = Settings {
        local_inbounds: vec![LocalInboundCfg {
            listen: "0.0.0.0".into(),
            auth: "password".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let (_lock, _tmp, h) = boot_inbounds(&settings);

    let exposed = exposure_message(SafetyCode::SocksListenerExposed("0.0.0.0".into()));
    assert!(
        h.query_by_label(&exposed).is_none(),
        "requiring password auth closes the exposure; {exposed} must not render"
    );
}

#[test]
fn editing_listen_to_loopback_live_clears_warning() {
    let (_lock, _tmp, mut h) = boot_inbounds(&settings_with_socks_listen("0.0.0.0"));
    let exposed = exposure_message(SafetyCode::SocksListenerExposed("0.0.0.0".into()));
    assert!(
        h.query_by_label(&exposed).is_some(),
        "the warning must render before the edit"
    );

    // Replace the SOCKS listen address (the field named by its own "listen
    // address" label) with a loopback address, exactly like the shared
    // smoke-test editing flow.
    let listen_label = t(Language::En, Key::InboundsListenAddress);
    h.get_by_role_and_label(egui::accesskit::Role::TextInput, listen_label)
        .click();
    h.run();
    h.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::TextInput, listen_label)
        .type_text("127.0.0.1");
    h.run_steps(4);

    assert!(
        h.query_by_label(&exposed).is_none(),
        "fixing the listen field must clear the warning without a restart"
    );
}

#[test]
fn enabling_password_auth_live_clears_warning() {
    let (_lock, _tmp, mut h) = boot_inbounds(&settings_with_socks_listen("0.0.0.0"));
    let exposed = exposure_message(SafetyCode::SocksListenerExposed("0.0.0.0".into()));
    assert!(
        h.query_by_label(&exposed).is_some(),
        "the warning must render before the toggle"
    );

    // Rows render in list order, and the seed list holds SOCKS first, so
    // the first "require authentication" checkbox belongs to the SOCKS row.
    h.query_all_by_label("require authentication")
        .next()
        .expect("SOCKS require-authentication checkbox")
        .click();
    h.run_steps(4);

    assert!(
        h.query_by_label(&exposed).is_none(),
        "requiring password auth must clear the warning live"
    );
}

#[test]
fn dokodemo_enabled_exposed_listen_renders_warning() {
    let (_lock, _tmp, h) = boot_inbounds(&settings_with_dokodemo(true));

    let exposed = exposure_message(SafetyCode::DokodemoListenerExposed("0.0.0.0".into()));
    assert!(
        h.query_by_label(&exposed).is_some(),
        "an enabled dokodemo entry on a non-loopback listen must warn inline: {exposed}"
    );
}

#[test]
fn dokodemo_disabled_listen_renders_no_warning() {
    let (_lock, _tmp, h) = boot_inbounds(&settings_with_dokodemo(false));

    let exposed = exposure_message(SafetyCode::DokodemoListenerExposed("0.0.0.0".into()));
    assert!(
        h.query_by_label(&exposed).is_none(),
        "assess ignores disabled inbounds; no warning may render: {exposed}"
    );
}

/// Non-applicable options never render in the structured inbounds
/// editor — dokodemo UNIX mode, `followRedirect` (Linux iptables-only), and
/// the HTTP `allowTransparent` knob (Linux transparent-proxy-only). The i18n
/// keys were removed with the widgets, so the expected labels are literals.
#[test]
fn non_applicable_options_never_render() {
    let settings = Settings {
        local_inbounds: vec![LocalInboundCfg {
            protocol: LocalInboundProtocol::Http,
            ..Default::default()
        }],
        dokodemo: vec![DokodemoCfg {
            tag: "in-doko-a".into(),
            enabled: true,
            listen_port: 10810,
            listen: "127.0.0.1".into(),
            network: "tcp,udp".into(),
            address: "1.2.3.4".into(),
            port: 80,
            ..Default::default()
        }],
        ..Default::default()
    };
    let (_lock, _tmp, h) = boot_inbounds(&settings);

    assert!(
        h.query_by_label("UNIX socket").is_none(),
        "dokodemo network mode must not offer the UNIX socket option"
    );
    assert!(
        h.query_by_label_contains("follow redirect").is_none(),
        "dokodemo followRedirect must not render"
    );
    assert!(
        h.query_by_label("allow transparent proxy requests")
            .is_none(),
        "the HTTP allowTransparent knob must not render"
    );
}

/// A listener the emitter drops never reaches the settings walk, so its
/// mask's findings stay off the row — the same predicate the neighbouring
/// sniffing row uses. Enabling the listener brings the finding back.
#[test]
fn disabled_listener_filter_row_matches_the_gate() {
    let message = bad_filter_message();
    {
        let (_lock, _tmp, h) = boot_inbounds(&settings_with_bad_filter(false));
        assert!(
            h.query_by_label(&message).is_none(),
            "a disabled listener's filter finding must not render: {message}"
        );
    }
    {
        let (_lock, _tmp, h) = boot_inbounds(&settings_with_bad_filter(true));
        assert!(
            h.query_by_label(&message).is_some(),
            "an emitted listener's filter finding must render: {message}"
        );
    }
}
