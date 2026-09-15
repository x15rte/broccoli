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
use broccoli::i18n::safety_finding_message;
use broccoli::model::safety::{HazardClass, SafetyCode, SafetyFinding};
use broccoli::model::settings::{Language, Settings};
use broccoli::model::{DokodemoCfg, LocalInboundCfg, LocalInboundProtocol};
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::{Mutex, MutexGuard};

static APPDATA_LOCK: Mutex<()> = Mutex::new(());

/// The expected inline message for one exposure finding, rendered through
/// the i18n renderer the UI itself consumes.
fn exposure_message(code: SafetyCode) -> String {
    let finding = SafetyFinding {
        path: String::new(),
        class: HazardClass::Exposure,
        code,
    };
    safety_finding_message(&finding, Language::En)
}

/// Boot the real app against `settings` persisted into a temp APPDATA,
/// dismiss the first-run wizard, and navigate to the Inbounds screen.
/// The window is tall so every section (including dokodemo-door, which sits
/// below SOCKS/HTTP) renders into the AccessKit tree without scrolling.
fn boot_inbounds(
    settings: &Settings,
) -> (
    MutexGuard<'static, ()>,
    tempfile::TempDir,
    Harness<'static, BroccoliApp>,
) {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: APPDATA_LOCK serializes every test that reads or writes
    // broccoli state through a harness in this process.
    unsafe {
        std::env::set_var("APPDATA", tmp.path());
    }
    let state_dir = tmp.path().join("broccoli/state");
    std::fs::create_dir_all(&state_dir).unwrap();
    std::fs::write(
        state_dir.join("settings.json"),
        serde_json::to_vec_pretty(settings).unwrap(),
    )
    .unwrap();

    let mut h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    h.set_size(egui::Vec2::new(1100.0, 2800.0));
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Inbounds")
        .click();
    h.run();
    (lock, tmp, h)
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

    // Replace the SOCKS listen address (the only field holding 0.0.0.0) with
    // a loopback address, exactly like the shared smoke-test editing flow.
    let field = h
        .get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("0.0.0.0"))
        .expect("SOCKS listen address input");
    field.click();
    h.run();
    h.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    h.run();
    h.get_all_by_role(egui::accesskit::Role::TextInput)
        .find(|node| node.value().as_deref() == Some("0.0.0.0"))
        .expect("listen input should keep the typed value")
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
