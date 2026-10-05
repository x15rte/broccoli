//! Coverage: a TUN configuration needs at least one IPv4 gateway.
//!
//! The gateway entries become the adapter's addresses, and the in-tun DNS
//! address is derived from the gateway's IPv4 (the core's DNS leak block
//! permits port-53 only inside the TUN subnet, so the adapter DNS must point
//! at the in-tun listener). An empty or IPv6-only gateway list with TUN
//! enabled is therefore a validation error: the generator refuses to emit a
//! config (Apply/Connect are blocked through `config_error`), the TUN screen
//! renders the error inline under the gateway editor, and the old hardcoded
//! `10.255.0.1` fallback can never reach the wire.
//!
//! The harness boots the real `BroccoliApp` for the UI assertions (the
//! shared UI harness pattern: temp APPDATA with a pre-seeded settings.json,
//! first-run wizard dismissed). Safety: production startup is read-only
//! with respect to Windows settings. Tests are serialized because changing
//! a process environment variable while another harness reads it is
//! undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::r#gen::generate_with_api_port;
use broccoli::i18n::{Key, t, t_fmt, validation_message};
use broccoli::model::settings::{Language, Mode, Settings};
use broccoli::model::validation::{ValidationCode, Verdict, validate_settings};
use broccoli::model::{ServersFile, TunCfg};
use broccoli::ui::Screen;
use egui_kittest::{Harness, kittest::NodeT, kittest::Queryable};
use parking_lot::MutexGuard;

#[path = "common/nav.rs"]
mod nav;
#[path = "common/screen.rs"]
mod screen;

mod common;

/// The gateway rule's message, rendered from the model code the verdict
/// pass emits (the same bytes the generator surfaces and the screen shows).
fn gateway_error() -> String {
    validation_message(&ValidationCode::TunIpv4GatewayRequired, Language::En)
}

/// The settings-level verdict for `settings`, with no server profiles and a
/// fixed API port — the same scope and entry point generation judges, with
/// the port named because this suite is about the TUN gateway rules rather
/// than the collision rule the real port participates in.
fn verdict(settings: &Settings) -> Verdict {
    validate_settings(settings, &ServersFile::default(), 19999)
}

/// True when the verdict carries the IPv4-gateway rule.
fn verdict_rejects_gateway(settings: &Settings) -> bool {
    verdict(settings)
        .iter()
        .any(|issue| issue.code == ValidationCode::TunIpv4GatewayRequired)
}

/// The seeded dual-stack gateway from `TunCfg::default()`, so a re-default
/// cannot silently dodge these tests.
fn seeded_gateway() -> Vec<String> {
    TunCfg::default().gateway
}

/// TUN mode on with the given gateway list; `Settings::default()` seeds the
/// DNS module, so the in-tun DNS listener participates in every generation.
fn tun_settings(gateway: Vec<String>) -> Settings {
    Settings {
        mode: Mode::Tun,
        tun: TunCfg {
            gateway,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn generate(settings: &Settings) -> Result<serde_json::Value, String> {
    generate_with_api_port(&ServersFile::default(), settings, 19999)
        .map_err(|error| error.to_string())
}

// ---------- model-level validation ----------

#[test]
fn tun_on_with_cleared_gateway_is_a_validation_error() {
    let settings = tun_settings(Vec::new());
    assert!(
        verdict_rejects_gateway(&settings),
        "the settings verdict must carry the IPv4-gateway rule"
    );
    let error = generate(&settings).expect_err("cleared gateway must be rejected");
    assert!(
        error.contains(gateway_error().as_str()),
        "the error must name the IPv4-gateway requirement: {error:?}"
    );
}

#[test]
fn tun_on_with_ipv6_only_gateway_is_a_validation_error() {
    let settings = tun_settings(vec!["fd00::1/64".into()]);
    assert!(
        verdict_rejects_gateway(&settings),
        "the settings verdict must carry the IPv4-gateway rule"
    );
    let error = generate(&settings).expect_err("an IPv6-only gateway must be rejected");
    assert!(
        error.contains(gateway_error().as_str()),
        "the error must name the IPv4-gateway requirement: {error:?}"
    );
}

#[test]
fn tun_on_with_dual_stack_gateway_generates_unchanged() {
    // The valid dual-stack shape keeps every wire behavior: the adapter DNS
    // pins the gateway's IPv4, which is also the address the runtime binds
    // the in-tun listener on (src/rt/dns_in.rs).
    let settings = tun_settings(seeded_gateway());
    let cfg = generate(&settings).expect("the seeded dual-stack gateway must stay valid");
    let tun = cfg["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|inbound| inbound["protocol"] == "tun")
        .expect("tun inbound");
    assert_eq!(tun["settings"]["dns"], serde_json::json!(["10.255.0.1"]));
}

#[test]
fn readding_an_ipv4_gateway_clears_the_error_and_derives_from_it() {
    // Recovery: the same model with an IPv4 gateway re-added must generate,
    // and the in-tun DNS address must derive from the re-added gateway —
    // never from a constant.
    let mut settings = tun_settings(Vec::new());
    let error = generate(&settings).expect_err("cleared gateway must be rejected first");
    assert!(error.contains(gateway_error().as_str()), "{error:?}");

    settings.tun.gateway = vec!["192.168.10.1/30".into(), "fd00::1/64".into()];
    let cfg = generate(&settings).expect("re-adding an IPv4 gateway must recover");
    let tun = cfg["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|inbound| inbound["protocol"] == "tun")
        .expect("tun inbound");
    assert_eq!(
        tun["settings"]["dns"],
        serde_json::json!(["192.168.10.1"]),
        "the in-tun DNS address must be the gateway's IPv4, not a constant"
    );
}

#[test]
fn cleared_gateway_cannot_reach_the_wire() {
    // The old fallback (10.255.0.1 when no IPv4 gateway exists) must never
    // reach the wire: generation is blocked outright, so no config — and no
    // fallback literal — can be emitted for the cleared state.
    let settings = tun_settings(Vec::new());
    assert!(
        verdict_rejects_gateway(&settings),
        "the settings verdict must carry the IPv4-gateway rule"
    );
    let error = generate(&settings).expect_err("generation must block the cleared state");
    assert!(error.contains(gateway_error().as_str()), "{error:?}");

    let ipv6_only = tun_settings(vec!["fd00::1/64".into()]);
    assert!(
        verdict_rejects_gateway(&ipv6_only),
        "the settings verdict must carry the IPv4-gateway rule"
    );
    let error = generate(&ipv6_only).expect_err("generation must block the IPv6-only state");
    assert!(error.contains(gateway_error().as_str()), "{error:?}");
}

#[test]
fn tun_disabled_with_cleared_gateway_is_valid() {
    // TUN off (mode Off): the gateway list is not consulted, so a cleared
    // list must not block generation of otherwise-valid settings.
    let settings = Settings {
        mode: Mode::Off,
        tun: TunCfg {
            gateway: Vec::new(),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(
        !verdict_rejects_gateway(&settings),
        "TUN off must not consult the gateway list"
    );
    generate(&settings).expect("TUN off must not consult the gateway list");
}

// ---------- leak-block validation ----------

/// The message the verdict renders for one leak rule.
fn leak_message(code: &ValidationCode) -> String {
    validation_message(code, Language::En)
}

/// TUN mode with the seeded module and the given leak list; every other TUN
/// setting keeps its seeded value, so the routing table and adapter DNS are
/// non-empty unless the test clears them.
fn leak_settings(leak: Vec<String>) -> Settings {
    Settings {
        mode: Mode::Tun,
        tun: TunCfg {
            auto_system_wfp_block_leak: leak,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// True when the verdict carries the given code, blocking or advisory.
fn verdict_carries(settings: &Settings, code: &ValidationCode) -> bool {
    verdict(settings).iter().any(|issue| &issue.code == code)
}

#[test]
fn leak_block_without_a_routing_table_is_a_validation_error() {
    // The core installs its filters over the routes of
    // autoSystemRoutingTable and refuses the pair when the table is empty
    // (confirmed against the pinned binary: "autoSystemWfpBlockLeak needs
    // autoSystemRoutingTable to be set").
    let mut settings = leak_settings(TunCfg::default().auto_system_wfp_block_leak);
    settings.tun.auto_system_routing_table.clear();
    assert!(verdict_carries(
        &settings,
        &ValidationCode::TunLeakRoutingTableRequired
    ));
    let error = generate(&settings).expect_err("an empty routing table must be rejected");
    assert!(
        error.contains(leak_message(&ValidationCode::TunLeakRoutingTableRequired).as_str()),
        "the error must name the routing-table requirement: {error:?}"
    );
}

#[test]
fn unknown_leak_value_is_a_validation_error() {
    // Any value outside {dns, misconfigtun} makes the core refuse the whole
    // document at load ("unknown autoSystemWfpBlockLeak value: ...", confirmed
    // against the pinned binary).
    let settings = leak_settings(vec!["bogus".into()]);
    assert!(verdict_carries(
        &settings,
        &ValidationCode::TunLeakValueUnknown("bogus".into())
    ));
    let error = generate(&settings).expect_err("an unknown leak value must be rejected");
    assert!(
        error.contains(leak_message(&ValidationCode::TunLeakValueUnknown("bogus".into())).as_str()),
        "the error must name the unknown value: {error:?}"
    );
}

#[test]
fn leak_halves_fold_case_insensitively_like_the_core() {
    // The core lowercases each entry before it compares, so a mixed-case
    // spelling is the same half and passes the vocabulary gate.
    let settings = leak_settings(vec!["DNS".into(), "MisconfigTun".into()]);
    assert!(!verdict(&settings).has_blocking());
    generate(&settings).expect("mixed-case halves are the core's own values");
}

#[test]
fn a_switched_off_family_half_warns_with_what_reopens() {
    // The key still reaches the wire (the DNS module is present), but without
    // the unrouted-family half an address family the routing table does not
    // route into the tunnel can egress. Advisory, never a gate.
    let settings = leak_settings(vec!["dns".into()]);
    assert!(
        verdict(&settings)
            .advisory()
            .any(|issue| issue.code == ValidationCode::TunLeakMisconfigTunOff),
        "a missing family half must warn"
    );
    generate(&settings).expect("a switched-off half must not block generation");
}

#[test]
fn the_leak_rules_are_gated_on_the_key_reaching_the_wire() {
    // The generator writes the key only while the TUN inbound and the DNS
    // module are both present, so a model state the core never sees must not
    // block: with no module, a cleared routing table and an unknown value are
    // both latent.
    let mut settings = leak_settings(vec!["bogus".into()]);
    settings.tun.auto_system_routing_table.clear();
    settings.dns.servers.clear();
    settings.dns.enable_parallel_query = false;
    assert!(
        verdict(&settings).iter().all(|issue| {
            issue.code != ValidationCode::TunLeakValueUnknown("bogus".into())
                && issue.code != ValidationCode::TunLeakRoutingTableRequired
                && issue.code != ValidationCode::TunLeakMisconfigTunOff
        }),
        "no module means no leak key on the wire, so no leak finding"
    );
    generate(&settings).expect("the key never reaches the core without a module");
}

#[test]
fn the_leak_rules_do_not_fire_outside_tun_mode() {
    let mut settings = leak_settings(vec!["bogus".into()]);
    settings.mode = Mode::Off;
    assert!(
        verdict(&settings).iter().all(|issue| !matches!(
            issue.code,
            ValidationCode::TunLeakValueUnknown(_)
                | ValidationCode::TunLeakRoutingTableRequired
                | ValidationCode::TunLeakMisconfigTunOff
        )),
        "TUN off means the key is never emitted"
    );
    generate(&settings).expect("TUN off leaves the leak list untouched");
}

// ---------- UI: inline error + Apply/Connect blocking ----------

/// Boot through the shared fixture against `settings` persisted into the temp
/// APPDATA, dismiss the first-run wizard, and optionally navigate to the given
/// screen (None = stay on the dashboard). The window is tall so every section
/// renders into the AccessKit tree without scrolling.
fn boot(
    settings: &Settings,
    screen: Option<Screen>,
) -> (
    MutexGuard<'static, ()>,
    common::TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    let state = screen::BootState {
        settings: settings.clone(),
        servers: ServersFile::default(),
    };
    nav::boot_screen(state, screen, egui::Vec2::new(1100.0, 2800.0))
}

#[test]
fn deleting_every_gateway_row_shows_inline_error_and_readding_clears_it() {
    let settings = tun_settings(seeded_gateway());
    let (_lock, _tmp, mut h) = boot(&settings, Some(Screen::Tun));

    assert!(
        h.query_by_label_contains(gateway_error().as_str())
            .is_none(),
        "a dual-stack gateway must not show the inline error"
    );

    // Delete both gateway rows. The gateways section renders before
    // auto-routes, so the first 🗑 button is always a gateway row while
    // both remain.
    for _ in 0..2 {
        h.query_all_by_label("🗑")
            .next()
            .expect("gateway row delete button")
            .click();
        h.run_steps(4);
    }
    assert!(
        h.query_by_label_contains(gateway_error().as_str())
            .is_some(),
        "deleting every gateway row must show the inline error"
    );

    // Re-add an IPv4 gateway: "+ Add" in the gateways section is the first
    // add button on the screen.
    h.query_all_by_label("+ Add")
        .next()
        .expect("gateways add button")
        .click();
    h.run_steps(4);
    // The row fields carry their list's label ("gateways") as the accessible
    // name, so the new row is addressed by name, not by its empty value.
    let gateway_label = t(Language::En, Key::TunGatewaysLabel);
    h.get_by_role_and_label(egui::accesskit::Role::TextInput, gateway_label)
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::TextInput, gateway_label)
        .type_text("10.255.0.1/30");
    h.run_steps(4);

    assert!(
        h.query_by_label_contains(gateway_error().as_str())
            .is_none(),
        "re-adding an IPv4 gateway must clear the inline error"
    );
}

/// The label the shell stores for a generation failure: the
/// `GenerationFailed` template around the crate's bounded excerpt (the shell's
/// echo boundary), so this asserts the template, not a copy of the bound.
fn shell_generation_error(message: &str) -> String {
    t_fmt(
        Language::En,
        Key::GenerationFailed,
        &[&broccoli::excerpt::excerpt(message)],
    )
}

#[test]
fn cleared_gateway_blocks_connect_and_surfaces_the_error() {
    // The connect verdict has one owner — the shell's generation — and the
    // dashboard's inline label renders the shell's stored error: an invalid
    // TUN config must disable every Connect button and show the shell's
    // excerpt-bounded generation text next to it.
    let error = generate(&tun_settings(Vec::new())).expect_err("cleared gateway must be rejected");
    let (_lock, _tmp, h) = boot(&tun_settings(Vec::new()), None);

    let expected = shell_generation_error(&error);
    assert!(
        h.query_all_by_label(expected.as_str()).next().is_some(),
        "the dashboard must render the shell's generation error next to Connect: {expected:?}"
    );
    assert!(
        h.query_by_label_contains(gateway_error().as_str())
            .is_none(),
        "the inline label carries the shell's excerpt-bounded text, not the unbounded generator message"
    );
    let connects: Vec<_> = h
        .query_all_by_role_and_label(egui::accesskit::Role::Button, "Connect")
        .collect();
    assert!(!connects.is_empty(), "Connect buttons must exist");
    for connect in &connects {
        assert!(
            connect.accesskit_node().is_disabled(),
            "Connect must be blocked while the TUN gateway list has no IPv4 entry"
        );
    }
}

#[test]
fn valid_tun_config_does_not_surface_the_gateway_error() {
    // Guard: the error surface must stay quiet for the valid dual-stack
    // config, so the blocking above cannot be blamed on a global flag.
    // (Connect itself is disabled in the harness either way — the managed
    // core is not installed — so only the error surface is asserted.)
    let settings = tun_settings(seeded_gateway());
    let (_lock, _tmp, h) = boot(&settings, None);

    assert!(
        h.query_by_label_contains(gateway_error().as_str())
            .is_none(),
        "a valid TUN config must not surface the gateway error"
    );
}

#[test]
fn fresh_install_default_gateway_stays_valid() {
    // A fresh install keeps the seeded dual-stack gateway: generation and
    // the UI must be unaffected (acceptance: fresh install keeps working).
    let settings = tun_settings(TunCfg::default().gateway);
    generate(&settings).expect("the fresh-install default must keep generating");
    let (_lock, _tmp, h) = boot(&settings, Some(Screen::Tun));
    assert!(
        h.query_by_label_contains(gateway_error().as_str())
            .is_none(),
        "the fresh-install default must not show the inline error"
    );
}
