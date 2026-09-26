//! kittest coverage: non-applicable options (fields that cannot
//! function on Windows or carry no meaning for a user-side client) never
//! render in the structured server editors. The model keeps the fields —
//! values still round-trip — and the raw JSON override remains the only path
//! to them. The protocol editors with hidden fields are covered here; the
//! wireguard editor (peer email, noKernelTun) is covered by its own test
//! below because it needs a seeded peer, and the outbound sockopt editor
//! (Windows-inert knobs) by another because it needs the TLS/ECH mount.
//!
//! The harness boots the real `BroccoliApp` (the shared UI harness pattern:
//! temp APPDATA with a pre-seeded servers.json and settings.json, first-run
//! wizard dismissed) and navigates to the Servers screen. The removed
//! widgets' labels came from i18n keys that were deleted with the widgets,
//! so the expected labels are literals mirroring the removed
//! English copy.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! Tests are serialized because changing a process environment variable while
//! another harness reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::settings::{Language, Settings};
use broccoli::model::{
    OutboundModel, Protocol, ProtocolSettings, Security, ServerProfile, ServersFile, SockoptModel,
    TlsModel, WireguardPeer,
};
use egui::accesskit::Role;
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::MutexGuard;
use serde_json::Map;

#[path = "common/screen.rs"]
mod screen;

mod common;

/// Boot the real app through the shared fixture against `profiles` persisted
/// into the temp APPDATA (settings seeded with the observatory off, like the
/// other harness tests), dismiss the first-run wizard, and open the Servers
/// screen with the first profile active. The window is the default 1100x720.
fn boot_servers(
    profiles: Vec<ServerProfile>,
) -> (
    MutexGuard<'static, ()>,
    common::TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    let servers = ServersFile {
        version: 1,
        active: profiles.first().map(|profile| profile.id.clone()),
        profiles,
        extra: Map::new(),
    };
    let mut settings = Settings::default();
    settings.routing.observatory.enabled = false;
    settings.routing.burst_observatory.enabled = false;
    let (lock, tmp, mut h) = screen::boot_state(screen::BootState { settings, servers });

    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    common::dismiss_wizard(&mut h);
    h.get_by_role_and_label(Role::Button, "Servers").click();
    h.run();
    (lock, tmp, h)
}

/// The structured editors must not render non-applicable fields: outbound
/// user `email` (server-side accounting) on every protocol editor, and
/// freedom `redirect` (a transparent-proxy leftover). Each seeded profile is
/// selected in turn and the hidden label asserted absent — after asserting
/// the profile's own editor is on screen, so a blank or stale panel cannot
/// satisfy the absence check for the wrong reason.
#[test]
fn server_editors_hide_non_applicable_fields() {
    let cases = [
        (Protocol::Vless, "email"),
        (Protocol::Vmess, "email"),
        (Protocol::Trojan, "email"),
        (Protocol::Shadowsocks, "email"),
        (Protocol::Socks, "email"),
        (Protocol::Http, "email"),
        (Protocol::Freedom, "redirect"),
    ];
    let profiles: Vec<ServerProfile> = cases
        .iter()
        .enumerate()
        .map(|(index, (protocol, _))| {
            ServerProfile::new(format!("p{index}"), OutboundModel::new(*protocol))
        })
        .collect();
    let (_lock, _tmp, mut h) = boot_servers(profiles);

    for (index, (protocol, hidden_label)) in cases.iter().enumerate() {
        let name = format!("p{index}");
        if index > 0 {
            h.get_by_label(name.as_str()).click();
            h.run();
        }
        // Positive render evidence first: the editor's protocol selector
        // shows this profile's protocol (the combo is in the editor header),
        // which proves the selected profile's editor is the one under test.
        let protocol_shown = protocol.as_str();
        assert!(
            h.query_all_by_role(Role::ComboBox)
                .any(|node| node.value().as_deref() == Some(protocol_shown)),
            "the {name} editor must render with its protocol selector showing {protocol_shown:?}"
        );
        assert!(
            h.query_by_label(hidden_label).is_none(),
            "the {name} editor must not render the non-applicable \
             {hidden_label:?} field"
        );
    }
}

/// The wireguard editor hides the per-peer `email` field and the Linux-only
/// `noKernelTun` knob. A seeded peer is required — the peer
/// email rendered once per peer row.
#[test]
fn wireguard_editor_hides_non_applicable_fields() {
    let mut profile = ServerProfile::new("wg", OutboundModel::new(Protocol::Wireguard));
    if let ProtocolSettings::Wireguard(settings) = &mut profile.outbound.settings {
        settings.peers.push(WireguardPeer {
            public_key: "peer-a".into(),
            ..Default::default()
        });
    }
    let (_lock, _tmp, h) = boot_servers(vec![profile]);

    // Positive render evidence first: the editor's protocol selector shows
    // wireguard and the seeded peer row renders its public key, so the
    // absence checks below cannot pass on a blank or stale editor.
    assert!(
        h.query_all_by_role(Role::ComboBox)
            .any(|node| node.value().as_deref() == Some(Protocol::Wireguard.as_str())),
        "the wireguard editor must render with its protocol selector showing wireguard"
    );
    assert!(
        h.query_all_by_role_and_label(Role::TextInput, t(Language::En, Key::SrvPublicKey))
            .any(|node| node.value().as_deref() == Some("peer-a")),
        "the seeded wireguard peer row must render its public key field"
    );
    assert!(
        h.query_by_label("email").is_none(),
        "the wireguard peer rows must not render the email field"
    );
    assert!(
        h.query_by_label("disable kernel WireGuard TUN").is_none(),
        "the wireguard editor must not render the noKernelTun knob"
    );
}

/// The outbound sockopt editor renders no widget for a value the Windows
/// outbound path never reads: the Linux-only knobs (`mark`, `tproxy`,
/// `tcpCongestion`, `tcpWindowClamp`, `tcpMaxSeg`, `tcpUserTimeout`),
/// `tcpMptcp` (Go's dialer consumes it on Linux only) and the listener-only
/// values.
///
/// `PINS` are the labels the editor rendered before the deletion — the two
/// group titles and the `tcpMptcp` checkbox — so a resurrected group or
/// checkbox fails here. `GUARDS` are the field labels those groups carried:
/// they sat in collapsed headers, whose bodies egui never builds, so they pin
/// the fields against a future direct widget rather than against this change.
/// The same editor also renders inside every UDP mask's socket options
/// (`SockoptUsage::Mask`), which this test does not reach.
#[test]
fn sockopt_editor_hides_fields_without_a_windows_reader() {
    /// Labels rendered before this change: the regression pins.
    const PINS: &[&str] = &[
        "Non-Windows outbound socket options",
        "Listener/server-only (no outbound effect)",
        "tcpMptcp",
    ];
    /// Field labels the deleted groups carried, mirrored from the deleted
    /// English copy.
    const GUARDS: &[&str] = &[
        "tcpCongestion",
        "tcpWindowClamp",
        "tcpMaxSeg",
        "tcpUserTimeout (ms)",
        "mark",
        "tproxy",
        "v6only",
        "acceptProxyProtocol",
        "trustedXForwardedFor",
    ];

    let mut profile = ServerProfile::new("sockopts", OutboundModel::new(Protocol::Vless));
    profile.outbound.stream.security = Security::Tls;
    profile.outbound.stream.tls_settings = Some(TlsModel {
        ech_config_list: "https://1.1.1.1/dns-query".into(),
        ech_sockopt: Some(SockoptModel::default()),
        ..Default::default()
    });
    let (_lock, _tmp, mut h) = boot_servers(vec![profile]);

    let assert_absent = |h: &Harness<'static, BroccoliApp>, mount: &str| {
        for label in PINS.iter().chain(GUARDS) {
            assert!(
                h.query_by_label(label).is_none(),
                "the {mount} sockopt block must not render {label:?}"
            );
        }
    };

    // The stream block sits in the Advanced tab's sockopt section, whose own
    // editable fields must be on screen before the absence checks mean
    // anything.
    h.get_by_role_and_label(Role::Button, "Advanced").click();
    h.run();
    assert!(
        h.query_by_label("interface (bind NIC)").is_some(),
        "the Advanced tab must render the stream sockopt block's editable fields"
    );
    assert_absent(&h, "stream");

    // The ECH DNS-query block renders the same editor; its checkbox is the
    // positive evidence that the block (and the editor inside it) is mounted.
    h.get_by_role_and_label(Role::Button, "Security").click();
    h.run();
    assert!(
        h.query_by_label("ECH DNS-query socket options").is_some(),
        "the Security tab must render the ECH DNS-query socket options block"
    );
    assert_absent(&h, "ECH");
}
