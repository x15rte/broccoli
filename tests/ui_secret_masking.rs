//! kittest coverage: the Servers screen masks the credentials a profile dials
//! with, and masks its server information while the Privacy setting asks for
//! it. The reveal control shows the masked values again, and the reveal never
//! outlives the visit: leaving the screen hides them.
//!
//! The harness boots the real `BroccoliApp` (the shared UI harness pattern:
//! temp APPDATA with a pre-seeded servers.json and settings.json, first-run
//! wizard dismissed) and navigates to the Servers screen. A masked value is
//! asserted through the frame's accessibility tree — the one place rendered
//! text surfaces — so a value that reaches the screen through any widget fails
//! the absence check.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! Tests are serialized because changing a process environment variable while
//! another harness reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::settings::Language;
use broccoli::model::{
    OutboundModel, Protocol, ProtocolSettings, ServerProfile, ServersFile, Settings,
};
use broccoli::ui::Screen;
use egui::accesskit::Role;
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::MutexGuard;
use serde_json::Map;

#[path = "common/screen.rs"]
mod screen;

mod common;

/// The credential the editor must never render while masked.
const SENTINEL_ID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
/// The endpoint the editor masks only while the Privacy setting asks for it.
const SENTINEL_ADDRESS: &str = "masked-host.invalid";

/// Boot the real app with one VLESS profile carrying [`SENTINEL_ID`] and
/// [`SENTINEL_ADDRESS`], and open the Servers screen with it selected. An empty
/// `id` is left empty when `empty_id` is set, so the field carries a verdict
/// the masked row must keep rendering.
fn boot_servers(
    hide_server_info: bool,
    empty_id: bool,
) -> (
    MutexGuard<'static, ()>,
    common::TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    let mut profile = ServerProfile::new("p", OutboundModel::new(Protocol::Vless));
    if let ProtocolSettings::Vless(settings) = &mut profile.outbound.settings {
        settings.id = if empty_id {
            String::new()
        } else {
            SENTINEL_ID.into()
        };
        settings.address = SENTINEL_ADDRESS.into();
        settings.port = 443;
    }
    let servers = ServersFile {
        version: 1,
        active: Some(profile.id.clone()),
        profiles: vec![profile],
        extra: Map::new(),
    };
    let mut settings = Settings::default();
    settings.routing.observatory.enabled = false;
    settings.routing.burst_observatory.enabled = false;
    settings.hide_server_info = hide_server_info;
    let (lock, tmp, mut h) = screen::boot_state(screen::BootState { settings, servers });

    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    common::dismiss_wizard(&mut h);
    h.get_by_role_and_label(Role::Button, Screen::Servers.label(Language::En))
        .click();
    h.run();
    (lock, tmp, h)
}

/// Whether any node of the frame's accessibility tree carries `needle` as its
/// value or its label — the two channels a rendered field's text reaches.
/// Exhaustive by construction: a value that renders anywhere in the frame is
/// found, whichever widget carries it.
fn tree_contains(h: &Harness<'_, BroccoliApp>, needle: &str) -> bool {
    h.query_all_by(|node| {
        node.value().as_deref().is_some_and(|v| v.contains(needle))
            || node.label().as_deref().is_some_and(|l| l.contains(needle))
    })
    .next()
    .is_some()
}

/// The control that shows what the screen hides, by the label of the state it
/// is in.
fn reveal_control(h: &Harness<'_, BroccoliApp>, revealed: bool) -> bool {
    let key = if revealed {
        Key::SrvHideSecrets
    } else {
        Key::SrvRevealSecrets
    };
    h.query_by_role_and_label(Role::Button, t(Language::En, key))
        .is_some()
}

#[test]
fn credentials_render_masked_and_the_reveal_is_transient() {
    let (_lock, _tmp, mut h) = boot_servers(false, false);

    // Positive render evidence first: the editor's protocol selector shows
    // vless, so the checks below cannot pass on a blank or stale panel.
    assert!(
        h.query_all_by_role(Role::ComboBox)
            .any(|node| node.value().as_deref() == Some(Protocol::Vless.as_str())),
        "the vless editor must render with its protocol selector showing vless"
    );
    assert!(
        !tree_contains(&h, SENTINEL_ID),
        "the editor must not render the profile's uuid while it is masked"
    );
    assert!(
        // The masked stand-in's bullet glyphs, wherever the frame renders them.
        tree_contains(&h, "\u{2022}"),
        "the masked row must render the stand-in in the credential's place"
    );

    // The reveal shows it, and the control flips to the hiding state.
    h.get_by_role_and_label(Role::Button, t(Language::En, Key::SrvRevealSecrets))
        .click();
    h.run();
    assert!(
        tree_contains(&h, SENTINEL_ID),
        "the reveal control must render the uuid"
    );
    assert!(
        reveal_control(&h, true),
        "the control must offer to hide the values again while revealed"
    );

    // A reveal never outlives the visit: another screen and back masks again.
    h.get_by_role_and_label(Role::Button, Screen::Settings.label(Language::En))
        .click();
    h.run();
    h.get_by_role_and_label(Role::Button, Screen::Servers.label(Language::En))
        .click();
    h.run();
    assert!(
        reveal_control(&h, false),
        "re-entering the screen must show the reveal control in its hidden state"
    );
    assert!(
        !tree_contains(&h, SENTINEL_ID),
        "leaving the screen must mask the uuid again"
    );
}

#[test]
fn server_information_stays_visible_while_the_setting_is_off() {
    let (_lock, _tmp, h) = boot_servers(false, false);

    assert!(
        tree_contains(&h, SENTINEL_ADDRESS),
        "the endpoint renders while the Privacy setting is off"
    );
    assert!(
        !tree_contains(&h, SENTINEL_ID),
        "the credentials are masked whatever the Privacy setting says"
    );
}

#[test]
fn hiding_server_information_masks_the_endpoint_and_keeps_the_verdict() {
    // An empty credential: the masked row must still carry its verdict, so the
    // absent uuid below is the masking, not an empty editor.
    let (_lock, _tmp, mut h) = boot_servers(true, true);

    assert!(
        !tree_contains(&h, SENTINEL_ADDRESS),
        "the Privacy setting must mask the endpoint"
    );
    assert!(
        tree_contains(&h, t(Language::En, Key::SrvUuidRequired)),
        "a masked field must keep rendering its verdict"
    );
    assert!(
        tree_contains(&h, "\u{2022}"),
        "the masked endpoint must render the stand-in"
    );

    // The one control shows the hidden endpoint as well as the credentials.
    h.get_by_role_and_label(Role::Button, t(Language::En, Key::SrvRevealSecrets))
        .click();
    h.run();
    assert!(
        tree_contains(&h, SENTINEL_ADDRESS),
        "the reveal control must render the endpoint the setting masks"
    );
}
