//! The XDRIVE transport's `remoteFolder` names a directory on this machine
//! for the `local` service and an opaque folder id or template token for the
//! others, so the folder row carries a folder picker for `local` alone — and
//! the picker comes and goes in the same frame the service choice does.
//!
//! What a test cannot pin: the native folder dialog itself. Clicking the
//! button opens a modal no automated input reaches, so the click is left to
//! the user — the browse buttons of the path fields are covered the same way,
//! by the field they sit beside, never by their dialog. What this test pins
//! instead is what the user can observe without opening anything: the picker
//! renders on the local service's folder row and on no other service's row,
//! on the frame the service changed, while the row's hint and its
//! required-folder verdict keep following the service. The picker's own
//! write path — the text a trailing control yields landing in the field's
//! buffer and counting as the field's change — is pinned by the widget test
//! `validated_field_trailing_control_feeds_the_field_it_sits_beside` in
//! `src/ui/widgets/mod.rs`.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! Tests are serialized because changing a process environment variable while
//! another harness reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::settings::{Language, Settings};
use broccoli::model::stream::{
    Network, StreamModel, XDRIVE_SERVICE_DRIVE, XDRIVE_SERVICE_LOCAL, XDRIVE_SERVICE_TEMPLATE,
    XdriveTransport,
};
use broccoli::model::{OutboundModel, Protocol, ServerProfile, ServersFile};
use egui::accesskit::Role;
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::MutexGuard;
use serde_json::Map;

#[path = "common/screen.rs"]
mod screen;

mod common;

/// The folder field's own label: the row is addressed by it, never by its
/// position in the xdrive editor.
fn folder_label() -> &'static str {
    t(Language::En, Key::SrvXdriveRemoteFolder)
}

/// The picker button's text: the same "Browse…" the path fields' buttons
/// carry.
fn browse_label() -> &'static str {
    t(Language::En, Key::SrvBrowse)
}

/// The verdict the folder field renders while the service requires a folder
/// and none is set.
fn required_verdict() -> &'static str {
    t(Language::En, Key::SrvXdriveRemoteFolderRequired)
}

/// Boot the real app through the shared fixture against a temp APPDATA
/// seeded with one active profile whose transport is XDRIVE under `service`
/// (folder unset), then open the server editor's Transport tab, where the
/// folder row lives.
fn boot_with_service(
    service: &str,
) -> (
    MutexGuard<'static, ()>,
    common::TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    let mut profile = ServerProfile::new("xdrive", OutboundModel::new(Protocol::Freedom));
    profile.id = "0123456789abcdef".into();
    profile.outbound.stream = StreamModel {
        network: Network::Xdrive,
        xdrive_settings: Some(Box::new(XdriveTransport {
            service: service.into(),
            ..Default::default()
        })),
        ..Default::default()
    };
    let servers = ServersFile {
        version: 1,
        active: Some(profile.id.clone()),
        profiles: vec![profile],
        extra: Map::new(),
    };
    let mut settings = Settings::default();
    settings.routing.observatory.enabled = false;
    settings.routing.burst_observatory.enabled = false;
    let (lock, tmp, mut h) = screen::boot_state(screen::BootState { settings, servers });

    h.run();
    common::dismiss_wizard(&mut h);
    h.get_by_role_and_label(Role::Button, "Servers").click();
    h.run();
    h.get_by_role_and_label(Role::Button, t(Language::En, Key::SrvTabTransport))
        .click();
    h.run();
    (lock, tmp, h)
}

/// Whether the folder row's own picker renders: a "Browse…" button after the
/// row's text box and level with it. That geometry is what makes the button
/// the folder row's — the Transport tab renders no other browse button.
fn picker_on_the_folder_row(h: &Harness<'static, BroccoliApp>) -> bool {
    let field = h
        .get_by_role_and_label(Role::TextInput, folder_label())
        .rect();
    h.query_all_by_label(browse_label()).any(|node| {
        let rect = node.rect();
        rect.left() >= field.right()
            && rect.center().y >= field.top()
            && rect.center().y <= field.bottom()
    })
}

/// Whether the folder field shows `hint`: its placeholder is the hint the
/// service chose, so this is the row re-rendered under the chosen service.
fn folder_hint_is(h: &Harness<'static, BroccoliApp>, hint: &str) -> bool {
    h.query_all_by(|node| node.role() == Role::TextInput && node.placeholder() == Some(hint))
        .next()
        .is_some()
}

/// Pick `next` in the XDRIVE service combo, which shows `current` before the
/// click. The option click gets exactly one frame: the combo paints the
/// selected text it was built with, so a later lookup has to let the previous
/// choice settle into the display, while the assertions that follow read the
/// single frame in which the service changed.
fn choose_service(h: &mut Harness<'static, BroccoliApp>, current: &str, next: &str) {
    h.run();
    h.get_all_by_role(Role::ComboBox)
        .find(|node| node.value().as_deref() == Some(current))
        .expect("the xdrive service combo must show the service the model holds")
        .click();
    h.run();
    h.get_by_role_and_label(Role::Button, next).click();
    h.run_steps(1);
}

/// The folder picker belongs to the `local` service alone. It renders on the
/// local service's folder row — beside the row's unchanged hint and
/// required-folder verdict — and on no other service's row, appearing and
/// disappearing with the service choice in the frame that choice changes.
#[test]
fn folder_picker_follows_the_local_service_alone() {
    let (_lock, _tmp, mut h) = boot_with_service(XDRIVE_SERVICE_LOCAL);

    // Positive render evidence first: the folder row is on screen under the
    // local service, so the absence checks below cannot pass on a blank or
    // stale panel.
    assert!(
        folder_hint_is(&h, t(Language::En, Key::SrvXdriveFolderLocalHint)),
        "the local service's folder row must render with the local hint"
    );
    assert!(
        picker_on_the_folder_row(&h),
        "the local service's folder row must carry the folder picker"
    );
    // The picker is an addition to the row, not a replacement: the field's
    // required-folder verdict still renders (the seeded folder is empty).
    assert!(
        h.query_by_label(required_verdict()).is_some(),
        "the required-folder verdict must still render beside the picker"
    );

    // A Google Drive folder is an opaque id: the picker goes away, the hint
    // and the verdict follow the choice.
    choose_service(&mut h, XDRIVE_SERVICE_LOCAL, XDRIVE_SERVICE_DRIVE);
    assert!(
        folder_hint_is(&h, t(Language::En, Key::SrvXdriveFolderDriveHint)),
        "the folder hint must follow the service choice"
    );
    assert!(
        !picker_on_the_folder_row(&h),
        "the Drive folder id must render no folder picker"
    );

    // A template folder is a token, opaque the same way.
    choose_service(&mut h, XDRIVE_SERVICE_DRIVE, XDRIVE_SERVICE_TEMPLATE);
    assert!(
        folder_hint_is(&h, t(Language::En, Key::SrvXdriveFolderTemplateHint)),
        "the folder hint must follow the service choice"
    );
    assert!(
        !picker_on_the_folder_row(&h),
        "the template folder token must render no folder picker"
    );

    // Choosing the local service again brings the picker back with it.
    choose_service(&mut h, XDRIVE_SERVICE_TEMPLATE, XDRIVE_SERVICE_LOCAL);
    assert!(
        picker_on_the_folder_row(&h),
        "the picker must return with the local service"
    );
}
