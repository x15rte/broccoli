//! Regression: Discard changes must be available while a raw-JSON
//! editor holds INVALID uncommitted text, and clicking it must clear the
//! buffers so the editor re-seeds from the persisted profile.
//!
//! Before the fix Discard was gated on `changed_from_source`, which compares
//! the draft to the persisted source: invalid text never commits to the
//! draft, so the draft never differed and Discard stayed disabled — the user
//! was stuck with the error text until retyping valid JSON, switching the
//! mask type, or editing another field.
//!
//! Drives the real app through egui_kittest at the app's DEFAULT window size
//! 1100x720 (the action row stays reachable there): replace the raw text with
//! invalid JSON, assert Discard is enabled, Discard, and assert the editor
//! re-seeds from the persisted profile with no recommit on later keystrokes.
//! The valid edit path is driven too: it must keep enabling Discard and
//! reverting.

use broccoli::app::BroccoliApp;
use broccoli::model::{
    FinalmaskModel, FinalmaskTcpMask, OutboundModel, Protocol, ServerProfile, ServersFile, Settings,
};
use egui_kittest::{Harness, kittest::NodeT, kittest::Queryable};
use parking_lot::MutexGuard;
use serde_json::json;

#[path = "common/screen.rs"]
mod screen;

mod common;

/// Boot the app through the shared fixture against a temp APPDATA seeded with
/// one active profile whose finalmask holds an unknown (preserved-raw) TCP
/// mask.
fn harness_with_raw(
    raw: serde_json::Value,
) -> (
    MutexGuard<'static, ()>,
    common::TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    let mut profile = ServerProfile::new("raw-editor", OutboundModel::new(Protocol::Freedom));
    profile.id = "0123456789abcdef".into();
    profile.outbound.stream.finalmask = Some(FinalmaskModel {
        tcp: vec![FinalmaskTcpMask::Unknown(raw)],
        udp: Vec::new(),
        quic_params: None,
        extra: Default::default(),
    });
    let servers = ServersFile {
        version: 1,
        active: Some(profile.id.clone()),
        profiles: vec![profile],
        extra: Default::default(),
    };
    let mut settings = Settings::default();
    settings.routing.observatory.enabled = false;
    settings.routing.burst_observatory.enabled = false;
    screen::boot_state(screen::BootState { settings, servers })
}

/// The only multiline text input on the Advanced tab: the preserved-raw JSON
/// editor of the unknown finalmask.
fn raw_editor<'a>(h: &'a Harness<'a, BroccoliApp>) -> egui_kittest::Node<'a> {
    h.get_by_role(egui::accesskit::Role::MultilineTextInput)
}

/// The Discard changes action-row button.
fn discard_button<'a>(h: &'a Harness<'a, BroccoliApp>) -> egui_kittest::Node<'a> {
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Discard changes")
}

/// The Validate and save action-row button.
fn validate_button<'a>(h: &'a Harness<'a, BroccoliApp>) -> egui_kittest::Node<'a> {
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Validate and save")
}

/// Dismiss the first-run wizard, open the Servers screen (the seeded profile
/// is active, so its editor is already open), and switch to the Advanced tab
/// where the raw editor lives — at the app's DEFAULT window size 1100x720
/// (the action row stays reachable there).
fn open_advanced_tab(h: &mut Harness<'static, BroccoliApp>) {
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    common::dismiss_wizard(h);
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Servers")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Advanced")
        .click();
    h.run();
}

/// Replace the whole editor text with one raw document (select-all + type).
fn replace_raw_text(h: &mut Harness<'static, BroccoliApp>, text: &str) {
    raw_editor(h).focus();
    h.run();
    h.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    h.run();
    raw_editor(h).type_text(text);
    h.run();
}

/// An invalid raw-JSON edit must enable Discard (the draft itself never
/// changes — invalid text does not commit — so the old draft-vs-source gate
/// left the button disabled and the user stuck with the error text), and
/// Discard must clear the buffers so the editor re-seeds from the persisted
/// profile. A later keystroke must not recommit the discarded JSON, and
/// Validate must stay disabled while the buffer holds invalid text.
#[test]
fn invalid_raw_edit_enables_discard_and_discard_reseeds() {
    let (_lock, _tmp, mut h) = harness_with_raw(json!({"type": "future-mask", "ok": true}));
    open_advanced_tab(&mut h);

    let seeded = raw_editor(&h)
        .value()
        .expect("the seeded raw editor must expose its text");
    assert!(seeded.contains("future-mask"), "seeded text: {seeded}");

    // Invalid raw JSON: never commits to the draft, so only the buffer-dirty
    // gate can enable Discard. ("tru}" is not valid JSON; the text carries no
    // 'z' — the follow-up keystroke marker below.)
    replace_raw_text(&mut h, r#"{"type": "future-mask", "ok": tru}"#);
    assert!(
        raw_editor(&h)
            .value()
            .is_some_and(|text| text.contains("tru}")),
        "the invalid text must be in the buffer"
    );
    assert!(
        !discard_button(&h).accesskit_node().is_disabled(),
        "Discard must be enabled while the raw editor holds invalid \
         uncommitted text"
    );
    assert!(
        validate_button(&h).accesskit_node().is_disabled(),
        "Validate must stay disabled: invalid text never commits, so there \
         is no draft change to validate and save"
    );

    // Discard changes: the buffers clear and the editor re-seeds from the
    // persisted profile. The click's frame still renders the tab before the
    // buffer clear runs, so step a second frame for the re-seeded editor.
    discard_button(&h).click();
    h.run();
    h.run_steps(4);

    assert_eq!(
        raw_editor(&h).value().unwrap(),
        seeded,
        "after Discard the raw editor must re-seed from the persisted \
         profile instead of keeping the invalid text"
    );

    // A later keystroke must commit the reverted text, never the discarded
    // JSON. egui preserves the cursor offset across the re-seed, so the
    // character lands wherever the old cursor pointed — the contract is the
    // CONTENT: exactly one added character on the seeded base, and none of
    // the discarded JSON.
    raw_editor(&h).focus();
    h.run();
    raw_editor(&h).type_text("z");
    h.run();
    let after = raw_editor(&h).value().unwrap();
    assert!(
        !after.contains("tru}"),
        "the discarded invalid JSON must not recommit; got: {after}"
    );
    assert_eq!(
        after.len(),
        seeded.len() + 1,
        "exactly the typed character may be added; got: {after}"
    );
    assert_eq!(
        after.matches('z').count(),
        1,
        "the typed character must land exactly once; got: {after}"
    );
}

/// The valid-edit path must keep working exactly as before: valid JSON
/// commits, enables Discard, and Discard reverts the editor to the
/// persisted text.
#[test]
fn valid_raw_edit_still_enables_discard_and_reverts() {
    let (_lock, _tmp, mut h) = harness_with_raw(json!({"type": "future-mask", "ok": true}));
    open_advanced_tab(&mut h);

    let seeded = raw_editor(&h)
        .value()
        .expect("the seeded raw editor must expose its text");

    replace_raw_text(&mut h, r#"{"type": "future-mask", "ok": false}"#);
    assert_eq!(
        raw_editor(&h).value().unwrap(),
        r#"{"type": "future-mask", "ok": false}"#
    );
    assert!(
        !discard_button(&h).accesskit_node().is_disabled(),
        "a committed valid edit must enable Discard as before"
    );

    discard_button(&h).click();
    h.run();
    h.run_steps(4);
    assert_eq!(
        raw_editor(&h).value().unwrap(),
        seeded,
        "after Discard the raw editor must re-seed from the persisted profile"
    );
}
