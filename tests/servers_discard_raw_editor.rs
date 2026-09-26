//! Regression loop: Discard changes must clear the finalmask raw-JSON editor
//! buffers so the editor re-seeds from the reverted draft.
//!
//! Suspected bug: `ServersScreen::show_editor` clears `pem_buffers` on
//! Discard but omits `finalmask_raw`; the `JsonBuf` re-seeds only when its
//! egui-Id key changes (the key embeds the immutable profile id), so after
//! Discard the raw-JSON field keeps showing the discarded text and the next
//! keystroke silently re-commits it into the draft.
//!
//! Drives the real app through egui_kittest: boot with a seeded profile
//! carrying an unknown preserved-raw finalmask TCP mask, open the Advanced
//! tab, replace the raw text with valid JSON (a real discarded edit — invalid
//! text never commits and would not enable Discard), Discard, and assert the
//! editor holds the persisted text again.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::settings::Language;
use broccoli::model::{
    FinalmaskModel, FinalmaskTcpMask, OutboundModel, Protocol, ServerProfile, ServersFile, Settings,
};
use egui_kittest::{Harness, kittest::Queryable};
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

/// The preserved-raw JSON editor's own label: the editor is addressed by this
/// accessible name, never as the Advanced tab's only multiline field.
fn raw_editor_label() -> &'static str {
    t(Language::En, Key::SrvPreservedRawValue)
}

/// The preserved-raw JSON editor of the unknown finalmask.
fn raw_editor<'a>(h: &'a Harness<'a, BroccoliApp>) -> egui_kittest::Node<'a> {
    h.get_by_role_and_label(
        egui::accesskit::Role::MultilineTextInput,
        raw_editor_label(),
    )
}

/// Dismiss the first-run wizard, open the Servers screen (the seeded profile
/// is active, so its editor is already open), and switch to the Advanced tab
/// where the raw editor lives. Taller than the perf harness because the
/// editor's Validate/Discard buttons sit below the tab content; at 720 px
/// they fall off the bottom edge and egui never hit-tests them.
fn open_advanced_tab(h: &mut Harness<'static, BroccoliApp>) {
    h.set_size(egui::Vec2::new(1100.0, 1000.0));
    h.run();
    common::dismiss_wizard(h);
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Servers")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Advanced")
        .click();
    h.run();
}

/// Replace the whole editor text with one valid JSON document (select-all +
/// type), returning the new text.
fn replace_raw_text(h: &mut Harness<'static, BroccoliApp>, text: &str) {
    raw_editor(h).focus();
    h.run();
    h.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    h.run();
    raw_editor(h).type_text(text);
    h.run();
}

/// Discard changes must re-seed the finalmask raw-JSON editor from the
/// reverted draft, and a later keystroke must not pull the discarded JSON
/// back into the draft.
#[test]
fn discard_reseeds_finalmask_raw_editor_and_keystroke_does_not_recommit() {
    let (_lock, _tmp, mut h) = harness_with_raw(json!({"type": "future-mask", "ok": true}));
    open_advanced_tab(&mut h);

    let seeded = raw_editor(&h)
        .value()
        .expect("the seeded raw editor must expose its text");
    assert!(seeded.contains("future-mask"), "seeded text: {seeded}");

    // A real discarded edit: replace the whole document with different valid
    // JSON. Only valid JSON commits to the draft (invalid text stays in the
    // buffer with an error), so this is what enables Discard.
    replace_raw_text(&mut h, r#"{"type":"future-mask","ok":false}"#);
    let edited = raw_editor(&h).value().unwrap();
    assert_eq!(edited, r#"{"type":"future-mask","ok":false}"#);

    // Discard changes: the draft reverts to the persisted profile. The
    // click's frame still renders the tab before the buffer clear runs, so
    // step a second frame for the re-seeded editor.
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Discard changes")
        .click();
    h.run();
    h.run_steps(4);

    // …and the raw-JSON editor must show the persisted text again, not the
    // discarded edit.
    assert_eq!(
        raw_editor(&h).value().unwrap(),
        seeded,
        "after Discard the raw editor must re-seed from the reverted draft \
         instead of keeping the discarded text"
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
        !after.contains(r#""ok": false"#),
        "the discarded JSON must not recommit; got: {after}"
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
