//! Raw JSON editors parse only when their text
//! changes (revision-gated), and per-field buffer keys are derived from the
//! field's egui `Id` instead of being rebuilt with `format!` per frame.
//!
//! Contract under test:
//! - an open raw editor does zero parse work across idle frames,
//! - one text edit triggers exactly one parse (never one per frame),
//! - invalid JSON surfaces the validation error and keeps it across idle
//!   frames without re-parsing,
//! - replacing the text with valid JSON parses exactly once and clears the
//!   error.
//!
//! The seeded profile carries a ~45 KiB preserved-raw config so the editor
//! handles the same bulk the baseline harness seeds (large raw configs must
//! round-trip through the preserved-raw flow).
//!
//! Eviction: deleting the profile drops its cache entries
//! (resource counter to zero) and renaming it never grows the cache.

use broccoli::app::BroccoliApp;
use broccoli::model::{
    FinalmaskModel, FinalmaskTcpMask, OutboundModel, Protocol, ServerProfile, ServersFile, Settings,
};
use egui_kittest::{Harness, kittest::Queryable};
use parking_lot::{Mutex, MutexGuard};
use serde_json::{Value, json};

/// Serializes every test in this binary that mutates or reads the process
/// APPDATA env var (the `tests/ui_smoke.rs` convention: env mutation while
/// another thread reads it is undefined behavior). Each test binary has its
/// own process, so no cross-binary lock is needed.
static APPDATA_LOCK: Mutex<()> = Mutex::new(());

/// A deliberately large preserved-raw config (~45 KiB, structured), matching
/// the bulk the baseline harness seeds into profiles.
fn large_raw_value(seed: u64) -> Value {
    json!({
        "type": "future-mask",
        "seed": seed,
        "payload": {
            "entries": (0..1024)
                .map(|i| format!("{seed:04x}-{i:04x}-{}", "r".repeat(32)))
                .collect::<Vec<_>>(),
        },
    })
}

/// Boot the app against a temp APPDATA seeded with one active profile whose
/// finalmask holds an unknown (preserved-raw) TCP mask.
fn harness_with_raw(
    raw: Value,
) -> (
    MutexGuard<'static, ()>,
    tempfile::TempDir,
    Harness<'static, BroccoliApp>,
) {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    // SAFETY: APPDATA_LOCK excludes every test in this process that changes
    // or reads APPDATA through a BroccoliApp harness.
    unsafe { std::env::set_var("APPDATA", tmp.path()) };

    let broccoli_root = tmp.path().join("broccoli");
    std::fs::create_dir_all(broccoli_root.join("state")).unwrap();
    std::fs::create_dir_all(broccoli_root.join("config")).unwrap();
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
    std::fs::write(
        broccoli_root.join("state/servers.json"),
        serde_json::to_vec_pretty(&servers).unwrap(),
    )
    .unwrap();
    let mut settings = Settings::default();
    settings.routing.observatory.enabled = false;
    settings.routing.burst_observatory.enabled = false;
    std::fs::write(
        broccoli_root.join("state/settings.json"),
        serde_json::to_vec_pretty(&settings).unwrap(),
    )
    .unwrap();

    let h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    (lock, tmp, h)
}

/// The only multiline text input on the Advanced tab: the preserved-raw JSON
/// editor of the unknown finalmask.
fn raw_editor<'a>(h: &'a Harness<'a, BroccoliApp>) -> egui_kittest::Node<'a> {
    h.get_by_role(egui::accesskit::Role::MultilineTextInput)
}

/// Dismiss the first-run wizard, open the Servers screen (the seeded profile
/// is active, so its editor is already open), and switch to the Advanced tab
/// where the raw editor lives.
fn open_advanced_tab(h: &mut Harness<'static, BroccoliApp>) {
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Servers")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Advanced")
        .click();
    h.run();
}

fn raw_editor_parses(h: &Harness<'static, BroccoliApp>) -> u64 {
    h.state().metrics_snapshot().raw_editor_parses
}

/// Contract (a): an open raw editor does zero parse work across idle
/// frames, while the ~45 KiB seeded text keeps rendering.
#[test]
fn open_raw_editor_idle_frames_do_not_reparse() {
    let (_lock, _tmp, mut h) = harness_with_raw(large_raw_value(7));
    open_advanced_tab(&mut h);

    // Opening the Advanced tab seeded the buffer (a parse is a real event),
    // so assert on the delta across the idle window.
    let before = raw_editor_parses(&h);
    h.run_steps(120);
    assert_eq!(
        raw_editor_parses(&h) - before,
        0,
        "idle frames must not re-parse an open raw editor"
    );
}

/// Contract (b): one text edit triggers exactly one parse, and idle
/// frames after the edit do not re-parse.
#[test]
fn editing_raw_text_parses_exactly_once_per_edit() {
    let (_lock, _tmp, mut h) = harness_with_raw(large_raw_value(3));
    open_advanced_tab(&mut h);

    // A fresh focus places the cursor at the end of the text; one Text event
    // is one edit.
    raw_editor(&h).focus();
    h.run();
    let before = raw_editor_parses(&h);
    raw_editor(&h).type_text("x");
    h.run();
    assert_eq!(
        raw_editor_parses(&h) - before,
        1,
        "one text edit must trigger exactly one parse"
    );

    // Idle frames after the edit must not re-parse.
    h.run_steps(10);
    assert_eq!(
        raw_editor_parses(&h) - before,
        1,
        "idle frames after an edit must not re-parse"
    );
}

/// Contract (c): editing the text into invalid JSON surfaces the
/// validation error, and the error keeps rendering across idle frames
/// without re-parsing.
#[test]
fn invalid_json_shows_validation_error_until_fixed() {
    let (_lock, _tmp, mut h) = harness_with_raw(large_raw_value(5));
    open_advanced_tab(&mut h);

    // The seeded text parses clean: no error on first render.
    assert!(
        h.query_by_label_contains("invalid JSON").is_none(),
        "the seeded raw config must parse clean"
    );

    raw_editor(&h).focus();
    h.run();
    raw_editor(&h).type_text("x"); // trailing garbage: no longer valid JSON
    h.run();
    assert!(
        h.query_by_label_contains("invalid JSON").is_some(),
        "editing the raw text into invalid JSON must surface the validation error"
    );

    // The error keeps rendering on idle frames without re-parsing.
    let before = raw_editor_parses(&h);
    h.run_steps(10);
    assert_eq!(
        raw_editor_parses(&h) - before,
        0,
        "idle frames must not re-parse to keep the error visible"
    );
    assert!(
        h.query_by_label_contains("invalid JSON").is_some(),
        "the validation error must persist across idle frames"
    );
}

/// Contract (d): replacing the text with valid JSON parses exactly
/// once and clears the error.
#[test]
fn valid_json_parses_and_clears_the_error() {
    let (_lock, _tmp, mut h) = harness_with_raw(large_raw_value(9));
    open_advanced_tab(&mut h);

    raw_editor(&h).focus();
    h.run();
    raw_editor(&h).type_text("x");
    h.run();
    assert!(h.query_by_label_contains("invalid JSON").is_some());

    // Select all and replace with a complete valid document: one edit, one
    // parse, error gone.
    h.key_combination_modifiers(egui::Modifiers::COMMAND, &[egui::Key::A]);
    h.run();
    let before = raw_editor_parses(&h);
    raw_editor(&h).type_text(r#"{"type":"custom","ok":true}"#);
    h.run();
    assert_eq!(
        raw_editor_parses(&h) - before,
        1,
        "a valid replacement must parse exactly once"
    );
    assert!(
        h.query_by_label_contains("invalid JSON").is_none(),
        "valid JSON must clear the validation error"
    );
}

/// Contract (e): deleting the profile evicts its raw-editor cache
/// entries — the resource counter drops to zero, and idle frames afterwards
/// stay at zero.
#[test]
fn deleting_the_profile_evicts_its_raw_editor_entries() {
    let (_lock, _tmp, mut h) = harness_with_raw(large_raw_value(11));
    open_advanced_tab(&mut h);
    assert_eq!(
        h.state().metrics_snapshot().raw_editor_cache_entries,
        1,
        "the open raw editor must be cached"
    );

    h.get_by_role_and_label(egui::accesskit::Role::Button, "🗑")
        .click();
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Delete")
        .click();
    h.run_steps(4);
    assert_eq!(
        h.state().metrics_snapshot().raw_editor_cache_entries,
        0,
        "deleting the profile must evict its raw-editor entries"
    );
    // Idle frames must not resurrect cache entries.
    h.run_steps(30);
    assert_eq!(h.state().metrics_snapshot().raw_editor_cache_entries, 0);
}

/// Contract (f): renaming the profile (name-only; the id is
/// immutable) keeps its raw-editor buffer keyed and bounded — repeated
/// renames never grow the cache, and idle frames never touch it.
#[test]
fn renaming_the_profile_keeps_raw_editor_entries_bounded() {
    let (_lock, _tmp, mut h) = harness_with_raw(large_raw_value(13));
    open_advanced_tab(&mut h);
    assert_eq!(h.state().metrics_snapshot().raw_editor_cache_entries, 1);

    // The profile name field is the first singleline text input of the
    // editor (the name row renders above the tabs on every tab).
    for _ in 0..3 {
        h.get_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("profile name field")
            .focus();
        h.run();
        h.get_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("profile name field")
            .type_text("X");
        h.run();
        assert_eq!(
            h.state().metrics_snapshot().raw_editor_cache_entries,
            1,
            "a rename must not grow the raw-editor cache"
        );
    }
    // Idle frames must not touch the cache either.
    h.run_steps(30);
    assert_eq!(h.state().metrics_snapshot().raw_editor_cache_entries, 1);
}
