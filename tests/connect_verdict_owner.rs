//! One owner for the connect verdict.
//!
//! The shell's per-revision generation is the only producer: it records the
//! excerpt-bounded config-generation error and the raw-override verdict at
//! boot and on config persist, and every surface — top bar, tray, screens —
//! reads that verdict. The dashboard's Connect row renders the stored error
//! inline and never runs the generator itself: generating binds the ephemeral
//! control-plane port (`127.0.0.1:0`), which a paint pass must not do.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! A temporary APPDATA still isolates persistence, downloaded assets, and
//! logs. Tests are serialized because changing a process environment variable
//! while another harness/runtime thread reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::r#gen::generate_with_api_port;
use broccoli::i18n::{Key, t, t_fmt};
use broccoli::model::ServersFile;
use broccoli::model::settings::{Language, Mode, Settings};
use broccoli::rt::{CoreEvt, DownloadState};
use egui_kittest::{Harness, kittest::NodeT, kittest::Queryable};
use parking_lot::{Mutex, MutexGuard};

static APPDATA_LOCK: Mutex<()> = Mutex::new(());

/// A raw override that fails generation with a message longer than the
/// shell's 48-char excerpt, so the stored label is visibly bounded.
const BROKEN_RAW: &str = r#"{"api": {"listen": "127.0.0.1:10853"#;

/// A raw override that generates cleanly: a loopback control plane carrying
/// StatsService and no TUN inbound — what the shell's raw-override validation
/// requires before Connect may proceed.
const CLEAN_RAW: &str = r#"{"api": {"listen": "127.0.0.1:10853", "services": ["StatsService"]}}"#;

fn raw_settings(raw: &str) -> Settings {
    Settings {
        mode: Mode::Off,
        raw_override: Some(raw.into()),
        ..Default::default()
    }
}

/// The generation failure text for `settings`, produced with the API port
/// injected so the derivation never binds a socket.
fn generation_error(settings: &Settings) -> String {
    generate_with_api_port(&ServersFile::default(), settings, 19999)
        .expect_err("the settings must fail generation")
        .to_string()
}

/// The shell's stored text for a generation failure: the `GenerationFailed`
/// template around the 48-char excerpt every surface is bounded to before a
/// label or the log can see the raw message.
fn shell_generation_error(message: &str) -> String {
    const MAX_EXCERPT_CHARS: usize = 48;
    let mut end = MAX_EXCERPT_CHARS.min(message.len());
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    let excerpt = if end < message.len() {
        format!("{}…", &message[..end])
    } else {
        message.to_owned()
    };
    t_fmt(Language::En, Key::GenerationFailed, &[&excerpt])
}

/// Boot the real app against `settings` persisted into a temp APPDATA and
/// dismiss the first-run wizard (no core is installed, so the wizard modal
/// covers the dashboard until then).
fn boot(
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
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    (lock, tmp, h)
}

/// A raw override that cannot generate blocks Connect, and the shell's
/// stored error — excerpt-bounded — is the text the UI carries; the
/// unbounded generator message never reaches a label.
#[test]
fn broken_raw_override_blocks_connect_and_shows_the_shell_error() {
    let settings = raw_settings(BROKEN_RAW);
    let message = generation_error(&settings);
    let expected = shell_generation_error(&message);
    assert_ne!(
        expected, message,
        "the message must exceed the excerpt bound, or the label assertions cannot discriminate"
    );
    let (_lock, _tmp, h) = boot(&settings);

    assert!(
        h.query_all_by_label(expected.as_str()).next().is_some(),
        "the shell's stored generation error must render: {expected:?}"
    );
    assert!(
        h.query_by_label_contains(message.as_str()).is_none(),
        "the unbounded generator message must not reach a label: {message:?}"
    );
    let connects: Vec<_> = h
        .query_all_by_role_and_label(egui::accesskit::Role::Button, "Connect")
        .collect();
    assert!(!connects.is_empty(), "Connect buttons must exist");
    for connect in &connects {
        assert!(
            connect.accesskit_node().is_disabled(),
            "an ungeneratable raw override must block Connect"
        );
    }
}

/// Guard: a raw override that generates cleanly leaves the generation surface
/// quiet, so the blocking above cannot be blamed on a globally stuck error.
#[test]
fn clean_raw_override_leaves_the_generation_surface_quiet() {
    let (_lock, _tmp, h) = boot(&raw_settings(CLEAN_RAW));

    let template = t_fmt(Language::En, Key::GenerationFailed, &[&""]);
    assert!(
        h.query_by_label_contains(template.as_str()).is_none(),
        "a clean raw override must not surface a generation error"
    );
}

/// The Connect verdict belongs to the revision the last generation ran at:
/// the persist path re-records the raw-override verdict, so a verdict from an
/// older model state can never block Connect once the persisted model
/// generates again.
///
/// The mode radio drives the transition: a raw override may run only in Off
/// mode, so booting in TUN mode with a valid override records a generation
/// failure, and switching to Off persists (the session's first save, so not
/// throttled) and regenerates cleanly. A verified managed core is injected so
/// the install-core reason cannot mask the verdict branch — with the config
/// error cleared, the stored verdict is the only input left that can still
/// block Connect.
#[test]
fn persist_re_records_the_raw_override_verdict() {
    let settings = Settings {
        mode: Mode::Tun,
        raw_override: Some(CLEAN_RAW.into()),
        ..Default::default()
    };
    let (_lock, _tmp, mut h) = boot(&settings);
    h.state()
        .inject_event(CoreEvt::Download(DownloadState::Done("v1.0.0".into())));
    h.run_steps(30);

    let generation_text = t(Language::En, Key::RawOverrideOffMode);
    assert!(
        h.query_all_by_label(generation_text).next().is_some(),
        "the shell's stored generation error must render: {generation_text:?}"
    );
    for connect in connect_buttons(&h) {
        assert!(
            connect.accesskit_node().is_disabled(),
            "an override that cannot generate must block Connect"
        );
    }

    // Off mode makes the same override legal; the edit persists on this frame
    // and regenerates.
    h.query_all_by_role_and_label(egui::accesskit::Role::Button, t(Language::En, Key::Off))
        .next()
        .expect("the dashboard must render the Off mode radio")
        .click();
    h.run_steps(30);

    assert!(
        h.query_all_by_label(generation_text).next().is_none(),
        "the regeneration must clear the generation surface: {generation_text:?}"
    );
    for connect in connect_buttons(&h) {
        assert!(
            !connect.accesskit_node().is_disabled(),
            "the previous revision's verdict must not survive the persist"
        );
    }
}

/// Every Connect button the shell paints (top bar and dashboard).
fn connect_buttons<'a>(h: &'a Harness<'static, BroccoliApp>) -> Vec<egui_kittest::Node<'a>> {
    h.query_all_by_role_and_label(
        egui::accesskit::Role::Button,
        t(Language::En, Key::PhaseConnect),
    )
    .collect()
}
