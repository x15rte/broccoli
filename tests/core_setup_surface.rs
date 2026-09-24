//! The core setup surface and the terminal error block, driven through the
//! real app shell: the startup dialog's stale-core wording, the Connect gate
//! that fails visibly instead of doing nothing, the status zone that keeps the
//! phase beside the error chip, and the wrapped message block in the content
//! area.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! A temporary APPDATA still isolates persistence, downloaded assets, and
//! logs. Tests are serialized because changing a process environment variable
//! while another harness/runtime thread reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::diag::Diag;
use broccoli::i18n::{Key, t, t_fmt};
use broccoli::model::settings::Language;
use broccoli::rt::{CoreEvt, CorePhase, DownloadState, PhaseError};
use broccoli::sys::core_dl;
use broccoli::ui::Screen;
use egui_kittest::{Harness, kittest::Queryable as _};
use parking_lot::{Mutex, MutexGuard};

static APPDATA_LOCK: Mutex<()> = Mutex::new(());

/// The release version a seeded stale tree names: a build other than this one.
const STALE_VERSION: &str = "26.7.28";

/// The managed core's release metadata file name.
const RELEASE_METADATA: &str = ".broccoli-official-release.json";

/// Boot the real app against a temp APPDATA, optionally seeded with a managed
/// core tree that names another build's release — the stale install an app
/// update leaves behind (its payloads are not this build's, and its own
/// metadata says so).
fn boot(
    stale_core: bool,
) -> (
    MutexGuard<'static, ()>,
    tempfile::TempDir,
    Harness<'static, BroccoliApp>,
) {
    let lock = APPDATA_LOCK.lock();
    let tmp = tempfile::tempdir().unwrap();
    if stale_core {
        let core = tmp.path().join("broccoli").join("core");
        std::fs::create_dir_all(&core).unwrap();
        // Every field of the release metadata must be present for it to parse;
        // the version is what makes this tree a stale install, and the pin
        // compares fail on the metadata before any payload is hashed.
        for payload in ["xray.exe", "wintun.dll", "geoip.dat", "geosite.dat"] {
            std::fs::write(core.join(payload), b"another build's payload").unwrap();
        }
        let metadata = serde_json::json!({
            "schema": 0,
            "archive_asset": "other-build.zip",
            "archive_sha256": "0".repeat(64),
            "xray_sha256": "0".repeat(64),
            "wintun_sha256": "0".repeat(64),
            "geoip_sha256": "0".repeat(64),
            "geosite_sha256": "0".repeat(64),
            "version": STALE_VERSION,
        });
        std::fs::write(
            core.join(RELEASE_METADATA),
            serde_json::to_vec(&metadata).unwrap(),
        )
        .unwrap();
    }
    // SAFETY: APPDATA_LOCK excludes every test in this process that changes or
    // reads APPDATA through a BroccoliApp harness.
    unsafe { std::env::set_var("APPDATA", tmp.path()) };

    let mut h = Harness::new_eframe(|cc| BroccoliApp::new_headless(cc));
    h.set_size(egui::Vec2::new(1100.0, 720.0));
    h.run();
    (lock, tmp, h)
}

/// Dismiss the first-run wizard ("Set up later") — a fresh temp APPDATA has no
/// core, so the modal covers the window until then.
fn dismiss_wizard(h: &mut Harness<'static, BroccoliApp>) {
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Set up later")
        .click();
    h.run();
    assert!(
        h.query_all_by_label(t(Language::En, Key::WizardWelcome))
            .next()
            .is_none(),
        "the first-run wizard must be dismissed before probing the shell"
    );
}

/// A stale tree is an update, not a first install: the startup dialog names
/// both versions, and the surface carries the verification failure's own text.
#[test]
fn stale_core_dialog_names_both_versions_and_the_reason() {
    let (_lock, _tmp, h) = boot(true);

    let intro = t_fmt(
        Language::En,
        Key::WizardCoreUpdateRequired,
        &[&STALE_VERSION, &core_dl::pinned_core_version()],
    );
    assert!(
        h.query_all_by_label(intro.as_str()).next().is_some(),
        "the dialog must name the installed and the required version: {intro:?}"
    );
    assert!(
        h.query_all_by_label(t(Language::En, Key::WizardCoreMissing))
            .next()
            .is_none(),
        "a core that is present but stale is an update, not a first install"
    );
    for label in [
        t_fmt(
            Language::En,
            Key::CoreSetupInstalledVersionRow,
            &[&STALE_VERSION],
        ),
        t_fmt(
            Language::En,
            Key::CoreSetupRequiredVersionRow,
            &[&core_dl::pinned_core_version()],
        ),
    ] {
        assert!(
            h.query_all_by_label(label.as_str()).next().is_some(),
            "the surface must show {label:?}"
        );
    }
    assert!(
        h.query_all_by_label_contains(t(Language::En, Key::CoreDlMetadataMismatch))
            .next()
            .is_some(),
        "the verification failure's own text must render"
    );
    assert!(
        h.query_by_label(t(Language::En, Key::CoreSetupVerify))
            .is_some(),
        "the surface must offer the on-demand verification"
    );
}

/// Connect with no usable core fails visibly: the phase stays in the readout,
/// the status zone chips the message, the wrapped block carries it in the
/// content area, and its button opens the Settings screen that holds the core
/// setup section.
#[test]
fn connect_without_a_core_fails_in_the_content_area_and_opens_setup() {
    let (_lock, _tmp, mut h) = boot(false);
    dismiss_wizard(&mut h);

    h.get_all_by_role_and_label(
        egui::accesskit::Role::Button,
        t(Language::En, Key::PhaseConnect),
    )
    .next()
    .expect("the shell must render a Connect button")
    .click();
    h.run_steps(4);

    let gate = t(Language::En, Key::ConnectBlockedInstallCore);
    assert!(
        h.query_all_by_label(gate).next().is_some(),
        "the blocked attempt must fail visibly with {gate:?}"
    );
    assert!(
        h.query_all_by_label(t(Language::En, Key::AppPhaseStopped))
            .next()
            .is_some(),
        "the phase readout must keep the phase while the message stands"
    );
    assert!(
        h.query_all_by_label(t(Language::En, Key::TopbarErrorChip))
            .next()
            .is_some(),
        "the status zone must chip the terminal message"
    );

    // The message persists across frames until the state changes or an action
    // succeeds — it is not a transient toast.
    h.run_steps(10);
    assert!(
        h.query_all_by_label(gate).next().is_some(),
        "the terminal message must persist across frames"
    );

    // The block's button opens the core setup surface (the Settings section
    // that stays mounted in every core state).
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        t(Language::En, Key::DashboardOpenCoreSetup),
    )
    .click();
    h.run();
    assert!(
        h.query_all_by_label(t(Language::En, Key::SettingsAppearance))
            .next()
            .is_some(),
        "the button must open the Settings screen"
    );
    let required = t_fmt(
        Language::En,
        Key::CoreSetupRequiredVersionRow,
        &[&core_dl::pinned_core_version()],
    );
    assert!(
        h.query_all_by_label(required.as_str()).next().is_some(),
        "the Settings mount must carry the core setup surface: {required:?}"
    );
}

/// A start failure keeps the phase in the status zone, renders its message and
/// captured core output in the content area, persists across frames, clears
/// when the phase moves, and its chip jumps back to the message from another
/// screen.
#[test]
fn phase_error_keeps_the_phase_and_persists_until_the_phase_moves() {
    let (_lock, _tmp, mut h) = boot(false);
    dismiss_wizard(&mut h);

    let captured = "[stderr] failed to bind the API port";
    h.state().inject_event(CoreEvt::State(CorePhase::Error(
        PhaseError::new(Diag::new(Key::RtPhaseReadinessTimeout).arg(7)).with_tail(captured.into()),
    )));
    h.run_steps(30);

    let headline = t_fmt(Language::En, Key::RtPhaseReadinessTimeout, &[&7]);
    assert!(
        h.query_all_by_label(t(Language::En, Key::AppPhaseError))
            .next()
            .is_some(),
        "the phase must stay visible while the error stands"
    );
    assert!(
        h.query_all_by_label(t(Language::En, Key::TopbarErrorChip))
            .next()
            .is_some(),
        "the compact chip must stand beside the phase"
    );
    assert!(
        h.query_all_by_label(headline.as_str()).next().is_some(),
        "the message must render in the content area: {headline:?}"
    );
    assert!(
        h.query_all_by_label_contains(captured).next().is_some(),
        "the captured core output must render behind the message"
    );
    assert!(
        h.query_all_by_label(t(Language::En, Key::ProbeDiagnosticsWall))
            .next()
            .is_some(),
        "the captured output must render under its shared header"
    );

    h.run_steps(10);
    assert!(
        h.query_all_by_label(headline.as_str()).next().is_some(),
        "the message must persist across frames"
    );

    // The chip jumps back to the message from another screen.
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Settings.label(Language::En),
    )
    .click();
    h.run();
    assert!(
        h.query_all_by_label(headline.as_str()).next().is_none(),
        "the wrapped block lives in the content area, not over every screen"
    );
    h.get_all_by_label(t(Language::En, Key::TopbarErrorChip))
        .next()
        .expect("the status zone must chip the terminal message")
        .click();
    h.run();
    assert!(
        h.query_all_by_label(headline.as_str()).next().is_some(),
        "the chip must jump to the message"
    );

    // The phase moving on is the state change that clears it.
    h.state().inject_event(CoreEvt::State(CorePhase::Stopped));
    h.run_steps(30);
    assert!(
        h.query_all_by_label(headline.as_str()).next().is_none(),
        "a phase move must clear the message"
    );
    assert!(
        h.query_all_by_label(t(Language::En, Key::TopbarErrorChip))
            .next()
            .is_none(),
        "the chip must go with the message"
    );
}

/// The terminal message the content block renders stands while the failure
/// does: recorded with the phase, it keeps rendering on every idle frame.
///
/// The block and the chip borrow the text `TerminalError` formatted at record
/// time, so a redundant per-frame re-format would render identical text: the
/// rendered label is the observable half of that memo.
#[test]
fn terminal_message_keeps_rendering_while_the_failure_stands() {
    let (_lock, _tmp, mut h) = boot(false);
    dismiss_wizard(&mut h);

    h.state()
        .inject_event(CoreEvt::State(CorePhase::Error(PhaseError::new(
            Diag::new(Key::RtPhaseRestartCancelled),
        ))));
    h.run_steps(30);
    assert!(
        h.query_all_by_label(t(Language::En, Key::RtPhaseRestartCancelled))
            .next()
            .is_some(),
        "recording the failure must render its message in the block"
    );

    h.run_steps(30);
    assert!(
        h.query_all_by_label(t(Language::En, Key::RtPhaseRestartCancelled))
            .next()
            .is_some(),
        "the block must still carry the rendered message on idle frames"
    );
}

/// Connect with a stale core fails with the versions it must reconcile, not
/// with a missing-core message.
#[test]
fn connect_with_a_stale_core_names_both_versions() {
    let (_lock, _tmp, mut h) = boot(true);
    dismiss_wizard(&mut h);

    h.get_all_by_role_and_label(
        egui::accesskit::Role::Button,
        t(Language::En, Key::PhaseConnect),
    )
    .next()
    .expect("the shell must render a Connect button")
    .click();
    h.run_steps(4);

    let gate = t_fmt(
        Language::En,
        Key::ConnectBlockedCoreUpdate,
        &[&STALE_VERSION, &core_dl::pinned_core_version()],
    );
    assert!(
        h.query_all_by_label(gate.as_str()).next().is_some(),
        "the blocked attempt must name the installed and the required version: {gate:?}"
    );
    assert!(
        h.query_all_by_label(t(Language::En, Key::ConnectBlockedInstallCore))
            .next()
            .is_none(),
        "a stale core is not a missing core"
    );
}

/// A rollback terminal re-derives the facts from the tree on disk: the
/// install claimed success, the transaction then restored the previous tree,
/// and the surface must read what is actually installed — not the
/// candidate's verified claim.
#[test]
fn a_rollback_terminal_re_derives_the_installed_tree() {
    let (_lock, _tmp, mut h) = boot(false);
    dismiss_wizard(&mut h);

    // The synthetic install runs to its verified success while no tree
    // exists on disk (the state a gate rollback leaves behind, where the
    // restored tree no longer matches the new pin).
    h.state()
        .inject_event(CoreEvt::Download(DownloadState::Working {
            stage: Diag::new(Key::CoreSetupHealthCheck),
            done: 0,
            total: 0,
        }));
    h.state()
        .inject_event(CoreEvt::Download(DownloadState::Done(
            core_dl::pinned_core_version().to_owned(),
        )));
    h.run_steps(30);
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Settings.label(Language::En),
    )
    .click();
    h.run();
    assert!(
        h.query_all_by_label(t(Language::En, Key::CoreSetupInstalled))
            .next()
            .is_some(),
        "the install's success event claims a verified tree first"
    );

    // The transaction's terminal reports the rollback: the facts must come
    // from the tree the transaction left, not from the candidate.
    h.state()
        .inject_event(CoreEvt::Download(DownloadState::Failed(
            Diag::new(Key::RtFrameUpdatedCoreSpawnRestored).into(),
        )));
    h.run_steps(30);
    assert!(
        h.query_all_by_label(t(Language::En, Key::CoreSetupInstalled))
            .next()
            .is_none(),
        "the candidate's verified claim must not survive the rollback"
    );
    assert!(
        h.query_all_by_label(t(Language::En, Key::CoreSetupNoInstalledVersion))
            .next()
            .is_some(),
        "the versions row must read the tree the transaction left, not the candidate"
    );
}

/// After a rollback the Connect gate reads the restored tree: the attempt
/// fails with the versions the restored install actually carries instead of
/// starting a doomed spawn against the candidate's pin.
#[test]
fn a_rollback_leaves_the_gate_reading_the_restored_tree() {
    let (_lock, _tmp, mut h) = boot(true);
    dismiss_wizard(&mut h);

    h.state()
        .inject_event(CoreEvt::Download(DownloadState::Working {
            stage: Diag::new(Key::CoreSetupHealthCheck),
            done: 0,
            total: 0,
        }));
    h.state()
        .inject_event(CoreEvt::Download(DownloadState::Done(
            core_dl::pinned_core_version().to_owned(),
        )));
    h.run_steps(30);
    h.state()
        .inject_event(CoreEvt::Download(DownloadState::Failed(
            Diag::new(Key::RtFrameUpdatedCoreSpawnRestored).into(),
        )));
    h.run_steps(30);

    h.get_all_by_role_and_label(
        egui::accesskit::Role::Button,
        t(Language::En, Key::PhaseConnect),
    )
    .next()
    .expect("the shell must render a Connect button")
    .click();
    h.run_steps(4);

    let gate = t_fmt(
        Language::En,
        Key::ConnectBlockedCoreUpdate,
        &[&STALE_VERSION, &core_dl::pinned_core_version()],
    );
    assert!(
        h.query_all_by_label(gate.as_str()).next().is_some(),
        "the gate must read the restored tree and name both versions: {gate:?}"
    );
}

/// The Settings section documents what the state, an install, and a failure
/// mean: the note renders under the state row there and never in the startup
/// dialog, which keeps its own shorter wording.
#[test]
fn core_setup_note_renders_in_the_settings_section() {
    let (_lock, _tmp, mut h) = boot(true);

    let note = t(Language::En, Key::CoreSetupNote);
    assert!(
        h.query_all_by_label(note).next().is_none(),
        "the note belongs to the Settings section, not to the dialog"
    );

    dismiss_wizard(&mut h);
    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        Screen::Settings.label(Language::En),
    )
    .click();
    h.run();
    assert!(
        h.query_all_by_label(note).next().is_some(),
        "the Settings section must carry the explanation it documents: {note:?}"
    );
}

/// Verify re-checks the installed tree on demand: with the tree gone since
/// boot, the fresh pass reports the state that exists now instead of the
/// memoized one, and the dialog's wording follows it.
#[test]
fn verify_rechecks_the_installed_tree_on_demand() {
    let (_lock, tmp, mut h) = boot(true);
    let stale_state = t(Language::En, Key::CoreSetupUpdateRequired);
    assert!(
        h.query_all_by_label(stale_state).next().is_some(),
        "the seeded stale tree must read as an update first"
    );

    // The tree disappears while the app runs — inside the render memo's
    // lifetime, so only a fresh pass can observe it.
    std::fs::remove_dir_all(tmp.path().join("broccoli").join("core")).unwrap();

    h.get_by_role_and_label(
        egui::accesskit::Role::Button,
        t(Language::En, Key::CoreSetupVerify),
    )
    .click();
    h.run_steps(4);

    assert!(
        h.query_all_by_label(t(Language::En, Key::CoreSetupNotInstalled))
            .next()
            .is_some(),
        "Verify must re-check the tree and report the state it finds"
    );
    assert!(
        h.query_all_by_label(stale_state).next().is_none(),
        "the memoized verdict must not survive a fresh pass"
    );
    assert!(
        h.query_all_by_label(t(Language::En, Key::WizardCoreMissing))
            .next()
            .is_some(),
        "the dialog's wording must follow the re-checked state"
    );
}

/// A successful install is an action success: it clears the message it
/// answered, and it never resumes the blocked attempt by itself.
#[test]
fn install_success_clears_the_message_without_resuming_the_attempt() {
    let (_lock, _tmp, mut h) = boot(false);
    dismiss_wizard(&mut h);

    h.get_all_by_role_and_label(
        egui::accesskit::Role::Button,
        t(Language::En, Key::PhaseConnect),
    )
    .next()
    .expect("the shell must render a Connect button")
    .click();
    h.run_steps(4);
    let gate = t(Language::En, Key::ConnectBlockedInstallCore);
    assert!(
        h.query_all_by_label(gate).next().is_some(),
        "the blocked attempt must fail visibly first"
    );

    h.state()
        .inject_event(CoreEvt::Download(DownloadState::Done(
            core_dl::pinned_core_version().to_owned(),
        )));
    h.run_steps(30);

    assert!(
        h.query_all_by_label(gate).next().is_none(),
        "a successful install clears the message it answered"
    );
    assert!(
        h.query_all_by_label(t(Language::En, Key::AppPhaseStopped))
            .next()
            .is_some(),
        "the install must not resume the attempt: the phase stays Stopped"
    );
}
