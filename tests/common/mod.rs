//! Shared boot fixture for the screen tests that drive the real `BroccoliApp`
//! through kittest: the temporary `APPDATA` tree, the process-wide environment
//! lock, the headless eframe harness, and the first-run wizard dismissal.
//!
//! The fixture is harness-bound by design: the lock, the redirect and the app
//! under kittest are one step, which is what a screen test needs. The
//! runtime-level tests that drive `spawn_runtime` directly keep guards of their
//! own: they never build the app, and an app boot is not inert — it sweeps
//! scratch state out of the temp tree and creates the state directories, in the
//! very tree those tests assert on.
//!
//! Safety: production startup is read-only with respect to Windows settings.
//! A temporary APPDATA still isolates persistence, downloaded assets, and
//! logs. Tests are serialized because changing a process environment variable
//! while another harness or runtime thread reads it is undefined behavior.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::settings::Language;
use egui::accesskit::Role;
use egui_kittest::{Harness, kittest::Queryable as _};
use parking_lot::{Mutex, MutexGuard};
use std::ffi::OsString;
use std::path::Path;

/// Serializes every test in this process that changes a process environment
/// variable a harness reads. [`boot`] takes it before the first mutation and
/// hands it out as the fixture tuple's first element, so it is released after
/// everything it protects has been dropped.
static APPDATA_LOCK: Mutex<()> = Mutex::new(());

/// The fixture's temp root and the process environment variables pointing at
/// it: `APPDATA` (whose `broccoli/` subtree holds the app's state),
/// `TMP`/`TEMP` (where the app stages temporary files, e.g. an isolated
/// latency probe's throwaway core). Every redirected variable is restored on
/// drop, which runs while the serialization guard is still held — the guard
/// is the fixture tuple's first element and therefore drops last.
pub struct TempEnvironment {
    dir: tempfile::TempDir,
    appdata: Option<OsString>,
    tmp: Option<OsString>,
    temp: Option<OsString>,
}

impl TempEnvironment {
    /// Take ownership of `root` and point `APPDATA`/`TMP`/`TEMP` at it.
    fn redirect(root: tempfile::TempDir) -> Self {
        let previous = Self {
            appdata: std::env::var_os("APPDATA"),
            tmp: std::env::var_os("TMP"),
            temp: std::env::var_os("TEMP"),
            dir: root,
        };
        // SAFETY: the caller holds APPDATA_LOCK, which excludes every other
        // test that changes or reads these variables through a harness.
        unsafe {
            std::env::set_var("APPDATA", previous.dir.path());
            std::env::set_var("TMP", previous.dir.path());
            std::env::set_var("TEMP", previous.dir.path());
        }
        previous
    }

    /// The temp root. The app's state lives under `broccoli/` inside it, and
    /// temporary files are staged directly inside it.
    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for TempEnvironment {
    fn drop(&mut self) {
        // SAFETY: the caller still holds APPDATA_LOCK until the fixture's
        // whole tuple drops, which excludes every other harness test.
        unsafe {
            match self.appdata.take() {
                Some(value) => std::env::set_var("APPDATA", value),
                None => std::env::remove_var("APPDATA"),
            }
            match self.tmp.take() {
                Some(value) => std::env::set_var("TMP", value),
                None => std::env::remove_var("TMP"),
            }
            match self.temp.take() {
                Some(value) => std::env::set_var("TEMP", value),
                None => std::env::remove_var("TEMP"),
            }
        }
    }
}

/// Boot the real app: a fresh temp `APPDATA` (isolating persistence,
/// downloaded assets, and logs), the serialization lock, and the headless
/// eframe harness. `seed` runs once the environment is in place and before the
/// app starts, so a test can pre-write the state it wants the boot to read
/// (`broccoli/state/settings.json` and friends).
///
/// `frame_step` is the simulated seconds egui advances per harness frame.
/// `None` keeps egui_kittest's own quarter-second step, which is what most
/// screen tests want; a test that pins the input clock per frame passes a
/// finer step so the frames it does not pin stay a known small distance from
/// the clock it pinned.
///
/// Bind the result as `(lock, tmp, h)`: the harness then drops first, the temp
/// tree second, and the serialization guard last.
pub fn boot(
    seed: impl FnOnce(&Path),
    frame_step: Option<f32>,
) -> (
    MutexGuard<'static, ()>,
    TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    let lock = APPDATA_LOCK.lock();
    let env = TempEnvironment::redirect(tempfile::tempdir().unwrap());
    seed(env.path());
    let mut builder = Harness::builder();
    if let Some(frame_step) = frame_step {
        builder = builder.with_step_dt(frame_step);
    }
    let h = builder.build_eframe(|cc| BroccoliApp::new_headless(cc));
    (lock, env, h)
}

/// Dismiss the first-run wizard ("Set up later"): a fresh temp APPDATA has no
/// core, so the modal covers the window and swallows nav clicks until then.
pub fn dismiss_wizard(h: &mut Harness<'static, BroccoliApp>) {
    h.get_by_role_and_label(Role::Button, t(Language::En, Key::CoreSetupSetUpLater))
        .click();
    h.run();
    assert!(
        h.query_all_by_label(t(Language::En, Key::WizardWelcome))
            .next()
            .is_none(),
        "the first-run wizard must be dismissed before navigating"
    );
}
