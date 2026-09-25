//! The screen-test fixture: the state a test wants the app to boot with, and
//! the navigation that gets it to the screen under test.
//!
//! A sibling of `common` rather than a part of it, because these helpers are
//! only compiled by the test binaries that declare this module: a binary that
//! boots the app without seeding state (or without navigating) would otherwise
//! carry them as dead code, and the repository forbids the lint attribute that
//! would silence it.
//!
//! Include it beside `common`:
//!
//! ```text
//! #[path = "common/screen.rs"]
//! mod screen;
//! ```

use broccoli::app::BroccoliApp;
use broccoli::model::{ServersFile, Settings};
use egui_kittest::Harness;
use parking_lot::MutexGuard;

use crate::common::{TempEnvironment, boot};

/// The state a test wants the app to boot with — the settings and the server
/// list the boot reads.
///
/// Written through the app's own save path (`Settings::save` /
/// `ServersFile::save`), so a test states the state it wants and the fixture
/// owns the storage layout: a file name, an encoding, or a migration touches
/// this file rather than every test that seeds one.
#[derive(Clone, Default)]
pub struct BootState {
    pub settings: Settings,
    /// The server list; the default (no profiles) boots the app with an empty
    /// list, which is what a test that only cares about settings wants.
    pub servers: ServersFile,
}

/// Boot with a [`BootState`] pre-written through the app's own writers.
pub fn boot_state(
    state: BootState,
    frame_step: Option<f32>,
) -> (
    MutexGuard<'static, ()>,
    TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    boot(
        move |_root| {
            state
                .settings
                .save()
                .expect("seed settings.json through the app's own writer");
            state
                .servers
                .save()
                .expect("seed servers.json through the app's own writer");
        },
        frame_step,
    )
}
