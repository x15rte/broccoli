//! The restart hand-off between the GUI and `main`.
//!
//! A restart cannot run inside the frame loop: `eframe::run_native` owns the
//! event loop until it returns, and the single-instance mutex that turns away
//! a second launch is held by `main` for the whole run. The app therefore only
//! records the request and closes its window; `main` releases the mutex,
//! starts a replacement, and exits.

use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(debug_assertions)]
use super::inject;

/// Whether this run must hand over to a replacement process.
static RESTART_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Record that the app asked for a restart.
pub fn request() {
    RESTART_REQUESTED.store(true, Ordering::Release);
}

/// Take the restart request, clearing it, so one run starts at most one
/// replacement.
pub fn take_requested() -> bool {
    RESTART_REQUESTED.swap(false, Ordering::AcqRel)
}

/// Start a replacement of this executable, detached.
///
/// Call only after the single-instance mutex is released: the replacement
/// acquires it at startup and would otherwise be turned away as a second
/// launch. The replacement inherits this process's console, so a debug run
/// keeps its log output.
pub fn spawn_replacement() -> std::io::Result<()> {
    let executable = std::env::current_exe()?;
    let mut command = std::process::Command::new(executable);
    // The debug-only injection hooks belong to the run under test: a
    // replacement that inherited them would re-fire the fault it is recovering
    // from.
    #[cfg(debug_assertions)]
    {
        command.env_remove(inject::DEVICE_LOSS);
        command.env_remove(inject::RESTART);
    }
    command.spawn()?;
    Ok(())
}
