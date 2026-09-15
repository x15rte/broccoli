//! Exit-time maintenance: the two Settings actions — "Clean Up
//! and Exit" (full cleanup) and "Reset to default…" (keep the server list
//! and the verified core, wipe everything else) — executed by `main` after
//! the GUI has fully shut down (core/helper stopped, single-instance holder
//! released).
//!
//! Sequencing contract: the UI only stashes the request here (via
//! [`request`]). The real work runs after `eframe::run_native` returns, so
//! the app's `Drop` (core shutdown) and the tracing-worker release always
//! precede the filesystem action. Both modes are idempotent — deleting an
//! absent root (or a reset with no root) is a no-op; a reset with no
//! `servers.json` simply has nothing to preserve.

use std::io::ErrorKind;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

/// How long a deletion retries a transient in-use failure before giving up.
/// Windows can report a file as busy for a few hundred ms after the last
/// handle closes, so a short retry window absorbs the common case without
/// stalling the exit path.
const DELETE_RETRY_WINDOW: Duration = Duration::from_millis(1500);
/// Pause between deletion retries.
const DELETE_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// Which exit-time maintenance action to run after the GUI has shut down.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CleanupMode {
    /// Remove broccoli from this PC entirely: delete the whole app-data root.
    Full,
    /// Restore a fresh install's defaults while keeping the server list and
    /// the verified core: wipe everything under the root except `core/` and
    /// `state/servers.json`.
    ResetFiles,
}

/// Exit-maintenance request communicated from the UI thread to `main`, which
/// reads it after [`run`] returns — the `TRAY_EVENT_TARGET` static precedent
/// for cross-layer flags. An atomic keeps the hand-off race-free and
/// test-resettable (no one-shot `OnceLock` that would pin the first test's
/// value for the whole process). Stored as a raw byte: 0 = no request,
/// 1 = [`CleanupMode::Full`], 2 = [`CleanupMode::ResetFiles`].
static REQUESTED: AtomicU8 = AtomicU8::new(0);

/// Stash an exit-time maintenance request for the process exit path. Called
/// by the app shell right before it commits the quit through the normal
/// shutdown path; `main` consumes it with [`take_requested`] once the app is
/// gone.
pub fn request(mode: CleanupMode) {
    let stored = match mode {
        CleanupMode::Full => 1,
        CleanupMode::ResetFiles => 2,
    };
    REQUESTED.store(stored, Ordering::Relaxed);
}

/// Read and clear the stashed exit-maintenance request. `None` means the
/// session ended without one (e.g. a plain tray quit).
pub fn take_requested() -> Option<CleanupMode> {
    match REQUESTED.swap(0, Ordering::Relaxed) {
        1 => Some(CleanupMode::Full),
        2 => Some(CleanupMode::ResetFiles),
        _ => None,
    }
}

/// The filesystem half of exit maintenance: dispatches on [`CleanupMode`] —
/// [`CleanupMode::Full`] deletes the entire `%APPDATA%\broccoli` root,
/// [`CleanupMode::ResetFiles`] wipes everything except the core and the
/// server list. Both retry transient in-use failures and are no-ops when
/// their targets are absent. A residual failure still leaves a working app —
/// the next launch recreates the root via `paths::ensure_dirs` — so callers
/// log and continue rather than abort.
pub fn run(mode: CleanupMode, root: &Path) -> std::io::Result<()> {
    match mode {
        CleanupMode::Full => delete_root(root),
        CleanupMode::ResetFiles => reset_keep_servers(root),
    }
}

/// The filesystem half of "Reset to default…": deletes every child of
/// `root` except the verified `core` directory and `state/servers.json`.
/// Everything else under `state/` goes — settings, crash reports,
/// quarantines — but the `state` directory itself stays, so the next launch
/// is a fresh install that keeps the server list and skips the xray
/// re-download. Idempotent: an absent root is a no-op; with no
/// `servers.json` there is nothing to preserve and the state is wiped like
/// everything else. Never panics.
fn reset_keep_servers(root: &Path) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        if name == "core" {
            // The verified core survives so the next launch does not
            // re-download xray.
            continue;
        }
        if name == "state" {
            clear_state_keep_servers(&entry.path())?;
            continue;
        }
        remove_with_retry(&entry.path())?;
    }
    Ok(())
}

/// Delete every child of `state_dir` except `servers.json` (which carries
/// the active-profile selection), keeping the directory itself — it may end
/// up empty. An absent directory is a no-op; an absent `servers.json` just
/// means every child is deleted.
fn clear_state_keep_servers(state_dir: &Path) -> std::io::Result<()> {
    let entries = match std::fs::read_dir(state_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_name() == "servers.json" {
            continue;
        }
        remove_with_retry(&entry.path())?;
    }
    Ok(())
}

/// Delete `path` whether it is a file, a directory, or a symlink, applying
/// the shared transient-in-use retry. An absent path is success.
fn remove_with_retry(path: &Path) -> std::io::Result<()> {
    with_delete_retry(|| match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(metadata) if metadata.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
    })
}

/// Shared deletion retry policy: run `attempt` immediately; if it reports a
/// transient in-use failure, retry for [`DELETE_RETRY_WINDOW`] before the
/// last error surfaces. Non-`PermissionDenied` errors (ACL, corrupt path)
/// will not clear themselves and surface immediately. `attempt` treats an
/// absent path as success.
fn with_delete_retry(mut attempt: impl FnMut() -> std::io::Result<()>) -> std::io::Result<()> {
    match attempt() {
        Ok(()) => Ok(()),
        Err(first) => {
            if first.kind() != ErrorKind::PermissionDenied {
                // Only a transient in-use failure is worth retrying; any
                // other error (ACL, corrupt path) will not clear itself.
                return Err(first);
            }
            let deadline = Instant::now() + DELETE_RETRY_WINDOW;
            let mut last = first;
            while Instant::now() < deadline {
                std::thread::sleep(DELETE_RETRY_INTERVAL);
                match attempt() {
                    Ok(()) => return Ok(()),
                    Err(error) if error.kind() == ErrorKind::PermissionDenied => last = error,
                    Err(error) => return Err(error),
                }
            }
            Err(last)
        }
    }
}

/// Recursively delete `root`. Idempotent (an absent root is success);
/// retries briefly when Windows reports a transient in-use failure; never
/// panics.
pub fn delete_root(root: &Path) -> std::io::Result<()> {
    with_delete_retry(|| match std::fs::remove_dir_all(root) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    })
}

#[cfg(test)]
mod tests {
    use super::{CleanupMode, delete_root, request, run, take_requested};
    use std::path::Path;

    /// Lay out a fake app-data root (core/config/state/logs with files,
    /// mirroring the real layout under `%APPDATA%\broccoli`).
    fn sample_root(base: &Path) -> std::path::PathBuf {
        let root = base.join("broccoli");
        for dir in ["core", "config", "state", "logs"] {
            std::fs::create_dir_all(root.join(dir)).expect("create dir");
        }
        std::fs::write(root.join("core").join("xray.exe"), "core").expect("write core file");
        std::fs::write(root.join("config").join("config.json"), "{}").expect("write config");
        std::fs::write(root.join("state").join("settings.json"), "{}").expect("write settings");
        std::fs::write(root.join("logs").join("app.log"), "log").expect("write log");
        root
    }

    #[test]
    fn full_cleanup_deletes_the_root_and_everything_under_it() {
        let base = tempfile::tempdir().expect("temp dir");
        let root = sample_root(base.path());
        assert!(
            root.join("core").join("xray.exe").is_file(),
            "precondition: the root must be populated"
        );

        run(CleanupMode::Full, &root).expect("full cleanup succeeds");
        assert!(!root.exists(), "the entire app-data root must be deleted");
    }

    #[test]
    fn full_cleanup_leaves_files_outside_the_root_untouched() {
        let base = tempfile::tempdir().expect("temp dir");
        let root = sample_root(base.path());
        let neighbor = base.path().join("other-app-data.txt");
        std::fs::write(&neighbor, "keep me").expect("write neighbor");

        run(CleanupMode::Full, &root).expect("full cleanup succeeds");
        assert!(!root.exists(), "the app-data root must be deleted");
        assert_eq!(
            std::fs::read_to_string(&neighbor).expect("read neighbor"),
            "keep me",
            "files outside the root must survive full cleanup"
        );
    }

    #[test]
    fn full_cleanup_is_idempotent() {
        let base = tempfile::tempdir().expect("temp dir");
        let root = sample_root(base.path());

        // First run deletes the root; the second run sees an absent root and
        // must succeed.
        run(CleanupMode::Full, &root).expect("first full run");
        run(CleanupMode::Full, &root).expect("second full run on an absent root");
        assert!(!root.exists(), "the root must stay deleted");
    }

    #[test]
    fn full_cleanup_with_an_absent_root_is_a_noop() {
        let base = tempfile::tempdir().expect("temp dir");
        let missing = base.path().join("never-created");

        run(CleanupMode::Full, &missing).expect("an absent root must not be an error");
        assert!(!missing.exists());
    }

    #[test]
    fn cleanup_request_is_taken_and_reset() {
        // No request: take_requested reads None.
        assert_eq!(take_requested(), None, "no request must read as None");

        request(CleanupMode::Full);
        assert_eq!(
            take_requested(),
            Some(CleanupMode::Full),
            "a stashed full-cleanup request must be read once"
        );
        assert_eq!(
            take_requested(),
            None,
            "take_requested must clear the request after reading it"
        );

        request(CleanupMode::ResetFiles);
        assert_eq!(
            take_requested(),
            Some(CleanupMode::ResetFiles),
            "a stashed reset request must be read once"
        );
        assert_eq!(
            take_requested(),
            None,
            "take_requested must clear the request after reading it"
        );
    }

    #[test]
    fn delete_root_itself_is_idempotent() {
        let base = tempfile::tempdir().expect("temp dir");
        let root = sample_root(base.path());

        delete_root(&root).expect("first deletion succeeds");
        delete_root(&root).expect("deleting an absent root must succeed");
        assert!(!root.exists());
    }

    #[test]
    fn reset_keeps_servers_and_core_deletes_everything_else() {
        let base = tempfile::tempdir().expect("temp dir");
        let root = base.path().join("broccoli");
        for dir in ["core", "config", "state", "logs"] {
            std::fs::create_dir_all(root.join(dir)).expect("create dir");
        }
        std::fs::write(root.join("core").join("xray.exe"), "core").expect("write core");
        std::fs::write(root.join("state").join("servers.json"), "{}").expect("write servers");
        std::fs::write(root.join("state").join("settings.json"), "{}").expect("write settings");
        std::fs::write(root.join("state").join("report-1.toml"), "report").expect("write report");
        std::fs::create_dir_all(root.join("state").join(".broken-0")).expect("create quarantine");
        std::fs::write(
            root.join("state").join(".broken-0").join("settings.json"),
            "{}",
        )
        .expect("write quarantined file");
        std::fs::write(root.join("config").join("config.json"), "{}").expect("write config");
        std::fs::write(root.join("logs").join("app.log"), "log").expect("write log");
        std::fs::write(root.join("core.bak"), "backup").expect("write core backup");
        std::fs::write(root.join("update-marker"), "marker").expect("write update marker");

        run(CleanupMode::ResetFiles, &root).expect("reset succeeds");

        assert!(
            root.join("core").join("xray.exe").is_file(),
            "the verified core must survive the reset"
        );
        assert!(
            root.join("state").join("servers.json").is_file(),
            "the server list must survive the reset"
        );
        assert!(
            root.join("state").is_dir(),
            "the state dir itself must stay"
        );
        assert!(
            !root.join("state").join("settings.json").exists(),
            "settings must be wiped (defaults are re-seeded on next launch)"
        );
        assert!(
            !root.join("state").join("report-1.toml").exists(),
            "crash reports must be wiped"
        );
        assert!(
            !root.join("state").join(".broken-0").exists(),
            "quarantined files must be wiped"
        );
        assert!(
            !root.join("config").exists(),
            "generated configs must be wiped"
        );
        assert!(!root.join("logs").exists(), "logs must be wiped");
        assert!(
            !root.join("core.bak").exists(),
            "core-update residue must be wiped"
        );
        assert!(
            !root.join("update-marker").exists(),
            "root-level marker files must be wiped"
        );
    }

    #[test]
    fn reset_is_idempotent() {
        let base = tempfile::tempdir().expect("temp dir");
        let root = base.path().join("broccoli");
        std::fs::create_dir_all(root.join("core")).expect("create core");
        std::fs::create_dir_all(root.join("state")).expect("create state");
        std::fs::write(root.join("core").join("xray.exe"), "core").expect("write core");
        std::fs::write(root.join("state").join("servers.json"), "{}").expect("write servers");
        std::fs::write(root.join("state").join("settings.json"), "{}").expect("write settings");

        // First run wipes everything except core and servers.json; the
        // second run sees the survivors and must succeed again.
        run(CleanupMode::ResetFiles, &root).expect("first reset");
        run(CleanupMode::ResetFiles, &root).expect("second reset on the wiped root");

        assert!(
            root.join("core").join("xray.exe").is_file(),
            "core must survive both runs"
        );
        assert!(
            root.join("state").join("servers.json").is_file(),
            "servers.json must survive both runs"
        );
        assert!(
            !root.join("state").join("settings.json").exists(),
            "settings stay wiped"
        );
    }

    #[test]
    fn reset_with_an_absent_root_is_a_noop() {
        let base = tempfile::tempdir().expect("temp dir");
        let missing = base.path().join("never-created");

        run(CleanupMode::ResetFiles, &missing).expect("an absent root must not be an error");
        assert!(!missing.exists());
    }
}
