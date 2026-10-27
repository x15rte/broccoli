//! Canonical on-disk locations for broccoli. Everything user-visible lives under
//! `%APPDATA%\broccoli` (per-user, no admin).
//!
//! # User-only DACL at creation
//!
//! [`ensure_dirs`] is the single DACL enforcement point: right after
//! `create_dir_all` it applies the current-user-only, inheritable, protected
//! DACL built by `sys::security::with_user_restricted_security_descriptor`
//! to every ensured root, so no file — config, state, core payload, or log —
//! can land under the inherited `%APPDATA%` ACLs. Files created inside the
//! protected roots inherit the user-only ACE. Re-application is idempotent
//! and cheap, and it also hardens pre-existing roots created by older
//! releases with default ACLs — once per process run, for the resolved root
//! tuple (see [`ensure_dirs`]). Fails closed: a root that cannot be secured
//! is an error and callers must not write credential-bearing files after a
//! failure.

use std::path::{Path, PathBuf};

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

/// `%APPDATA%\broccoli`
pub fn broccoli_root() -> PathBuf {
    let appdata = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    appdata.join("broccoli")
}

/// `%APPDATA%\broccoli\core` — xray.exe, geoip.dat, geosite.dat, wintun.dll, licenses.
pub fn core_dir() -> PathBuf {
    broccoli_root().join("core")
}

/// `%APPDATA%\broccoli\core\xray.exe`
pub fn xray_exe() -> PathBuf {
    core_dir().join("xray.exe")
}

/// `%APPDATA%\broccoli\config` — generated config.json (+ .new / .lastgood).
pub fn config_dir() -> PathBuf {
    broccoli_root().join("config")
}

/// `%APPDATA%\broccoli\state` — servers.json, settings.json (GUI source of truth).
pub fn state_dir() -> PathBuf {
    broccoli_root().join("state")
}

/// `%APPDATA%\broccoli\logs` — GUI + core log files.
pub fn logs_dir() -> PathBuf {
    broccoli_root().join("logs")
}

/// `%APPDATA%\broccoli\logs\app.log` — the file the GUI's own records go to
/// (rotated beside it as `app.log.N`).
pub fn app_log() -> PathBuf {
    logs_dir().join("app.log")
}

/// Create every directory above — each carrying the user-only, inheritable,
/// protected DACL before any file can be written into it — and harden
/// pre-existing roots created by older releases with default ACLs. The DACL
/// step runs once per process run for a given four-root tuple: this function
/// runs before every state save (up to five times a second), and re-applying
/// four DACLs through `SetFileSecurityW` each time is pure overhead once the
/// roots are hardened. `create_dir_all` still runs on every call. The tuple
/// is the *resolved* path set, so a redirected `%APPDATA%` (tests) hardens
/// again. Fails closed: a directory that cannot be secured returns an error,
/// the tuple is not recorded, and callers must not proceed with writes after
/// that.
pub fn ensure_dirs() -> std::io::Result<()> {
    let roots = [core_dir(), config_dir(), state_dir(), logs_dir()];
    let needs_hardening = !roots_already_hardened(&roots);
    for dir in &roots {
        std::fs::create_dir_all(dir)?;
        if needs_hardening {
            // Harden each root immediately after it exists, so no newly
            // created root sits under the inherited `%APPDATA%` ACLs while
            // the remaining roots are created.
            secure_dir_user_only(dir)?;
        }
    }
    if needs_hardening {
        remember_hardened_roots(&roots);
    }
    Ok(())
}

/// The four-root tuple whose DACLs were last applied successfully.
///
/// Keyed on the resolved paths rather than a bare "done" flag: tests redirect
/// `APPDATA`, so a different root tuple must harden before its files are
/// written. Only a fully successful hardening pass is recorded — a failed one
/// leaves no entry, so the next call retries and still fails closed.
static HARDENED_ROOTS: std::sync::Mutex<Option<[PathBuf; 4]>> = std::sync::Mutex::new(None);

/// Lock the hardened-tuple cell, tolerating a poisoned mutex: the cell holds
/// plain paths and a panic while it was held left them untouched, so a
/// poisoned lock is no reason to fail a directory setup.
fn hardened_roots_guard() -> std::sync::MutexGuard<'static, Option<[PathBuf; 4]>> {
    HARDENED_ROOTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn roots_already_hardened(roots: &[PathBuf; 4]) -> bool {
    hardened_roots_guard().as_ref() == Some(roots)
}

fn remember_hardened_roots(roots: &[PathBuf; 4]) {
    *hardened_roots_guard() = Some(roots.clone());
}

/// Locate a usable xray.exe for tests/tools: `$XRAY_EXE` override, else the
/// managed core dir. Returns `None` when the core was never downloaded.
pub fn locate_xray() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("XRAY_EXE") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let p = xray_exe();
    p.is_file().then_some(p)
}

// ---------- user-only DACL on every ensured root ----------
//
// The descriptor comes from the shared `sys::security` builder —
// `with_user_restricted_security_descriptor` — the single implementation of
// this shape (the historical per-module copies were migrated here; see
// the `sys::security` module docs). Owner/group stay unset: the kernel
// assigns the creator.

/// Apply a current-user-only, inheritable, protected DACL to `dir`,
/// so `dir` and everything created inside it are readable and
/// writable only by the current user. Fails closed: when the user SID or the
/// descriptor cannot be built, or `SetFileSecurityW` fails, an error is
/// returned — the caller must not proceed with a directory other users can
/// read.
fn secure_dir_user_only(dir: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_DIR_DACL.load(Ordering::Relaxed) {
        return Err(std::io::Error::other(
            "test seam: state/config dir DACL failure injected",
        ));
    }
    let applied = crate::sys::security::apply_user_restricted_dacl(dir).map_err(|_| {
        std::io::Error::other(format!(
            "cannot build a user-restricted DACL for {}",
            dir.display()
        ))
    })?;
    if !applied.as_bool() {
        return Err(std::io::Error::other(format!(
            "applying user-restricted DACL to {} failed: {}",
            dir.display(),
            windows::core::Error::from_thread()
        )));
    }
    Ok(())
}

/// Test seam: force [`ensure_dirs`]'s DACL step to fail so tests can
/// exercise the fail-closed state/config save without depending on real
/// filesystem/DACL behavior. Callers MUST hold
/// [`sys::appdata::APPDATA_ENV_LOCK`](crate::sys::appdata::APPDATA_ENV_LOCK)
/// (i.e. run inside `with_appdata`) while the seam is armed so the failure
/// window never overlaps a concurrent state write.
#[cfg(test)]
pub(crate) fn set_fail_dir_dacl(fail: bool) {
    FAIL_DIR_DACL.store(fail, Ordering::Relaxed);
}

#[cfg(test)]
static FAIL_DIR_DACL: AtomicBool = AtomicBool::new(false);
