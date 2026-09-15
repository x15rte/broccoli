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
//! releases with default ACLs on every startup run. Fails closed: a root
//! that cannot be secured is an error and callers must not write
//! credential-bearing files after a failure.

use std::os::windows::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, SetFileSecurityW};
use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows::core::PCWSTR;

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

/// Create every directory above — each carrying the user-only, inheritable,
/// protected DACL before any file can be written into it — and
/// re-harden pre-existing roots on every run. Idempotent: re-application
/// replaces the DACL with the same protected user-only shape, so a second
/// run is effect-free. Fails closed: a directory that cannot be secured
/// returns an error, and callers must not proceed with writes after that.
pub fn ensure_dirs() -> std::io::Result<()> {
    for d in [core_dir(), config_dir(), state_dir(), logs_dir()] {
        std::fs::create_dir_all(&d)?;
        secure_dir_user_only(&d)?;
    }
    Ok(())
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
    let wide: Vec<u16> = dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let applied = crate::sys::security::with_user_restricted_security_descriptor(
        FILE_ALL_ACCESS.0,
        |descriptor| {
            // SAFETY: `wide` is a NUL-terminated wide path alive for the call;
            // `descriptor` is the absolute, initialized security descriptor
            // built by `crate::sys::security::with_user_restricted_security_descriptor`
            // (all Set* calls returned Ok) and alive for the call — the
            // kernel copies the DACL out of the live buffers before it
            // returns. Only the DACL is replaced
            // (`DACL_SECURITY_INFORMATION`). The BOOLEAN result is checked by
            // the caller.
            unsafe {
                SetFileSecurityW(PCWSTR(wide.as_ptr()), DACL_SECURITY_INFORMATION, descriptor)
            }
        },
    )
    .map_err(|_| {
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
