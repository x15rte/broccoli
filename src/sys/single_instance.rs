//! Single-instance enforcement: a named session mutex. When a
//! second launch detects the first, it restores and foregrounds the existing
//! window (matched by its "broccoli" title) and declines to start.
//!
//! Security: the mutex is created with an explicit DACL
//! granting access only to the current user's SID (read from the process
//! token), so no other principal can open or pre-create it. The mutex holder
//! publishes its PID in `HKCU\Software\Broccoli\SingleInstance\HolderPid`; a
//! second instance foregrounds a found window only after verifying the
//! window's owning process is really the holder — `GetWindowThreadProcessId`
//! plus an `OpenProcess`/`GetProcessId` round-trip, gated by the pure
//! [`may_foreground`] check. Every verification failure fails closed: the
//! window is left alone and the second instance still exits.

use super::security::with_user_restricted_attributes;
use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HWND};
use windows::Win32::System::Threading::{
    CreateMutexW, GetProcessId, MUTEX_ALL_ACCESS, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    FindWindowW, GetWindowThreadProcessId, SW_RESTORE, SetForegroundWindow, ShowWindow,
};
use windows::core::{PCWSTR, w};
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_SET_VALUE};

const MUTEX_NAME: PCWSTR = w!("Local\\broccoli-gui-single-instance");
const WINDOW_TITLE: PCWSTR = w!("broccoli");

/// HKCU key/value where the mutex holder publishes its PID, so a second
/// instance can verify that a found window really belongs to the holder
/// before raising it.
const PID_KEY: &str = r"Software\Broccoli\SingleInstance";
const PID_VALUE: &str = "HolderPid";

/// RAII hold on the single-instance mutex; closing the handle releases it.
/// Dropping also removes the published holder PID.
pub struct InstanceGuard(HANDLE);

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        // Best-effort cleanup: no second instance outlives the mutex, so a
        // stale PID must not survive a clean exit. A failure here only makes
        // a later instance skip the (best-effort) foreground nudge.
        clear_holder_pid();
        // SAFETY: `self.0` is the mutex handle returned by `CreateMutexW`,
        // owned exclusively by this guard and never closed elsewhere; `Drop`
        // runs exactly once, so the handle is closed exactly once, releasing
        // the named mutex.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Pure gate: may the window owned by `window_pid` be raised as the single
/// instance's window? Only when the mutex holder's published PID is known and
/// matches the window's owning PID; any unknown PID fails closed.
fn may_foreground(window_pid: u32, holder_pid: u32) -> bool {
    window_pid != 0 && window_pid == holder_pid
}

/// PID of the process that owns `hwnd`, verified to be a live process whose
/// identity round-trips: `GetWindowThreadProcessId` yields the window's PID,
/// `OpenProcess` must open that PID, and `GetProcessId` on the returned
/// handle must re-derive the same PID. `None` fails the verification closed.
fn verified_window_pid(hwnd: HWND) -> Option<u32> {
    unsafe {
        let mut pid = 0u32;
        // SAFETY: `hwnd` is the valid HWND returned by `FindWindowW` (checked
        // non-invalid by the caller); `&mut pid` is a valid out-parameter. On
        // failure the call returns 0 and leaves `pid` at 0, which the check
        // below rejects.
        let _ = GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid == 0 {
            return None;
        }
        // SAFETY: `pid` is a nonzero PID from `GetWindowThreadProcessId`;
        // `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION` fails (`Err`)
        // for a dead or inaccessible process, failing the verification closed.
        // On success the handle is owned by this call and closed exactly once
        // below.
        let Ok(process) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return None;
        };
        // SAFETY: `process` is the valid, still-open handle from `OpenProcess`
        // above; `GetProcessId` re-derives its PID to confirm the handle
        // refers to the window's owning process.
        let round_trips = GetProcessId(process) == pid;
        // SAFETY: `process` is owned by this call and never closed elsewhere;
        // `CloseHandle` closes it exactly once.
        let _ = CloseHandle(process);
        round_trips.then_some(pid)
    }
}

/// Raise the first instance's window. Only foregrounded when the found
/// window's owning PID verifiably matches the published holder PID — never a
/// same-session window that merely carries the "broccoli" title.
fn nudge_first_instance() {
    let Some(holder_pid) = read_holder_pid() else {
        return;
    };
    // SAFETY: `FindWindowW` takes a null class plus a static NUL-terminated
    // title and returns a valid HWND or `Err` for NULL; a raced dead window
    // is rejected by the PID verification below, not dereferenced.
    let Ok(hwnd) = (unsafe { FindWindowW(PCWSTR::null(), WINDOW_TITLE) }) else {
        return;
    };
    if hwnd.is_invalid() {
        return;
    }
    let Some(window_pid) = verified_window_pid(hwnd) else {
        return;
    };
    if !may_foreground(window_pid, holder_pid) {
        return;
    }
    // SAFETY: `hwnd` is the HWND returned by `FindWindowW` whose owning
    // process was just verified to be the mutex holder; `ShowWindow` and
    // `SetForegroundWindow` use it synchronously — a raced dead window makes
    // them fail with 0, not UB.
    unsafe {
        let _ = ShowWindow(hwnd, SW_RESTORE);
        let _ = SetForegroundWindow(hwnd);
    }
}

/// Publish the current process's PID as the mutex holder's. Best-effort: if
/// the write fails, later second instances skip the foreground nudge
/// (fail-closed); the mutex itself is unaffected.
fn publish_holder_pid() {
    let Ok((key, _)) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(PID_KEY) else {
        return;
    };
    if let Err(error) = key.set_value(PID_VALUE, &std::process::id()) {
        tracing::warn!("publishing single-instance holder PID failed: {error}");
    }
}

/// Read the mutex holder's published PID; `None` when absent or unreadable.
fn read_holder_pid() -> Option<u32> {
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(PID_KEY, KEY_READ)
        .ok()?;
    key.get_value::<u32, _>(PID_VALUE).ok()
}

/// Best-effort removal of the published holder PID on a clean exit.
fn clear_holder_pid() {
    let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(PID_KEY, KEY_SET_VALUE)
    else {
        return;
    };
    let _ = key.delete_value(PID_VALUE);
}

/// Outcome of [`acquire`]. "Another instance is running" and "the mutex could
/// not be created" are different conditions for the caller: the first is a
/// normal second launch that exits quietly, the second must be reported.
pub enum SingleInstance {
    /// This process owns the single-instance mutex; the guard releases it
    /// (and removes the published holder PID) when it drops.
    Acquired(InstanceGuard),
    /// Another process already holds the mutex. Its window was nudged to the
    /// foreground; this process declines to start.
    AlreadyRunning,
    /// The mutex could not be created — the message names the failed step.
    /// The mutex is never created with a weaker, default DACL.
    Unavailable(String),
}

/// Try to become the single instance: [`SingleInstance::Acquired`] for the
/// first process, [`SingleInstance::AlreadyRunning`] when another instance
/// already runs (after nudging its window to the foreground), and
/// [`SingleInstance::Unavailable`] when the mutex itself could not be created
/// — including when its user-restricted DACL cannot be built.
pub fn acquire() -> SingleInstance {
    let built = with_user_restricted_attributes(MUTEX_ALL_ACCESS.0, |attributes| {
        // SAFETY: `attributes` points at the `SECURITY_ATTRIBUTES` built by
        // `with_user_restricted_attributes`, valid for the duration of this
        // closure; `MUTEX_NAME` is a static NUL-terminated wide literal
        // (`w!`), valid for the call; the crate maps the NULL-handle failure
        // to `Err`. `GetLastError` is read immediately after the call, as
        // documented, to detect the pre-existing-mutex case.
        unsafe {
            match CreateMutexW(Some(attributes), true, MUTEX_NAME) {
                Ok(handle) => Ok((handle, GetLastError() == ERROR_ALREADY_EXISTS)),
                Err(error) => Err(format!("CreateMutexW failed: {error}")),
            }
        }
    });
    let (handle, already_exists) = match built {
        Ok(Ok(created)) => created,
        Ok(Err(reason)) => return SingleInstance::Unavailable(reason),
        Err(error) => {
            return SingleInstance::Unavailable(format!(
                "the user-restricted DACL for the single-instance mutex could not be built: \
                 {error}"
            ));
        }
    };
    if already_exists {
        // SAFETY: `handle` is the mutex handle just obtained, owned by this
        // call and not referenced elsewhere; `CloseHandle` closes it exactly
        // once. The named mutex itself survives because the first instance
        // still holds it.
        unsafe {
            let _ = CloseHandle(handle);
        }
        nudge_first_instance();
        return SingleInstance::AlreadyRunning;
    }
    // First instance: publish our PID so later second instances can verify
    // the window they find belongs to us.
    publish_holder_pid();
    SingleInstance::Acquired(InstanceGuard(handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::{
        GetSecurityDescriptorDacl, IsValidSecurityDescriptor, PSECURITY_DESCRIPTOR,
        SECURITY_ATTRIBUTES,
    };
    use windows::core::{BOOL, HSTRING};

    #[test]
    fn may_foreground_requires_matching_nonzero_pids() {
        assert!(may_foreground(1234, 1234));
        assert!(!may_foreground(1234, 5678));
        assert!(!may_foreground(0, 1234), "unknown window PID fails closed");
        assert!(!may_foreground(1234, 0), "unknown holder PID fails closed");
        assert!(!may_foreground(0, 0));
    }

    #[test]
    fn invalid_window_fails_pid_verification() {
        // A null HWND has no owning thread/process: verification must fail
        // closed instead of panicking or returning a bogus PID.
        assert_eq!(verified_window_pid(HWND::default()), None);
    }

    #[test]
    fn user_restricted_attributes_carry_a_valid_dacl() {
        let built = with_user_restricted_attributes(MUTEX_ALL_ACCESS.0, |attributes| {
            assert!(!attributes.is_null());
            // SAFETY: `attributes` is the valid, alive pointer built by
            // `with_user_restricted_attributes` for the duration of this
            // closure; the descriptor it references is initialized.
            let security = unsafe { &*attributes };
            assert_eq!(
                security.nLength,
                std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32
            );
            assert_eq!(security.bInheritHandle, BOOL(0));
            assert!(!security.lpSecurityDescriptor.is_null());
            let descriptor = PSECURITY_DESCRIPTOR(security.lpSecurityDescriptor);
            // SAFETY: `descriptor` is the initialized, alive security
            // descriptor built by the helper; the Win32 validators read it
            // without modifying it.
            unsafe {
                assert!(IsValidSecurityDescriptor(descriptor).as_bool());
                let mut dacl_present = BOOL(0);
                let mut dacl = std::ptr::null_mut();
                let mut dacl_defaulted = BOOL(0);
                assert!(
                    GetSecurityDescriptorDacl(
                        descriptor,
                        &mut dacl_present,
                        &mut dacl,
                        &mut dacl_defaulted,
                    )
                    .is_ok()
                );
                assert!(dacl_present.as_bool(), "DACL must be present");
                assert!(!dacl.is_null(), "DACL must be non-null");
            }
        })
        .ok();
        assert!(
            built.is_some(),
            "user-restricted attributes must be buildable"
        );
    }

    #[test]
    fn restricted_mutex_is_creatable_and_reopenable() {
        let name = HSTRING::from(format!(
            "Local\\broccoli-single-instance-test-{}",
            std::process::id()
        ));
        let already_exists = with_user_restricted_attributes(MUTEX_ALL_ACCESS.0, |attributes| {
            // SAFETY: `attributes` is the helper's alive `SECURITY_ATTRIBUTES`
            // pointer; `name` is a NUL-terminated wide string alive for both
            // calls. The second open must observe the pre-existing mutex,
            // which also proves the DACL grants the current user enough
            // access to open the mutex (not just create it).
            unsafe {
                let first = CreateMutexW(Some(attributes), true, PCWSTR(name.as_ptr()))
                    .expect("create test mutex with user-restricted DACL");
                let second = CreateMutexW(Some(attributes), true, PCWSTR(name.as_ptr()))
                    .expect("open existing test mutex with user-restricted DACL");
                let already_exists = GetLastError() == ERROR_ALREADY_EXISTS;
                let _ = CloseHandle(second);
                let _ = CloseHandle(first);
                already_exists
            }
        })
        .expect("user-restricted attributes must build on this machine");
        assert!(
            already_exists,
            "second open of the same mutex must see ERROR_ALREADY_EXISTS"
        );
    }
}
