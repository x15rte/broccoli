//! The one home of the `%APPDATA%` redirect discipline for in-crate tests.
//!
//! Code that resolves `%APPDATA%\broccoli` paths reads the process-global
//! environment, so a test that redirects the variable must exclude every
//! concurrent reader of those paths, and must restore the previous value
//! before that exclusion ends — including when the test panics. That lock +
//! redirect + restore pattern used to be copied into every test module that
//! needed it, each copy carrying its own `unsafe` and SAFETY argument for the
//! same invariant. This module is the single definition: [`APPDATA_ENV_LOCK`]
//! serializes, [`AppDataRedirect`] owns the redirect/restore pair, and
//! [`with_appdata`] / [`with_appdata_async`] run a whole test body inside a
//! fresh temporary root.
//!
//! Nothing here runs in production: the module is `#[doc(hidden)]` and only
//! tests call it. It is `pub` rather than `pub(crate)` because the binary's
//! own test module links this crate as a dependency and cannot see
//! `pub(crate)` or `#[cfg(test)]` items; separate test binaries (integration
//! tests) each own their process and keep their own process-local lock.

use std::ffi::OsString;
use std::path::Path;
use std::sync::LazyLock;

/// Serializes tests that mutate the process-global `APPDATA` env var against
/// tests that read `%APPDATA%\broccoli` paths. Env vars are process-wide, so
/// a test-local `set_var` races parallel readers even on the same thread.
///
/// Every mutator takes this lock first and holds it until after its
/// [`AppDataRedirect`] has restored the previous value. The lock is
/// process-local: the lib test binary, the binary's test module and each
/// integration test binary hold their own instance.
#[doc(hidden)]
pub static APPDATA_ENV_LOCK: LazyLock<tokio::sync::Mutex<()>> =
    LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Redirects `%APPDATA%` to a directory for the guard's lifetime, restoring
/// the previous value on drop — even while a panicked test unwinds.
///
/// Callers MUST hold [`APPDATA_ENV_LOCK`] from before [`AppDataRedirect::to`]
/// until after this guard drops: the variable is process-wide, so the window
/// must exclude every concurrent reader of `%APPDATA%\broccoli` paths, and
/// the restore must happen while that exclusion still holds. Declaring the
/// guard after the lock guard gives exactly that order.
#[doc(hidden)]
pub struct AppDataRedirect(Option<OsString>);

impl AppDataRedirect {
    /// Point `%APPDATA%` at `root` until the returned guard drops.
    #[doc(hidden)]
    pub fn to(root: &Path) -> Self {
        let previous = std::env::var_os("APPDATA");
        // SAFETY: on Windows — the only supported platform — `std::env`
        // documents `set_var`/`remove_var` as always sound, single- or
        // multi-threaded, because SetEnvironmentVariableW updates the process
        // environment block per variable; a concurrent env read observes
        // either the old or the new value, never a torn one. Soundness of the
        // *view* still rests on the lock: the caller holds
        // `APPDATA_ENV_LOCK`, so no reader of `%APPDATA%\broccoli` paths runs
        // inside the redirect window, and `root` is a live directory the
        // caller keeps past this guard's drop.
        unsafe { std::env::set_var("APPDATA", root) };
        Self(previous)
    }
}

impl Drop for AppDataRedirect {
    fn drop(&mut self) {
        match self.0.take() {
            Some(previous) => {
                // SAFETY: same Windows per-variable soundness as `to`, and
                // the caller still holds `APPDATA_ENV_LOCK` (this guard drops
                // before the lock guard declared above it), so the restore
                // cannot be observed by a concurrent path reader.
                unsafe { std::env::set_var("APPDATA", previous) };
            }
            None => {
                // SAFETY: same soundness and lock discipline as the `Some`
                // arm; removing the variable restores the pre-redirect state
                // when `APPDATA` was unset.
                unsafe { std::env::remove_var("APPDATA") };
            }
        }
    }
}

/// Run `f` with `%APPDATA%` redirected to a fresh temporary directory,
/// holding the serialization lock for the whole call. The previous value is
/// restored before the lock is released, and the temporary directory is
/// removed afterwards — both also when `f` panics.
#[doc(hidden)]
pub fn with_appdata<T>(f: impl FnOnce() -> T) -> T {
    let _lock = APPDATA_ENV_LOCK.blocking_lock();
    let temporary = tempfile::tempdir().expect("temporary AppData root");
    let _redirect = AppDataRedirect::to(temporary.path());
    f()
}

/// Async twin of [`with_appdata`] for tests already running on a tokio
/// runtime, where [`APPDATA_ENV_LOCK`]'s blocking acquire would panic.
#[doc(hidden)]
pub async fn with_appdata_async<T>(f: impl Future<Output = T>) -> T {
    let _lock = APPDATA_ENV_LOCK.lock().await;
    let temporary = tempfile::tempdir().expect("temporary AppData root");
    let _redirect = AppDataRedirect::to(temporary.path());
    f.await
}
