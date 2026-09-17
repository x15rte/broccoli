//! Bounded process exit.
//!
//! `main` finishes the process's own teardown — state flushed, core and helper
//! stopped — and then only the OS exit path is left: `ExitProcess` running the
//! CRT's atexit work and every loaded DLL's detach handler. Code attached to the
//! process from outside (an injected capture hook, the GPU driver, shell COM)
//! can stall that path for many seconds, which leaves the window on screen after
//! Quit and reads to the user as "the program did not exit".
//!
//! The bound is armed only after our own work is done, so a normal exit — well
//! under a second — never reaches it. When it does fire, terminating is the
//! honest outcome: nothing of ours is left to flush, and the kernel releases
//! everything the process owns.

use std::time::Duration;

/// How long the OS teardown after `main`'s work may take before the process is
/// terminated.
pub const TEARDOWN_BOUND: Duration = Duration::from_secs(3);

/// Terminate the process if it is still alive `bound` after this call.
///
/// A failure to spawn the watchdog is reported and otherwise ignored: the
/// process then exits through the normal path, stalled or not.
pub fn arm(bound: Duration) {
    let spawned = std::thread::Builder::new()
        .name("exit-bound".into())
        .spawn(move || {
            std::thread::sleep(bound);
            tracing::warn!(
                "process teardown exceeded {bound:?} after the app's own shutdown; terminating"
            );
            #[cfg(windows)]
            {
                use windows::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};
                // SAFETY: terminating the current process with an exit code the
                // normal path would have used; every handle, child process, and
                // handle-less resource this process owns is released by the
                // kernel at termination.
                unsafe {
                    let _ = TerminateProcess(GetCurrentProcess(), 0);
                }
            }
        });
    if let Err(error) = spawned {
        tracing::warn!("exit bound could not be armed: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::TEARDOWN_BOUND;

    /// The bound must sit between a normal exit (measured well under a
    /// second) and the multi-second stalls it exists to cut: too low would cut
    /// off a legitimate teardown — the log worker's last records, the CRT's
    /// flush — and too high would leave the window on screen after Quit.
    #[test]
    fn bound_sits_between_normal_exits_and_stalls() {
        assert!(
            TEARDOWN_BOUND >= std::time::Duration::from_secs(2),
            "a normal exit must never reach the bound"
        );
        assert!(
            TEARDOWN_BOUND <= std::time::Duration::from_secs(10),
            "the bound must cut the multi-second stalls it exists for"
        );
    }
}
