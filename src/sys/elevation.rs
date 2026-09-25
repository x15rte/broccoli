//! Elevation helpers: admin-token check and UAC relaunch of
//! this binary as the `--core-helper` process used for TUN mode.

use std::fs::File;
use std::io::Write as _;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};

use super::security::{Sid, TokenHandle, with_protected_attributes};
use crate::diag::Diag;
use crate::i18n::Key;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, PSID, SECURITY_MAX_SID_SIZE, TOKEN_QUERY,
    WinBuiltinAdministratorsSid,
};
use windows::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
};
use windows::Win32::UI::Shell::{
    FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath, ShellExecuteW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows::core::{BOOL, PCWSTR, w};

#[link(name = "ole32")]
// SAFETY: the declared function is the documented ole32 export
// `CoTaskMemFree`, which accepts either a pointer returned by
// `CoTaskMemAlloc` (or by `SHGetKnownFolderPath`) or NULL (a no-op); the
// caller must not use the memory after the call. The `unsafe extern` block is
// the edition-2024 way to declare such an ABI function, and every call site
// below upholds the pointer contract.
unsafe extern "system" {
    fn CoTaskMemFree(memory: *const core::ffi::c_void);
}

/// `SE_ERR_ACCESSDENIED` from ShellExecuteW: the user cancelled the UAC prompt.
const SE_ERR_ACCESSDENIED: isize = 5;

/// SID buffer aligned for the Win32 `SID` layout (`Rev`, `SubAuthorityCount`,
/// a 6-byte authority, `SubAuthority: [u32; 1]` — alignment 4), which a bare
/// `[u8; N]` would leave to stack luck. `SECURITY_MAX_SID_SIZE` is the
/// documented capacity for any well-known SID; the Administrators alias SID
/// needs 16 of its bytes.
#[repr(align(4))]
struct SidBuffer([u8; SECURITY_MAX_SID_SIZE as usize]);

/// `true` when the current process token is a member of the Administrators
/// group (i.e. running elevated, or as a service/system account).
pub fn is_elevated() -> bool {
    unsafe {
        // SAFETY: `buffer` covers `SECURITY_MAX_SID_SIZE` bytes at an address
        // 4-byte aligned by its type, and `cb` is that length, so
        // `CreateWellKnownSid` writes at most `cb` bytes into the live,
        // writable buffer and reports the used size back through `cb`; on
        // success the buffer holds a valid SID at offset 0 and
        // `PSID(buffer.as_ptr()…)` points at it, aligned for the `SID`
        // fields, for `CheckTokenMembership` (which reads it in place).
        // `member` is a valid BOOL out-parameter, and every error return is
        // handled rather than ignored.
        let mut buffer = SidBuffer([0u8; SECURITY_MAX_SID_SIZE as usize]);
        let mut cb = buffer.0.len() as u32;
        if CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            None,
            Some(PSID(buffer.0.as_mut_ptr() as *mut core::ffi::c_void)),
            &mut cb,
        )
        .is_err()
        {
            return false;
        }
        let mut member = BOOL(0);
        match CheckTokenMembership(
            None,
            PSID(buffer.0.as_ptr() as *mut core::ffi::c_void),
            &mut member,
        ) {
            Ok(()) => member.as_bool(),
            Err(_) => false,
        }
    }
}

/// Why the elevated helper did not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperLaunchError {
    /// The user declined the UAC prompt (SE_ERR_ACCESSDENIED).
    Declined,
    /// Another launch failure; the message carries its cause.
    Failed(Diag),
}

impl HelperLaunchError {
    /// The message layer this failure adds to the error chain. The caller
    /// renders it in the active language at the display boundary.
    pub(crate) fn diag(&self) -> Diag {
        match self {
            Self::Declined => Diag::new(Key::HelperLaunchDeclined),
            Self::Failed(diag) => diag.clone(),
        }
    }
}

impl std::fmt::Display for HelperLaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.diag())
    }
}

impl std::error::Error for HelperLaunchError {}

/// Environment variable that carries the one-shot helper auth token from the
/// launching GUI to the elevated helper. A process's argv is readable by any
/// same-user process for the child's lifetime; its environment block is not
/// (there is no public API), so the token travels through the environment the
/// elevated child inherits from its launcher instead of the command line.
/// Cross-user UAC elevations rebuild the child's environment from the target
/// admin profile, so the variable does not always survive; the ProgramData
/// token file (`helper_token_path`) is the fallback channel.
pub const HELPER_TOKEN_ENV: &str = "BROCCOLI_CORE_HELPER_TOKEN";

/// The ProgramData token file for `pipe_id`. The path derives from the
/// immutable `--helper-pipe` argument, which already travels on the UAC
/// command line, so no secret crosses argv; the GUI (writer) and the elevated
/// helper (reader) derive the same location.
fn helper_token_path(pipe_id: &str) -> PathBuf {
    program_data().join(format!("broccoli-core-helper-token-{pipe_id}"))
}

/// Well-known ProgramData literal used when the shell API fails or returns a
/// path that cannot be decoded; it is the documented system-wide location.
const PROGRAM_DATA_FALLBACK: &str = r"C:\ProgramData";

/// ProgramData root. System-wide, so both the standard user's GUI and the
/// elevated helper (which may run under a different admin account) resolve
/// the same directory.
fn program_data() -> PathBuf {
    match unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) } {
        Ok(pointer) => {
            // SAFETY: `pointer` is the non-null, NUL-terminated UTF-16 path
            // string returned above; `to_string()` reads only up to the
            // terminator while the allocation is still alive (freed on the
            // next line).
            let decoded = unsafe { pointer.to_string() }.ok();
            // SAFETY: `pointer` is the `CoTaskMemAlloc`-allocated buffer from
            // `SHGetKnownFolderPath`, still alive and not previously freed;
            // this is its single free, after which it is never used again.
            unsafe { CoTaskMemFree(pointer.0 as *const core::ffi::c_void) };
            program_data_from(decoded)
        }
        Err(_) => PathBuf::from(PROGRAM_DATA_FALLBACK),
    }
}

/// The ProgramData root a shell decode result resolves to.
///
/// A path that cannot be decoded (or decodes to nothing) falls back to the
/// well-known literal exactly like a failed `SHGetKnownFolderPath` call: an
/// empty path would place the one-shot helper token file relative to the
/// process's current directory, where the elevated helper (launched with a
/// different working directory) could never read it — and where it would
/// linger outside the documented ProgramData location.
fn program_data_from(decoded: Option<String>) -> PathBuf {
    match decoded {
        Some(path) if !path.is_empty() => PathBuf::from(path),
        _ => PathBuf::from(PROGRAM_DATA_FALLBACK),
    }
}

/// Create `path` with an explicit protected DACL — SYSTEM, Administrators,
/// and the launching user get full control and nothing else — so the token is
/// readable by the elevated helper (full-admin token) and by the GUI's own
/// processes, but not by filtered (medium-integrity) processes of the admin
/// account, whose Administrators group is deny-only and therefore ignored by
/// the access check. Owner/group are left unset: the kernel assigns the
/// creator (the launching GUI), which any token may own.
fn write_token_file(path: &Path, token: &str) -> Result<(), HelperLaunchError> {
    let user = TokenHandle::open_current_process(TOKEN_QUERY)
        .and_then(|token| Sid::token_user(&token))
        .map_err(|error| {
            HelperLaunchError::Failed(Diag::new(Key::HelperTokenFileOwnerFailed).arg(error))
        })?;
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // `with_protected_attributes` builds the absolute descriptor (SYSTEM +
    // Administrators full control first, then the launching user with full
    // control, DACL protected, owner/group left to the kernel) and runs
    // `attributes` while the descriptor and its buffers are alive.
    let handle = with_protected_attributes(None, &[(&user, FILE_ALL_ACCESS.0)], |attributes| {
        // SAFETY: `wide` is a NUL-terminated wide path valid for the call;
        // `attributes` is the `SECURITY_ATTRIBUTES` built by
        // `with_protected_attributes` (nLength set, `lpSecurityDescriptor`
        // pointing at the live descriptor, `bInheritHandle` false), and the
        // SID/ACL buffers it references stay alive through the synchronous
        // call while the kernel copies them. The crate maps a kernel failure
        // to `Err`, and `Ok` is a valid handle.
        unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                FILE_ALL_ACCESS.0,
                FILE_SHARE_READ,
                Some(attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map_err(|error| {
            HelperLaunchError::Failed(Diag::new(Key::HelperTokenFileCreateFailed).arg(error))
        })
    })
    .map_err(|error| {
        HelperLaunchError::Failed(Diag::new(Key::HelperTokenFileSecurityFailed).arg(error))
    })??;
    // SAFETY: `handle` is a valid, open file handle (`Ok` above), and
    // ownership of it transfers to the returned `File`: its `Drop` closes the
    // handle exactly once.
    let mut file = unsafe { File::from_raw_handle(handle.0 as RawHandle) };
    file.write_all(token.as_bytes()).map_err(|error| {
        HelperLaunchError::Failed(Diag::new(Key::HelperTokenFileWriteFailed).arg(error))
    })?;
    Ok(())
}

/// One-shot read of the ProgramData token file written by the launching GUI
/// (`helper_token_path`). The file is deleted on a successful read so the
/// credential cannot linger or be replayed by a later process. The caller
/// (`main.rs --core-helper`) consumes the file only when the environment
/// channel is absent (cross-user UAC elevation).
pub fn read_helper_token_file(pipe_id: &str) -> Option<String> {
    let path = helper_token_path(pipe_id);
    let token = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// Build the immutable UAC command line for the elevated helper. Deliberately
/// never includes the auth token — that travels via `HELPER_TOKEN_ENV` — so a
/// same-user process reading the child's argv cannot learn it.
pub(crate) fn helper_command_line(pipe_id: &str, parent_pid: u32) -> String {
    format!("--core-helper --helper-pipe={pipe_id} --helper-parent={parent_pid}")
}

/// RAII guard that places the one-shot helper token where the elevated child
/// can read it and removes every copy when the elevation launch window ends.
/// Two channels: `HELPER_TOKEN_ENV` in this process's environment block (the
/// child of a same-user UAC elevation inherits it), and a ProgramData token
/// file read by the helper when the UAC elevation rebuilt the child's
/// environment for a different account — cross-user elevation — where the
/// environment variable does not survive. ShellExecuteW — the only API that
/// triggers the UAC `runas` prompt — has no `lpEnvironment` parameter (and
/// the alternatives that accept one cannot elevate: CreateProcessWithLogonW
/// needs credentials, CreateProcess cannot trigger UAC), so the file is the
/// only channel that reaches a cross-user child.
pub(crate) struct HelperTokenGuard {
    pipe_id: String,
}

impl HelperTokenGuard {
    /// `pipe_id` and `token` must be the ASCII hex secrets generated for this
    /// launch (`uuid::Uuid::new_v4().simple()`), so they are non-empty,
    /// NUL-free and well under Windows' per-variable size limit. The token
    /// file write is fallible (ProgramData locked down, disk full): a launch
    /// that cannot stage the credential must fail before the UAC prompt,
    /// never hang at the pipe connect. The file is written before the
    /// environment variable is set — and a failed write removes any partial
    /// file on the way out — so an unsuccessful staging leaves no copy of
    /// the token behind: the variable is only ever set by a staging that is
    /// already committed and immediately covered by the returned guard.
    pub(crate) fn new(pipe_id: &str, token: &str) -> Result<Self, HelperLaunchError> {
        // Tests share one process environment: a staging outside the window
        // held by `lock_helper_token_env` lands inside another test's
        // before/after snapshot of the variable (the elevation staging-failure
        // test reads it across this call). Reject it where it happens instead
        // of letting the other test's assertion blame the wrong call.
        #[cfg(test)]
        assert!(
            HELPER_TOKEN_ENV_LOCK_HELD.with(std::cell::Cell::get),
            "HelperTokenGuard must be staged inside a `lock_helper_token_env` window"
        );
        // `write_token_file` is the only fallible staging step. Stage the
        // file channel first so an error returns before `set_var` runs and
        // can never leak the token into this process's environment block.
        let token_path = helper_token_path(pipe_id);
        if let Err(error) = write_token_file(&token_path, token) {
            // The write may have created the file before failing mid-way
            // (disk full), leaving a partial copy; remove it so a failed
            // staging leaves no token file behind. The path embeds the random
            // pipe id, so this cannot delete anything but this launch's own
            // file. An ignored failure would leave a partial token fragment
            // that nothing can guess or reuse.
            let _ = std::fs::remove_file(&token_path);
            return Err(error);
        }
        // SAFETY: `HELPER_TOKEN_ENV` is a fixed ASCII name and `token` is the
        // caller's non-empty NUL-free hex value (documented precondition), so
        // `set_var` cannot panic here. The Rust 2024 contract for `set_var` is
        // satisfied on the only supported platform: `std::env` documents that
        // on Windows `set_var`/`remove_var` are always sound, single- or
        // multi-threaded, because SetEnvironmentVariableW updates the process
        // environment block per variable — a concurrent env read from this
        // process's other threads (e.g. `paths::broccoli_root` on runtime
        // workers) observes either the old or the new value, never a torn one.
        // The single-writer discipline still holds for the variable itself:
        // `HELPER_TOKEN_ENV` is written by exactly one code path
        // (`launch_core_helper`, once per launch inside one `spawn_blocking`
        // task serialized by the lifecycle operation machine) and never read
        // in this process. This rationale is Windows-specific: on any other OS
        // the contract forbids concurrent env access in multi-threaded
        // programs (and std itself reads env for DNS lookups), so the guard
        // must be re-audited before porting.
        unsafe { std::env::set_var(HELPER_TOKEN_ENV, token) };
        // Nothing between `set_var` and the guard construction is fallible,
        // so every environment write is followed immediately by a guard whose
        // `Drop` removes the variable when the launch window ends.
        Ok(Self {
            pipe_id: pipe_id.to_string(),
        })
    }
}

impl Drop for HelperTokenGuard {
    fn drop(&mut self) {
        // Removing the variable is the staging window's other transition, so
        // it must run inside the same window as `new` (see there).
        #[cfg(test)]
        assert!(
            HELPER_TOKEN_ENV_LOCK_HELD.with(std::cell::Cell::get),
            "HelperTokenGuard must be dropped inside its `lock_helper_token_env` window"
        );
        // SAFETY: removing a fixed ASCII variable cannot panic; a null value
        // deletes the variable. On Windows, per-variable environment updates
        // are always sound against concurrent env reads from other threads
        // (see `new`), so this races no reader in this process. `Drop` runs
        // exactly once — including when the elevation launch returns early on
        // a UAC decline or other error — so the token cannot outlive the
        // launch window in this process. The elevated child has already copied
        // it into its own environment block by the time the guard drops
        // (ShellExecuteW creates the process synchronously).
        unsafe { std::env::remove_var(HELPER_TOKEN_ENV) };
        // The elevated helper deletes the token file right after reading it;
        // this is the fallback for launches where it never read it (declined
        // UAC, launch failure, helper crash). Ignored failures leave an
        // unreachable stale file: the path embeds the random pipe id, so
        // nothing can guess or reuse it.
        let _ = std::fs::remove_file(helper_token_path(&self.pipe_id));
    }
}

/// Tests that exercise `HelperTokenEnv` mutate a process-wide environment
/// variable, so they serialize on this lock first (same discipline as
/// `sys::appdata::APPDATA_ENV_LOCK`). Every test that stages the token — in
/// this module or another — holds it for its whole staging window through
/// [`lock_helper_token_env`], the only way to acquire it.
#[cfg(test)]
static HELPER_TOKEN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
thread_local! {
    /// Whether the *current thread* holds [`HELPER_TOKEN_ENV_LOCK`]. Set by
    /// [`HelperTokenEnvLock`], read by `HelperTokenGuard`'s test-build
    /// assertions: a raw mutex cannot tell *who* holds it, and an unlocked
    /// staging is exactly the defect the assertions exist to catch.
    static HELPER_TOKEN_ENV_LOCK_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// A test's whole helper-token staging window: holds the process-wide
/// environment lock and marks the current thread as its holder.
#[cfg(test)]
pub(crate) struct HelperTokenEnvLock(std::sync::MutexGuard<'static, ()>);

#[cfg(test)]
impl Drop for HelperTokenEnvLock {
    fn drop(&mut self) {
        // Drop runs before the guard field is released, so the flag clears
        // while the lock is still held; the flag is this thread's alone, so
        // another thread acquiring the lock never observes this one's staging.
        let _ = &self.0;
        HELPER_TOKEN_ENV_LOCK_HELD.with(|held| held.set(false));
    }
}

/// Open a helper-token staging window for a test: serializes against every
/// other test that stages or snapshots the token, and marks this thread so
/// [`HelperTokenGuard`]'s test-build assertions accept the staging.
#[cfg(test)]
pub(crate) fn lock_helper_token_env() -> HelperTokenEnvLock {
    let guard = HELPER_TOKEN_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    HELPER_TOKEN_ENV_LOCK_HELD.with(|held| held.set(true));
    HelperTokenEnvLock(guard)
}

/// Relaunch this executable elevated as a uniquely addressed helper, hidden.
/// `pipe_id` and `token` are random per launch. The one-shot `token` reaches
/// the helper through `HELPER_TOKEN_ENV` in the environment block the
/// elevated child inherits and through the ProgramData token file — never via
/// argv, which any same-user process can read for the child's lifetime. The
/// returned guard holds both copies until the caller has finished the pipe
/// handshake, then removes them. The GUI PID is also passed as an immutable
/// UAC argument so the helper can bind the named-pipe client to the process
/// that initiated this exact elevation request.
pub(crate) fn launch_core_helper(
    pipe_id: &str,
    token: &str,
) -> Result<HelperTokenGuard, HelperLaunchError> {
    let exe = std::env::current_exe()
        .map_err(|e| HelperLaunchError::Failed(Diag::new(Key::HelperLaunchExePathFailed).arg(e)))?;
    let exe_w: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let parent_pid = std::process::id();
    let params = helper_command_line(pipe_id, parent_pid);
    let params_w: Vec<u16> = std::ffi::OsStr::new(&params)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // Stage the credential before the UAC prompt: the env var for same-user
    // elevations, the ProgramData file for cross-user ones. A staging failure
    // fails the launch here — before any prompt — rather than hanging at the
    // pipe connect.
    let credentials = HelperTokenGuard::new(pipe_id, token)?;
    // SAFETY: `exe_w` and `params_w` are NUL-terminated wide buffers (built
    // with a trailing 0 above) that stay alive for the duration of the call;
    // `w!("runas")` is a static NUL-terminated literal, and `HWND::default()`
    // plus a null working directory are the documented defaults (desktop
    // window, inherit the caller's directory). ShellExecuteW copies all
    // strings during the call; the returned value is a status code that the
    // caller interprets per the docs and never dereferences. `credentials` is
    // alive for the whole call, so the child created here inherits the token
    // from this process's environment block.
    let instance = unsafe {
        ShellExecuteW(
            Some(HWND::default()),
            w!("runas"),
            PCWSTR(exe_w.as_ptr()),
            PCWSTR(params_w.as_ptr()),
            PCWSTR::null(),
            SW_HIDE,
        )
    };
    // Per ShellExecuteW docs the returned HINSTANCE is really a status code;
    // values <= 32 are errors. On either error path `credentials` drops and
    // removes both token copies.
    let code = instance.0 as isize;
    if code > 32 {
        Ok(credentials)
    } else if code == SE_ERR_ACCESSDENIED {
        Err(HelperLaunchError::Declined)
    } else {
        Err(HelperLaunchError::Failed(
            Diag::new(Key::HelperShellExecuteFailed).arg(code),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        HELPER_TOKEN_ENV, HelperLaunchError, HelperTokenGuard, helper_command_line,
        helper_token_path, lock_helper_token_env, program_data, program_data_from,
        read_helper_token_file,
    };
    use std::path::PathBuf;

    /// Same fixed-width hex credential shape the runtime generates for a real
    /// launch (`uuid::Uuid::new_v4().simple()`), written as literals so the
    /// expectations are independent of the code under test.
    const PIPE_ID: &str = "0123456789abcdef0123456789abcdef";
    const TOKEN: &str = "fedcba9876543210fedcba9876543210";

    /// The elevated child's argv must never carry the auth token —
    /// any same-user process can read a child's command line for its lifetime.
    #[test]
    fn helper_command_line_never_carries_the_auth_token() {
        let argv = helper_command_line(PIPE_ID, 4242);
        assert!(!argv.contains("--helper-token"));
        assert!(!argv.contains(TOKEN));
    }

    #[test]
    fn helper_command_line_keeps_the_immutable_identity_arguments() {
        let argv = helper_command_line(PIPE_ID, 4242);
        assert!(argv.contains("--core-helper"));
        assert!(argv.contains("--helper-pipe=0123456789abcdef0123456789abcdef"));
        assert!(argv.contains("--helper-parent=4242"));
    }

    /// The token reaches the elevated child through the environment block and
    /// through the ProgramData token file, and the guard removes both copies
    /// as soon as the child exists. The file channel is what survives a
    /// cross-user UAC elevation, whose environment is rebuilt for the target
    /// admin account (diagnosed: `token_env=false` on the real machine).
    #[test]
    fn helper_token_reaches_the_environment_and_file_and_both_are_removed() {
        let _env_lock = lock_helper_token_env();
        let previous = std::env::var_os(HELPER_TOKEN_ENV);
        let token_path = helper_token_path(PIPE_ID);
        let _ = std::fs::remove_file(&token_path);

        let _guard = HelperTokenGuard::new(PIPE_ID, TOKEN).expect("staging helper credentials");
        assert_eq!(
            std::env::var(HELPER_TOKEN_ENV).as_deref(),
            Ok(TOKEN),
            "the elevated child must inherit the token from the environment block"
        );
        assert_eq!(
            std::fs::read_to_string(&token_path).as_deref().ok(),
            Some(TOKEN),
            "the elevated child must be able to read the token file (cross-user UAC)"
        );

        // The helper consumes the file when the env channel is absent (the
        // cross-user case) and the file is deleted on a successful read.
        assert_eq!(
            read_helper_token_file(PIPE_ID).as_deref(),
            Some(TOKEN),
            "the helper must be able to read the token file"
        );
        assert!(
            !token_path.exists(),
            "the token file must be deleted once read"
        );

        drop(_guard);
        assert!(
            matches!(
                std::env::var(HELPER_TOKEN_ENV),
                Err(std::env::VarError::NotPresent)
            ),
            "the token must be removed once the child exists"
        );
        assert!(
            !token_path.exists(),
            "the guard must not leave a token file behind"
        );

        // Restore whatever this test binary inherited, so the process-wide
        // variable is exactly as it was before the test ran.
        match previous {
            Some(value) => {
                // SAFETY: `HELPER_TOKEN_ENV_LOCK` guarantees no parallel test
                // observes this write, and the value is the original one.
                unsafe { std::env::set_var(HELPER_TOKEN_ENV, value) };
            }
            None => {
                // SAFETY: same single-mutator discipline as the `Some` arm.
                unsafe { std::env::remove_var(HELPER_TOKEN_ENV) };
            }
        }
    }

    /// A staging failure must leave no token copy behind: the file
    /// channel is staged before the environment variable, so a failed file
    /// write returns without ever setting the variable — which would otherwise
    /// stay in this process's environment block and be inherited by every
    /// later child for the process lifetime — and the partial file from the
    /// failed write is removed on the way out.
    #[test]
    fn failed_token_file_staging_leaves_no_token_copy_behind() {
        let _env_lock = lock_helper_token_env();
        let previous = std::env::var_os(HELPER_TOKEN_ENV);
        // A distinct pipe id, so this test's file never collides with the one
        // staged by the success-path test above.
        let pipe_id = "abababababababababababababababab";
        let token_path = helper_token_path(pipe_id);
        let _ = std::fs::remove_file(&token_path);
        // `write_token_file` opens with CREATE_NEW, so a file already sitting
        // at the token path makes the stage fail deterministically. (A real
        // launch can never collide: pipe ids are random per launch.)
        std::fs::write(&token_path, "stale")
            .expect("pre-creating the blocking token file must succeed");
        let result = HelperTokenGuard::new(pipe_id, TOKEN);
        assert!(
            matches!(result, Err(HelperLaunchError::Failed(_))),
            "staging must fail when the token file cannot be written"
        );
        assert_eq!(
            std::env::var_os(HELPER_TOKEN_ENV),
            previous,
            "a failed staging must never set the token environment variable"
        );
        assert!(
            !token_path.exists(),
            "a failed staging must not leave a token file behind"
        );
    }

    /// The GUI writes and the elevated helper reads exactly this path (derived
    /// from the immutable `--helper-pipe` argument, so no secret crosses
    /// argv); a silent rename on either side would strand the token.
    #[test]
    fn helper_token_file_path_is_the_shared_contract() {
        let path = helper_token_path(PIPE_ID);
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        assert!(
            file_name.starts_with("broccoli-core-helper-token-") && file_name.ends_with(PIPE_ID),
            "token file path must be the shared GUI/helper contract"
        );
    }

    /// A missing or unreadable token file must yield no token (the helper
    /// exits 2), never a panic.
    #[test]
    fn helper_token_file_read_missing_returns_none() {
        let _env_lock = lock_helper_token_env();
        let path = helper_token_path("00000000000000000000000000000000");
        let _ = std::fs::remove_file(&path);
        assert!(read_helper_token_file("00000000000000000000000000000000").is_none());
    }

    /// An undecodable shell result must not degrade the token-file location:
    /// an empty path would put the credential relative to the launcher's
    /// current directory, where the elevated helper — spawned with a different
    /// working directory — never looks for it. Both a failed decode and an
    /// empty string resolve to the well-known ProgramData literal instead.
    #[test]
    fn undecodable_program_data_falls_back_to_the_well_known_literal() {
        let fallback = PathBuf::from(r"C:\ProgramData");
        assert_eq!(program_data_from(None), fallback);
        assert_eq!(program_data_from(Some(String::new())), fallback);
        assert_eq!(
            program_data_from(Some(r"C:\ProgramData".to_owned())),
            fallback
        );
        assert!(
            program_data().is_absolute(),
            "the resolved ProgramData root must be absolute"
        );
    }
}
