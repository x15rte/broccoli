//! Elevated Xray helper for Windows TUN mode.
//!
//! The GUI remains unelevated. Each request carries a random pipe/token plus
//! the immutable launching GUI PID and its kernel creation time (a recycled
//! PID is born later and rejected). Before any Xray spawn, the helper stages
//! exactly the config content the GUI validated and sent over the
//! authenticated pipe — it never re-reads the user-writable active config
//! path at elevated time — into a fresh
//! protected ProgramData directory alongside only pinned runtime payloads,
//! validates that staged config there, and never executes or loads assets
//! from user-writable AppData.

use std::error::Error as _;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read as _, Seek as _, SeekFrom, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::diag::{Diag, DiagArg, DiagError, DiagResult};
use crate::i18n::Key;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_MORE_DATA, FILETIME, GENERIC_READ, GENERIC_WRITE, HANDLE, WAIT_OBJECT_0,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetFileSecurityW,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    SECURITY_DESCRIPTOR_CONTROL, SetFileSecurityW, TOKEN_QUERY, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, FILE_SHARE_READ, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    ReadFile,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, NAMED_PIPE_MODE, PIPE_NOWAIT,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT, PeekNamedPipe, SetNamedPipeHandleState,
    WaitNamedPipeW,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    WaitForSingleObject,
};
use windows::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows::core::{BOOL, HRESULT, PCWSTR};

use crate::model::inbound::TUN_INBOUND_TAG;
use crate::rt::supervisor::CREATE_NO_WINDOW;
use crate::sys::security::{
    Sid, TokenHandle, is_invalid_owner_error, with_protected_attributes, with_protected_descriptor,
};

const PIPE_PREFIX: &str = r"\\.\pipe\broccoli-core-helper-";
/// Format marker of the fallback line the GUI shows when a log record
/// cannot be decoded: helper-authored records carry keyed layers instead.
const HELPER_LINE_PREFIX: &str = "helper: ";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const PIPE_POLL: Duration = Duration::from_millis(50);
/// Capacity of the bounded helper→runtime event channel: one TUN flood
/// window of lines, drained in bulk by the
/// runtime select loop between bounded commands. Mirrors the 2048-slot GUI
/// event channel (`rt::EVT_CHANNEL_CAPACITY`), whose LogGate already sets
/// the drop-and-coalesce precedent this hop follows. Lines beyond the cap
/// are never queued — `HopLogGate` counts them and delivers one summary.
const HELPER_EVT_CHANNEL_CAPACITY: usize = super::EVT_CHANNEL_CAPACITY;
/// Upper bound for one wire message on the helper pipe. A decoded line is
/// capped at
/// [`super::supervisor::MAX_LINE_BYTES`], but JSON escaping expands it up to
/// ~6× on the wire (control characters become `\u00XX`), so 16× the line
/// cap covers the worst case with headroom. Messages beyond this are
/// truncated at the cap and their remainder drained — never fatal.
const MAX_WIRE_MESSAGE_BYTES: usize = 16 * super::supervisor::MAX_LINE_BYTES;
/// Full-hop retry window for a lifecycle event (`State`/`Exit`) crossing
/// the helper hop. The GUI channel's lifecycle
/// window ([`super::EVENT_SEND_BOUND`], 250 ms) is sized to the GUI frame
/// cycle, but this hop's consumer is the single current-thread runtime
/// select loop, which suspends its events arm for the whole duration of
/// any command handler — and healthy handlers stall far beyond 250 ms: the
/// stats poll runs sequential bounded RPCs (~1.5 s), a TUN teardown is
/// bounded by [`super::TUN_CLOSE_DEADLINE`] (3.25 s), and payload hashing
/// freezes the loop for up to ~0.6 s. A TUN-mode core's unsolicited `Exit`
/// is the only signal its Pipe backend ever gets, so an event must survive
/// any legitimate stall: 4 s outlasts every documented handler bound. The
/// event is dropped only after a whole window with no drain at all, when
/// the runtime is wedged or gone (no event is observable anyway).
const LIFECYCLE_SEND_WINDOW: Duration = Duration::from_millis(4000);
/// Upper bound for settling a previous TUN session's wintun teardown before
/// spawning the replacement core (see `clean_leftover_tun_adapter`).
const TUN_CLEAN_TIMEOUT: Duration = Duration::from_secs(10);
const STAGE_BASE: &str = ".broccoli-secure-runtime";
const STAGE_PREFIX: &str = "stage-";
const STAGE_MARKER: &str = ".broccoli-secure-stage";
const STAGE_MARKER_CONTENT: &[u8] = b"broccoli-secure-stage-v1";
const STAGED_CONFIG: &str = "config.json";
const CONFIG_TEST_TIMEOUT: Duration = Duration::from_secs(10);
const STAGE_ENTRIES: &[&str] = &[
    "xray.exe",
    "wintun.dll",
    "geoip.dat",
    "geosite.dat",
    STAGED_CONFIG,
    STAGE_MARKER,
];

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

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn is_hex_secret(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validated_pipe_name(pipe_id: &str) -> Result<String, DiagError> {
    if !is_hex_secret(pipe_id) {
        return Err(DiagError::new(Diag::new(Key::HelperPipeIdInvalid)));
    }
    Ok(format!("{PIPE_PREFIX}{pipe_id}"))
}

/// Parse exactly one immutable GUI PID from the elevated UAC command line.
/// Duplicate, zero, malformed, or missing values are rejected.
pub fn parse_helper_parent_arg(args: &[String]) -> Result<u32, DiagError> {
    let mut values = args
        .iter()
        .filter_map(|argument| argument.strip_prefix("--helper-parent="));
    let value = values
        .next()
        .ok_or_else(|| DiagError::new(Diag::new(Key::HelperParentArgMissing)))?;
    if values.next().is_some() {
        return Err(DiagError::new(Diag::new(Key::HelperParentArgDuplicate)));
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid != 0)
        .ok_or_else(|| DiagError::new(Diag::new(Key::HelperParentArgInvalid)))
}

/// Immutable identity of the launching GUI, fixed the moment the helper
/// opens the argv PID: the PID from the UAC command line plus the kernel
/// creation time of the exact process object that PID named then. A bare
/// PID is recyclable — if the GUI dies in
/// the launch window, a same-user process can be born later with the same
/// PID and pass a number-only check. Creation time is assigned by the
/// kernel at process birth and never changes, so the pair pins the parent
/// to the process the helper authenticated at launch; a recycled PID is
/// born later and is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParentIdentity {
    pid: u32,
    /// Creation FILETIME (100 ns intervals since 1601-01-01) as a u64.
    created: u64,
}

fn filetime_value(time: FILETIME) -> u64 {
    u64::from(time.dwLowDateTime) | (u64::from(time.dwHighDateTime) << 32)
}

/// Creation time of the process behind the open handle `handle`, in
/// [`filetime_value`] units.
fn process_creation_time(handle: HANDLE) -> windows::core::Result<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: `handle` is a valid, open process handle owned by the caller
    // (from `OpenProcess` in `serve` or `process_creation_time_of`), still
    // open; every out-parameter points at an initialized `FILETIME` alive
    // for the call. The windows crate maps a failure to `Err`.
    unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) }?;
    Ok(filetime_value(creation))
}

/// Current creation time of the live process `pid`, opened fresh with the
/// minimal query right. Fails closed when the process is gone or the open
/// is denied, so an acceptance-time query never guesses.
fn process_creation_time_of(pid: u32) -> Result<u64, DiagError> {
    // SAFETY: `pid` is a kernel-reported pipe client PID; no security
    // attributes, and `PROCESS_QUERY_LIMITED_INFORMATION` is the minimal
    // right `GetProcessTimes` needs — the same combination `serve` uses for
    // the launching GUI. The windows crate maps a NULL handle to `Err`
    // (wrapped by the diag), so `Ok` is a valid handle this function
    // owns and closes exactly once below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
        .diag_with(Diag::new(Key::HelperProcessOpenFailed).arg(pid))?;
    let created = process_creation_time(handle)
        .diag_with(Diag::new(Key::HelperProcessTimeReadFailed).arg(pid));
    // SAFETY: `handle` is the valid, still-open handle from `OpenProcess`
    // above; this function is its exclusive owner, so `CloseHandle` runs
    // exactly once here.
    unsafe {
        let _ = CloseHandle(handle);
    }
    created
}

/// Accept the pipe client as the launching GUI only when it is the exact
/// process the helper authenticated at launch: the kernel-reported client
/// PID must equal the argv PID *and* its current creation time must equal
/// the creation time captured from that process at helper start. A recycled
/// PID is born later, so its creation time differs and the client is
/// rejected — fail closed, exactly like every other identity mismatch.
fn parent_identity_accepts(
    expected: &ParentIdentity,
    actual_pid: u32,
    actual_created: u64,
) -> bool {
    expected.pid != 0
        && expected.created != 0
        && actual_pid == expected.pid
        && actual_created == expected.created
}

fn token_matches(expected: &str, presented: &str) -> bool {
    if !is_hex_secret(expected) || presented.len() != expected.len() {
        return false;
    }
    expected
        .bytes()
        .zip(presented.bytes())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn wait_for_connection(handle: HANDLE, parent: Option<HANDLE>) -> Result<(), DiagError> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    loop {
        // SAFETY: `parent` is a valid open handle to the launching GUI process
        // (from `OpenProcess` in `serve`), still open; timeout 0 polls without
        // blocking, and the result is compared against `WAIT_OBJECT_0`.
        if parent.is_some_and(|parent| unsafe { WaitForSingleObject(parent, 0) == WAIT_OBJECT_0 }) {
            return Err(DiagError::new(Diag::new(
                Key::HelperParentExitedBeforeConnect,
            )));
        }
        // SAFETY: `handle` is the valid open pipe handle from
        // `CreateNamedPipeW`, still listening; `None` (null overlapped) is the
        // synchronous form — on this PIPE_NOWAIT pipe the call returns
        // immediately, and the caller handles the documented 535/536 error
        // codes while keeping the handle valid for retry.
        match unsafe { ConnectNamedPipe(handle, None) } {
            Ok(()) => return Ok(()),
            Err(error) if error.code() == windows::core::HRESULT::from_win32(535) => {
                // Client connected between CreateNamedPipe and this call.
                return Ok(());
            }
            Err(error) if error.code() == windows::core::HRESULT::from_win32(536) => {
                if Instant::now() >= deadline {
                    return Err(DiagError::new(Diag::new(Key::HelperConnectTimeout)));
                }
                std::thread::sleep(PIPE_POLL);
            }
            Err(error) => {
                return Err(DiagError::new(Diag::new(Key::HelperConnectFailed)).caused_by(error));
            }
        }
    }
}

/// Wait until one complete client write is available without ever entering a
/// blocking read. `Ok(false)` means the authenticated parent exited or closed
/// its pipe, which is the helper watchdog signal.
fn wait_for_message(
    pipe: HANDLE,
    deadline: Option<Instant>,
    parent: Option<HANDLE>,
) -> Result<bool, DiagError> {
    loop {
        // SAFETY: `parent` is a valid open handle to the launching GUI process
        // (from `OpenProcess` in `serve`), still open; timeout 0 polls without
        // blocking and the result is checked against `WAIT_OBJECT_0`.
        if let Some(parent) = parent
            && unsafe { WaitForSingleObject(parent, 0) } == WAIT_OBJECT_0
        {
            return Ok(false);
        }
        let mut available = 0u32;
        // SAFETY: `pipe` is the valid open server pipe handle; a null
        // `lpBuffer` with `nBufferSize` 0 is the documented peek-that-reads-
        // nothing form (no bytes copied), and `available` is a valid
        // out-parameter the kernel writes before returning. The result is
        // checked by the caller.
        match unsafe { PeekNamedPipe(pipe, None, 0, None, Some(&mut available), None) } {
            Ok(()) if available > 0 => return Ok(true),
            Ok(()) => {}
            Err(error) => {
                return Err(DiagError::new(Diag::new(Key::HelperPipeClosed)).caused_by(error));
            }
        }
        if deadline.is_some_and(|value| Instant::now() >= value) {
            return Err(DiagError::new(Diag::new(Key::HelperAuthTimeout)));
        }
        std::thread::sleep(PIPE_POLL);
    }
}

/// Read one complete message from the message-mode pipe `handle`, sized to
/// the message instead of a fixed 8 KiB buffer.
///
/// Message-mode reads fail with `ERROR_MORE_DATA` when the caller's buffer is
/// smaller than the message (the bytes that fit are consumed from the pipe).
/// This peeks for the buffered size and reads exactly that, looping across
/// `ERROR_MORE_DATA` when the writer is mid-message, so a message larger than
/// the old `BufReader` capacity arrives intact instead of killing the loop.
///
/// A message larger than `cap` is truncated at `cap` bytes and the rest is
/// drained so the pipe stays aligned; the caller's JSON parse of the
/// truncated bytes fails and the message is skipped — never fatal. `Ok(None)`
/// means no message is currently buffered; `Err` means the pipe is gone.
fn read_pipe_message(handle: HANDLE, cap: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut available = 0u32;
    // SAFETY: `handle` is the valid open pipe handle owned by the caller's
    // `File`; a null buffer with size 0 peeks without reading, and
    // `available` is a valid out-parameter the kernel fills before returning.
    // A failed peek means the peer has closed the pipe: report `Err` so the
    // reader loop exits and the owning side learns the pipe is gone (an
    // empty peek, by contrast, is a live pipe with no message buffered yet).
    if let Err(error) = unsafe { PeekNamedPipe(handle, None, 0, None, Some(&mut available), None) }
    {
        return Err(std::io::Error::other(error));
    }
    if available == 0 {
        return Ok(None);
    }
    let mut message: Vec<u8> = Vec::with_capacity((available as usize).min(cap));
    let mut chunk = vec![0u8; 8 * 1024];
    loop {
        let mut read = 0u32;
        // SAFETY: `handle` is the valid open pipe handle; `chunk` is a
        // writable buffer alive for the call; `read` is a valid
        // out-parameter. The result is checked below.
        let result = unsafe { ReadFile(handle, Some(&mut chunk[..]), Some(&mut read), None) };
        match result {
            Ok(()) => {
                message.extend_from_slice(&chunk[..read as usize]);
                if message.len() > cap {
                    message.truncate(cap);
                }
                return Ok(Some(message));
            }
            Err(error) if error.code() == HRESULT::from_win32(ERROR_MORE_DATA.0) => {
                message.extend_from_slice(&chunk[..read as usize]);
                if message.len() >= cap {
                    drain_pipe_remainder(handle)?;
                    message.truncate(cap);
                    return Ok(Some(message));
                }
            }
            Err(error) => return Err(std::io::Error::other(error)),
        }
    }
}

/// Discard the rest of the current over-cap message (up to the message
/// boundary) so the next read starts at the next message.
fn drain_pipe_remainder(handle: HANDLE) -> std::io::Result<()> {
    let mut chunk = vec![0u8; 8 * 1024];
    loop {
        let mut read = 0u32;
        // SAFETY: `handle` is the valid open pipe handle; `chunk` is a
        // writable buffer alive for the call; `read` is a valid
        // out-parameter. The result is checked below.
        let result = unsafe { ReadFile(handle, Some(&mut chunk[..]), Some(&mut read), None) };
        match result {
            Ok(()) => return Ok(()),
            Err(error) if error.code() == HRESULT::from_win32(ERROR_MORE_DATA.0) => {}
            Err(error) => return Err(std::io::Error::other(error)),
        }
    }
}

/// The launching GUI process's user SID — the principal granted read/write
/// access on the helper pipe's protected DACL. Read from the immutable
/// process handle opened by the caller, which holds the
/// `PROCESS_QUERY_LIMITED_INFORMATION` access `OpenProcessToken` needs.
fn parent_token_user(parent: HANDLE) -> Result<Sid, DiagError> {
    let token = TokenHandle::open_process_token(parent, TOKEN_QUERY)
        .diag(Key::HelperParentTokenOpenFailed)?;
    Sid::token_user(&token).diag(Key::HelperParentSidReadFailed)
}

/// The helper's own user SID — the owner/group fallback when the token
/// cannot assign the Administrators group, and the acceptable-owner
/// comparison for the protected runtime directories (see
/// `create_helper_pipe` and `create_protected_directory`).
fn current_process_user_sid() -> Result<Sid, DiagError> {
    let token =
        TokenHandle::open_current_process(TOKEN_QUERY).diag(Key::HelperOwnTokenOpenFailed)?;
    Sid::token_user(&token).diag(Key::HelperOwnSidReadFailed)
}

/// Create the helper pipe, preferring the Administrators group as owner —
/// the owner that keeps a medium-integrity process from reclaiming WRITE_DAC
/// through owner rights (see `sys::security::with_protected_attributes`).
/// Assigning Administrators as owner requires `SeRestorePrivilege` or the
/// elevated-token `SE_GROUP_OWNER` attribute; a token without either
/// (unelevated test runs, some cross-user UAC tokens) fails with
/// `ERROR_INVALID_OWNER` (1307), so the pipe is retried with the helper's
/// own user SID as owner/group — assignable by any token. Access control is
/// identical in both branches: the protected DACL still names SYSTEM,
/// Administrators, and the launching GUI.
fn create_helper_pipe(wide_name: &[u16], parent_user: &Sid) -> Result<HANDLE, DiagError> {
    let administrators =
        Sid::well_known(WinBuiltinAdministratorsSid).diag(Key::HelperWellKnownSidFailed)?;
    let create = |owner: Option<&Sid>| {
        with_protected_attributes(
            owner,
            &[(parent_user, GENERIC_READ.0 | GENERIC_WRITE.0)],
            |attributes| unsafe {
                CreateNamedPipeW(
                    PCWSTR(wide_name.as_ptr()),
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
                    1,
                    64 * 1024,
                    64 * 1024,
                    0,
                    Some(attributes),
                )
            },
        )
        .diag(Key::HelperPipeAttributesFailed)
    };
    let mut handle = create(Some(&administrators))?;
    // No API call may run between `CreateNamedPipeW` inside `create` and this
    // error read, or `GetLastError` would be clobbered.
    if handle.is_invalid() && is_invalid_owner_error(&windows::core::Error::from_thread()) {
        // ERROR_INVALID_OWNER: this token cannot assign Administrators as
        // owner; retry with our own user SID, which is always assignable.
        let own = current_process_user_sid()?;
        handle = create(Some(&own))?;
    }
    Ok(handle)
}

fn path_to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
}

fn trusted_program_data() -> Result<PathBuf, DiagError> {
    // SAFETY: `&FOLDERID_ProgramData` is a static GUID valid for the call;
    // `hToken = None` uses the current user's token and `KF_FLAG_DEFAULT`
    // requests the default path. The crate maps the FAILED HRESULT to `Err`,
    // so `Ok` is a non-null `PWSTR` to a `CoTaskMemAlloc`-allocated,
    // NUL-terminated path string owned by the caller and freed below.
    let pointer = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
        .diag(Key::HelperProgramDataResolveFailed)?;
    // SAFETY: `pointer` is the non-null, NUL-terminated UTF-16 path string
    // returned above; `to_string()` reads only up to the terminator while the
    // allocation is still alive (it is freed on the next line).
    let decoded = unsafe { pointer.to_string() };
    // SAFETY: `pointer` is the `CoTaskMemAlloc`-allocated buffer from
    // `SHGetKnownFolderPath`, still alive and not previously freed; this is
    // its single free, after which the pointer is never used again.
    unsafe {
        CoTaskMemFree(pointer.0.cast());
    }
    let path = PathBuf::from(decoded.diag(Key::HelperProgramDataDecodeFailed)?);
    let metadata = fs::symlink_metadata(&path)
        .diag_with(Diag::new(Key::HelperProgramDataInspectFailed).arg(path.display()))?;
    if !path.is_absolute() || !metadata.is_dir() || is_reparse(&metadata) {
        return Err(DiagError::new(Diag::new(
            Key::HelperProgramDataNotDirectory,
        )));
    }
    Ok(path)
}

/// Loaded security state of a protected runtime directory. `dacl` (when
/// `dacl_present`) and the owner SID used by [`load_protected_directory`]
/// point into `words`, so the storage must stay alive while they are used.
struct LoadedProtectedDirectory {
    /// Word storage for the self-relative descriptor written by
    /// [`load_protected_directory`]. A descriptor embeds pointer fields, so
    /// it must be read at an 8-byte-aligned address; `Vec<u8>` only
    /// guarantees 1-byte alignment by contract.
    words: Vec<u64>,
    /// Number of descriptor bytes initialized at the base of `words`.
    byte_len: usize,
    control: SECURITY_DESCRIPTOR_CONTROL,
    owner_is_expected: bool,
    dacl_present: bool,
    dacl: *mut ACL,
}

impl LoadedProtectedDirectory {
    /// The loaded descriptor bytes, for the `validated_ace` bounds check.
    fn bytes(&self) -> &[u8] {
        // SAFETY: `words` is a live allocation of `byte_len.div_ceil(8)`
        // `u64`s, so at least `byte_len` bytes from its base are addressable
        // and were initialized (zeroed before the load, then written by the
        // successful `GetFileSecurityW`). The returned view borrows `words`,
        // so it cannot outlive the storage the `dacl`/SID pointers target.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.byte_len) }
    }
}

/// Load a protected runtime directory's descriptor, control bits, owner
/// acceptability, and DACL in one pass. Shared by the strict verification
/// and the benign-deviation diagnosis below.
fn load_protected_directory(path: &Path) -> Result<LoadedProtectedDirectory, DiagError> {
    let metadata = fs::symlink_metadata(path)
        .diag_with(Diag::new(Key::HelperDirectoryInspectFailed).arg(path.display()))?;
    if !metadata.is_dir() || is_reparse(&metadata) {
        return Err(DiagError::new(Diag::new(Key::HelperDirectoryNotOrdinary)));
    }

    let wide = path_to_wide(path);
    let information = OWNER_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0;
    let mut required = 0u32;
    // SAFETY: `wide` is a NUL-terminated wide path valid for the call. A null
    // descriptor buffer with 0 length is the documented sizing query: the API
    // writes the required size into `required` and fails with
    // ERROR_INSUFFICIENT_BUFFER (ignored here by design); no buffer is
    // written.
    let _ = unsafe { GetFileSecurityW(PCWSTR(wide.as_ptr()), information, None, 0, &mut required) };
    if required == 0 {
        return Err(DiagError::new(Diag::new(
            Key::HelperDescriptorSizeQueryFailed,
        )));
    }
    let byte_len = required as usize;
    // A self-relative security descriptor carries pointer fields, so it must
    // be read at an 8-byte-aligned address. `Vec<u8>` is only 1-byte aligned
    // by contract — the system allocator's over-alignment is not a language
    // guarantee — so the storage is `u64` words covering the same byte span,
    // the same rule `sys::security::Sid::token_user` and
    // `sys::netif::AdapterBuffer` apply to their Win32 buffers.
    let mut words = vec![0u64; byte_len.div_ceil(std::mem::size_of::<u64>())];
    let descriptor = PSECURITY_DESCRIPTOR(words.as_mut_ptr().cast());
    // SAFETY: `words` covers at least `required` zeroed bytes from its base
    // and stays alive through all the descriptor reads below; `descriptor`
    // points into it, so the kernel writes at most `required` bytes. The
    // storage is 8-byte aligned (`Vec<u64>`), satisfying the descriptor's
    // pointer-field alignment when read back. The result is checked via
    // `loaded.as_bool()` plus the thread's last error.
    let loaded = unsafe {
        GetFileSecurityW(
            PCWSTR(wide.as_ptr()),
            information,
            Some(descriptor),
            required,
            &mut required,
        )
    };
    if !loaded.as_bool() {
        return Err(windows::core::Error::from_thread()).diag(Key::HelperDescriptorReadFailed);
    }

    let mut control = SECURITY_DESCRIPTOR_CONTROL(0);
    let mut revision = 0u32;
    // SAFETY: `descriptor` points at the valid, fully initialized
    // self-relative security descriptor written by the successful
    // `GetFileSecurityW` above (the `words` storage stays alive); `control` and
    // `revision` are valid out-parameters and the return is checked.
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control.0, &mut revision) }
        .diag(Key::HelperDescriptorControlReadFailed)?;

    let administrators =
        Sid::well_known(WinBuiltinAdministratorsSid).diag(Key::HelperWellKnownSidFailed)?;
    let mut owner = PSID(std::ptr::null_mut());
    let mut owner_defaulted = BOOL(0);
    // SAFETY: `descriptor` is the valid descriptor in the live `words`
    // storage; `owner` and `owner_defaulted` are valid out-parameters, the
    // return is checked, and on success `owner` points into the same buffer
    // (or is null when no owner is set, which the following `EqualSid`
    // rejects).
    unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) }
        .diag(Key::HelperOwnerReadFailed)?;
    // SAFETY: `owner` is the SID pointer written by `GetSecurityDescriptorOwner`
    // (null when absent — EqualSid then fails with ERROR_INVALID_PARAMETER,
    // which bails below); `administrators.psid()` is the well-known SID built
    // above. Both are alive, and EqualSid only reads them. A helper token
    // that cannot assign Administrators as owner (unelevated runs) creates
    // the directory with its own user SID instead — equally acceptable,
    // since access is governed by the protected DACL.
    let owner_is_expected = unsafe { EqualSid(owner, administrators.psid()) }.is_ok()
        || current_process_user_sid()
            .ok()
            .is_some_and(|own| unsafe { EqualSid(owner, own.psid()) }.is_ok());

    let mut dacl_present = BOOL(0);
    let mut dacl_defaulted = BOOL(0);
    let mut dacl = std::ptr::null_mut::<ACL>();
    // SAFETY: `descriptor` is the valid descriptor in the live `words`
    // storage; the three out-parameters are valid, the return is checked, and
    // on success `dacl` (when `dacl_present`) points into the same storage —
    // alive until the function returns.
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    }
    .diag(Key::HelperDaclReadFailed)?;

    Ok(LoadedProtectedDirectory {
        words,
        byte_len,
        control,
        owner_is_expected,
        dacl_present: dacl_present.as_bool(),
        dacl,
    })
}

/// The ACE fields the verification loops read, decoded from the bytes
/// [`validated_ace`] checked.
///
/// The fields come back as values rather than behind a typed pointer because
/// the descriptor storage is byte-addressed — the loader keeps it in `Vec<u64>`
/// words, and the tests hand in `[u8; N]` — so no `ACE_HEADER` or
/// `ACCESS_ALLOWED_ACE` place exists at any particular offset, and a typed
/// pointer into it would assert an alignment the storage does not promise.
/// Decoding the bytes directly is also why the validator needs no `unsafe`.
struct ValidatedAce {
    /// `AceType`; `0` is `ACCESS_ALLOWED_ACE_TYPE`, the only type whose fields
    /// the callers compare.
    ace_type: u8,
    /// `AceFlags`; the strict shapes the callers accept carry `0`.
    ace_flags: u8,
    /// `Mask`, meaningful only for the allow-ACEs (`ace_type == 0`).
    mask: u32,
    /// `SidStart`: the embedded SID, alive as long as the validated buffer, and
    /// the only thing handed back as a pointer (`EqualSid` walks it). For the
    /// allow-ACEs whose `SidStart` the callers compare, the validator has also
    /// proven the SID's header and sub-authorities fit the declared `AceSize`;
    /// every other ACE type is rejected by the callers before any SID read.
    sid: PSID,
}

/// Check that `ace` (as returned by `GetAce`) lies fully inside the loaded
/// descriptor's `buffer` and declares an `AceSize` large enough for the fixed
/// prefix the verification loops read (4-byte header + 4-byte mask + a
/// minimum 12-byte SID). For the allow-ACEs whose embedded SID the callers
/// compare, the SID's own header and sub-authorities must fit that `AceSize`
/// too, because `EqualSid` derives the compared length from the SID's
/// `SubAuthorityCount` field. The DACL is only trusted after this check: a
/// corrupt `AceSize` on disk would otherwise walk the pointer far past the
/// buffer, and the benign-deviation path runs exactly while the DACL is
/// user-writable.
fn validated_ace(ace: *const core::ffi::c_void, buffer: &[u8]) -> Option<ValidatedAce> {
    // The ACE arrives as a pointer, but every byte of it is read through
    // `buffer`: the offset is what the bounds checks need, and decoding the
    // bytes as bytes keeps the whole read in safe code — no `ACE_HEADER` or
    // `ACCESS_ALLOWED_ACE` place exists at an offset whose alignment the
    // storage cannot promise.
    let offset = ace.addr().checked_sub(buffer.as_ptr().addr())?;
    if offset.checked_add(4)? > buffer.len() {
        return None;
    }
    let ace_type = buffer[offset];
    let ace_flags = buffer[offset + 1];
    let size = usize::from(u16::from_le_bytes([buffer[offset + 2], buffer[offset + 3]]));
    if size < 20 || offset.checked_add(size)? > buffer.len() {
        return None;
    }
    if ace_type == 0 {
        // ACCESS_ALLOWED_ACE_TYPE only: the callers compare the `SidStart` of
        // exactly these ACEs, and `EqualSid` walks the SID by its own
        // `SubAuthorityCount` — a forged count must not push that walk past
        // the validated `AceSize`. Every other ACE type keeps its previous
        // size-only treatment (the callers reject it before any SID read).
        // The count sits at offset 9, inside the `AceSize >= 20` bytes checked
        // above.
        let sub_authorities = usize::from(buffer[offset + 9]);
        if 8 + 4 * sub_authorities > size - 8 {
            return None;
        }
    }
    Some(ValidatedAce {
        ace_type,
        ace_flags,
        // `Mask` occupies offsets 4..8, also inside the checked bytes; the
        // descriptor is little-endian on every target this app builds for.
        mask: u32::from_le_bytes([
            buffer[offset + 4],
            buffer[offset + 5],
            buffer[offset + 6],
            buffer[offset + 7],
        ]),
        // `SidStart` sits at offset 8, inside the validated bytes; the pointer
        // is handed to `EqualSid` and never read here.
        sid: PSID(buffer.as_ptr().wrapping_add(offset + 8).cast_mut().cast()),
    })
}

fn verify_protected_directory(path: &Path) -> Result<(), DiagError> {
    let loaded = load_protected_directory(path)?;
    if !loaded.control.contains(SE_DACL_PRESENT) || !loaded.control.contains(SE_DACL_PROTECTED) {
        return Err(DiagError::new(Diag::new(Key::HelperDaclMissingOrInherited)));
    }
    if !loaded.owner_is_expected {
        return Err(DiagError::new(Diag::new(Key::HelperOwnerUnexpected)));
    }
    if !loaded.dacl_present || loaded.dacl.is_null() {
        return Err(DiagError::new(Diag::new(Key::HelperDaclMissing)));
    }
    // SAFETY: `loaded.dacl` is only dereferenced after the `dacl_present` and
    // `dacl.is_null()` checks above, so it points at the DACL inside the
    // valid, 8-byte-aligned descriptor storage (fully initialized by
    // `GetFileSecurityW`); its header (AceCount at offset 2) is therefore
    // initialized too.
    let ace_count = unsafe { (*loaded.dacl).AceCount };
    if ace_count != 2 {
        return Err(DiagError::new(
            Diag::new(Key::HelperDaclUnexpectedPrincipals).arg(ace_count),
        ));
    }

    let system = Sid::well_known(WinLocalSystemSid).diag(Key::HelperWellKnownSidFailed)?;
    let administrators =
        Sid::well_known(WinBuiltinAdministratorsSid).diag(Key::HelperWellKnownSidFailed)?;
    let mut saw_system = false;
    let mut saw_administrators = false;
    for index in 0..2 {
        let mut raw_ace = std::ptr::null_mut();
        // SAFETY: `loaded.dacl` is the valid, non-null DACL returned above;
        // `index` is 0..2, within the AceCount (== 2) just verified; `raw_ace`
        // is a valid out-parameter and the return is checked.
        unsafe { GetAce(loaded.dacl, index, &mut raw_ace) }.diag(Key::HelperAceReadFailed)?;
        // `validated_ace` proved the ACE — and, for an allow-ACE, the SID it
        // names — lies inside `loaded`'s buffer, alive through the loop.
        let Some(ace) = validated_ace(raw_ace.cast(), loaded.bytes()) else {
            return Err(DiagError::new(Diag::new(Key::HelperAceMalformed)));
        };
        if ace.ace_type != 0 || ace.ace_flags != 0 || ace.mask != FILE_ALL_ACCESS.0 {
            return Err(DiagError::new(Diag::new(Key::HelperAceNotFullControl)));
        }
        // SAFETY: `ace.sid` points at the `SidStart` of the ACE — an embedded,
        // well-formed SID (its length fits the ACE's `AceSize`) inside the
        // live DACL buffer; `system.psid()` is the well-known SYSTEM SID
        // built above. EqualSid only reads both.
        if unsafe { EqualSid(ace.sid, system.psid()) }.is_ok() {
            if saw_system {
                return Err(DiagError::new(Diag::new(Key::HelperAceSystemRepeated)));
            }
            saw_system = true;
            // SAFETY: as above — `ace.sid` is the embedded SID in the live
            // DACL buffer and `administrators.psid()` is the well-known
            // Administrators SID built above; EqualSid only reads them.
        } else if unsafe { EqualSid(ace.sid, administrators.psid()) }.is_ok() {
            if saw_administrators {
                return Err(DiagError::new(Diag::new(
                    Key::HelperAceAdministratorsRepeated,
                )));
            }
            saw_administrators = true;
        } else {
            return Err(DiagError::new(Diag::new(Key::HelperAceUnexpectedSid)));
        }
    }
    if !saw_system || !saw_administrators {
        return Err(DiagError::new(Diag::new(Key::HelperAcePrincipalMissing)));
    }
    Ok(())
}

/// True when `path`'s only deviation from the strict protected shape is one
/// extra full-control allow-ACE next to an intact SYSTEM + Administrators
/// pair — exactly what Explorer's "permanently get access" prompt adds to a
/// folder a user clicked into. Only an elevated process (or the user
/// granting themselves access first) can create such a state, so repairing
/// it restores the invariant without helping any attacker. Any read
/// problem, and every other deviation, reports false: the caller then fails
/// closed on the original verification error.
fn dacl_deviation_is_benign(path: &Path) -> bool {
    let Ok(loaded) = load_protected_directory(path) else {
        return false;
    };
    if !loaded.control.contains(SE_DACL_PRESENT)
        || !loaded.control.contains(SE_DACL_PROTECTED)
        || !loaded.owner_is_expected
        || !loaded.dacl_present
        || loaded.dacl.is_null()
    {
        return false;
    }
    // SAFETY: `loaded.dacl` is non-null and valid here (checked above); it
    // points at the DACL inside the live, 8-byte-aligned storage written by
    // `load_protected_directory`.
    if unsafe { (*loaded.dacl).AceCount } != 3 {
        return false;
    }
    // The extra ACE must belong to the current user: Explorer adds the SID
    // of whoever clicks "Continue", and only an elevated process or that
    // same user could have created the deviation. A well-known or foreign
    // SID is not the documented shape and stays fail-closed.
    let Ok(own) = current_process_user_sid() else {
        return false;
    };
    let own_sid = own.psid();
    let Ok(system) = Sid::well_known(WinLocalSystemSid) else {
        return false;
    };
    let Ok(administrators) = Sid::well_known(WinBuiltinAdministratorsSid) else {
        return false;
    };
    let mut saw_system = false;
    let mut saw_administrators = false;
    let mut extra_aces = 0u32;
    for index in 0..3 {
        let mut raw_ace = std::ptr::null_mut();
        // SAFETY: `loaded.dacl` is the valid, non-null DACL from the loader;
        // `index` is within the AceCount (== 3) just verified; `raw_ace` is a
        // valid out-parameter and the return is checked.
        if unsafe { GetAce(loaded.dacl, index, &mut raw_ace) }.is_err() {
            return false;
        }
        // `validated_ace` proved the ACE — and, for an allow-ACE, the SID it
        // names — lies inside `loaded`'s buffer, alive through the loop.
        let Some(ace) = validated_ace(raw_ace.cast(), loaded.bytes()) else {
            return false;
        };
        if ace.ace_type != 0 || ace.mask != FILE_ALL_ACCESS.0 {
            return false;
        }
        if ace.ace_flags != 0 {
            // SAFETY: `ace.sid` points into the live DACL buffer and `own_sid`
            // into the current user's owned SID storage; EqualSid only reads
            // both.
            if !unsafe { EqualSid(ace.sid, own_sid) }.is_ok() {
                return false;
            }
            extra_aces += 1;
            continue;
        }
        // SAFETY: `ace.sid` is the embedded SID in the live DACL buffer and
        // the well-known SIDs are alive above; EqualSid only reads them.
        if unsafe { EqualSid(ace.sid, system.psid()) }.is_ok() {
            if saw_system {
                return false;
            }
            saw_system = true;
        } else if unsafe { EqualSid(ace.sid, administrators.psid()) }.is_ok() {
            if saw_administrators {
                return false;
            }
            saw_administrators = true;
        } else {
            return false;
        }
    }
    saw_system && saw_administrators && extra_aces == 1
}

/// Rewrite `path`'s DACL to the strict SYSTEM + Administrators shape. Only
/// the DACL is replaced (`DACL_SECURITY_INFORMATION`); owner, group, and
/// control bits are left untouched. The deviation is re-classified as
/// benign immediately before the write.
fn repair_protected_directory_dacl(path: &Path) -> Result<(), DiagError> {
    // Re-load and re-classify the deviation immediately before the write:
    // the DACL could have changed since `ensure_protected_directory`'s
    // earlier check, and the repair must never touch a shape it has not
    // just judged benign (defense in depth; the post-repair verify still
    // fails closed regardless).
    if !dacl_deviation_is_benign(path) {
        return Err(DiagError::new(Diag::new(Key::HelperDeviationNotBenign)));
    }
    let wide = path_to_wide(path);
    let applied = with_protected_descriptor(None, &[], |descriptor| unsafe {
        // SAFETY: `wide` is a NUL-terminated wide path valid for the call;
        // `descriptor` is the fully initialized protected descriptor built by
        // `sys::security::with_protected_descriptor` (its SID/ACL buffers
        // stay alive for the call) and the kernel copies the DACL out before
        // it returns. The BOOLEAN result is checked by the caller below.
        SetFileSecurityW(PCWSTR(wide.as_ptr()), DACL_SECURITY_INFORMATION, descriptor)
    })
    .diag(Key::HelperDescriptorBuildFailed)?;
    if !applied.as_bool() {
        return Err(windows::core::Error::from_thread()).diag(Key::HelperDaclRepairFailed);
    }
    Ok(())
}

/// Verify `path`'s strict protected DACL; when the only deviation is a
/// benign extra ACE (a user clicked into the folder and Explorer granted
/// them permanent access), repair the DACL in place and re-verify. Any
/// other deviation still fails closed, exactly as before.
fn ensure_protected_directory(path: &Path) -> Result<(), DiagError> {
    if let Err(first) = verify_protected_directory(path) {
        if !dacl_deviation_is_benign(path) {
            return Err(first);
        }
        repair_protected_directory_dacl(path)?;
        verify_protected_directory(path)?;
    }
    Ok(())
}

fn create_protected_directory(path: &Path, allow_existing: bool) -> Result<(), DiagError> {
    let wide = path_to_wide(path);
    let administrators =
        Sid::well_known(WinBuiltinAdministratorsSid).diag(Key::HelperWellKnownSidFailed)?;
    let create = |owner: Option<&Sid>| {
        with_protected_attributes(owner, &[], |attributes| unsafe {
            CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(attributes))
        })
        .diag(Key::HelperDirectoryAttributesFailed)
    };
    // SAFETY: `wide` is a NUL-terminated wide path valid for the call;
    // `attributes` is the fully initialized `SECURITY_ATTRIBUTES` built by
    // `with_protected_attributes` (`nLength` set, `lpSecurityDescriptor`
    // pointing at the live descriptor, `bInheritHandle` false) and stays
    // alive for the synchronous call, as do the SID/ACL buffers the
    // descriptor references. The BOOLEAN result is checked by the caller
    // (`Ok(())` vs error).
    let mut created = create(Some(&administrators))?;
    if let Err(error) = &created
        && is_invalid_owner_error(error)
    {
        // ERROR_INVALID_OWNER: this token cannot assign Administrators as
        // owner (unelevated helper runs); retry with our own user SID, which
        // any token may be assigned. Access control is unchanged — the
        // protected DACL still names SYSTEM and Administrators.
        let own = current_process_user_sid()?;
        created = create(Some(&own))?;
    }
    match created {
        Ok(()) => {}
        Err(error) if allow_existing && error.code() == windows::core::HRESULT::from_win32(183) => {
        }
        Err(error) => {
            return Err(error)
                .diag_with(Diag::new(Key::HelperDirectoryCreateFailed).arg(path.display()));
        }
    }
    ensure_protected_directory(path)
}

fn secure_stage_base() -> Result<PathBuf, DiagError> {
    let base = trusted_program_data()?.join(STAGE_BASE);
    create_protected_directory(&base, true)?;
    Ok(base)
}

fn stage_entry_allowed(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| STAGE_ENTRIES.contains(&name))
}

fn remove_secure_stage(path: &Path, require_marker: bool) -> Result<(), DiagError> {
    ensure_protected_directory(path)?;
    let marker_path = path.join(STAGE_MARKER);
    let mut entries = Vec::new();
    for entry in fs::read_dir(path)
        .diag_with(Diag::new(Key::HelperStageEnumerateFailed).arg(path.display()))?
    {
        let entry = entry.diag(Key::HelperStageEntryReadFailed)?;
        let metadata = fs::symlink_metadata(entry.path())
            .diag_with(Diag::new(Key::HelperStageEntryInspectFailed).arg(entry.path().display()))?;
        if !stage_entry_allowed(&entry.file_name()) || !metadata.is_file() || is_reparse(&metadata)
        {
            return Err(DiagError::new(Diag::new(Key::HelperStageEntryUnexpected)));
        }
        entries.push(entry.path());
    }
    if require_marker && fs::read(&marker_path).ok().as_deref() != Some(STAGE_MARKER_CONTENT) {
        return Err(DiagError::new(Diag::new(Key::HelperStageMarkerMissing)));
    }
    for entry in entries {
        fs::remove_file(&entry)
            .diag_with(Diag::new(Key::HelperStageEntryRemoveFailed).arg(entry.display()))?;
    }
    fs::remove_dir(path).diag_with(Diag::new(Key::HelperStageRemoveFailed).arg(path.display()))
}

fn cleanup_stale_secure_stages(base: &Path) {
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.starts_with(STAGE_PREFIX))
        {
            let _ = remove_secure_stage(&entry.path(), true);
        }
    }
}

/// Write exactly `config` — the GUI-validated config content that crossed
/// the authenticated pipe — as [`STAGED_CONFIG`] inside `directory`, flush
/// it, then prove byte fidelity with a SHA-256 copy proof against the
/// source bytes. The
/// returned read-only handle is the same deny-write/delete lock shape the
/// runtime payloads use: it blocks write and delete opens while letting
/// xray read the config. The user-writable active config path is never
/// consulted for what gets staged, so a same-user swap after the GUI's
/// validation cannot reach the stage.
fn stage_config_bytes_at(directory: &Path, config: &[u8]) -> Result<File, DiagError> {
    let target_path = directory.join(STAGED_CONFIG);
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(&target_path)
        .diag_with(Diag::new(Key::HelperStagedConfigCreateFailed).arg(target_path.display()))?;
    target
        .write_all(config)
        .diag(Key::HelperStagedConfigWriteFailed)?;
    target.sync_all().diag(Key::HelperStagedConfigFlushFailed)?;
    drop(target);
    let expected = sha256_bytes(config);
    let mut target_lock = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(&target_path)
        .diag_with(Diag::new(Key::HelperStagedConfigLockFailed).arg(target_path.display()))?;
    let actual = sha256_handle(&mut target_lock)?;
    if actual != expected {
        return Err(DiagError::new(Diag::new(
            Key::HelperStagedConfigProofFailed,
        )));
    }
    Ok(target_lock)
}

struct SecureRuntimeStage {
    path: PathBuf,
    locks: Vec<File>,
}

impl SecureRuntimeStage {
    fn create() -> Result<Self, DiagError> {
        let base = secure_stage_base()?;
        cleanup_stale_secure_stages(&base);
        let path = base.join(format!("{STAGE_PREFIX}{}", uuid::Uuid::new_v4().simple()));
        create_protected_directory(&path, false)?;
        let stage = Self {
            path,
            locks: Vec::new(),
        };
        let marker = stage.path.join(STAGE_MARKER);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(&marker)
            .diag_with(Diag::new(Key::HelperStageMarkerCreateFailed).arg(marker.display()))?;
        file.write_all(STAGE_MARKER_CONTENT)
            .diag(Key::HelperStageMarkerWriteFailed)?;
        file.sync_all().diag(Key::HelperStageMarkerFlushFailed)?;
        Ok(stage)
    }

    /// Stage exactly `config` — the bytes the launching GUI validated and
    /// carried over the authenticated pipe.
    /// The user-writable active config path is never consulted for what gets
    /// staged; see [`stage_config_bytes_at`].
    fn stage_config_bytes(&mut self, config: &[u8]) -> Result<(), DiagError> {
        let lock = stage_config_bytes_at(&self.path, config)?;
        self.locks.push(lock);
        Ok(())
    }
}

impl Drop for SecureRuntimeStage {
    fn drop(&mut self) {
        self.locks.clear();
        let _ = remove_secure_stage(&self.path, false);
    }
}

fn sha256_handle(file: &mut File) -> Result<String, DiagError> {
    file.seek(SeekFrom::Start(0))
        .diag(Key::HelperHashRewindFailed)?;
    let mut hasher = Sha256::new();
    // One-shot hash of a user-sized staged config: keep the 64 KiB read
    // buffer off the elevated helper's serve-loop stack.
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).diag(Key::HelperHashReadFailed)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    Ok(output)
}

/// SHA-256 hex of in-memory `bytes`, the expected digest a staged copy is
/// proven against (see [`stage_config_bytes_at`]).
fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

/// The `start` command's DAT-suspension flag, as the GUI derived it from the
/// exact config being staged (see [`start_command`]). The elevated server
/// trusts the flag and fails closed when it is absent, null, or not a
/// boolean — a stale GUI must behave strictly, never the reverse.
fn wire_dat_pins_suspended(command: &serde_json::Value) -> bool {
    command
        .get("dat_pins_suspended")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn path_from_wire(value: Option<&serde_json::Value>) -> Result<PathBuf, DiagError> {
    let units = value
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| DiagError::new(Diag::new(Key::HelperWirePathMissing)))?;
    if units.is_empty() || units.len() > 32_767 {
        return Err(DiagError::new(Diag::new(Key::HelperWirePathLengthInvalid)));
    }
    let mut wide = Vec::with_capacity(units.len());
    for unit in units {
        let unit = unit
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| DiagError::new(Diag::new(Key::HelperWirePathUnitInvalid)))?;
        if unit == 0 {
            return Err(DiagError::new(Diag::new(Key::HelperWirePathNul)));
        }
        wide.push(unit);
    }
    let path = PathBuf::from(OsString::from_wide(&wide));
    if !path.is_absolute() {
        return Err(DiagError::new(Diag::new(Key::HelperWirePathNotAbsolute)));
    }
    Ok(path)
}

/// Decode the `start` command's config content: base64 of the exact bytes
/// the launching GUI validated in the same operation. The elevated helper
/// stages precisely these bytes and
/// never re-reads the user-writable active config path. An absent or
/// undecodable payload is rejected; the whole wire message is already
/// bounded by [`MAX_WIRE_MESSAGE_BYTES`] on both ends, so the decoded
/// content is bounded by that cap minus the envelope.
fn config_from_wire(command: &serde_json::Value) -> Result<Vec<u8>, DiagError> {
    let encoded = command
        .get("config_base64")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| DiagError::new(Diag::new(Key::HelperWireConfigMissing)))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| DiagError::new(Diag::new(Key::HelperWireConfigEncodingInvalid)))?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Elevated server
// ---------------------------------------------------------------------------

struct Job(HANDLE);

// SAFETY: the wrapped `HANDLE` is an opaque kernel-object reference with value
// semantics — no process memory is dereferenced through it, and every Win32
// call used on it (`SetInformationJobObject`, `AssignProcessToJobObject`,
// `TerminateJobObject`, `CloseHandle`) carries no thread affinity; the kernel
// serializes access. Ownership is exclusive: the handle is created by
// `CreateJobObjectW` and closed exactly once in `Drop`, on whatever thread
// drops the value, so moving a `Job` between threads cannot race a close or
// alias a second owner. (`Sync` is not needed: the job is only ever owned,
// never shared by reference across threads.)
unsafe impl Send for Job {}

impl Job {
    fn new_kill_on_close() -> windows::core::Result<Self> {
        // SAFETY: `None` means default security attributes and
        // `PCWSTR::null()` means an anonymous (name-less) job object, so no
        // string needs to be valid. The windows crate maps the NULL-handle
        // failure to `Err`, so `Ok(job)` is a valid job handle; ownership of
        // it moves into the `Job` wrapper, whose `Drop` closes it exactly once.
        let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }?;
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `job` is the valid job handle created above and stays open
        // for the call. `info` is fully initialized (defaulted, then
        // `LimitFlags` set) and lives on this stack frame for the duration of
        // the call; the length is exactly
        // `size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()`, so the kernel
        // reads one complete, valid structure. Failure is mapped to `Err` and
        // propagated with `?`; the handle remains valid on either path.
        unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }?;
        Ok(Self(job))
    }

    fn assign(&self, process: HANDLE) -> windows::core::Result<()> {
        // SAFETY: `self.0` is a valid job handle kept open for `self`'s
        // lifetime; `process` is the raw process handle of the just-spawned
        // xray child (`child.as_raw_handle()`), valid while the `Child` value
        // still owns it — which it does for the duration of the call. The API
        // reports failure as an error (mapped to `Err`) and never leaves
        // partial state.
        unsafe { AssignProcessToJobObject(self.0, process) }
    }

    fn terminate(&self) {
        // SAFETY: `self.0` is a valid open job handle; `TerminateJobObject`
        // is thread-safe and the boolean failure is deliberately ignored
        // because this is a best-effort fallback (the child kill and
        // KILL_ON_JOB_CLOSE back it up). The handle stays valid after the
        // call and is closed once in `Drop`.
        unsafe {
            let _ = TerminateJobObject(self.0, 1);
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the handle from `CreateJobObjectW`, never
        // closed before; `Drop` runs exactly once and `Job` is the exclusive
        // owner, so the handle is closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct WatchedParent(HANDLE);

impl Drop for WatchedParent {
    fn drop(&mut self) {
        // SAFETY: `self.0` is the process handle from `OpenProcess` in
        // `serve`, owned exclusively by this guard; `Drop` runs exactly once,
        // so the handle is closed exactly once.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct HelperChild {
    child: std::process::Child,
    job: Job,
    state: String,
    api_port: u16,
    _stage: SecureRuntimeStage,
}

impl HelperChild {
    /// Stop the running core: ask Xray to remove the TUN inbound — bounded by
    /// [`super::TUN_CLOSE_DEADLINE`], since `RemoveInbound` runs the Windows
    /// TUN teardown synchronously — then fall back to the Job Object and
    /// `Child::kill`.
    ///
    /// This blocks the calling thread for that bounded window (a fresh
    /// current-thread runtime runs the gRPC call to completion), and every
    /// caller intentionally holds the helper slot's `Mutex` guard across the
    /// call — the guard is what serializes start/stop, so it also stalls the
    /// reaper threads and the serve loop for the window. Nothing reachable
    /// from the awaited gRPC call or the terminate fallback may acquire that
    /// slot lock; doing so would turn the bounded stall into a deadlock.
    fn kill(&mut self) {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            self.state = "stopped".to_string();
            return;
        }

        // Xray's Windows TUN cleanup runs from the inbound handler's Close.
        // RemoveInbound is synchronous in Xray; only then use the Job Object as
        // a bounded fallback for the remaining core process.
        if let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            let _ = runtime.block_on(async {
                let grpc = crate::rt::grpc::GrpcClient::new(self.api_port);
                // Outer give-up = this client's own per-RPC bound (grpc's
                // TUN_RPC_TIMEOUT) plus the shared classification margin, so
                // the RPC deadline fires first and the fallback has explicit
                // slack instead of a zero-margin race.
                tokio::time::timeout(
                    super::TUN_CLOSE_DEADLINE,
                    grpc.remove_inbound(TUN_INBOUND_TAG),
                )
                .await
            });
        }

        self.job.terminate();
        let _ = self.child.kill();
        self.state = "stopped".to_string();
    }
}

/// Entry point for `broccoli --core-helper`; never returns.
pub fn run_helper(pipe_id: &str, token: &str, expected_parent_pid: u32) -> ! {
    let code = match serve(pipe_id, token, expected_parent_pid) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("broccoli core-helper: {error:#}");
            1
        }
    };
    std::process::exit(code);
}

fn serve(pipe_id: &str, token: &str, expected_parent_pid: u32) -> Result<(), DiagError> {
    if !is_hex_secret(token) {
        return Err(DiagError::new(Diag::new(Key::HelperAuthTokenInvalid)));
    }
    if expected_parent_pid == 0 {
        return Err(DiagError::new(Diag::new(Key::HelperParentPidInvalid)));
    }
    // Acquire the immutable process object before publishing a pipe. This
    // closes PID-reuse and lets an over-the-shoulder helper grant the original
    // standard-user SID access without opening the privileged pipe broadly.
    let parent = WatchedParent(
        // SAFETY: `expected_parent_pid` is the immutable GUI PID parsed from
        // the UAC command line; `bInheritHandle = false`, no security
        // attributes, and requested access is exactly the documented
        // combination for waiting and querying the token. The windows crate
        // maps the NULL failure to `Err` (propagated by `.context`), so `Ok`
        // is a valid process handle whose ownership moves into `WatchedParent`
        // (closed in its `Drop`).
        unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                expected_parent_pid,
            )
        }
        .diag(Key::HelperParentOpenFailed)?,
    );
    // SAFETY: `parent.0` is the valid, still-open handle from `OpenProcess`
    // above; timeout 0 polls without blocking and the result is checked
    // against `WAIT_OBJECT_0`.
    if unsafe { WaitForSingleObject(parent.0, 0) } == WAIT_OBJECT_0 {
        return Err(DiagError::new(Diag::new(Key::HelperParentExitedBeforePipe)));
    }
    // Capture the launching GUI's kernel creation time from the exact
    // process object opened above, before any credential or pipe exists.
    // Every later client acceptance must present a process with this same
    // creation time; a parent that cannot be
    // timestamped cannot be authenticated — fail closed.
    let parent_identity = ParentIdentity {
        pid: expected_parent_pid,
        created: process_creation_time(parent.0).diag(Key::HelperParentTimeReadFailed)?,
    };
    let parent_user = parent_token_user(parent.0)?;
    let pipe_name = validated_pipe_name(pipe_id)?;
    let wide_name = to_wide(&pipe_name);
    // SAFETY: `wide_name` is a NUL-terminated wide pipe path (`\\.\pipe\…`,
    // per `PIPE_PREFIX`) valid for the call. The descriptor is built inside
    // `create_helper_pipe` from owned `Sid`s, alive through the synchronous
    // kernel copy, and the returned handle is checked for validity right
    // below.
    let handle = create_helper_pipe(&wide_name, &parent_user)?;
    if handle.is_invalid() {
        return Err(DiagError::new(Diag::new(Key::HelperPipeCreateFailed))
            .caused_by(windows::core::Error::from_thread()));
    }
    // SAFETY: `handle` is a valid, open pipe handle (checked non-invalid
    // above), and ownership of it transfers to the returned `File`: its `Drop`
    // closes the handle exactly once. The raw `handle` value is still used by
    // the server-side calls below while the `File` is alive, and no other code
    // path closes it.
    let pipe = unsafe { File::from_raw_handle(handle.0 as RawHandle) };
    wait_for_connection(handle, Some(parent.0))?;
    let blocking_message_mode: NAMED_PIPE_MODE = PIPE_READMODE_MESSAGE | PIPE_WAIT;
    // SAFETY: `handle` is the valid open pipe handle owned by `pipe`;
    // `&blocking_message_mode` is a fully initialized `NAMED_PIPE_MODE` value
    // on the stack, alive for the call; the collection/ timeout pointers are
    // null because a server never uses them. The return is checked.
    unsafe {
        SetNamedPipeHandleState(handle, Some(&blocking_message_mode as *const _), None, None)
    }
    .diag(Key::HelperPipeModeFailed)?;

    // The kernel-reported client must still be the exact immutable process.
    // A wrong first client may only make this helper exit. Beyond the PID
    // number, the client's CURRENT creation time must match the creation
    // time captured from the launching process at helper start: a same-PID
    // process born later is a recycled PID and is rejected.
    let mut actual_client_pid = 0u32;
    // SAFETY: `handle` is the valid open pipe handle owned by `pipe`;
    // `actual_client_pid` is a valid out-parameter. The return is checked.
    unsafe { GetNamedPipeClientProcessId(handle, &mut actual_client_pid) }
        .diag(Key::HelperClientPidReadFailed)?;
    let actual_client_created =
        process_creation_time_of(actual_client_pid).diag(Key::HelperClientTimeReadFailed)?;
    if !parent_identity_accepts(&parent_identity, actual_client_pid, actual_client_created) {
        return Err(DiagError::new(Diag::new(Key::HelperClientNotLaunchingGui)));
    }

    let writer = Arc::new(Mutex::new(
        pipe.try_clone().diag(Key::HelperPipeDuplicateFailed)?,
    ));
    // Reads go through the raw handle, message-size-aware, so a wire
    // message larger than an 8 KiB `BufReader` buffer
    // cannot surface as `ERROR_MORE_DATA` and kill this serve loop.
    let pipe_handle = handle;

    // No privileged state or command dispatch exists before bounded
    // authentication. Parent loss also terminates this wait.
    wait_for_message(handle, Some(Instant::now() + AUTH_TIMEOUT), Some(parent.0))?;
    let Some(auth_bytes) =
        read_pipe_message(pipe_handle, MAX_WIRE_MESSAGE_BYTES).diag(Key::HelperAuthReadFailed)?
    else {
        return Err(DiagError::new(Diag::new(Key::HelperAuthMessageMissing)));
    };
    let auth: serde_json::Value =
        serde_json::from_slice(&auth_bytes).diag(Key::HelperAuthParseFailed)?;
    let presented = auth
        .get("token")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if !token_matches(token, presented) {
        return Err(DiagError::new(Diag::new(Key::HelperAuthRejected)));
    }
    let current: Arc<Mutex<Option<HelperChild>>> = Arc::new(Mutex::new(None));
    loop {
        match wait_for_message(handle, None, Some(parent.0)) {
            Ok(true) => {}
            Ok(false) | Err(_) => break,
        }
        let command_bytes = match read_pipe_message(pipe_handle, MAX_WIRE_MESSAGE_BYTES) {
            Ok(Some(bytes)) => bytes,
            Ok(None) | Err(_) => break,
        };
        let Ok(command) = serde_json::from_slice::<serde_json::Value>(&command_bytes) else {
            continue;
        };
        match command.get("cmd").and_then(serde_json::Value::as_str) {
            Some("start") => {
                let api_port = command
                    .get("api_port")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| u16::try_from(value).ok())
                    .filter(|value| *value != 0);
                let dat_pins_suspended = wire_dat_pins_suspended(&command);
                let core_source = path_from_wire(command.get("core_path_utf16"));
                let config_bytes = config_from_wire(&command);
                match (api_port, core_source, config_bytes) {
                    (Some(api_port), Ok(core_source), Ok(config_bytes)) => {
                        helper_start(
                            &current,
                            &writer,
                            api_port,
                            &core_source,
                            &config_bytes,
                            dat_pins_suspended,
                        );
                    }
                    (_, core, config) => {
                        let detail = core.err().or_else(|| config.err()).unwrap_or_else(|| {
                            DiagError::new(Diag::new(Key::HelperWirePortInvalid))
                        });
                        send_log_record(
                            &writer,
                            &DiagError::new(Diag::new(Key::HelperMalformedStartCommand))
                                .caused_by(detail),
                        );
                        send_event(&writer, &serde_json::json!({"event":"exit","code":-1}));
                    }
                }
            }
            Some("stop") => {
                let Ok(mut slot) = current.lock() else {
                    continue;
                };
                if let Some(child) = slot.as_mut() {
                    child.kill();
                } else {
                    drop(slot);
                    send_event(
                        &writer,
                        &serde_json::json!({"event":"state","state":"stopped","pid":0}),
                    );
                }
            }
            Some("status") => {
                let Ok(slot) = current.lock() else {
                    continue;
                };
                let (state, pid) = match slot.as_ref() {
                    Some(child) => (child.state.clone(), child.child.id()),
                    None => ("stopped".to_string(), 0),
                };
                drop(slot);
                send_event(
                    &writer,
                    &serde_json::json!({"event":"state","state":state,"pid":pid}),
                );
            }
            _ => {}
        }
    }

    // Pipe EOF or parent-handle signal means the GUI died. Close TUN before
    // the hard process fallback so routes/DNS/Wintun are not abandoned.
    if let Ok(mut slot) = current.lock()
        && let Some(child) = slot.as_mut()
    {
        child.kill();
    }
    Ok(())
}

fn send_event(writer: &Arc<Mutex<File>>, value: &serde_json::Value) {
    let mut message = value.to_string();
    message.push('\n');
    if let Ok(mut writer) = writer.lock() {
        let _ = writer.write_all(message.as_bytes());
        let _ = writer.flush();
    }
}

/// Sync counterpart of `supervisor::read_capped_line` for the elevated
/// helper's stream threads (plain std I/O, no tokio reactor there). Bounds
/// one captured xray line at [`supervisor::MAX_LINE_BYTES`] with the shared
/// truncation marker, so an over-long line cannot grow an unbounded buffer in
/// the elevated helper either (CWE-400/770).
fn read_capped_line_sync<R>(reader: &mut R) -> std::io::Result<Option<String>>
where
    R: BufRead,
{
    let keep = super::supervisor::MAX_LINE_BYTES - super::supervisor::TRUNCATED_MARKER.len();
    let mut line: Vec<u8> = Vec::with_capacity(keep.min(256));
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            // EOF: a partial final line is still a line.
            return Ok(if line.is_empty() {
                None
            } else {
                Some(finish_line_sync(line))
            });
        }
        if let Some(pos) = available.iter().position(|&byte| byte == b'\n') {
            let take = pos.min(keep.saturating_sub(line.len()));
            line.extend_from_slice(&available[..take]);
            reader.consume(pos + 1);
            if take < pos {
                line.truncate(keep);
                line.extend_from_slice(super::supervisor::TRUNCATED_MARKER.as_bytes());
            }
            return Ok(Some(finish_line_sync(line)));
        }
        let take = available.len().min(keep.saturating_sub(line.len()));
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if line.len() >= keep {
            skip_rest_of_line_sync(reader)?;
            line.truncate(keep);
            line.extend_from_slice(super::supervisor::TRUNCATED_MARKER.as_bytes());
            return Ok(Some(finish_line_sync(line)));
        }
    }
}

fn skip_rest_of_line_sync<R: BufRead>(reader: &mut R) -> std::io::Result<()> {
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(());
        }
        if let Some(pos) = available.iter().position(|&byte| byte == b'\n') {
            reader.consume(pos + 1);
            return Ok(());
        }
        let len = available.len();
        reader.consume(len);
    }
}

fn finish_line_sync(mut line: Vec<u8>) -> String {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8_lossy(&line).into_owned()
}

fn staged_xray_command(stage: &Path, test_only: bool) -> std::process::Command {
    let mut command = std::process::Command::new(stage.join("xray.exe"));
    command.arg("run");
    if test_only {
        command.arg("-test");
    }
    command
        .arg("-config")
        .arg(stage.join(STAGED_CONFIG))
        .current_dir(stage)
        .env("XRAY_LOCATION_ASSET", stage)
        .stdin(std::process::Stdio::null());
    std::os::windows::process::CommandExt::creation_flags(&mut command, CREATE_NO_WINDOW);
    command
}

fn validate_staged_config(stage: &Path) -> Result<(), DiagError> {
    let mut command = staged_xray_command(stage, true);
    command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = command
        .spawn()
        .diag(Key::HelperStagedValidationSpawnFailed)?;
    let job = Job::new_kill_on_close().and_then(|job| {
        job.assign(HANDLE(child.as_raw_handle()))?;
        Ok(job)
    });
    let job = match job {
        Ok(job) => job,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).diag(Key::HelperStagedValidationIsolateFailed);
        }
    };
    let deadline = Instant::now() + CONFIG_TEST_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(DiagError::new(
                    Diag::new(Key::HelperStagedConfigRejected).arg(status),
                ));
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(PIPE_POLL);
            }
            Ok(None) => {
                job.terminate();
                let _ = child.kill();
                let _ = child.wait();
                return Err(DiagError::new(Diag::new(
                    Key::HelperStagedValidationTimeout,
                )));
            }
            Err(error) => {
                job.terminate();
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).diag(Key::HelperStagedValidationWaitFailed);
            }
        }
    }
}

/// True while the slot still names `pid` and that child has not exited —
/// the liveness probe the DNS-shield installer uses.
/// The shield's permit app-id names this child's staged `xray.exe`, so the
/// shield may only stay installed while this exact child is the live
/// current occupant: once the slot is empty, holds a different pid (a
/// superseding start), or holds this pid as a corpse, the stage is (or is
/// about to be) deleted and the shield must be removed. A poisoned slot
/// lock reports false — fail toward removing the shield, never toward
/// keeping a possibly-stale port-53 block.
fn child_is_live_current(current: &Arc<Mutex<Option<HelperChild>>>, pid: u32) -> bool {
    match current.lock() {
        Ok(mut slot) => slot.as_mut().is_some_and(|child| {
            child.child.id() == pid && matches!(child.child.try_wait(), Ok(None))
        }),
        Err(_) => false,
    }
}

fn helper_start(
    current: &Arc<Mutex<Option<HelperChild>>>,
    writer: &Arc<Mutex<File>>,
    api_port: u16,
    core_source: &Path,
    config_bytes: &[u8],
    dat_pins_suspended: bool,
) {
    let prepared = (|| -> Result<SecureRuntimeStage, DiagError> {
        // The staged config's own geodata block suspended the geo data pins
        // GUI-side; mirror that decision here so the stage copy accepts the
        // user-managed DAT pair. The geo data files are staged in both modes
        // (they are payload-set members either way); only the compare mode
        // differs.
        let mut verified = if dat_pins_suspended {
            crate::sys::core_dl::open_verified_core_user_managed_dats(core_source)?
        } else {
            crate::sys::core_dl::open_verified_core(core_source)?
        };
        let version = verified.version().to_string();
        let mut stage = SecureRuntimeStage::create()?;
        let payload_locks = verified.copy_runtime_payloads(&stage.path)?;
        stage.locks.extend(payload_locks);
        // The config is staged from the exact bytes the launching GUI
        // validated and carried over the authenticated pipe — never from a
        // re-read of the user-writable active path, which may have been
        // swapped since validation.
        stage.stage_config_bytes(config_bytes)?;
        validate_staged_config(&stage.path)?;
        send_log(writer, Diag::new(Key::HelperStageValidated).arg(version));
        Ok(stage)
    })();
    let mut stage = match prepared {
        Ok(stage) => stage,
        Err(error) => {
            send_log_record(
                writer,
                &DiagError::new(Diag::new(Key::HelperStageRefused)).caused_by(error),
            );
            send_event(writer, &serde_json::json!({"event":"exit","code":-1}));
            return;
        }
    };

    // Do not disturb a healthy old backend unless the complete replacement
    // has passed pins, ACL/copy proof, and staged `run -test`.
    if let Ok(mut slot) = current.lock()
        && let Some(old) = slot.as_mut()
    {
        old.kill();
    }

    // A previous TUN session may still be tearing down its wintun adapter or
    // have left a phantom devnode behind (hard kills never run xray's Close).
    // Creating the same-named adapter while that teardown is in flight stalls
    // `WintunCreateAdapter` indefinitely, and killing a core stuck there
    // wedges PnP device creation for every wintun user (2026-08-28).
    // Serialize the restart: remove leftovers for the staged config's tun
    // adapter name and wait until none remain, bounded.
    clean_leftover_tun_adapter(&stage.path, writer);

    let mut command = staged_xray_command(&stage.path, false);
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            send_log_record(
                writer,
                &DiagError::new(Diag::new(Key::HelperCoreSpawnFailed)).caused_by(error),
            );
            send_event(writer, &serde_json::json!({"event":"exit","code":-1}));
            return;
        }
    };
    let pid = child.id();
    let job = match Job::new_kill_on_close().and_then(|job| {
        job.assign(HANDLE(child.as_raw_handle()))?;
        Ok(job)
    }) {
        Ok(job) => job,
        Err(error) => {
            let _ = child.kill();
            send_log_record(
                writer,
                &DiagError::new(Diag::new(Key::HelperJobSetupFailed)).caused_by(error),
            );
            send_event(writer, &serde_json::json!({"event":"exit","code":-1}));
            return;
        }
    };

    let streams: [Option<Box<dyn std::io::Read + Send>>; 2] = [
        child.stdout.take().map(|stream| Box::new(stream) as _),
        child.stderr.take().map(|stream| Box::new(stream) as _),
    ];
    for stream in streams.into_iter().flatten() {
        let writer = Arc::clone(writer);
        std::thread::spawn(move || {
            // Capped like the direct-mode pump: an over-long xray line must
            // not grow an unbounded buffer in the elevated helper either
            // (CWE-400/770).
            let mut reader = BufReader::new(stream);
            while let Ok(Some(line)) = read_capped_line_sync(&mut reader) {
                send_event(
                    &writer,
                    &serde_json::json!({"event":"log","line":line.trim_end()}),
                );
            }
        });
    }

    // CreateProcess has consumed the staged payload paths; release the
    // deny-write/delete locks so the staged core's geodata updater can swap
    // the DAT files. The stage directory itself is still removed
    // on drop, after the child exits.
    stage.locks.clear();
    let stage_path = stage.path.clone();
    if let Ok(mut slot) = current.lock() {
        *slot = Some(HelperChild {
            child,
            job,
            state: "starting".to_string(),
            api_port,
            _stage: stage,
        });
    }
    // DNS shield (sing-box-style WFP): while a TUN core with a DNS module
    // runs, block direct DNS dials to port 53 outside the tunnel so Windows
    // multi-homed resolution cannot reach the physical adapters' on-link
    // gateway DNS. The permit set mirrors sing-tun's StrictRoute
    // DNSModeHijack: xray's app-id (12) > TUN-interface index (11) >
    // port-53 block (10). The TUN adapter (and its interface index) exists
    // only after the child's tun inbound comes up, so the index is resolved
    // by polling GetAdaptersAddresses for the staged tun name. Installed
    // after the slot assignment so a concurrently exiting previous child's
    // reaper never removes a shield this start has just installed (the
    // reaper only removes when no child occupies the slot). That same
    // publish-first order leaves this child's own startup window unguarded:
    // the shield install polls up to 10 s outside the slot lock, and if
    // this child dies during the poll nothing must keep a shield whose
    // permit app-id names a stage the reaper is about to delete. The
    // installer therefore re-checks slot/child liveness
    // after installing (and while polling) and removes the shield again
    // when the child is gone — see the poll and post-install checks below.
    // Best-effort: failures are logged, never fatal.
    let config_text = fs::read_to_string(stage_path.join(STAGED_CONFIG)).ok();
    let needs = config_text
        .as_deref()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .is_some_and(|config| crate::rt::wfp::config_needs_dns_shield(&config));
    let shield_error = if needs {
        let tun_name = config_text
            .as_deref()
            .and_then(crate::sys::wintun::staged_tun_adapter_name);
        match tun_name {
            Some(name) => {
                // The staged core can die while its TUN inbound is still
                // coming up (wintun fault, bad config, a racing stop).
                // Polling on would only resolve the index of an adapter
                // whose owner is gone, so the poll stops as soon as the
                // slot no longer holds this live child — the install below
                // then never runs for a
                // corpse, and this start's reaper reports the exit.
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                let mut ifindex = crate::rt::wfp::interface_index_by_name(&name);
                while ifindex.is_none() && std::time::Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(500));
                    if !child_is_live_current(current, pid) {
                        break;
                    }
                    ifindex = crate::rt::wfp::interface_index_by_name(&name);
                }
                match ifindex {
                    Some(ifindex) => {
                        // Residual race between the last poll and the WFP
                        // call: the child can exit while `set_dns_shield`
                        // runs. The reaper for this child only spawns after
                        // this whole block returns, so the installer itself
                        // re-checks liveness right after installing and
                        // removes the shield it just installed when the
                        // child is gone. Interleaving closed: child exits
                        // during the poll → this
                        // re-check (or the poll bail-out above) removes the
                        // shield before the reaper drops the stage, so no
                        // port-53 block can outlive the stage directory its
                        // permit app-id names. A live current child's shield
                        // is untouched; the reaper's removal serialization
                        // against superseding starts is unchanged.
                        match crate::rt::wfp::set_dns_shield(
                            true,
                            Some(&stage_path.join("xray.exe")),
                            Some(ifindex),
                        ) {
                            Ok(()) if child_is_live_current(current, pid) => None,
                            Ok(()) => match crate::rt::wfp::set_dns_shield(false, None, None) {
                                Ok(()) => Some(DiagError::new(
                                    Diag::new(Key::HelperShieldRemovedAfterExit).arg(pid),
                                )),
                                Err(error) => {
                                    send_log_record(
                                        writer,
                                        &DiagError::new(Diag::new(
                                            Key::HelperDnsShieldTeardownFailed,
                                        ))
                                        .caused_by(error),
                                    );
                                    Some(DiagError::new(
                                        Diag::new(Key::HelperShieldNotInstalledAfterExit).arg(pid),
                                    ))
                                }
                            },
                            Err(error) => Some(
                                DiagError::new(Diag::new(Key::HelperDnsShieldNotEngaged))
                                    .caused_by(error),
                            ),
                        }
                    }
                    None if !child_is_live_current(current, pid) => Some(DiagError::new(
                        Diag::new(Key::HelperShieldNotInstalledAfterExit).arg(pid),
                    )),
                    None => Some(DiagError::new(
                        Diag::new(Key::HelperTunAdapterMissing).arg(name),
                    )),
                }
            }
            None => Some(DiagError::new(Diag::new(Key::HelperConfigNoTunAdapter))),
        }
    } else {
        None
    };
    if let Some(error) = shield_error {
        send_log_record(writer, &error);
    }
    send_event(
        writer,
        &serde_json::json!({"event":"state","state":"starting","pid":pid}),
    );

    // Informational helper state. Runtime readiness still comes from gRPC.
    {
        let current = Arc::clone(current);
        let writer = Arc::clone(writer);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(1));
            let Ok(mut slot) = current.lock() else {
                return;
            };
            let Some(child) = slot.as_mut() else {
                return;
            };
            if child.child.id() == pid
                && child.state == "starting"
                && matches!(child.child.try_wait(), Ok(None))
            {
                child.state = "running".to_string();
                drop(slot);
                send_event(
                    &writer,
                    &serde_json::json!({"event":"state","state":"running","pid":pid}),
                );
            }
        });
    }

    // Report this exact child's eventual exit; a superseding start owns a new
    // pid and causes the old reaper to retire without touching its state.
    {
        let current = Arc::clone(current);
        let writer = Arc::clone(writer);
        std::thread::spawn(move || {
            let code = loop {
                {
                    let Ok(mut slot) = current.lock() else {
                        return;
                    };
                    let Some(child) = slot.as_mut() else {
                        return;
                    };
                    if child.child.id() != pid {
                        return;
                    }
                    match child.child.try_wait() {
                        Ok(Some(status)) => break status.code().unwrap_or(-1),
                        Ok(None) => {}
                        Err(_) => break -1,
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
            };
            let finished = match current.lock() {
                Ok(mut slot) if slot.as_ref().is_some_and(|child| child.child.id() == pid) => {
                    slot.take()
                }
                _ => None,
            };
            // DNS shield teardown: only when this reaper took the current
            // child AND no superseding start has claimed the slot. The
            // removal runs while holding the slot lock so it serializes
            // against helper_start's assign-then-install: either the new
            // start's slot write happened before this check (no removal), or
            // the start is blocked until the removal completes (its install
            // lands last). The exit event below — which triggers any
            // app-side restart — is sent after the removal, so a restart
            // re-installs the shield without racing this teardown. No
            // lock-order inversion: nothing acquires the slot lock while
            // holding the shield lock.
            if let Ok(slot) = current.lock()
                && finished.is_some()
                && slot.is_none()
                && let Err(error) = crate::rt::wfp::set_dns_shield(false, None, None)
            {
                send_log_record(
                    &writer,
                    &DiagError::new(Diag::new(Key::HelperDnsShieldTeardownFailed)).caused_by(error),
                );
            }
            // Dropping the exact exited child removes only the allowlisted
            // non-reparse secure-stage entries (payload locks were released
            // at spawn).
            drop(finished);
            send_event(&writer, &serde_json::json!({"event":"exit","code":code}));
            send_event(
                &writer,
                &serde_json::json!({"event":"state","state":"stopped","pid":pid}),
            );
        });
    }
}

/// Remove leftover wintun devnodes for the staged config's TUN adapter name
/// and wait (bounded) until the previous session's teardown has fully
/// settled. Runs elevated before every core spawn; a no-op when the staged
/// config has no TUN inbound.
fn clean_leftover_tun_adapter(stage: &Path, writer: &Arc<Mutex<File>>) {
    let config = match fs::read_to_string(stage.join(STAGED_CONFIG)) {
        Ok(config) => config,
        Err(error) => {
            send_log_record(
                writer,
                &DiagError::new(Diag::new(Key::HelperTunCleanupConfigReadFailed)).caused_by(error),
            );
            return;
        }
    };
    let Some(name) = crate::sys::wintun::staged_tun_adapter_name(&config) else {
        return; // no TUN inbound — nothing to clean
    };
    let (clean, lines) = crate::sys::wintun::ensure_clean(&name, TUN_CLEAN_TIMEOUT);
    for line in lines {
        send_event(
            writer,
            &serde_json::json!({"event":"log","line":format!("{HELPER_LINE_PREFIX}{line}")}),
        );
    }
    if !clean {
        send_log(writer, Diag::new(Key::HelperTunCleanupTimeout).arg(name));
    }
}

// ---------------------------------------------------------------------------
// Log records
// ---------------------------------------------------------------------------

/// The Rust name of every key the helper pipe can carry, in both directions:
/// the wire `key` string is the variant name, so a record cannot silently
/// drift from the locale table. A key outside this list degrades its line to
/// the English fallback text instead.
macro_rules! wire_keys {
    ($($key:ident),* $(,)?) => {
        /// The wire name of `key`, or `None` for a key outside the pipe
        /// vocabulary.
        fn key_name(key: Key) -> Option<&'static str> {
            match key {
                $(Key::$key => Some(stringify!($key)),)*
                _ => None,
            }
        }

        /// The key a wire name names, or `None` for an unknown name.
        fn key_from_name(name: &str) -> Option<Key> {
            match name {
                $(stringify!($key) => Some(Key::$key),)*
                _ => None,
            }
        }
    };
}

wire_keys!(
    ApplyActiveReadFailed,
    ApplyActiveReplaceFailed,
    ApplyCandidateSerializeFailed,
    ApplyConfigDirCreateFailed,
    ApplyCoreVerifyFailed,
    ApplyCoreVerifyWorkerFailed,
    ApplyFileCreateFailed,
    ApplyFileFlushFailed,
    ApplyFileParseFailed,
    ApplyFileReadFailed,
    ApplyFileWriteFailed,
    ApplyFilesystemWorkerFailed,
    ApplyLastgoodReplaceFailed,
    ApplyLastgoodStageFailed,
    ApplyListenInvalid,
    ApplyListenMissing,
    ApplyListenNotLoopback,
    ApplyRollbackMissing,
    ApplyRollbackRestoreFailed,
    ApplyRollbackStageFailed,
    ApplyValidationChildExited,
    ApplyValidationJobAssignFailed,
    ApplyValidationJobCreateFailed,
    ApplyValidationRunFailed,
    ApplyValidationSpawnFailed,
    ApplyValidationTimeout,
    CoreDlArchiveEntryUnreadable,
    CoreDlArchiveExtractFailed,
    CoreDlArchiveInvalid,
    CoreDlArchiveMismatch,
    CoreDlArchiveMissingXray,
    CoreDlArchiveOpenFailed,
    CoreDlArchivePayloadsMismatch,
    CoreDlArchivePinInvalid,
    CoreDlBackupNotDirectory,
    CoreDlBackupRemoveFailed,
    CoreDlBackupStagingFailed,
    CoreDlCoreNotDirectory,
    CoreDlCorePathNotAbsolute,
    CoreDlDirectoryCreateFailed,
    CoreDlDownloadFlushFailed,
    CoreDlDownloadLimitExceeded,
    CoreDlDownloadSizeOverflow,
    CoreDlDownloadStreamFailed,
    CoreDlDownloadTimeout,
    CoreDlDownloadTooLarge,
    CoreDlDownloadWriteFailed,
    CoreDlFileCopyFailed,
    CoreDlFileCreateFailed,
    CoreDlFileFlushFailed,
    CoreDlFileOpenFailed,
    CoreDlFileRemoveFailed,
    CoreDlFileReplaceFailed,
    CoreDlFileWriteFailed,
    CoreDlHashingFailed,
    CoreDlHttpRequestFailed,
    CoreDlHttpStatusRejected,
    CoreDlInstallFailed,
    CoreDlInterruptedWithoutCore,
    CoreDlMarkerCorrupt,
    CoreDlMetadataMismatch,
    CoreDlMetadataOpenFailed,
    CoreDlMetadataParseFailed,
    CoreDlMetadataSerializeFailed,
    CoreDlPayloadCopyFailed,
    CoreDlPayloadCreateFailed,
    CoreDlPayloadFlushFailed,
    CoreDlPayloadLockFailed,
    CoreDlPayloadOpenFailed,
    CoreDlPayloadProofFailed,
    CoreDlPayloadRestoreFailed,
    CoreDlPayloadRewindFailed,
    CoreDlPayloadStillDrifted,
    CoreDlPayloadVerifyFailed,
    CoreDlPristineCopyFailed,
    CoreDlPristineMismatch,
    CoreDlQuarantineFailed,
    CoreDlRecoverBackupFailed,
    CoreDlRecoverInterruptedFailed,
    CoreDlRestoreAfterValidationFailed,
    CoreDlRestoreCandidateFailed,
    CoreDlRestoreLastgoodFailed,
    CoreDlRestoreUnavailable,
    CoreDlSourceInspectFailed,
    CoreDlSourceNotDirectory,
    CoreDlSourceNotFile,
    CoreDlStageDownload,
    CoreDlStageInstall,
    CoreDlStageVerifyPin,
    CoreDlStagingMissing,
    CoreDlUpdatePendingHealth,
    CoreDlVersionInvalid,
    CoreDlVersionPrefixMissing,
    HelperAceAdministratorsRepeated,
    HelperAceMalformed,
    HelperAceNotFullControl,
    HelperAcePrincipalMissing,
    HelperAceReadFailed,
    HelperAceSystemRepeated,
    HelperAceUnexpectedSid,
    HelperAuthFlushFailed,
    HelperAuthMessageMissing,
    HelperAuthParseFailed,
    HelperAuthReadFailed,
    HelperAuthRejected,
    HelperAuthTimeout,
    HelperAuthTokenInvalid,
    HelperAuthWriteFailed,
    HelperClientNotLaunchingGui,
    HelperClientPidReadFailed,
    HelperClientPipeModeFailed,
    HelperClientTimeReadFailed,
    HelperConfigNoTunAdapter,
    HelperConfigTooLarge,
    HelperConnectCancelled,
    HelperConnectFailed,
    HelperConnectTimeout,
    HelperCoreSpawnFailed,
    HelperDaclMissing,
    HelperDaclMissingOrInherited,
    HelperDaclReadFailed,
    HelperDaclRepairFailed,
    HelperDaclUnexpectedPrincipals,
    HelperDescriptorBuildFailed,
    HelperDescriptorControlReadFailed,
    HelperDescriptorReadFailed,
    HelperDescriptorSizeQueryFailed,
    HelperDeviationNotBenign,
    HelperDirectoryAttributesFailed,
    HelperDirectoryCreateFailed,
    HelperDirectoryInspectFailed,
    HelperDirectoryNotOrdinary,
    HelperDnsShieldNotEngaged,
    HelperDnsShieldTeardownFailed,
    HelperHashReadFailed,
    HelperHashRewindFailed,
    HelperJobSetupFailed,
    HelperMalformedStartCommand,
    HelperOwnSidReadFailed,
    HelperOwnTokenOpenFailed,
    HelperOwnerReadFailed,
    HelperOwnerUnexpected,
    HelperParentArgDuplicate,
    HelperParentArgInvalid,
    HelperParentArgMissing,
    HelperParentExitedBeforeConnect,
    HelperParentExitedBeforePipe,
    HelperParentOpenFailed,
    HelperParentPidInvalid,
    HelperParentSidReadFailed,
    HelperParentTimeReadFailed,
    HelperParentTokenOpenFailed,
    HelperPipeAttributesFailed,
    HelperPipeClosed,
    HelperPipeCreateFailed,
    HelperPipeDuplicateFailed,
    HelperPipeFlushFailed,
    HelperPipeIdInvalid,
    HelperPipeModeFailed,
    HelperPipeWriteFailed,
    HelperPipeWriterPoisoned,
    HelperProcessOpenFailed,
    HelperProcessTimeReadFailed,
    HelperProgramDataDecodeFailed,
    HelperProgramDataInspectFailed,
    HelperProgramDataNotDirectory,
    HelperProgramDataResolveFailed,
    HelperReaderThreadFailed,
    HelperShieldNotInstalledAfterExit,
    HelperShieldRemovedAfterExit,
    HelperStageEntryInspectFailed,
    HelperStageEntryReadFailed,
    HelperStageEntryRemoveFailed,
    HelperStageEntryUnexpected,
    HelperStageEnumerateFailed,
    HelperStageMarkerCreateFailed,
    HelperStageMarkerFlushFailed,
    HelperStageMarkerMissing,
    HelperStageMarkerWriteFailed,
    HelperStageRefused,
    HelperStageRemoveFailed,
    HelperStageValidated,
    HelperStagedConfigCreateFailed,
    HelperStagedConfigFlushFailed,
    HelperStagedConfigLockFailed,
    HelperStagedConfigProofFailed,
    HelperStagedConfigRejected,
    HelperStagedConfigWriteFailed,
    HelperStagedValidationIsolateFailed,
    HelperStagedValidationSpawnFailed,
    HelperStagedValidationTimeout,
    HelperStagedValidationWaitFailed,
    HelperStartCorePathNotAbsolute,
    HelperStartPortInvalid,
    HelperTunAdapterMissing,
    HelperTunCleanupConfigReadFailed,
    HelperTunCleanupTimeout,
    HelperWellKnownSidFailed,
    HelperWireConfigEncodingInvalid,
    HelperWireConfigMissing,
    HelperWirePathLengthInvalid,
    HelperWirePathMissing,
    HelperWirePathNotAbsolute,
    HelperWirePathNul,
    HelperWirePathUnitInvalid,
    HelperWirePortInvalid,
    SupervisorChildExited,
    SupervisorJobAssignFailed,
    SupervisorJobCreateFailed,
    SupervisorSpawnFailed,
    SupervisorVerifyFailed,
    SupervisorVerifyWorkerFailed,
    WfpAppIdReadFailed,
    WfpEngineOpenFailed,
    WfpFilterAddFailed,
    WfpMissingTunIfindex,
    WfpMissingXrayPath,
    WfpSubLayerAddFailed,
);

/// One keyed message layer as the pipe carries it: the key name plus its
/// arguments, nested messages included.
fn wire_message(diag: &Diag) -> Option<serde_json::Value> {
    let mut args = Vec::with_capacity(diag.args().len());
    for arg in diag.args() {
        match arg {
            DiagArg::Text(text) => args.push(serde_json::Value::String(text.clone())),
            DiagArg::Message(message) => args.push(wire_message(message)?),
        }
    }
    Some(serde_json::json!({ "key": key_name(diag.key())?, "args": args }))
}

/// The message layers of `error`, outermost first, and the verbatim text of
/// an external cause when one ends the chain. `None` when a layer carries a
/// key outside the pipe vocabulary.
fn wire_layers(error: &DiagError) -> Option<(Vec<serde_json::Value>, Option<String>)> {
    let mut layers = vec![wire_message(error.diag())?];
    let mut cursor: Option<&(dyn std::error::Error + 'static)> = error.source();
    let mut tail = None;
    while let Some(current) = cursor {
        match current.downcast_ref::<DiagError>() {
            Some(inner) => layers.push(wire_message(inner.diag())?),
            None => {
                tail = Some(current.to_string());
                break;
            }
        }
        cursor = current.source();
    }
    Some((layers, tail))
}

/// Send one authored log line as a structured record: the keyed layers the
/// GUI renders in the active language, the verbatim external cause, and the
/// fallback text for a record that does not decode.
fn send_log_record(writer: &Arc<Mutex<File>>, error: &DiagError) {
    let fallback = serde_json::Value::String(format!("{HELPER_LINE_PREFIX}{error}"));
    let record = match wire_layers(error) {
        Some((keys, tail)) => {
            let mut record = serde_json::json!({
                "event":"log",
                "keys":keys,
            });
            if let Some(tail) = tail {
                record["tail"] = serde_json::Value::String(tail);
            }
            record["line"] = fallback;
            record
        }
        None => serde_json::json!({
            "event":"log",
            "line":fallback
        }),
    };
    send_event(writer, &record);
}

/// Send one authored log line that has no cause chain.
fn send_log(writer: &Arc<Mutex<File>>, diag: Diag) {
    send_log_record(writer, &DiagError::new(diag));
}

// ---------------------------------------------------------------------------
// Unelevated client
// ---------------------------------------------------------------------------

/// One helper-authored log record, or a raw line that stays verbatim: the
/// helper writes core output and its own messages to the same pipe.
#[derive(Debug)]
pub enum HelperLog {
    /// An authored message chain the GUI renders in the active language.
    Message(DiagError),
    /// A passthrough line (core output or an undecodable record).
    Raw(String),
}

#[derive(Debug)]
pub enum HelperEvent {
    State { state: String, pid: u32 },
    Log(HelperLog),
    Exit(i32),
}

/// Decode one `{"event":"log"}` record from the helper: a keyed message
/// chain when every layer resolves, else the verbatim line the record
/// carries. Unknown names and shapes never panic — they fall back to the
/// line.
pub(crate) fn decode_helper_log(value: &serde_json::Value) -> HelperLog {
    let raw = || {
        HelperLog::Raw(
            value
                .get("line")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(|| value.to_string()),
        )
    };
    let Some(keys) = value.get("keys").and_then(serde_json::Value::as_array) else {
        return raw();
    };
    let mut layers = Vec::with_capacity(keys.len());
    for entry in keys {
        let Some(diag) = decode_diag(entry) else {
            return raw();
        };
        layers.push(diag);
    }
    let Some(innermost) = layers.pop() else {
        return raw();
    };
    let mut error = DiagError::new(innermost);
    if let Some(tail) = value.get("tail").and_then(serde_json::Value::as_str) {
        error = error.caused_by_text(tail.to_owned());
    }
    for diag in layers.into_iter().rev() {
        error = DiagError::new(diag).caused_by(error);
    }
    HelperLog::Message(error)
}

/// One wire entry: the key plus its arguments, nested messages decoded
/// recursively. `None` on an unknown name or an argument that is neither a
/// string nor a nested entry.
fn decode_diag(value: &serde_json::Value) -> Option<Diag> {
    let name = value.get("key").and_then(serde_json::Value::as_str)?;
    let mut diag = Diag::new(key_from_name(name)?);
    if let Some(args) = value.get("args") {
        for arg in args.as_array()? {
            diag = match arg {
                serde_json::Value::String(text) => diag.arg(text),
                serde_json::Value::Object(_) => diag.arg_message(decode_diag(arg)?),
                _ => return None,
            };
        }
    }
    Some(diag)
}

// -- helper→runtime event hop -----------------------------------
//
// The reader thread forwards parsed events over a bounded channel drained by
// the runtime select loop. Log lines are drop-coalesced by `HopLogGate` when
// the channel is full (a flooding core must not grow the queue while the
// runtime is inside a bounded command); lifecycle events are never counted
// away — they wait one bounded drain window for a slot.

/// Drop/coalesce accounting for core log lines crossing the bounded
/// helper→runtime channel. Once the channel
/// rejects a log line, later lines are counted instead of queued, and the
/// count is delivered as one summary line as soon as the channel accepts
/// again — the same semantics as the GUI-side `LogGate` (rt/mod.rs), which
/// already bounds the direct-mode path. The reader never blocks
/// on a full channel, so the named pipe keeps draining and the elevated
/// helper's synchronous log writer is never backpressured.
struct HopLogGate {
    /// Lines dropped since the last delivered summary.
    suppressed: u64,
}

/// Outcome of [`HopLogGate::forward`] for one core log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HopForward {
    /// A pending summary and/or the line itself was queued.
    Queued,
    /// The line was dropped because the channel is full; counted toward the
    /// next summary.
    Suppressed,
    /// The runtime receiver is gone; the reader thread must stop.
    Disconnected,
}

impl HopLogGate {
    fn new() -> Self {
        Self { suppressed: 0 }
    }

    /// Forward one core log line over the bounded hop. When earlier lines
    /// were suppressed, their count is delivered first as the shared keyed
    /// summary; only once the channel accepts the summary is the counter
    /// reset and the triggering line queued. A full channel drops the line
    /// instead of blocking.
    fn forward(&mut self, line: HelperLog, sender: &mpsc::Sender<HelperEvent>) -> HopForward {
        if self.suppressed > 0 {
            // Deliver the summary of previously suppressed lines first; if
            // the channel still rejects it, suppress this line too.
            let summary =
                HelperLog::Message(DiagError::from(super::suppressed_summary(self.suppressed)));
            match sender.try_send(HelperEvent::Log(summary)) {
                Ok(()) => self.suppressed = 0,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    self.suppressed += 1;
                    return HopForward::Suppressed;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return HopForward::Disconnected,
            }
        }
        match sender.try_send(HelperEvent::Log(line)) {
            Ok(()) => HopForward::Queued,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.suppressed = 1;
                HopForward::Suppressed
            }
            Err(mpsc::error::TrySendError::Closed(_)) => HopForward::Disconnected,
        }
    }
}

/// Queue a non-log helper event (`State`/`Exit`) over the bounded hop.
/// Lifecycle events must never be silently coalesced away: a lost `Exit`
/// would leave a TUN backend the GUI believes it still owns, and `State`
/// drives the UI phase. When the channel is momentarily full they wait one
/// bounded drain window sized to the longest legitimate run-loop stall
/// ([`LIFECYCLE_SEND_WINDOW`]) — the GUI-side window
/// ([`super::EVENT_SEND_BOUND`]) only covers a frame cycle, while
/// this hop's runtime can stay inside one healthy handler for seconds —
/// and are dropped only when the runtime has not drained at all within
/// that window (wedged or gone, where no event is observable anyway).
/// Returns false when the runtime receiver is gone (the reader thread must
/// stop then).
fn send_helper_lifecycle_event(mut event: HelperEvent, sender: &mpsc::Sender<HelperEvent>) -> bool {
    let deadline = Instant::now() + LIFECYCLE_SEND_WINDOW;
    loop {
        match sender.try_send(event) {
            Ok(()) => return true,
            Err(mpsc::error::TrySendError::Full(pending)) => {
                event = pending;
                if Instant::now() >= deadline {
                    // The runtime has not drained for a whole window; drop
                    // rather than wedge the reader thread against it.
                    return true;
                }
                std::thread::sleep(super::EVENT_SEND_RETRY);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => return false,
        }
    }
}

/// Build the wire `start` command for the exact core source and config
/// content the GUI stages. The config travels as the base64 of the exact
/// bytes the GUI validated in the same operation, so the elevated helper
/// stages those bytes and never
/// re-reads the user-writable active config path. The `dat_pins_suspended`
/// flag is the shared predicate over that same content — the
/// same decision the direct spawn and the apply gate make from the same
/// config, so the elevated stage copy can never disagree with what the
/// config at hand generated. Content that does not parse fails closed
/// toward the hard pins, mirroring `core_dl::dat_pins_suspended_at`.
fn start_command(api_port: u16, core: &Path, config_bytes: &[u8]) -> serde_json::Value {
    let core_path_utf16: Vec<u16> = core.as_os_str().encode_wide().collect();
    let dat_pins_suspended = serde_json::from_slice::<serde_json::Value>(config_bytes)
        .is_ok_and(|config| crate::sys::core_dl::geodata_updater_configured(&config));
    serde_json::json!({
        "cmd":"start",
        "api_port":api_port,
        "dat_pins_suspended":dat_pins_suspended,
        "core_path_utf16":core_path_utf16,
        "config_base64":base64::engine::general_purpose::STANDARD.encode(config_bytes)
    })
}

/// The complete wire `start` message for `config_bytes`, refused when the
/// serialized message cannot cross the helper pipe within
/// [`MAX_WIRE_MESSAGE_BYTES`]. An
/// over-cap config is refused loudly here — never truncated into a
/// half-delivered message and never silently replaced by a path re-read.
fn start_wire_message(
    api_port: u16,
    core: &Path,
    config_bytes: &[u8],
) -> Result<serde_json::Value, DiagError> {
    let command = start_command(api_port, core, config_bytes);
    let message = command.to_string();
    if message.len().saturating_add(1) > MAX_WIRE_MESSAGE_BYTES {
        return Err(DiagError::new(
            Diag::new(Key::HelperConfigTooLarge)
                .arg(config_bytes.len())
                .arg(MAX_WIRE_MESSAGE_BYTES),
        ));
    }
    Ok(command)
}

pub struct HelperPipe {
    writer: Arc<Mutex<File>>,
    events: Option<mpsc::Receiver<HelperEvent>>,
    reader_cancel: Arc<AtomicBool>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl HelperPipe {
    /// Connect to this launch's unique pipe and authenticate before returning.
    /// Blocking: callers must use a blocking worker thread.
    pub(super) fn connect_cancellable(
        pipe_id: &str,
        token: &str,
        cancel: &AtomicBool,
    ) -> Result<Self, DiagError> {
        if !is_hex_secret(token) {
            return Err(DiagError::new(Diag::new(Key::HelperAuthTokenInvalid)));
        }
        let pipe_name = validated_pipe_name(pipe_id)?;
        let wide_name = to_wide(&pipe_name);
        let deadline = Instant::now() + CONNECT_TIMEOUT;
        let handle = loop {
            if cancel.load(Ordering::Acquire) {
                return Err(DiagError::new(Diag::new(Key::HelperConnectCancelled)));
            }
            // SAFETY: `wide_name` is a NUL-terminated wide pipe path valid for
            // the call; no security attributes, and `GENERIC_READ | GENERIC_
            // WRITE` are the documented access rights for a duplex message
            // pipe client. The windows crate maps INVALID_HANDLE_VALUE to
            // `Err`, so `Ok(handle)` is a valid pipe handle owned by this
            // caller (closed on every exit path below).
            let attempt = unsafe {
                CreateFileW(
                    PCWSTR(wide_name.as_ptr()),
                    GENERIC_READ.0 | GENERIC_WRITE.0,
                    FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    FILE_FLAGS_AND_ATTRIBUTES(0),
                    None,
                )
            };
            match attempt {
                Ok(handle) => break handle,
                Err(error) => {
                    if Instant::now() >= deadline {
                        return Err(DiagError::new(
                            Diag::new(Key::HelperConnectFailed).arg(&pipe_name),
                        )
                        .caused_by(error));
                    }
                    // SAFETY: `wide_name` is the same valid NUL-terminated
                    // path; the call waits up to 100 ms for a pipe instance to
                    // become available. Its boolean result is deliberately
                    // ignored — the retry loop's CreateFileW is the real
                    // probe, and a failure here means "keep polling".
                    let _ = unsafe { WaitNamedPipeW(PCWSTR(wide_name.as_ptr()), 100) };
                    std::thread::sleep(PIPE_POLL);
                }
            }
        };
        if cancel.load(Ordering::Acquire) {
            // SAFETY: `handle` is the valid handle returned by `CreateFileW`
            // above, still open and never closed elsewhere, so this closes it
            // exactly once.
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Err(DiagError::new(Diag::new(Key::HelperConnectCancelled)));
        }
        let mode: NAMED_PIPE_MODE = PIPE_READMODE_MESSAGE;
        // SAFETY: `handle` is the valid open pipe handle; `&mode` is a fully
        // initialized `NAMED_PIPE_MODE` on the stack, alive for the call. The
        // return is checked and the handle is closed on the error path.
        if let Err(error) =
            unsafe { SetNamedPipeHandleState(handle, Some(&mode as *const _), None, None) }
        {
            // SAFETY: `handle` is still the valid, open handle from
            // `CreateFileW` (the failed call above did not close it), so this
            // closes it exactly once before giving up.
            unsafe {
                let _ = CloseHandle(handle);
            }
            return Err(error).diag(Key::HelperClientPipeModeFailed);
        }

        // SAFETY: `handle` is a valid, open pipe handle whose ownership now
        // transfers to the returned `File`: its `Drop` closes it exactly once.
        // The raw `handle` value is not used by any further API call, and the
        // `try_clone` below duplicates it for the writer rather than sharing
        // the same ownership.
        let reader_file = unsafe { File::from_raw_handle(handle.0 as RawHandle) };
        let writer = Arc::new(Mutex::new(
            reader_file
                .try_clone()
                .diag(Key::HelperPipeDuplicateFailed)?,
        ));
        {
            let mut writer_guard = writer
                .lock()
                .map_err(|_| DiagError::new(Diag::new(Key::HelperPipeWriterPoisoned)))?;
            let mut auth = serde_json::json!({
                "cmd":"auth",
                "token":token
            })
            .to_string();
            auth.push('\n');
            writer_guard
                .write_all(auth.as_bytes())
                .diag(Key::HelperAuthWriteFailed)?;
            writer_guard.flush().diag(Key::HelperAuthFlushFailed)?;
        }

        let reader_cancel = Arc::new(AtomicBool::new(false));
        let thread_cancel = Arc::clone(&reader_cancel);
        let (sender, receiver) = mpsc::channel(HELPER_EVT_CHANNEL_CAPACITY);
        let reader = std::thread::Builder::new()
            .name("broccoli-helper-rd".to_string())
            .spawn(move || {
                // `reader_file` owns the pipe handle for this thread; reads
                // go through the raw handle, message-size-aware, so a wire
                // message larger than an 8 KiB
                // `BufReader` buffer cannot fail with `ERROR_MORE_DATA` and
                // kill this reader (which would tear down a running TUN
                // backend).
                let pipe_handle = HANDLE(reader_file.as_raw_handle());
                let mut log_gate = HopLogGate::new();
                while !thread_cancel.load(Ordering::Acquire) {
                    match read_pipe_message(pipe_handle, MAX_WIRE_MESSAGE_BYTES) {
                        Ok(Some(bytes)) => {
                            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
                            else {
                                continue;
                            };
                            let event = match value.get("event").and_then(serde_json::Value::as_str)
                            {
                                Some("state") => HelperEvent::State {
                                    state: value
                                        .get("state")
                                        .and_then(serde_json::Value::as_str)
                                        .unwrap_or_default()
                                        .to_string(),
                                    pid: value
                                        .get("pid")
                                        .and_then(serde_json::Value::as_u64)
                                        .unwrap_or_default()
                                        as u32,
                                },
                                Some("log") => HelperEvent::Log(decode_helper_log(&value)),
                                Some("exit") => HelperEvent::Exit(
                                    value
                                        .get("code")
                                        .and_then(serde_json::Value::as_i64)
                                        .unwrap_or(-1) as i32,
                                ),
                                _ => continue,
                            };
                            // The hop is bounded: log lines are
                            // drop-coalesced by `log_gate` when the runtime
                            // is busy; `State`/`Exit` wait one bounded drain
                            // window instead. A closed receiver means the
                            // runtime released this backend — stop the
                            // reader so pipe EOF hands the watchdog back.
                            match event {
                                HelperEvent::Log(line) => {
                                    if matches!(
                                        log_gate.forward(line, &sender),
                                        HopForward::Disconnected
                                    ) {
                                        break;
                                    }
                                }
                                lifecycle => {
                                    if !send_helper_lifecycle_event(lifecycle, &sender) {
                                        break;
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            std::thread::sleep(PIPE_POLL);
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            })
            .diag(Key::HelperReaderThreadFailed)?;

        Ok(Self {
            writer,
            events: Some(receiver),
            reader_cancel,
            reader: Some(reader),
        })
    }

    pub fn take_events(&mut self) -> mpsc::Receiver<HelperEvent> {
        self.events.take().expect("helper events already taken")
    }

    /// Send the authenticated `start` command for `config_bytes` — the exact
    /// config content the GUI validated in the same operation. The elevated
    /// helper stages precisely these bytes;
    /// the user-writable active config path is never re-read at elevated
    /// time, so a same-user swap after validation cannot reach the stage.
    /// An over-cap config is refused here — never truncated, never silently
    /// replaced by a path re-read — and the refusal is loud through the
    /// caller's Error phase.
    pub fn start(&self, api_port: u16, config_bytes: &[u8]) -> Result<(), DiagError> {
        if api_port == 0 {
            return Err(DiagError::new(Diag::new(Key::HelperStartPortInvalid)));
        }
        // Resolve the core source in the unelevated GUI account. An
        // over-the-shoulder helper has a different AppData and must never
        // derive it itself.
        let core = crate::sys::paths::core_dir();
        if !core.is_absolute() {
            return Err(DiagError::new(Diag::new(
                Key::HelperStartCorePathNotAbsolute,
            )));
        }
        self.send(&start_wire_message(api_port, &core, config_bytes)?)
    }

    pub fn stop(&self) -> Result<(), DiagError> {
        self.send(&serde_json::json!({"cmd":"stop"}))
    }

    pub fn status(&self) -> Result<(), DiagError> {
        self.send(&serde_json::json!({"cmd":"status"}))
    }

    fn send(&self, value: &serde_json::Value) -> Result<(), DiagError> {
        let mut message = value.to_string();
        message.push('\n');
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| DiagError::new(Diag::new(Key::HelperPipeWriterPoisoned)))?;
        writer
            .write_all(message.as_bytes())
            .diag(Key::HelperPipeWriteFailed)?;
        writer.flush().diag(Key::HelperPipeFlushFailed)?;
        Ok(())
    }
}

impl Drop for HelperPipe {
    fn drop(&mut self) {
        self.reader_cancel.store(true, Ordering::Release);
        let _ = self.stop();
        // No I/O cancel is needed to unblock the reader: the pipe is created
        // with `PIPE_NOWAIT` (`create_helper_pipe`), so `read_pipe_message`'s
        // `PeekNamedPipe` gate and reads return immediately, and the reader
        // loop re-checks the cancel flag every iteration, sleeping only
        // `PIPE_POLL` when no message is buffered; the join below is
        // therefore bounded. Cancelling I/O would instead need the pipe
        // handle, whose owning `File` moves into the reader thread — that
        // thread can exit (and close the handle) before this drop runs,
        // letting the OS recycle the value for an unrelated object.
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::Write as _;
    use std::os::windows::io::FromRawHandle as _;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    use super::{
        HelperLog, HelperPipe, MAX_WIRE_MESSAGE_BYTES, ParentIdentity, STAGED_CONFIG,
        SecureRuntimeStage, config_from_wire, current_process_user_sid, dacl_deviation_is_benign,
        decode_helper_log, ensure_protected_directory, parent_identity_accepts,
        parse_helper_parent_arg, path_from_wire, path_to_wide, process_creation_time_of,
        read_pipe_message, stage_config_bytes_at, stage_entry_allowed, start_wire_message, to_wide,
        token_matches, validated_ace, validated_pipe_name, verify_protected_directory,
    };
    use crate::diag::{Diag, DiagError};
    use crate::i18n::{Key, t, t_fmt};
    use crate::model::settings::Language;
    use crate::sys::security::Sid;
    use windows::Win32::Foundation::{ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE};
    use windows::Win32::Security::{
        ACL, ACL_REVISION, AddAccessAllowedAce, DACL_SECURITY_INFORMATION, InitializeAcl,
        InitializeSecurityDescriptor, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        SECURITY_DESCRIPTOR, SetFileSecurityW, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl, WinBuiltinAdministratorsSid, WinBuiltinUsersSid,
        WinLocalSystemSid,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ALL_ACCESS, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_WAIT,
    };
    use windows::core::{HRESULT, PCWSTR};

    #[test]
    fn helper_credentials_are_fixed_width_hex() {
        assert!(validated_pipe_name("0123456789abcdef0123456789abcdef").is_ok());
        assert!(validated_pipe_name("../shared").is_err());
        assert!(token_matches(
            "0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef"
        ));
        assert!(!token_matches(
            "0123456789abcdef0123456789abcdef",
            "1123456789abcdef0123456789abcdef"
        ));
    }

    /// One keyed record decodes into a message the GUI renders in the active
    /// language instead of the record's English fallback.
    #[test]
    fn decode_helper_log_reads_a_keyed_message() {
        let record = serde_json::json!({
            "event":"log",
            "keys":[{"key":"HelperTunCleanupTimeout","args":["broca-tun"]}],
            "line":"helper: the TUN adapter did not finish its cleanup in time"
        });
        match decode_helper_log(&record) {
            HelperLog::Message(error) => {
                assert_eq!(error.diag().key(), Key::HelperTunCleanupTimeout);
                assert_eq!(
                    error.text(Language::En),
                    t_fmt(Language::En, Key::HelperTunCleanupTimeout, &[&"broca-tun"])
                );
            }
            HelperLog::Raw(line) => panic!("a keyed record must decode, got: {line}"),
        }
    }

    /// A chain decodes outermost first, with the external tail kept verbatim
    /// below the keyed layers.
    #[test]
    fn decode_helper_log_reads_a_keyed_chain() {
        let record = serde_json::json!({
            "event":"log",
            "keys":[
                {"key":"HelperStageRefused","args":[]},
                {"key":"HelperStagedConfigProofFailed","args":[]}
            ],
            "tail":"denied by test",
            "line":"helper: fallback"
        });
        match decode_helper_log(&record) {
            HelperLog::Message(error) => {
                assert_eq!(error.diag().key(), Key::HelperStageRefused);
                assert_eq!(
                    error.text(Language::En),
                    format!(
                        "{}: {}: denied by test",
                        t(Language::En, Key::HelperStageRefused),
                        t(Language::En, Key::HelperStagedConfigProofFailed)
                    )
                );
            }
            HelperLog::Raw(line) => panic!("a keyed chain must decode, got: {line}"),
        }
    }

    /// A nested message argument decodes into the slot it fills.
    #[test]
    fn decode_helper_log_reads_a_nested_argument() {
        let record = serde_json::json!({
            "event":"log",
            "keys":[{
                "key":"HelperConnectFailed",
                "args":[{"key":"HelperStagedConfigProofFailed","args":[]}]
            }],
            "line":"helper: fallback"
        });
        match decode_helper_log(&record) {
            HelperLog::Message(error) => assert_eq!(
                error.text(Language::En),
                t_fmt(
                    Language::En,
                    Key::HelperConnectFailed,
                    &[&t(Language::En, Key::HelperStagedConfigProofFailed)],
                )
            ),
            HelperLog::Raw(line) => panic!("a nested argument must decode, got: {line}"),
        }
    }

    /// Unknown names and malformed shapes degrade to the record's line
    /// instead of panicking, so a helper/app drift never loses a message.
    #[test]
    fn decode_helper_log_degrades_malformed_records_to_raw() {
        // A record with no `keys` is the passthrough path (core output).
        match decode_helper_log(&serde_json::json!({"event":"log","line":"core line"})) {
            HelperLog::Raw(line) => assert_eq!(line, "core line"),
            other => panic!("a plain line must stay raw, got {other:?}"),
        }
        for record in [
            // Unknown key name.
            serde_json::json!({"event":"log","keys":[{"key":"HelperNoSuchKey","args":[]}],"line":"fallback"}),
            // Entry without a key.
            serde_json::json!({"event":"log","keys":[{"args":[]}],"line":"fallback"}),
            // Argument that is neither a string nor a nested entry.
            serde_json::json!({"event":"log","keys":[{"key":"HelperStageRefused","args":[7]}],"line":"fallback"}),
            // Empty and non-array shapes.
            serde_json::json!({"event":"log","keys":[],"line":"fallback"}),
            serde_json::json!({"event":"log","keys":"not an array","line":"fallback"}),
        ] {
            match decode_helper_log(&record) {
                HelperLog::Raw(line) => assert_eq!(line, "fallback", "{record}"),
                other => panic!("a malformed record must stay raw, got {other:?}"),
            }
        }
        // A record with neither keys nor a line degrades to its JSON text.
        let record = serde_json::json!({"event":"log"});
        match decode_helper_log(&record) {
            HelperLog::Raw(line) => assert_eq!(line, record.to_string()),
            other => panic!("a keyless record must stay raw, got {other:?}"),
        }
    }

    /// The converted helper errors render their keyed sentence, with the
    /// keyed chain below it.
    #[test]
    fn converted_helper_errors_render_their_keys() {
        let error = DiagError::new(Diag::new(Key::HelperStageRefused)).caused_by(DiagError::new(
            Diag::new(Key::HelperStagedConfigProofFailed),
        ));
        assert_eq!(error.diag().key(), Key::HelperStageRefused);
        assert_eq!(
            error.text(Language::En),
            format!(
                "{}: {}",
                t(Language::En, Key::HelperStageRefused),
                t(Language::En, Key::HelperStagedConfigProofFailed)
            )
        );

        let rejected = parse_helper_parent_arg(&["--helper-parent=0".to_string()])
            .expect_err("a zero parent pid must be rejected");
        assert_eq!(rejected.diag().key(), Key::HelperParentArgInvalid);
        assert_eq!(
            rejected.text(Language::En),
            t(Language::En, Key::HelperParentArgInvalid)
        );
    }
    /// The elevated helper's line capture is bounded the same way
    /// as the direct-mode pump — over-long lines are truncated with the
    /// shared marker and the following line stays intact.
    #[test]
    fn helper_line_capture_is_bounded_and_truncation_visible() {
        use std::io::Cursor;

        use super::read_capped_line_sync;
        use crate::rt::supervisor::{MAX_LINE_BYTES, TRUNCATED_MARKER};

        let keep = MAX_LINE_BYTES - TRUNCATED_MARKER.len();
        let mut data = Vec::new();
        data.extend_from_slice(b"ok\r\n");
        data.extend_from_slice(&vec![b'q'; keep * 2]);
        data.extend_from_slice(b"\ntail\n");
        let mut reader = Cursor::new(data);

        assert_eq!(
            read_capped_line_sync(&mut reader).expect("read ok"),
            Some("ok".to_string()),
            "CRLF stripped"
        );
        let truncated = read_capped_line_sync(&mut reader)
            .expect("read over-long")
            .expect("over-long line present");
        assert!(truncated.ends_with(TRUNCATED_MARKER));
        assert!(truncated.len() <= MAX_LINE_BYTES);
        assert_eq!(
            read_capped_line_sync(&mut reader).expect("read tail"),
            Some("tail".to_string())
        );
        assert!(
            read_capped_line_sync(&mut reader)
                .expect("read eof")
                .is_none()
        );
    }

    #[test]
    fn helper_parent_argument_and_pipe_identity_are_strict() {
        let args = vec!["broccoli.exe".to_string(), "--helper-parent=42".to_string()];
        assert_eq!(parse_helper_parent_arg(&args).expect("valid parent"), 42);

        for invalid in [
            vec!["broccoli.exe".to_string()],
            vec!["--helper-parent=0".to_string()],
            vec!["--helper-parent=not-a-pid".to_string()],
            vec![
                "--helper-parent=42".to_string(),
                "--helper-parent=42".to_string(),
            ],
        ] {
            assert!(parse_helper_parent_arg(&invalid).is_err());
        }

        // The identity pair pins the parent process: the same PID carrying a
        // different kernel creation time is a recycled process, not the
        // launching GUI. The genuine parent is
        // this test process itself, timestamped through the same query the
        // helper's acceptance runs.
        let pid = std::process::id();
        let created = process_creation_time_of(pid).expect("read own creation time");
        assert_ne!(created, 0, "a live process has a real creation time");
        let identity = ParentIdentity { pid, created };
        assert!(
            parent_identity_accepts(&identity, pid, created),
            "the genuine parent passes"
        );
        assert!(
            !parent_identity_accepts(&identity, pid, created.saturating_add(1)),
            "a same-PID process born later (recycled PID) must be rejected"
        );
        assert!(
            !parent_identity_accepts(&identity, pid, created.saturating_sub(1)),
            "a same-PID process claiming an earlier birth must be rejected"
        );
        assert!(
            !parent_identity_accepts(&identity, pid.wrapping_add(1), created),
            "a different PID must be rejected even with the matching creation time"
        );
        assert!(
            !parent_identity_accepts(&ParentIdentity { pid, created: 0 }, pid, created),
            "an untimestamped identity must never accept"
        );
        assert!(
            !parent_identity_accepts(&ParentIdentity { pid: 0, created }, pid, created),
            "a zero PID must never accept"
        );
    }

    #[test]
    fn start_source_paths_require_absolute_nul_free_utf16() {
        let absolute = serde_json::json!(
            "C:\\Users\\broccoli\\config.json"
                .encode_utf16()
                .collect::<Vec<u16>>()
        );
        assert_eq!(
            path_from_wire(Some(&absolute)).unwrap(),
            std::path::PathBuf::from(r"C:\Users\broccoli\config.json")
        );
        assert!(path_from_wire(Some(&serde_json::json!([114, 101, 108]))).is_err());
        assert!(path_from_wire(Some(&serde_json::json!([67, 58, 92, 0]))).is_err());
    }

    #[test]
    fn start_command_derives_the_suspension_flag_from_the_staged_config() {
        use super::start_command;

        let core = std::path::Path::new(r"C:\core");
        // The staged config is the exact config content the helper will
        // stage and run: its own geodata block must reach the wire as the
        // suspension flag, decided by the shared predicate over the carried
        // bytes.
        let geodata: &[u8] =
            br#"{"geodata":{"assets":[{"url":"https://example.com/geoip.dat","file":"geoip.dat"}]}}"#;
        let plain: &[u8] = br#"{"outbounds":[]}"#;

        let staged = start_command(12345, core, geodata);
        assert_eq!(staged["cmd"].as_str(), Some("start"));
        assert_eq!(staged["api_port"].as_u64(), Some(12345));
        assert_eq!(staged["dat_pins_suspended"].as_bool(), Some(true));
        let staged = start_command(12345, core, plain);
        assert_eq!(staged["dat_pins_suspended"].as_bool(), Some(false));
        // Config content that cannot be parsed fails closed on the wire too.
        let staged = start_command(12345, core, b"not json");
        assert_eq!(staged["dat_pins_suspended"].as_bool(), Some(false));
    }

    #[test]
    fn start_wire_stages_the_validated_bytes_not_the_swapped_disk_file() {
        use std::io::Read as _;

        use super::wire_dat_pins_suspended;

        let core = std::path::Path::new(r"C:\core");
        // The GUI validated these bytes in the apply operation and captured
        // them; an attacker then replaces the user-writable active config
        // file that the old helper used to copy at elevated time.
        let validated: &[u8] = br#"{"outbounds":[{"tag":"mine","protocol":"freedom"}]}"#;
        let swapped: &[u8] = br#"{"outbounds":[{"tag":"attacker","protocol":"socks"}]}"#;

        let dir = tempfile::tempdir().expect("config fixture dir");
        let active = dir.path().join("config.json");
        std::fs::write(&active, swapped).expect("write swapped active config");

        // The wire start command carries exactly the validated content; the
        // swapped file exists at stage time but is never consulted.
        let command = start_wire_message(12345, core, validated).expect("modest config crosses");
        assert_eq!(command["api_port"].as_u64(), Some(12345));
        assert!(!wire_dat_pins_suspended(&command));
        let wire_bytes = config_from_wire(&command).expect("server decodes the content");
        assert_eq!(wire_bytes, validated, "wire carries the validated bytes");
        assert_ne!(
            wire_bytes,
            std::fs::read(&active).expect("read swapped active config"),
            "the swapped disk file must differ from what travels on the wire"
        );

        // The stage is written from the pipe bytes with a byte-fidelity copy
        // proof, so the swap cannot reach the stage.
        let stage_dir = dir.path().join("stage");
        std::fs::create_dir(&stage_dir).expect("create stage dir");
        let lock = stage_config_bytes_at(&stage_dir, &wire_bytes).expect("stage pipe bytes");
        let mut staged = Vec::new();
        std::fs::File::open(stage_dir.join(STAGED_CONFIG))
            .expect("open staged config")
            .read_to_end(&mut staged)
            .expect("read staged config");
        assert_eq!(
            staged, validated,
            "pipe bytes win over the swapped disk file"
        );
        drop(lock);
    }

    #[test]
    fn start_wire_refuses_over_cap_config_without_a_fallback() {
        let core = std::path::Path::new(r"C:\core");
        let over_cap = vec![b'x'; MAX_WIRE_MESSAGE_BYTES];
        let error = start_wire_message(12345, core, &over_cap)
            .expect_err("an over-cap config must be refused, never truncated");
        assert_eq!(
            error.text(Language::En),
            t_fmt(
                Language::En,
                Key::HelperConfigTooLarge,
                &[&over_cap.len(), &MAX_WIRE_MESSAGE_BYTES],
            ),
            "the refusal must name the wire cap"
        );
        // A modest config still crosses with the full command shape.
        let command = start_wire_message(12345, core, br#"{"outbounds":[]}"#)
            .expect("a modest config crosses the wire");
        assert!(config_from_wire(&command).is_ok());
    }

    #[test]
    fn wire_dat_pins_suspended_fails_closed_on_absent_or_non_boolean_flags() {
        use serde_json::json;

        use super::wire_dat_pins_suspended;

        assert!(wire_dat_pins_suspended(
            &json!({"cmd": "start", "dat_pins_suspended": true})
        ));
        assert!(!wire_dat_pins_suspended(
            &json!({"cmd": "start", "dat_pins_suspended": false})
        ));
        assert!(
            !wire_dat_pins_suspended(&json!({"cmd": "start"})),
            "an absent flag from a stale GUI must stay strict"
        );
        assert!(!wire_dat_pins_suspended(
            &json!({"cmd": "start", "dat_pins_suspended": null})
        ));
        assert!(!wire_dat_pins_suspended(
            &json!({"cmd": "start", "dat_pins_suspended": "yes"})
        ));
        assert!(!wire_dat_pins_suspended(
            &json!({"cmd": "start", "dat_pins_suspended": 1})
        ));
    }

    #[test]
    fn stale_stage_cleanup_allowlist_rejects_unowned_entries() {
        assert!(stage_entry_allowed(OsStr::new("xray.exe")));
        assert!(stage_entry_allowed(OsStr::new(".broccoli-secure-stage")));
        assert!(!stage_entry_allowed(OsStr::new("attacker.dll")));
        assert!(!stage_entry_allowed(OsStr::new("nested")));
    }

    #[test]
    #[ignore = "requires an elevated Windows token to create the protected ACL"]
    fn protected_stage_acl_is_verified_and_stage_is_removed_on_drop() {
        let stage = SecureRuntimeStage::create().expect("create protected stage");
        let path = stage.path.clone();
        assert!(path.is_dir());
        drop(stage);
        assert!(!path.exists());
    }

    /// Zeroed 512-byte ACL buffer, aligned to 8 for the `ACL` header — the
    /// same layout `sys::security` uses internally. The probe writer below
    /// keeps a raw writer because it must apply deliberately deviating DACL
    /// shapes that the shared builder cannot express.
    #[repr(align(8))]
    struct AlignedAcl([u8; 512]);

    /// Build a probe DACL on `dir`: SYSTEM + Administrators (strict), plus
    /// each SID in `extra_sids` as a full-control ACE carrying
    /// Explorer-style inheritance flags, optionally omitting the
    /// Administrators ACE. Mirrors what Explorer's "permanently get access"
    /// prompt writes to a folder a user clicked into. The kernel collapses
    /// duplicate-SID ACEs on apply, so callers must pass distinct SIDs.
    fn write_probe_dacl(
        dir: &std::path::Path,
        extra_sids: &[PSID],
        omit_administrators: bool,
    ) -> windows::core::Result<()> {
        use windows::Win32::Security::{
            AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE, OBJECT_INHERIT_ACE,
        };
        let system = Sid::well_known(WinLocalSystemSid)?;
        let administrators = Sid::well_known(WinBuiltinAdministratorsSid)?;
        let mut acl_storage = AlignedAcl([0; 512]);
        let acl = acl_storage.0.as_mut_ptr().cast::<ACL>();
        // SAFETY: `acl` points at a live 512-byte aligned buffer; the ACEs
        // appended reference SIDs whose owned storage stays alive through
        // the writes; every call's return is checked by `?`.
        unsafe {
            InitializeAcl(acl, acl_storage.0.len() as u32, ACL_REVISION)?;
            AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS.0, system.psid())?;
            if !omit_administrators {
                AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS.0, administrators.psid())?;
            }
            for sid in extra_sids {
                AddAccessAllowedAceEx(
                    acl,
                    ACL_REVISION,
                    CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                    FILE_ALL_ACCESS.0,
                    *sid,
                )?;
            }
        }
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        let descriptor_pointer =
            PSECURITY_DESCRIPTOR((&mut descriptor as *mut SECURITY_DESCRIPTOR).cast());
        // SAFETY: `descriptor` is a zeroed, aligned, alive stack descriptor;
        // the Set* calls record pointers to the live SID/ACL buffers, and the
        // kernel copies them during SetFileSecurityW below. Every call's
        // return is checked.
        unsafe {
            InitializeSecurityDescriptor(descriptor_pointer, 1)?;
            SetSecurityDescriptorDacl(descriptor_pointer, true, Some(acl), false)?;
            SetSecurityDescriptorControl(descriptor_pointer, SE_DACL_PROTECTED, SE_DACL_PROTECTED)?;
        }
        let wide = path_to_wide(dir);
        let applied = unsafe {
            SetFileSecurityW(
                PCWSTR(wide.as_ptr()),
                DACL_SECURITY_INFORMATION,
                descriptor_pointer,
            )
        };
        if !applied.as_bool() {
            return Err(windows::core::Error::from_thread());
        }
        Ok(())
    }

    /// A per-run unique probe directory in the system temp directory. Stale
    /// dirs from interrupted runs keep the strict protected DACL (SYSTEM +
    /// Administrators only, no user ACE) and cannot be deleted by an
    /// unelevated token, so a PID-only name would collide with such a stale
    /// dir via PID reuse and fail the create. The nanos suffix makes a fresh
    /// run immune to any leftover, which then stays inert garbage.
    fn probe_dir(kind: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "broccoli-dacl-probe-{kind}-{}-{unique}",
            std::process::id()
        ))
    }

    #[test]
    fn benign_user_ace_deviation_is_detected_and_repaired() {
        let dir = probe_dir("benign");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("create probe dir");
        let own = current_process_user_sid().expect("current user SID");
        let own_sid = own.psid();
        write_probe_dacl(&dir, &[], false).expect("apply strict probe DACL");
        assert!(
            verify_protected_directory(&dir).is_ok(),
            "strict 2-ACE shape must verify"
        );
        write_probe_dacl(&dir, &[own_sid], false).expect("apply user-ACE probe DACL");
        assert!(
            verify_protected_directory(&dir).is_err(),
            "3-ACE shape must fail strict verification"
        );
        assert!(
            dacl_deviation_is_benign(&dir),
            "user-ACE deviation must be diagnosed as benign"
        );
        ensure_protected_directory(&dir).expect("benign deviation must repair in place");
        assert!(
            verify_protected_directory(&dir).is_ok(),
            "repaired directory must verify strictly"
        );
        // The repair leaves the strict SYSTEM+Admins-only DACL, which an
        // unelevated token cannot delete, so restore the user ACE first or
        // every run leaks a probe dir into the system temp directory
        // (hundreds accumulated via PID reuse collisions).
        write_probe_dacl(&dir, &[own_sid], false).expect("restore probe user ACE");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_benign_dacl_deviations_stay_fail_closed() {
        let dir = probe_dir("strict");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("create probe dir");
        let own = current_process_user_sid().expect("current user SID");
        let own_sid = own.psid();
        let users = Sid::well_known(WinBuiltinUsersSid).expect("Users SID");
        let users = users.psid();
        // Two extra ACEs: not the single Explorer-style grant.
        write_probe_dacl(&dir, &[], false).expect("apply strict probe DACL");
        write_probe_dacl(&dir, &[own_sid, users], false).expect("apply 4-ACE probe DACL");
        assert!(
            !dacl_deviation_is_benign(&dir),
            "4-ACE shape must not be benign"
        );
        assert!(
            ensure_protected_directory(&dir).is_err(),
            "4-ACE deviation must stay fail-closed"
        );
        // Three ACEs but missing Administrators: also not benign.
        write_probe_dacl(&dir, &[], false).expect("apply strict probe DACL");
        write_probe_dacl(&dir, &[own_sid, users], true).expect("apply admins-less probe DACL");
        assert!(
            !dacl_deviation_is_benign(&dir),
            "admins-less shape must not be benign"
        );
        assert!(
            ensure_protected_directory(&dir).is_err(),
            "admins-less deviation must stay fail-closed"
        );
        // Three ACEs but the extra ACE belongs to a well-known SID (Users),
        // not the current user: the documented deviation shape is Explorer
        // granting *the user* access, so this must stay fail-closed too.
        write_probe_dacl(&dir, &[], false).expect("apply strict probe DACL");
        write_probe_dacl(&dir, &[users], false).expect("apply Users-ACE probe DACL");
        assert!(
            !dacl_deviation_is_benign(&dir),
            "foreign-SID extra ACE must not be benign"
        );
        assert!(
            ensure_protected_directory(&dir).is_err(),
            "foreign-SID deviation must stay fail-closed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validated_ace_rejects_malformed_ace_sizes() {
        // A valid 24-byte ACE (header + mask + 12-byte minimum SID) inside a
        // 24-byte buffer passes.
        let mut buffer = [0u8; 24];
        buffer[2] = 24;
        buffer[9] = 1;
        let ace = buffer.as_ptr().cast::<core::ffi::c_void>();
        assert!(
            validated_ace(ace, &buffer).is_some(),
            "in-bounds ACE with exact AceSize must pass"
        );
        // A declared size larger than the buffer must be rejected.
        buffer[2] = 100;
        assert!(
            validated_ace(ace, &buffer).is_none(),
            "AceSize beyond the buffer must be rejected"
        );
        // A size too small to hold the fixed prefix must be rejected.
        buffer[2] = 8;
        assert!(
            validated_ace(ace, &buffer).is_none(),
            "undersized AceSize must be rejected"
        );
        // A pointer starting past the end of the buffer must be rejected.
        let past = buffer.as_ptr().wrapping_add(20).cast::<core::ffi::c_void>();
        assert!(
            validated_ace(past, &buffer).is_none(),
            "ACE pointer past the buffer must be rejected"
        );
        // A pointer at the very end leaves no room for the header.
        let end = buffer.as_ptr().wrapping_add(24).cast::<core::ffi::c_void>();
        assert!(
            validated_ace(end, &buffer).is_none(),
            "ACE pointer at the buffer end must be rejected"
        );
        // An allow-ACE (`ACCESS_ALLOWED_ACE_TYPE`) whose embedded SID would
        // extend past its declared `AceSize` must be rejected: `EqualSid`
        // walks the SID by its own `SubAuthorityCount`, so a forged count
        // would otherwise read past the ACE and possibly past the descriptor
        // buffer.
        buffer[2] = 20;
        buffer[9] = 4;
        assert!(
            validated_ace(ace, &buffer).is_none(),
            "SID count overflowing the declared AceSize must be rejected"
        );
        // The same SID fits once the declared `AceSize` covers it.
        buffer[2] = 24;
        buffer[9] = 2;
        assert!(
            validated_ace(ace, &buffer).is_some(),
            "SID count within the declared AceSize must pass"
        );
        // Non-allow ACE types keep the size-only check: the callers never
        // compare their `SidStart`.
        buffer[0] = 1;
        buffer[2] = 20;
        buffer[9] = 4;
        assert!(
            validated_ace(ace, &buffer).is_some(),
            "non-allow ACE must keep the size-only check"
        );
        // The same valid allow-ACE at an odd offset of its buffer must pass
        // too: the descriptor storage is byte-addressed (the loader's words,
        // the fixtures here), so nothing may depend on the ACE sitting at an
        // aligned address. The fixture base is 8-aligned, so the ACE at offset
        // 1 is odd and the case cannot pass by luck.
        buffer[0] = 0;
        buffer[2] = 24;
        buffer[9] = 2;
        #[repr(align(8))]
        struct AlignedPadded([u8; 25]);
        let mut padded = AlignedPadded([0u8; 25]);
        padded.0[1..].copy_from_slice(&buffer);
        let shifted = &padded.0[1..];
        assert!(
            validated_ace(shifted.as_ptr().cast(), shifted).is_some(),
            "an ACE at an odd offset must validate"
        );
        // The decoded fields come from their own offsets, not from the header:
        // the access mask is compared by the callers, so it has to survive the
        // decode.
        buffer[4..8].copy_from_slice(&FILE_ALL_ACCESS.0.to_ne_bytes());
        let decoded = validated_ace(ace, &buffer).expect("valid allow-ACE decodes");
        assert_eq!(decoded.ace_type, 0, "allow-ACEs report their type");
        assert_eq!(decoded.ace_flags, 0, "allow-ACEs report their flags");
        assert_eq!(decoded.mask, FILE_ALL_ACCESS.0, "the mask is decoded");
    }

    /// The GUI binary these probes spawn: the running test executable lives in
    /// `target/<triple>/debug/deps`, so the bin target sits one directory up.
    /// `CARGO_BIN_EXE_*` is set for integration tests only, and
    /// `CARGO_MANIFEST_DIR/target/debug` misses the per-target layout that
    /// `--target` produces — the layout CI builds, where that path never
    /// exists.
    fn gui_binary() -> std::path::PathBuf {
        let exe = std::env::current_exe()
            .expect("locate the running test executable")
            .parent()
            .and_then(std::path::Path::parent)
            .expect("the test executable lives in target/<triple>/debug/deps")
            .join("broccoli.exe");
        assert!(
            exe.is_file(),
            "these probes spawn the GUI binary; build it for the same target first — \
             `cargo test` and `cargo test --all-targets` build it, `cargo test --lib` does not: {}",
            exe.display()
        );
        exe
    }

    #[test]
    fn probe_spawn_exe_held_open_with_share_read_only() {
        use std::fs::{self, OpenOptions};
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

        let exe = gui_binary();
        let probe_dir =
            std::env::temp_dir().join(format!("broccoli-spawn-share-probe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&probe_dir);
        fs::create_dir_all(&probe_dir).expect("create probe dir");
        let probe_exe = probe_dir.join("xray.exe");
        fs::copy(&exe, &probe_exe).expect("copy probe exe");

        // Case A: lock with share=READ only (production lock semantics).
        let locked_read = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(&probe_exe)
            .expect("open probe exe share-read-only");
        let result_a = std::process::Command::new(&probe_exe)
            .args([
                "--core-helper",
                "--helper-pipe=deadbeefdeadbeefdeadbeefdeadbeef",
                "--helper-parent=4294967294",
            ])
            .spawn();
        drop(locked_read);
        if let Ok(mut child) = result_a {
            let _ = child.kill();
            let _ = child.wait();
        }

        // Case B: lock with share=READ|WRITE, spawn again.
        let locked_rw = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
            .open(&probe_exe)
            .expect("open probe exe share-rw");
        let result_b = std::process::Command::new(&probe_exe)
            .args([
                "--core-helper",
                "--helper-pipe=deadbeefdeadbeefdeadbeefdeadbeef",
                "--helper-parent=4294967294",
            ])
            .spawn();
        drop(locked_rw);
        if let Ok(mut child) = result_b {
            let _ = child.kill();
            let _ = child.wait();
        }

        // Case D: production lock shape — WRITE-mode handle with share=READ
        // only (copy_runtime_payloads opens each staged payload write-only +
        // share READ). Does spawning succeed?
        let locked_write = OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ.0)
            .open(&probe_exe)
            .expect("open probe exe write-mode share-read (D)");
        let result_d = std::process::Command::new(&probe_exe)
            .args([
                "--core-helper",
                "--helper-pipe=deadbeefdeadbeefdeadbeefdeadbeef",
                "--helper-parent=4294967294",
            ])
            .spawn();
        drop(locked_write);

        if let Ok(mut child) = result_d {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&probe_dir);
    }

    #[test]
    fn probe_full_protocol_with_live_helper() {
        // The guard below stages the one-shot token into this process's
        // environment block, so this test holds the staging window for its
        // whole duration: the elevation tests snapshot `HELPER_TOKEN_ENV`
        // across their own staging and must never observe this test's write.
        let _env_lock = crate::sys::elevation::lock_helper_token_env();
        let pipe_id = uuid::Uuid::new_v4().simple().to_string();
        let token = uuid::Uuid::new_v4().simple().to_string();
        let helper_exe = gui_binary();
        let parent_pid = std::process::id();
        // Stage the credential the way the production GUI does, then spawn
        // the helper WITHOUT the env token — the cross-user UAC case where
        // the child's environment was rebuilt and only the ProgramData token
        // file survives. This exercises the exact regression channel.
        let _credentials = crate::sys::elevation::HelperTokenGuard::new(&pipe_id, &token)
            .expect("staging helper credentials");
        let mut child = std::process::Command::new(&helper_exe)
            .args([
                "--core-helper",
                &format!("--helper-pipe={pipe_id}"),
                &format!("--helper-parent={parent_pid}"),
            ])
            .env_remove(crate::sys::elevation::HELPER_TOKEN_ENV)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn live helper");

        let start = Instant::now();
        let cancel = AtomicBool::new(false);
        let mut pipe = match HelperPipe::connect_cancellable(&pipe_id, &token, &cancel) {
            Ok(pipe) => pipe,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let mut stderr = String::new();
                if let Some(mut stream) = child.stderr.take() {
                    use std::io::Read as _;
                    let _ = stream.read_to_string(&mut stderr);
                }
                panic!(
                    "connect to live helper failed after {:?}: {error:#}; helper stderr: {stderr}",
                    start.elapsed()
                );
            }
        };
        let mut events = pipe.take_events();
        pipe.status().expect("send status command");
        let mut got_state = false;
        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < wait_deadline {
            if let Ok(event) = events.try_recv()
                && matches!(event, super::HelperEvent::State { state, .. } if state == "stopped")
            {
                got_state = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(got_state, "helper must answer status with state=stopped");

        // Drive the full production flow: the GUI sends the exact active
        // config content it validated, the helper stages the
        // real pinned core and that content, validates the staged config by
        // spawning xray, then spawns it for real. This is the exact sequence
        // that the user's elevated run reports failing with
        // ERROR_SHARING_VIOLATION (os error 32) at the validation spawn.
        let api_port = {
            use std::net::TcpListener;
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind probe api port");
            listener.local_addr().expect("probe api addr").port()
        };
        let config_bytes = std::fs::read(crate::rt::apply::active_path()).unwrap_or_else(|_| {
            br#"{"log":{"loglevel":"warning"},"outbounds":[{"protocol":"freedom","tag":"probe"}]}"#
                .to_vec()
        });
        pipe.start(api_port, &config_bytes)
            .expect("send start command");
        let mut saw_starting = false;
        let mut saw_refusal = false;
        let start_deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < start_deadline {
            if let Ok(event) = events.try_recv() {
                match &event {
                    super::HelperEvent::State { state, .. }
                        if state == "starting" || state == "running" =>
                    {
                        saw_starting = true;
                    }
                    super::HelperEvent::Log(super::HelperLog::Message(error))
                        if error.diag().key() == Key::HelperStageRefused =>
                    {
                        saw_refusal = true;
                    }
                    super::HelperEvent::Exit { .. } => break,
                    _ => {}
                }
                if saw_starting && !saw_refusal {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = pipe.stop();
        drop(pipe);

        let status = child.wait().expect("wait helper");
        let mut stderr = String::new();
        if let Some(mut stream) = child.stderr.take() {
            use std::io::Read as _;
            let _ = stream.read_to_string(&mut stderr);
        }
        assert!(
            status.success(),
            "live helper must exit cleanly, stderr: {stderr}"
        );
    }

    #[test]
    fn live_helper_accepts_its_genuine_parent() {
        let pipe_id = uuid::Uuid::new_v4().simple().to_string();
        let token = uuid::Uuid::new_v4().simple().to_string();
        let helper_exe = gui_binary();
        let parent_pid = std::process::id();
        // Same-user elevation channel: the env token the child inherits. No
        // start command is sent, so this exercises the full authentication
        // ceremony — launch identity capture, pipe creation, PID + creation
        // time acceptance — without any protected ProgramData staging, and
        // therefore without an elevated token.
        let mut child = std::process::Command::new(&helper_exe)
            .args([
                "--core-helper",
                &format!("--helper-pipe={pipe_id}"),
                &format!("--helper-parent={parent_pid}"),
            ])
            .env(crate::sys::elevation::HELPER_TOKEN_ENV, &token)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn live helper");

        let cancel = AtomicBool::new(false);
        let mut pipe = match HelperPipe::connect_cancellable(&pipe_id, &token, &cancel) {
            Ok(pipe) => pipe,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let mut stderr = String::new();
                if let Some(mut stream) = child.stderr.take() {
                    use std::io::Read as _;
                    let _ = stream.read_to_string(&mut stderr);
                }
                panic!("connect to live helper failed: {error:#}; helper stderr: {stderr}");
            }
        };
        // The helper captured this test process's PID and creation time at
        // launch and must accept this exact process as the launching GUI.
        let mut events = pipe.take_events();
        pipe.status().expect("send status command");
        let mut got_state = false;
        let wait_deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < wait_deadline {
            if let Ok(event) = events.try_recv()
                && matches!(event, super::HelperEvent::State { state, .. } if state == "stopped")
            {
                got_state = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            got_state,
            "helper must accept its genuine parent and answer status"
        );
        drop(pipe);

        let status = child.wait().expect("wait helper");
        let mut stderr = String::new();
        if let Some(mut stream) = child.stderr.take() {
            use std::io::Read as _;
            let _ = stream.read_to_string(&mut stderr);
        }
        assert!(
            status.success(),
            "live helper must exit cleanly after a genuine-parent session, stderr: {stderr}"
        );
    }

    /// Create a connected message-mode pipe pair for wire tests: server
    /// handle (read side) plus client `File` (write side).
    fn test_message_pipe() -> (HANDLE, File) {
        static NEXT_PIPE: AtomicU32 = AtomicU32::new(0);
        let name = format!(
            r"\\.\pipe\broccoli-helper-test-{}-{}",
            std::process::id(),
            NEXT_PIPE.fetch_add(1, Ordering::Relaxed)
        );
        let wide = to_wide(&name);
        // SAFETY: `wide` is a NUL-terminated wide pipe path valid for the
        // call; message mode matches the serve loop; no security attributes.
        // `CreateNamedPipeW` returns INVALID_HANDLE_VALUE on failure, checked
        // below.
        let server = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                64 * 1024,
                64 * 1024,
                0,
                None,
            )
        };
        assert!(
            !server.is_invalid(),
            "create test pipe failed: {}",
            windows::core::Error::from_thread()
        );
        // SAFETY: `wide` is the same valid path; GENERIC_READ | GENERIC_WRITE
        // are the documented access rights for a duplex message-pipe client.
        let client = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        }
        .expect("connect test pipe");
        // The client may connect before the server accepts; the kernel then
        // reports ERROR_PIPE_CONNECTED, which means the connection is up.
        if let Err(error) = unsafe { ConnectNamedPipe(server, None) } {
            assert_eq!(
                error.code(),
                HRESULT::from_win32(ERROR_PIPE_CONNECTED.0),
                "test pipe must accept its client"
            );
        }
        // SAFETY: `client` is the valid open handle from `CreateFileW`; the
        // `File` closes it exactly once on drop.
        let client = unsafe { File::from_raw_handle(client.0) };
        (server, client)
    }

    /// A wire message larger than the old 8 KiB
    /// `BufReader` buffer is delivered intact — the previous reader failed
    /// with ERROR_MORE_DATA and killed the channel.
    #[test]
    fn pipe_reader_delivers_messages_beyond_eight_kib() {
        let (server, mut client) = test_message_pipe();
        let big = vec![b'x'; 20 * 1024];
        client.write_all(b"small\n").expect("write small message");
        client.write_all(&big).expect("write 20 KiB message");
        client.write_all(b"tail\n").expect("write tail message");

        let read = |cap: usize| {
            read_pipe_message(HANDLE(server.0), cap)
                .expect("read from test pipe")
                .expect("message available")
        };

        let first = read(MAX_WIRE_MESSAGE_BYTES);
        assert_eq!(first.as_slice(), &b"small\n"[..]);
        let second = read(MAX_WIRE_MESSAGE_BYTES);
        assert_eq!(second.len(), big.len(), "20 KiB message delivered intact");
        assert!(second.iter().all(|byte| *byte == b'x'));
        let third = read(MAX_WIRE_MESSAGE_BYTES);
        assert_eq!(third.as_slice(), &b"tail\n"[..]);
    }

    /// A message beyond the wire cap is truncated at
    /// the cap and its remainder drained — never fatal, and the channel
    /// stays aligned for the next message.
    #[test]
    fn pipe_reader_truncates_over_cap_message_without_dropping_channel() {
        let (server, mut client) = test_message_pipe();
        let cap = 4096usize;
        let exact = vec![b'y'; cap];
        let over = vec![b'z'; cap * 4];
        client.write_all(b"small\n").expect("write small message");
        client.write_all(&exact).expect("write exact-cap message");
        client.write_all(&over).expect("write over-cap message");
        client.write_all(b"tail\n").expect("write tail message");

        let read = |cap: usize| {
            read_pipe_message(HANDLE(server.0), cap)
                .expect("read from test pipe")
                .expect("message available")
        };
        let first = read(cap);
        assert_eq!(first.as_slice(), &b"small\n"[..]);
        let second = read(cap);
        assert_eq!(second.len(), cap, "exactly-cap message delivered intact");
        let truncated = read(cap);
        assert_eq!(
            truncated.len(),
            cap,
            "over-cap message truncated at the cap"
        );
        let tail = read(cap);
        assert_eq!(
            tail.as_slice(),
            &b"tail\n"[..],
            "channel survives over-cap message"
        );
    }

    /// Regression: a peer that closed the pipe must
    /// surface as `Err`, not as an empty poll — the client reader loop exits
    /// on `Err` and the runtime learns the helper is gone; `Ok(None)` would
    /// make it poll a dead pipe forever and never detect the loss.
    #[test]
    fn pipe_reader_reports_closed_peer_as_error_not_empty_poll() {
        let (server, mut client) = test_message_pipe();
        // Writing then dropping the client closes the peer end; the server
        // end then fails with ERROR_BROKEN_PIPE on every subsequent call.
        client.write_all(b"bye\n").expect("write last message");
        drop(client);
        let handle = HANDLE(server.0);
        // The buffered message is still readable before the break surfaces.
        let message = read_pipe_message(handle, MAX_WIRE_MESSAGE_BYTES)
            .expect("buffered message must read")
            .expect("message available");
        assert_eq!(message.as_slice(), &b"bye\n"[..]);
        // After the buffered data is gone the closed peer must be an error.
        assert!(
            read_pipe_message(handle, MAX_WIRE_MESSAGE_BYTES).is_err(),
            "closed peer must surface as Err, never as an empty poll"
        );
    }

    // -- helper→runtime hop bound ----------------------

    /// A flooding core must not grow the bounded helper→runtime
    /// queue; lines beyond capacity are counted, then coalesced into exactly
    /// one summary on the next successful send (LogGate semantics, now on
    /// the TUN hop). Without the bounded channel this test cannot pass: an
    /// unbounded queue never rejects, so nothing is suppressed and no
    /// summary exists to deliver.
    #[test]
    fn hop_log_gate_coalesces_lines_when_channel_is_full() {
        use tokio::sync::mpsc;

        use super::{HelperEvent, HelperLog, HopForward, HopLogGate};

        let (sender, mut receiver) = mpsc::channel(2);
        let mut gate = HopLogGate::new();
        let mut queued = 0;
        for _ in 0..5 {
            if gate.forward(HelperLog::Raw("line".to_string()), &sender) == HopForward::Queued {
                queued += 1;
            }
        }
        // Capacity 2: exactly two lines fit; the rest were counted, not queued.
        assert_eq!(queued, 2);

        // The runtime catches up (drains the queue); the next line emits the
        // summary of the 3 suppressed lines followed by the line itself.
        while receiver.try_recv().is_ok() {}
        assert_eq!(
            gate.forward(HelperLog::Raw("fresh".to_string()), &sender),
            HopForward::Queued
        );
        let mut drained = Vec::new();
        while let Ok(evt) = receiver.try_recv() {
            drained.push(evt);
        }
        assert_eq!(drained.len(), 2, "summary plus the fresh line");
        match &drained[0] {
            HelperEvent::Log(HelperLog::Message(message)) => assert_eq!(
                message.text(Language::En),
                super::super::suppressed_summary(3).text(Language::En)
            ),
            other => panic!("expected suppression summary, got {other:?}"),
        }
        match &drained[1] {
            HelperEvent::Log(HelperLog::Raw(line)) => assert_eq!(line, "fresh"),
            other => panic!("expected the fresh line, got {other:?}"),
        }
        assert!(
            matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "no further events queued — the summary is delivered exactly once"
        );
    }

    /// The summary uses the singular wording for one suppressed
    /// line, the counter resets after delivery, and a second flood
    /// coalesces independently of the first.
    #[test]
    fn hop_log_gate_resets_after_summary_and_recoalesces() {
        use tokio::sync::mpsc;

        use super::{HelperEvent, HelperLog, HopForward, HopLogGate};

        let (sender, mut receiver) = mpsc::channel(2);
        let mut gate = HopLogGate::new();
        assert_eq!(
            gate.forward(HelperLog::Raw("first".to_string()), &sender),
            HopForward::Queued
        );
        assert_eq!(
            gate.forward(HelperLog::Raw("second".to_string()), &sender),
            HopForward::Queued
        );
        assert_eq!(
            gate.forward(HelperLog::Raw("third".to_string()), &sender),
            HopForward::Suppressed
        );
        assert_eq!(gate.suppressed, 1, "one line counted, not queued");
        while receiver.try_recv().is_ok() {}

        // Next success delivers the singular summary first, then the line.
        assert_eq!(
            gate.forward(HelperLog::Raw("fourth".to_string()), &sender),
            HopForward::Queued
        );
        let mut drained = Vec::new();
        while let Ok(evt) = receiver.try_recv() {
            drained.push(evt);
        }
        assert_eq!(drained.len(), 2, "singular summary plus the fourth line");
        match &drained[0] {
            HelperEvent::Log(HelperLog::Message(message)) => assert_eq!(
                message.text(Language::En),
                super::super::suppressed_summary(1).text(Language::En)
            ),
            other => panic!("expected singular suppression summary, got {other:?}"),
        }
        assert_eq!(gate.suppressed, 0, "summary delivery resets the counter");

        // A second flood after the summary restarts the count from zero.
        assert_eq!(
            gate.forward(HelperLog::Raw("fifth".to_string()), &sender),
            HopForward::Queued
        );
        assert_eq!(
            gate.forward(HelperLog::Raw("sixth".to_string()), &sender),
            HopForward::Queued
        );
        assert_eq!(
            gate.forward(HelperLog::Raw("seventh".to_string()), &sender),
            HopForward::Suppressed
        );
        assert_eq!(
            gate.forward(HelperLog::Raw("eighth".to_string()), &sender),
            HopForward::Suppressed
        );
        assert_eq!(gate.suppressed, 2, "second flood counts from zero");
        while receiver.try_recv().is_ok() {}
        assert_eq!(
            gate.forward(HelperLog::Raw("ninth".to_string()), &sender),
            HopForward::Queued
        );
        let mut drained = Vec::new();
        while let Ok(evt) = receiver.try_recv() {
            drained.push(evt);
        }
        assert_eq!(drained.len(), 2, "second summary plus the ninth line");
        match &drained[0] {
            HelperEvent::Log(HelperLog::Message(message)) => assert_eq!(
                message.text(Language::En),
                super::super::suppressed_summary(2).text(Language::En)
            ),
            other => panic!("expected second summary with a fresh count, got {other:?}"),
        }
        match &drained[1] {
            HelperEvent::Log(HelperLog::Raw(line)) => assert_eq!(line, "ninth"),
            other => panic!("expected the ninth line, got {other:?}"),
        }
    }

    /// Lifecycle events (state/exit) are never coalesced away
    /// when the hop is full — the bounded fallback waits for the next drain
    /// cycle to free a slot, mirroring the GUI channel's lifecycle handling.
    /// An `Exit` lost to the drop counter would strand a TUN backend the
    /// runtime believes it still owns.
    #[test]
    fn hop_lifecycle_event_waits_for_a_slot_when_channel_is_full() {
        use tokio::sync::mpsc;

        use super::{HelperEvent, send_helper_lifecycle_event};

        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .try_send(HelperEvent::Log(HelperLog::Raw("filler".to_string())))
            .expect("fill the hop");
        let full_sender = sender.clone();
        let blocker = std::thread::spawn(move || {
            send_helper_lifecycle_event(HelperEvent::Exit(23), &full_sender)
        });
        // Free the slot; the waiting exit event arrives next.
        assert!(matches!(
            receiver.blocking_recv(),
            Some(HelperEvent::Log(HelperLog::Raw(line))) if line == "filler"
        ));
        assert!(matches!(
            receiver.blocking_recv(),
            Some(HelperEvent::Exit(23))
        ));
        blocker.join().expect("lifecycle send completes");
    }

    /// When the runtime never drains the hop, the lifecycle fallback
    /// returns within the extended bounded window instead of wedging the
    /// reader thread forever; the event is dropped only then. The window
    /// now covers the longest legitimate run-loop stall, so a drop means
    /// the runtime is genuinely wedged or gone.
    #[test]
    fn hop_lifecycle_event_waits_bounded_window_then_drops() {
        use tokio::sync::mpsc;

        use super::{HelperEvent, LIFECYCLE_SEND_WINDOW, send_helper_lifecycle_event};

        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .try_send(HelperEvent::Log(HelperLog::Raw("filler".to_string())))
            .expect("fill the hop");
        let full_sender = sender.clone();
        let started = Instant::now();
        let blocker = std::thread::spawn(move || {
            send_helper_lifecycle_event(HelperEvent::Exit(23), &full_sender)
        });
        blocker.join().expect("bounded fallback must return");
        let waited = started.elapsed();
        assert!(
            waited >= LIFECYCLE_SEND_WINDOW / 2,
            "the bounded window must actually wait for a drain cycle, got {waited:?}"
        );
        // Only the filler remains; the exit event was dropped after the
        // bound because the runtime never drained.
        assert!(matches!(
            receiver.try_recv(),
            Ok(HelperEvent::Log(HelperLog::Raw(line))) if line == "filler"
        ));
        assert!(
            matches!(receiver.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
            "the lifecycle event is dropped only when the runtime never drains"
        );
    }

    /// Regression: a lifecycle event queued while the
    /// hop is full must survive a runtime stall longer than the GUI-frame
    /// window — the helper hop's consumer is the single current-thread
    /// runtime, which can stay inside one healthy handler for seconds
    /// (stats poll ~1.5 s, TUN teardown up to 3.25 s, payload hashing).
    /// The channel stays full for a stall beyond the old 250 ms bound but
    /// well inside the new [`LIFECYCLE_SEND_WINDOW`]; when the runtime
    /// drains, the exit event must be delivered — not dropped.
    #[test]
    fn hop_lifecycle_event_survives_stall_longer_than_gui_event_bound() {
        use tokio::sync::mpsc;

        use super::{HelperEvent, LIFECYCLE_SEND_WINDOW, send_helper_lifecycle_event};

        // A stall a healthy runtime can legitimately exceed the old
        // GUI-side bound by (3× the old window), yet far below the new
        // 4 s drop window.
        let stall = super::super::EVENT_SEND_BOUND * 3;
        assert!(stall < LIFECYCLE_SEND_WINDOW);

        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .try_send(HelperEvent::Log(HelperLog::Raw("filler".to_string())))
            .expect("fill the hop");
        let full_sender = sender.clone();
        let started = Instant::now();
        let blocker = std::thread::spawn(move || {
            send_helper_lifecycle_event(HelperEvent::Exit(23), &full_sender)
        });
        // Runtime stalled (hop full, undrained) past the old bound...
        std::thread::sleep(stall);
        // ...and draining now: the waiting exit event must arrive instead
        // of having been dropped at the old 250 ms window.
        assert!(matches!(
            receiver.blocking_recv(),
            Some(HelperEvent::Log(HelperLog::Raw(line))) if line == "filler"
        ));
        assert!(matches!(
            receiver.blocking_recv(),
            Some(HelperEvent::Exit(23))
        ));
        let delivered = blocker.join().expect("lifecycle send completes");
        assert!(
            delivered,
            "a drained runtime must accept the lifecycle event"
        );
        assert!(
            started.elapsed() < LIFECYCLE_SEND_WINDOW,
            "the event must be delivered before the drop window elapses"
        );
    }

    /// Mechanism check: `child_is_live_current` is the
    /// probe the DNS-shield installer uses to keep a shield from outliving
    /// the child (and stage directory) it was installed for. It must hold
    /// only while the slot names this exact pid and the process has not
    /// exited — false for an empty slot, a different occupant pid, or a
    /// dead occupant are the exact states in which the installer removes
    /// the shield it just installed (and in which the reaper deletes the
    /// staged payload the shield's permit app-id names).
    #[test]
    fn dns_shield_liveness_probe_tracks_the_installed_child() {
        use std::process::{Command, Stdio};
        use std::sync::{Arc, Mutex};

        use super::{HelperChild, Job, SecureRuntimeStage, child_is_live_current};

        let mut command = Command::new("cmd");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        std::os::windows::process::CommandExt::creation_flags(
            &mut command,
            crate::rt::supervisor::CREATE_NO_WINDOW,
        );
        let child = command.spawn().expect("spawn probe child");
        let pid = child.id();
        let job = Job::new_kill_on_close().expect("create probe job");
        let stage = SecureRuntimeStage {
            path: std::env::temp_dir().join(format!("broccoli-probe-stage-{}", std::process::id())),
            locks: Vec::new(),
        };
        let current = Arc::new(Mutex::new(Some(HelperChild {
            child,
            job,
            state: "starting".to_string(),
            api_port: 0,
            _stage: stage,
        })));
        // The probe child stays alive while its piped stdin stays open.
        assert!(
            child_is_live_current(&current, pid),
            "a live occupant with the matching pid must keep the shield"
        );
        // A different pid (superseding start): not this child.
        assert!(!child_is_live_current(&current, pid.wrapping_add(1)));
        // Empty slot (the reaper took the child): not this child.
        let mut taken = current
            .lock()
            .expect("probe slot lock")
            .take()
            .expect("occupied probe slot");
        assert!(!child_is_live_current(&current, pid));
        // Dead occupant still in the slot (reaper has not run yet): the
        // installer must remove the shield it just installed.
        taken.child.kill().expect("kill probe child");
        let _ = taken.child.wait();
        *current.lock().expect("probe slot lock") = Some(taken);
        assert!(!child_is_live_current(&current, pid));
    }
}
