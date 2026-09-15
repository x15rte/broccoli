//! Windows security primitives: token-handle guards, owned SIDs, and the
//! absolute security-descriptor/DACL builders behind every protected object
//! this process creates.
//!
//! # Single implementation for four callers
//!
//! The DACL/descriptor machinery here was historically copy-pasted across
//! four modules — the state/config-dir protection in `model`, the
//! elevated helper's pipe and secure-stage protection in `rt::helper`, the
//! elevation token file in `sys::elevation`, and the single-instance mutex in
//! `sys::single_instance`. Each copy was a near-twin of the others with
//! small, load-bearing differences:
//!
//! * the single-instance mutex wants a user-only DACL whose single ACE has no
//!   inheritance flags and whose DACL is not protected;
//! * the state/config dirs want a user-only DACL whose ACE carries
//!   container+object inheritance and whose DACL *is* protected from the
//!   parent's inheritable ACEs;
//! * the helper pipe, the helper's secure-stage directory, and the elevation
//!   token file want a protected DACL naming SYSTEM + Administrators (full
//!   control) plus zero or more extra principals;
//! * objects owned by a principal that a medium-integrity process may not
//!   outrank prefer the Administrators group as owner/group, falling back to
//!   the creator's own user SID when the calling token cannot assign
//!   Administrators (`ERROR_INVALID_OWNER`, 1307).
//!
//! This module is the single implementation of those shapes. The four
//! legacy copies were migrated here (model state/config
//! dirs, rt::helper pipe + secure stage, elevation token file,
//! single-instance mutex); no caller-local DACL construction remains except
//! `rt::helper`'s documented test-only deviation writer. Any future change
//! to a shape must land here first, never in a caller.
//!
//! # Lifetime model
//!
//! The builders construct *absolute* descriptors: the Set* calls record
//! pointers into the caller-owned SID storage and this module's own ACL
//! buffer instead of copying. `operation` therefore runs — and every kernel
//! call that consumes the descriptor (`CreateMutexW`, `CreateNamedPipeW`,
//! `CreateDirectoryW`, `CreateFileW`, `SetFileSecurityW`) must complete —
//! while those buffers are still alive, i.e. inside the builder call. The
//! kernel copies the security information out of them before returning, so a
//! descriptor never outlives its buffers.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    ACE_FLAGS, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE, CreateWellKnownSid,
    GetLengthSid, GetTokenInformation, InitializeAcl, InitializeSecurityDescriptor,
    OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
    SetSecurityDescriptorGroup, SetSecurityDescriptorOwner, TOKEN_ACCESS_MASK, TOKEN_QUERY,
    TOKEN_USER, TokenUser, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{BOOL, Result};

/// `ERROR_INVALID_OWNER` (1307): the process's token cannot be assigned as —
/// or cannot assign — the requested owner SID. Raised by the object manager
/// when a create names an owner that the creating token has no
/// `SeRestorePrivilege` / `SE_GROUP_OWNER` right to set; the trigger for the
/// owner fallback (prefer Administrators, retry with the caller's own user
/// SID, which any token may always assign).
pub const ERROR_INVALID_OWNER: u32 = 1307;

/// `ERROR_INVALID_PARAMETER` (87): used when a token-information query
/// returns data that violates the documented `TOKEN_USER` layout.
const ERROR_INVALID_PARAMETER: u32 = 87;

/// A `windows::core::Error` carrying `ERROR_INVALID_PARAMETER`.
fn invalid_parameter_error() -> windows::core::Error {
    windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(ERROR_INVALID_PARAMETER))
}

/// Zeroed 512-byte ACL buffer, aligned to 8 for the `ACL` header. 512 bytes
/// fits the ACL header plus up to six full-size ACEs (76 bytes each with a
/// 68-byte `SECURITY_MAX_SID_SIZE` SID); the builders append at most four
/// ACEs (SYSTEM + Administrators + two extra principals), and an append
/// beyond capacity fails the Win32 call with `ERROR_ALLOTTED_SPACE_EXCEEDED`
/// rather than overflowing the buffer.
#[repr(align(8))]
struct AclBuffer([u8; 512]);

/// Guard for an open token handle from `OpenProcessToken`, closed exactly
/// once on drop. `HANDLE` itself has no ownership semantics, so a raw token
/// handle must never outlive this guard — the handle is only valid while a
/// `TokenHandle` that owns it is alive.
pub struct TokenHandle {
    handle: HANDLE,
    /// Test seam: when `Some`, `Drop` also bumps the counter so tests can
    /// observe the exactly-once close deterministically. Always `None` in
    /// production paths; never present in non-test builds.
    #[cfg(test)]
    close_seen: Option<&'static std::sync::atomic::AtomicUsize>,
}

impl TokenHandle {
    /// Open the current process's token with `desired_access`.
    pub fn open_current_process(desired_access: TOKEN_ACCESS_MASK) -> Result<Self> {
        // SAFETY: `GetCurrentProcess` returns the pseudo-handle of the
        // calling process, always valid and never closed by the caller.
        let process = unsafe { GetCurrentProcess() };
        Self::open_process_token(process, desired_access)
    }

    /// Open `process`'s token with `desired_access`. The caller must hold a
    /// valid open handle to `process` that grants at least
    /// `PROCESS_QUERY_LIMITED_INFORMATION` (the access `OpenProcessToken`
    /// requires); `GetCurrentProcess()`'s pseudo-handle is always valid.
    pub fn open_process_token(process: HANDLE, desired_access: TOKEN_ACCESS_MASK) -> Result<Self> {
        let mut raw = HANDLE::default();
        // SAFETY: `process` is a valid open handle to the process whose token
        // is wanted (the caller's contract above); `&mut raw` is a valid
        // out-parameter. On failure nothing is written; on success the token
        // handle is owned by the guard created immediately below.
        unsafe { OpenProcessToken(process, desired_access, &mut raw) }?;
        Ok(Self::new(raw))
    }

    /// The wrapped handle. Valid only while this guard is alive.
    pub fn handle(&self) -> HANDLE {
        self.handle
    }

    #[cfg(not(test))]
    fn new(handle: HANDLE) -> Self {
        Self { handle }
    }

    #[cfg(test)]
    fn new(handle: HANDLE) -> Self {
        Self {
            handle,
            close_seen: None,
        }
    }
}

impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is the token handle returned by
        // `OpenProcessToken`, owned exclusively by this guard and never
        // closed elsewhere; `Drop` runs exactly once, so the handle is closed
        // exactly once.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
        #[cfg(test)]
        if let Some(counter) = self.close_seen {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// An owned SID: either a well-known SID (`Sid::well_known`) or the user SID
/// of a token (`Sid::token_user`). The storage lives inside the value, so a
/// `PSID` obtained from [`Sid::psid`] stays valid (and points at the same
/// SID) as long as the `Sid` is alive — including after any move, because
/// the storage is heap-allocated.
pub struct Sid {
    storage: Vec<u8>,
}

impl Sid {
    /// Create the well-known SID of `kind` (SYSTEM, Administrators, …).
    /// `CreateWellKnownSid` fails for kinds that require a domain SID, which
    /// the alias kinds used in this crate never do.
    pub fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Result<Self> {
        // SECURITY_MAX_SID_SIZE (68) is the documented capacity for any
        // well-known SID.
        let mut storage = vec![0u8; 68];
        let mut length = storage.len() as u32;
        let sid = PSID(storage.as_mut_ptr().cast());
        // SAFETY: `storage` is 68 bytes (`SECURITY_MAX_SID_SIZE`), the
        // documented capacity for any well-known SID, so the cast pointer is
        // writable for `length` bytes and stays alive for the call; `None`
        // domain SID is valid for the alias kinds used here. On success the
        // buffer holds a valid SID at offset 0 and `length` reports its
        // exact size.
        unsafe { CreateWellKnownSid(kind, None, Some(sid), &mut length) }?;
        storage.truncate(length as usize);
        Ok(Self { storage })
    }

    /// The user SID of the token guarded by `handle` (the current process's
    /// token, or another process's token when `handle` came from
    /// [`TokenHandle::open_process_token`]). The SID is copied out of the
    /// `TOKEN_USER` buffer, so the result stays valid after `handle` drops.
    pub fn token_user(handle: &TokenHandle) -> Result<Self> {
        let token = handle.handle();
        let mut required = 0u32;
        // SAFETY: `token` is the valid open token handle kept alive by the
        // `TokenHandle` guard. A null buffer with length 0 is the documented
        // sizing query: the API writes the required byte count into
        // `required` and fails with ERROR_INSUFFICIENT_BUFFER, which is
        // deliberately ignored here — no buffer is read or written.
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut required) };
        if required < std::mem::size_of::<TOKEN_USER>() as u32 {
            return Err(invalid_parameter_error());
        }
        // `TOKEN_USER` carries a pointer field, so it must be read from an
        // 8-byte-aligned address. `Vec<u8>` is only 1-byte aligned by
        // contract — the system allocator's over-alignment is not a language
        // guarantee — so the buffer is word storage covering the same byte
        // span, the same rule `sys::netif::AdapterBuffer` applies to its
        // `GetAdaptersAddresses` buffer.
        let buffer_bytes = required as usize;
        let mut buffer = vec![0u64; buffer_bytes.div_ceil(std::mem::size_of::<u64>())];
        // SAFETY: `token` is the valid open token handle. `buffer` covers at
        // least the `required` bytes the sizing query reported, is 8-byte
        // aligned (`Vec<u64>` storage), and stays alive for the call. On
        // success the API has fully initialized the structure at the buffer
        // base and `required` holds the final size.
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                required,
                &mut required,
            )
        }?;

        // The SID lives inside `buffer` right after the fixed `TOKEN_USER`
        // prefix, and `TOKEN_USER.User.Sid` points at it. Read the pointer,
        // validate that it really lies inside the buffer, then copy the SID
        // bytes out so this `Sid` owns them.
        // SAFETY: `buffer` covers at least `size_of::<TOKEN_USER>()` bytes
        // (the guard above) and is 8-byte aligned (`Vec<u64>` storage), so
        // casting its base to `TOKEN_USER` and reading the fully initialized
        // structure is valid. The structure was written by the successful
        // `GetTokenInformation` call above.
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let sid = user.User.Sid;
        if sid.is_invalid() {
            return Err(invalid_parameter_error());
        }
        let base = buffer.as_ptr() as usize;
        let allocated = buffer.len() * std::mem::size_of::<u64>();
        let sid_offset = sid.0 as usize;
        // SAFETY: `sid` is the non-null SID pointer the API reported; the
        // pointer arithmetic below only compares addresses (no dereference).
        if sid_offset < base || sid_offset >= base + allocated {
            return Err(invalid_parameter_error());
        }
        // SAFETY: `sid` points inside the live, initialized `buffer` (bounds
        // checked above) at a valid SID written by the kernel; `GetLengthSid`
        // reads only the SID's own header, which the API initialized.
        let sid_length = unsafe { GetLengthSid(sid) } as usize;
        if sid_length == 0 || sid_offset + sid_length > base + allocated {
            return Err(invalid_parameter_error());
        }
        let mut storage = vec![0u8; sid_length];
        // SAFETY: the bounds checks above guarantee `sid` points at
        // `sid_length` initialized bytes inside the live `buffer`, and
        // `storage` is an exactly-sized, alive destination; both ranges are
        // disjoint (heap allocations).
        unsafe {
            std::ptr::copy_nonoverlapping(sid.0.cast::<u8>(), storage.as_mut_ptr(), sid_length);
        }
        Ok(Self { storage })
    }

    /// A raw pointer to the SID bytes, which start at offset 0 of the owned
    /// storage (both constructors lay the SID out first). Valid as long as
    /// `self` is alive and never mutated; kernel APIs only read SIDs.
    pub fn psid(&self) -> PSID {
        PSID(self.storage.as_ptr().cast::<core::ffi::c_void>().cast_mut())
    }
}

/// One extra allow-ACE for a protected descriptor: `sid` is granted `access`.
/// See [`with_protected_descriptor`] for ordering and flags.
type ExtraGrant<'a> = (&'a Sid, u32);

/// Build an absolute, initialized `SECURITY_DESCRIPTOR` over an ACL of
/// allow-ACEs and hand its pointer to `operation`, which runs (and must
/// consume the descriptor) while the descriptor and its buffers are alive.
///
/// * `owner` — when `Some`, the SID becomes both owner and group; when
///   `None` both stay unset and the kernel assigns the creator.
/// * `ace_flags` — ACE inheritance flags for every appended ACE (0 for
///   kernel objects like mutexes, pipes, and files; container+object
///   inheritance for directories).
/// * `protected` — when true, `SE_DACL_PROTECTED` is set so the parent's
///   inheritable ACEs never leak into the protected object.
/// * `grants` — allow-ACEs appended in order, each granting `access` to one
///   SID.
///
/// The caller must ensure every `Sid` in `grants`/`owner` outlives
/// `operation`.
fn build_descriptor<'a, T>(
    owner: Option<&'a Sid>,
    ace_flags: ACE_FLAGS,
    protected: bool,
    grants: impl IntoIterator<Item = ExtraGrant<'a>>,
    operation: impl FnOnce(PSECURITY_DESCRIPTOR) -> T,
) -> Result<T> {
    let mut acl_storage = AclBuffer([0; 512]);
    let acl = acl_storage.0.as_mut_ptr().cast::<ACL>();
    // SAFETY: `acl` points at `acl_storage.0`, a 512-byte zero-initialized
    // buffer (aligned to 8 via `#[repr(align(8))]`) that stays alive through
    // the calls and is large enough for the ACL header plus up to four ACEs
    // with the largest supported SIDs. `InitializeAcl` initializes it, then
    // each `AddAccessAllowedAceEx` appends one ACE referencing a SID from a
    // live `Sid` owned by the caller (valid and alive through the call; an
    // append beyond capacity fails with ERROR_ALLOTTED_SPACE_EXCEEDED and
    // propagates, never overflowing the buffer). Every call's return is
    // checked.
    unsafe {
        InitializeAcl(acl, acl_storage.0.len() as u32, ACL_REVISION)?;
        for (sid, access) in grants {
            AddAccessAllowedAceEx(acl, ACL_REVISION, ace_flags, access, sid.psid())?;
        }
    }

    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let descriptor_pointer =
        PSECURITY_DESCRIPTOR((&mut descriptor as *mut SECURITY_DESCRIPTOR).cast());
    // SAFETY: `descriptor` is a stack `SECURITY_DESCRIPTOR::default()` (zeroed
    // by the crate's Default), correctly aligned and alive for the calls;
    // `InitializeSecurityDescriptor` puts it in absolute format, so the Set*
    // calls record a pointer to the caller's owner SID (or none, in which
    // case the kernel assigns the creator as owner/group) and to `acl`
    // (`acl_storage`) rather than copying. Those buffers stay alive until
    // `operation(descriptor_pointer)` returns, by which point the kernel has
    // copied the security information into the created object. Every call's
    // return is checked.
    unsafe {
        InitializeSecurityDescriptor(descriptor_pointer, 1)?;
        if let Some(owner) = owner {
            let owner_sid = owner.psid();
            SetSecurityDescriptorOwner(descriptor_pointer, Some(owner_sid), false)?;
            SetSecurityDescriptorGroup(descriptor_pointer, Some(owner_sid), false)?;
        }
        SetSecurityDescriptorDacl(descriptor_pointer, true, Some(acl), false)?;
        if protected {
            SetSecurityDescriptorControl(descriptor_pointer, SE_DACL_PROTECTED, SE_DACL_PROTECTED)?;
        }
    }
    Ok(operation(descriptor_pointer))
}

/// Wrap `descriptor` in a `SECURITY_ATTRIBUTES` and hand it to `operation` —
/// the shape kernel create calls (`CreateMutexW`, `CreateNamedPipeW`,
/// `CreateDirectoryW`, `CreateFileW`) consume.
fn wrap_attributes<T>(
    descriptor: PSECURITY_DESCRIPTOR,
    operation: impl FnOnce(*const SECURITY_ATTRIBUTES) -> T,
) -> T {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: BOOL(0),
    };
    operation(&attributes)
}

/// The current process's user SID — the principal behind every
/// user-restricted DACL.
fn current_process_user_sid() -> Result<Sid> {
    let token = TokenHandle::open_current_process(TOKEN_QUERY)?;
    Sid::token_user(&token)
}

/// Build an absolute descriptor whose DACL grants `access` only to the
/// current user's SID, with object/container inheritance so files and
/// subdirectories created inside the protected directory carry the same
/// restriction, and with the DACL protected (`SE_DACL_PROTECTED`) so the
/// parent's inheritable ACEs never leak in. Owner/group stay unset: the
/// kernel assigns the creator. Hand the descriptor to `operation` (alive for
/// the call). Fails (and never runs `operation`) when the user SID or the
/// descriptor cannot be built; callers fail closed rather than fall back to
/// a default DACL.
pub fn with_user_restricted_security_descriptor<T>(
    access: u32,
    operation: impl FnOnce(PSECURITY_DESCRIPTOR) -> T,
) -> Result<T> {
    let user = current_process_user_sid()?;
    build_descriptor(
        None,
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
        true,
        [(&user, access)],
        operation,
    )
}

/// Build a `SECURITY_ATTRIBUTES` whose DACL grants `access` only to the
/// current user's SID and hand it to `operation` (alive for the call). The
/// single ACE carries no inheritance flags and the DACL is not protected:
/// the shape of the named single-instance mutex. Fails (and never runs
/// `operation`) when the user SID or the descriptor cannot be built; callers
/// fail closed rather than create the object with a weaker default DACL.
pub fn with_user_restricted_attributes<T>(
    access: u32,
    operation: impl FnOnce(*const SECURITY_ATTRIBUTES) -> T,
) -> Result<T> {
    let user = current_process_user_sid()?;
    build_descriptor(None, ACE_FLAGS(0), false, [(&user, access)], |descriptor| {
        wrap_attributes(descriptor, operation)
    })
}

/// Build an absolute protected descriptor — SYSTEM and Administrators get
/// `FILE_ALL_ACCESS`, then each `(sid, access)` entry in `extras` is appended
/// as a further allow-ACE, in order; `SE_DACL_PROTECTED` is always set and
/// no ACE carries inheritance flags (kernel objects: pipes, files, and
/// directories whose children need no further access). `owner`, when `Some`,
/// becomes both owner and group: callers pass the Administrators SID (not
/// the creator's user SID), so a medium-integrity process cannot reclaim
/// WRITE_DAC through owner rights — or the creator's own user SID when the
/// calling token lacks the privilege to assign Administrators as owner (see
/// [`is_invalid_owner_error`]); when `None`, the kernel assigns the creator.
/// Hand the descriptor to `operation` (alive for the call).
pub fn with_protected_descriptor<T>(
    owner: Option<&Sid>,
    extras: &[ExtraGrant<'_>],
    operation: impl FnOnce(PSECURITY_DESCRIPTOR) -> T,
) -> Result<T> {
    let system = Sid::well_known(WinLocalSystemSid)?;
    let administrators = Sid::well_known(WinBuiltinAdministratorsSid)?;
    let base = [
        (&system, FILE_ALL_ACCESS.0),
        (&administrators, FILE_ALL_ACCESS.0),
    ];
    build_descriptor(
        owner,
        ACE_FLAGS(0),
        true,
        base.into_iter().chain(extras.iter().copied()),
        operation,
    )
}

/// Wrap [`with_protected_descriptor`] in a `SECURITY_ATTRIBUTES` for one
/// synchronous kernel create.
pub fn with_protected_attributes<T>(
    owner: Option<&Sid>,
    extras: &[ExtraGrant<'_>],
    operation: impl FnOnce(*const SECURITY_ATTRIBUTES) -> T,
) -> Result<T> {
    with_protected_descriptor(owner, extras, |descriptor| {
        wrap_attributes(descriptor, operation)
    })
}

/// Pure decision for the owner-fallback flow: does `error` mean the calling
/// token cannot assign the requested owner SID (`ERROR_INVALID_OWNER`,
/// 1307)? When a create that names Administrators as owner fails with this
/// code, retry with the caller's own user SID, which any token may assign —
/// access control is unchanged because the protected DACL still names the
/// same principals.
pub fn is_invalid_owner_error(error: &windows::core::Error) -> bool {
    error.code() == windows::core::HRESULT::from_win32(ERROR_INVALID_OWNER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, GetHandleInformation};
    use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, EqualSid, GetAce, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner,
        IsValidSecurityDescriptor, IsValidSid, SE_DACL_PRESENT, SECURITY_DESCRIPTOR_CONTROL,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, MUTEX_ALL_ACCESS};

    /// Handles wrapped with `close_seen: Some(&CLOSE_COUNT)` bump this
    /// counter on drop; only the drop test below wraps handles this way, so
    /// the count is deterministic.
    static CLOSE_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    fn current_user_sid() -> Sid {
        let token = TokenHandle::open_current_process(TOKEN_QUERY)
            .expect("open current process token for test");
        Sid::token_user(&token).expect("read current user SID for test")
    }

    /// Shape read back from a built descriptor: control bits, owner/group
    /// SIDs, and the ordered allow-ACE list (type, flags, access mask, SID).
    type Readback = (
        SECURITY_DESCRIPTOR_CONTROL,
        Option<PSID>,
        Option<PSID>,
        Vec<(u8, u8, u32, PSID)>,
    );

    /// Read a descriptor built in memory back through the Win32 accessors:
    /// control bits, owner/group SIDs, and the ordered allow-ACE list
    /// (type, flags, access mask, SID). All returned pointers are valid only
    /// while the descriptor is alive.
    fn readback(descriptor: PSECURITY_DESCRIPTOR) -> Readback {
        // SAFETY: `descriptor` is the initialized, alive absolute security
        // descriptor built by the helpers; the Win32 accessors read it
        // without modifying it, and every out-parameter below is valid.
        unsafe {
            assert!(
                IsValidSecurityDescriptor(descriptor).as_bool(),
                "built descriptor must validate"
            );
            let mut control = SECURITY_DESCRIPTOR_CONTROL(0);
            let mut revision = 0u32;
            GetSecurityDescriptorControl(descriptor, &mut control.0, &mut revision)
                .expect("read descriptor control");

            // A descriptor without an owner/group makes these accessors
            // report absence either as success with a null SID or as an
            // error, depending on the Windows version; both map to `None`.
            let owner = {
                let mut owner = PSID(std::ptr::null_mut());
                let mut owner_defaulted = BOOL(0);
                match GetSecurityDescriptorOwner(descriptor, &mut owner, &mut owner_defaulted) {
                    Ok(()) => (!owner.is_invalid()).then_some(owner),
                    Err(_) => None,
                }
            };
            let group = {
                let mut group = PSID(std::ptr::null_mut());
                let mut group_defaulted = BOOL(0);
                match GetSecurityDescriptorGroup(descriptor, &mut group, &mut group_defaulted) {
                    Ok(()) => (!group.is_invalid()).then_some(group),
                    Err(_) => None,
                }
            };

            let mut dacl_present = BOOL(0);
            let mut dacl = std::ptr::null_mut::<ACL>();
            let mut dacl_defaulted = BOOL(0);
            GetSecurityDescriptorDacl(
                descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
            .expect("read descriptor DACL");
            assert!(
                dacl_present.as_bool() && !dacl.is_null(),
                "built DACL must be present and non-null"
            );

            let ace_count = u32::from((*dacl).AceCount);
            let mut aces = Vec::with_capacity(ace_count as usize);
            for index in 0..ace_count {
                let mut raw_ace = std::ptr::null_mut();
                GetAce(dacl, index, &mut raw_ace).expect("read ACE");
                // SAFETY: `GetAce` succeeded, so `raw_ace` points at a valid
                // ACE inside the live DACL buffer; its declared `AceSize`
                // covers the fixed prefix read here (header at 0, `Mask` at
                // 4, `SidStart` at 8 — shared by all SID-carrying ACE
                // types). The buffer stays alive for the test.
                let ace = &*raw_ace.cast::<ACCESS_ALLOWED_ACE>();
                let sid =
                    PSID(std::ptr::addr_of!(ace.SidStart).cast::<core::ffi::c_void>() as *mut _);
                aces.push((ace.Header.AceType, ace.Header.AceFlags, ace.Mask, sid));
            }
            (control, owner, group, aces)
        }
    }

    fn same_sid(a: PSID, b: PSID) -> bool {
        // SAFETY: both SIDs are valid and alive for the call: `a` from the
        // live descriptor/DACL buffer, `b` from the live `Sid` storage.
        // `EqualSid` only reads them.
        unsafe { EqualSid(a, b) }.is_ok()
    }

    #[test]
    fn open_current_process_token_is_a_valid_token_handle() {
        let token =
            TokenHandle::open_current_process(TOKEN_QUERY).expect("open current process token");
        let mut flags = 0u32;
        // SAFETY: `token.handle()` is the valid open token handle owned by
        // the guard, alive for the call; `&mut flags` is a valid
        // out-parameter. A closed or bogus handle would fail the call.
        unsafe { GetHandleInformation(token.handle(), &mut flags) }
            .expect("token handle must be a live kernel handle");
        drop(token);
    }

    #[test]
    fn open_process_token_path_opens_the_current_process_token() {
        // SAFETY: `GetCurrentProcess` returns the always-valid
        // pseudo-handle of the calling process.
        let token = TokenHandle::open_process_token(unsafe { GetCurrentProcess() }, TOKEN_QUERY)
            .expect("open current process token via process handle");
        let user = Sid::token_user(&token).expect("read user SID");
        assert!(
            !user.psid().is_invalid(),
            "token user SID must be a non-null SID"
        );
        // SAFETY: `user.psid()` is a valid, alive SID (constructed above);
        // IsValidSid only reads it.
        assert!(unsafe { IsValidSid(user.psid()) }.as_bool());
    }

    #[test]
    fn token_handle_drop_closes_the_handle_exactly_once() {
        let mut raw = HANDLE::default();
        // SAFETY: `GetCurrentProcess()` returns the always-valid process
        // pseudo-handle; `&mut raw` is a valid out-parameter. On success the
        // token handle is owned exclusively by the tracked guard below.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) }
            .expect("open current process token for drop test");
        {
            let _guard = TokenHandle {
                handle: raw,
                close_seen: Some(&CLOSE_COUNT),
            };
        }
        assert_eq!(
            CLOSE_COUNT.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "Drop must close the token handle exactly once"
        );
    }

    #[test]
    fn well_known_sids_are_valid_and_distinct() {
        let system = Sid::well_known(WinLocalSystemSid).expect("build SYSTEM SID");
        let system_again = Sid::well_known(WinLocalSystemSid).expect("rebuild SYSTEM SID");
        let administrators =
            Sid::well_known(WinBuiltinAdministratorsSid).expect("build Administrators SID");
        // SAFETY: both `psid()` results point at valid, alive SID storage.
        assert!(unsafe { IsValidSid(system.psid()) }.as_bool());
        assert!(unsafe { IsValidSid(administrators.psid()) }.as_bool());
        assert!(same_sid(system.psid(), system_again.psid()));
        assert!(!same_sid(system.psid(), administrators.psid()));
    }

    #[test]
    fn token_user_sid_storage_outlives_the_token_handle() {
        let token =
            TokenHandle::open_current_process(TOKEN_QUERY).expect("open current process token");
        let user = Sid::token_user(&token).expect("read current user SID");
        let user_again = Sid::token_user(&token).expect("re-read current user SID");
        drop(token);
        // The SID was copied out of the token-information buffer: it must
        // stay valid and equal after the token handle itself is gone.
        assert!(same_sid(user.psid(), user_again.psid()));
        // SAFETY: `user.psid()` is valid, alive storage (see above).
        assert!(unsafe { IsValidSid(user.psid()) }.as_bool());
        // The token user is a domain SID, never one of the well-known
        // aliases the protected builders grant.
        let administrators =
            Sid::well_known(WinBuiltinAdministratorsSid).expect("build Administrators SID");
        assert!(!same_sid(user.psid(), administrators.psid()));
    }

    #[test]
    fn is_invalid_owner_error_detects_the_1307_fallback_trigger() {
        let invalid_owner =
            windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(1307));
        let denied = windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(5));
        let already_exists =
            windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(183));
        let no_error = windows::core::Error::from_hresult(windows::core::HRESULT(0));
        assert!(is_invalid_owner_error(&invalid_owner));
        assert!(!is_invalid_owner_error(&denied));
        assert!(!is_invalid_owner_error(&already_exists));
        assert!(!is_invalid_owner_error(&no_error));
    }

    /// The single-instance mutex shape: user-only DACL, one plain ACE with
    /// no inheritance flags, DACL present but not protected, owner unset.
    #[test]
    fn user_restricted_attributes_carry_the_mutex_dacl_shape() {
        let user = current_user_sid();
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
            let (control, owner, group, aces) =
                readback(PSECURITY_DESCRIPTOR(security.lpSecurityDescriptor));
            assert!(
                control.contains(SE_DACL_PRESENT) && !control.contains(SE_DACL_PROTECTED),
                "mutex DACL must be present but not protected"
            );
            assert!(owner.is_none(), "mutex owner must be left to the kernel");
            assert!(group.is_none(), "mutex group must be left to the kernel");
            assert_eq!(aces.len(), 1, "mutex DACL must grant one principal");
            let (ace_type, flags, mask, sid) = aces[0];
            assert_eq!(ace_type, 0, "ACE must be access-allowed");
            assert_eq!(flags, 0, "mutex ACE must not be inheritable");
            assert_eq!(mask, MUTEX_ALL_ACCESS.0);
            assert!(
                same_sid(sid, user.psid()),
                "mutex DACL must grant only the current user"
            );
        });
        built.expect("user-restricted attributes must build");
    }

    /// The state/config-dir shape: user-only DACL whose ACE inherits to
    /// files and subdirectories, protected from the parent's ACEs, owner
    /// unset.
    #[test]
    fn user_restricted_security_descriptor_carries_the_directory_dacl_shape() {
        let user = current_user_sid();
        let built = with_user_restricted_security_descriptor(FILE_ALL_ACCESS.0, |descriptor| {
            let (control, owner, group, aces) = readback(descriptor);
            assert!(
                control.contains(SE_DACL_PRESENT) && control.contains(SE_DACL_PROTECTED),
                "directory DACL must be present and protected from inheritance"
            );
            assert!(
                owner.is_none(),
                "directory owner must be left to the kernel"
            );
            assert!(
                group.is_none(),
                "directory group must be left to the kernel"
            );
            assert_eq!(aces.len(), 1, "directory DACL must grant one principal");
            let (ace_type, flags, mask, sid) = aces[0];
            assert_eq!(ace_type, 0, "ACE must be access-allowed");
            assert_eq!(
                flags,
                (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE).0 as u8,
                "directory ACE must inherit to files and subdirectories"
            );
            assert_eq!(mask, FILE_ALL_ACCESS.0);
            assert!(
                same_sid(sid, user.psid()),
                "directory DACL must grant only the current user"
            );
        });
        built.expect("user-restricted descriptor must build");
    }

    /// The helper-pipe shape: SYSTEM + Administrators full control, then the
    /// launching user with generic read/write, protected DACL, and
    /// Administrators as owner and group.
    #[test]
    fn protected_descriptor_carries_system_admin_and_client_aces_with_owner() {
        let administrators =
            Sid::well_known(WinBuiltinAdministratorsSid).expect("build Administrators SID");
        let system = Sid::well_known(WinLocalSystemSid).expect("build SYSTEM SID");
        let user = current_user_sid();
        let client_access = GENERIC_READ.0 | GENERIC_WRITE.0;
        let built = with_protected_descriptor(
            Some(&administrators),
            &[(&user, client_access)],
            |descriptor| {
                let (control, owner, group, aces) = readback(descriptor);
                assert!(
                    control.contains(SE_DACL_PRESENT) && control.contains(SE_DACL_PROTECTED),
                    "protected DACL must be present and protected"
                );
                let owner = owner.expect("owner must be set");
                let group = group.expect("group must be set");
                assert!(
                    same_sid(owner, administrators.psid()),
                    "owner must be Administrators"
                );
                assert!(
                    same_sid(group, administrators.psid()),
                    "group must match the owner"
                );
                assert_eq!(
                    aces.len(),
                    3,
                    "protected DACL must grant SYSTEM, Administrators, and the client"
                );
                assert!(aces.iter().all(|ace| ace.0 == 0 && ace.1 == 0));
                assert_eq!(aces[0].2, FILE_ALL_ACCESS.0);
                assert!(same_sid(aces[0].3, system.psid()));
                assert_eq!(aces[1].2, FILE_ALL_ACCESS.0);
                assert!(same_sid(aces[1].3, administrators.psid()));
                assert_eq!(aces[2].2, client_access);
                assert!(
                    same_sid(aces[2].3, user.psid()),
                    "client ACE must name the launching user"
                );
            },
        );
        built.expect("protected descriptor must build");
    }

    /// The secure-stage/repair shape: protected DACL naming exactly SYSTEM
    /// and Administrators, no owner (kernel assigns the creator).
    #[test]
    fn protected_attributes_without_owner_or_extras_name_only_system_and_administrators() {
        let administrators =
            Sid::well_known(WinBuiltinAdministratorsSid).expect("build Administrators SID");
        let system = Sid::well_known(WinLocalSystemSid).expect("build SYSTEM SID");
        let built = with_protected_attributes(None, &[], |attributes| {
            assert!(!attributes.is_null());
            // SAFETY: `attributes` is the valid, alive pointer built by
            // `with_protected_attributes` for the duration of this closure;
            // the descriptor it references is initialized.
            let security = unsafe { &*attributes };
            assert_eq!(
                security.nLength,
                std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32
            );
            assert_eq!(security.bInheritHandle, BOOL(0));
            let (control, owner, group, aces) =
                readback(PSECURITY_DESCRIPTOR(security.lpSecurityDescriptor));
            assert!(
                control.contains(SE_DACL_PRESENT) && control.contains(SE_DACL_PROTECTED),
                "protected DACL must be present and protected"
            );
            assert!(owner.is_none(), "owner must be left to the kernel");
            assert!(group.is_none(), "group must be left to the kernel");
            assert_eq!(
                aces.len(),
                2,
                "protected DACL must grant exactly SYSTEM and Administrators"
            );
            assert_eq!(aces[0].1, 0);
            assert_eq!(aces[0].2, FILE_ALL_ACCESS.0);
            assert!(same_sid(aces[0].3, system.psid()));
            assert_eq!(aces[1].2, FILE_ALL_ACCESS.0);
            assert!(same_sid(aces[1].3, administrators.psid()));
        });
        built.expect("protected attributes must build");
    }

    /// The elevation-token-file shape: SYSTEM + Administrators + the current
    /// user, each with full control — a full-access extra principal.
    #[test]
    fn protected_descriptor_extra_principal_can_carry_full_access() {
        let administrators =
            Sid::well_known(WinBuiltinAdministratorsSid).expect("build Administrators SID");
        let system = Sid::well_known(WinLocalSystemSid).expect("build SYSTEM SID");
        let user = current_user_sid();
        let built = with_protected_descriptor(None, &[(&user, FILE_ALL_ACCESS.0)], |descriptor| {
            let (control, owner, _group, aces) = readback(descriptor);
            assert!(control.contains(SE_DACL_PROTECTED));
            assert!(owner.is_none());
            assert_eq!(aces.len(), 3);
            assert!(same_sid(aces[0].3, system.psid()));
            assert!(same_sid(aces[1].3, administrators.psid()));
            assert_eq!(aces[2].2, FILE_ALL_ACCESS.0);
            assert!(
                same_sid(aces[2].3, user.psid()),
                "token file must grant the current user full control"
            );
        });
        built.expect("protected descriptor must build");
    }
}
