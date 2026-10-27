// Windows system integration.
pub(crate) mod aligned;
#[doc(hidden)]
pub mod appdata;
pub mod cleanup;
pub mod core_dl;
pub mod dns_takeover;
pub mod durable;
pub mod elevation;
pub mod exit_bound;
pub mod geodata;
pub mod net_table;
pub mod netif;
pub mod paths;
pub mod security;
pub mod selfupd;
pub mod single_instance;
pub mod wintun;

use std::path::{Path, PathBuf};

use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};
use windows::core::BOOL;

/// `std::process::Command` preconfigured with CREATE_NO_WINDOW so helper
/// processes never pop a console window.
///
/// `program` must be an absolute path. Windows searches the application
/// directory before every other location for a bare name, so inside the
/// elevated helper a same-named file dropped beside the portable
/// `broccoli.exe` would run with the helper's administrator token. The
/// assertion keeps that search order out of every call; resolve a system tool
/// through [`system32_exe`] or [`windows_exe`] first.
pub(crate) fn hidden_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    use std::os::windows::process::CommandExt;
    let program = program.as_ref();
    assert!(
        Path::new(program).is_absolute(),
        "hidden_command requires an absolute program path"
    );
    let mut cmd = std::process::Command::new(program);
    cmd.creation_flags(windows::Win32::System::Threading::CREATE_NO_WINDOW.0);
    cmd
}

/// Absolute path of `name` inside the Windows system directory
/// (`GetSystemDirectoryW`, normally `C:\Windows\System32`), when that file
/// exists.
///
/// The elevated helper must never spawn a system tool by bare name: Windows
/// resolves a bare executable name against the application directory before
/// the system directories, and the helper is the same portable `broccoli.exe`
/// the user runs. A medium-integrity process that writes `ipconfig.exe` beside
/// that binary would otherwise have it run with the helper's administrator
/// token. `None` means the file is absent (or the directory cannot be read);
/// it never degrades to the bare name.
pub(crate) fn system32_exe(name: &str) -> Option<PathBuf> {
    existing_file(&os_directory(GetSystemDirectoryW)?, name)
}

/// Absolute path of `name` inside the Windows directory
/// (`GetWindowsDirectoryW`, normally `C:\Windows`), when that file exists.
/// Same contract as [`system32_exe`]; used for tools that live beside
/// `System32` rather than in it.
pub(crate) fn windows_exe(name: &str) -> Option<PathBuf> {
    existing_file(&os_directory(GetWindowsDirectoryW)?, name)
}

/// Open `path` in File Explorer.
///
/// Explorer lives in the Windows directory and is spawned by its absolute
/// path: Windows searches the application directory before the system
/// directories, so a bare `explorer` could run a planted program beside a
/// portable install. A missing `explorer.exe` or a failed spawn comes back as
/// a message for the caller's log line; there is no bare-name fallback.
pub(crate) fn open_in_explorer(path: &Path) -> Result<(), String> {
    let explorer = windows_exe("explorer.exe")
        .ok_or_else(|| String::from("explorer.exe is not available in the Windows directory"))?;
    hidden_command(explorer)
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Read one OS-owned directory (`GetSystemDirectoryW`, `GetWindowsDirectoryW`)
/// as an absolute path. Both report the required length including the
/// terminator when the buffer is too small, so the buffer grows until the
/// path fits; a zero length means the query failed.
fn os_directory(read: unsafe fn(Option<&mut [u16]>) -> u32) -> Option<PathBuf> {
    let mut capacity = 260usize;
    loop {
        let mut buffer = vec![0u16; capacity];
        // SAFETY: `buffer` is a live, writable slice of exactly `capacity`
        // UTF-16 units, and the only functions handed here are the two
        // directory getters, which write at most that many units (terminator
        // included) and return the length they used or need; the returned
        // value is checked before the buffer is read.
        let written = unsafe { read(Some(&mut buffer)) } as usize;
        if written == 0 {
            return None;
        }
        if written >= capacity {
            capacity = written + 1;
            continue;
        }
        buffer.truncate(written);
        let path = PathBuf::from(String::from_utf16(&buffer).ok()?);
        return path.is_absolute().then_some(path);
    }
}

/// `directory\name` when that is an existing file, and never anything else:
/// the result is absolute because the directory is, and only a plain file
/// name is accepted so no caller can be redirected out of the directory.
fn existing_file(directory: &Path, name: &str) -> Option<PathBuf> {
    let name = Path::new(name);
    if name.file_name() != Some(name.as_os_str()) {
        return None;
    }
    let path = directory.join(name);
    path.is_file().then_some(path)
}

/// Flush the DNS client resolver cache (`DnsFlushResolverCache`). The
/// helper runs this after it engages or restores the captured DNS servers,
/// so answers the resolver cached through the tunnel do not outlive the
/// session.
///
/// The windows crate's metadata does not carry this `dnsapi.dll` export, so
/// the import is declared here with the same `raw-dylib` linkage its
/// generated bindings use. A `false` result is the API's failure report; the
/// thread's last error is the reason.
pub(crate) fn flush_dns_cache() -> windows::core::Result<()> {
    // SAFETY: `DnsFlushResolverCache` takes no arguments and only touches the
    // local DNS client's cache; the declared signature (no arguments, a
    // `BOOL` result) is the export's documented one, and the import is
    // resolved against `dnsapi.dll` through the same raw-dylib mechanism the
    // rest of the `windows` crate uses.
    if unsafe { DnsFlushResolverCache() }.as_bool() {
        Ok(())
    } else {
        Err(windows::core::Error::from_thread())
    }
}

// SAFETY: `DnsFlushResolverCache` is the documented `dnsapi.dll` export with
// no arguments and a `BOOL` result; this declaration matches that ABI and is
// called only through [`flush_dns_cache`], which checks the result.
#[link(name = "dnsapi.dll", kind = "raw-dylib", modifiers = "+verbatim")]
unsafe extern "system" {
    fn DnsFlushResolverCache() -> BOOL;
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::{flush_dns_cache, system32_exe, windows_exe};

    #[test]
    fn system_tools_resolve_to_absolute_existing_files() {
        let iphlpapi = system32_exe("iphlpapi.dll").expect("iphlpapi.dll is a system32 file");
        assert!(iphlpapi.is_absolute(), "{iphlpapi:?} must be absolute");
        assert_eq!(iphlpapi.file_name(), Some(OsStr::new("iphlpapi.dll")));
        assert!(iphlpapi.is_file());

        let explorer =
            windows_exe("explorer.exe").expect("explorer.exe is a Windows directory file");
        assert!(explorer.is_absolute(), "{explorer:?} must be absolute");
        assert_eq!(explorer.file_name(), Some(OsStr::new("explorer.exe")));
        assert!(explorer.is_file());

        // A missing file and a name that would escape the directory both
        // answer `None`; neither ever degrades to a bare name.
        assert_eq!(system32_exe("broccoli-no-such-tool.exe"), None);
        assert_eq!(system32_exe("../ipconfig.exe"), None);
        assert_eq!(windows_exe("System32\\ipconfig.exe"), None);
    }

    #[test]
    fn the_resolver_cache_flush_reports_success() {
        // Flushing the local resolver cache needs no elevation, and the
        // export exists on every supported Windows build; an error here would
        // make the helper's post-restore flush silently never work.
        flush_dns_cache().expect("the resolver cache flush must succeed");
    }
}
