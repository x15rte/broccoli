// Windows system integration.
#[doc(hidden)]
pub mod appdata;
pub mod cleanup;
pub mod core_dl;
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

/// `std::process::Command` preconfigured with CREATE_NO_WINDOW so helper
/// processes (xray, schtasks) never pop a console window.
pub(crate) fn hidden_command(program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new(program);
    cmd.creation_flags(windows::Win32::System::Threading::CREATE_NO_WINDOW.0);
    cmd
}
