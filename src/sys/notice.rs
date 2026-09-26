//! Native dialog for a state the app cannot draw.
//!
//! Once the graphics device is gone the app has no renderer left, and the one
//! message it must still deliver is why the window vanished and what to do
//! about it. `MessageBoxW` needs no GPU and no window of ours: the box is
//! raised on a thread of its own, so waiting for the user's answer never
//! blocks the frame loop that keeps the tray and the core alive.

use windows::Win32::UI::WindowsAndMessaging::{
    MB_ICONERROR, MB_OK, MB_SETFOREGROUND, MB_TOPMOST, MessageBoxW,
};
use windows::core::PCWSTR;

/// Raise a topmost error box with `title` and `body`, on a thread of its own.
///
/// Returns as soon as the thread that raises the box is spawned; a thread that
/// cannot be spawned is logged, because a notice the user never sees must at
/// least leave a record.
pub(crate) fn show(title: String, body: String) {
    let spawned = std::thread::Builder::new()
        .name("notice".to_string())
        .spawn(move || {
            let body = wide(&body);
            let title = wide(&title);
            // SAFETY: both pointers come from live `Vec<u16>`s that outlive the
            // call and are NUL-terminated as the API requires. `None` gives the
            // box no owner window — the app's own window is hidden in this
            // state — and the call returns only after the user answers it.
            unsafe {
                MessageBoxW(
                    None,
                    PCWSTR(body.as_ptr()),
                    PCWSTR(title.as_ptr()),
                    MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST,
                );
            }
        });
    if let Err(error) = spawned {
        tracing::warn!("device-lost notice could not be shown: {error}");
    }
}

/// NUL-terminated UTF-16 for the Win32 wide-string APIs.
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
