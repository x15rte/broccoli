//! Debug-only fault injection for the render-loss recovery path.
//!
//! The module exists only in a debug build (`sys::mod` gates it), so a release
//! build carries no way to order a fault. A graphics device dies when the
//! driver decides it does — a rare event that no user action reproduces — so
//! the state the app recovers into cannot be reached on demand through the UI.
//! Two environment variables order the two legs instead:
//!
//! - `BROCCOLI_INJECT_DEVICE_LOSS=<frame>` destroys the wgpu device on that
//!   frame of the app's `logic` passes, which is the invalid-device state a
//!   driver loss leaves behind (`wgpu-core` marks a device invalid for a
//!   driver loss and for an explicit destroy alike, and every later staging
//!   write then fails).
//! - `BROCCOLI_INJECT_RESTART=<frame>` runs the tray restart on that frame,
//!   exercising the hand-off in `main` without a tray click.
//!
//! A replacement process must not inherit either hook, or an injected restart
//! would loop; [`super::restart::spawn_replacement`] removes both.

/// Environment variable naming the frame at which the wgpu device is destroyed.
pub(crate) const DEVICE_LOSS: &str = "BROCCOLI_INJECT_DEVICE_LOSS";

/// Environment variable naming the frame at which the restart hand-off runs.
pub(crate) const RESTART: &str = "BROCCOLI_INJECT_RESTART";

/// The frame number `var` orders an injection at, or `None` when the variable
/// is unset, empty, or not a whole number.
pub(crate) fn frame_at(var: &str) -> Option<u32> {
    parse_frame(std::env::var(var).ok().as_deref())
}

/// The whole number `value` names, or `None` for an absent or malformed value.
fn parse_frame(value: Option<&str>) -> Option<u32> {
    value?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::parse_frame;

    #[test]
    fn only_whole_numbers_name_a_frame() {
        assert_eq!(parse_frame(Some("30")), Some(30));
        assert_eq!(parse_frame(Some(" 7 ")), Some(7));
        assert_eq!(parse_frame(Some("0")), Some(0));
        for rejected in [None, Some(""), Some("   "), Some("three"), Some("3.5")] {
            assert_eq!(parse_frame(rejected), None, "accepted {rejected:?}");
        }
    }
}
