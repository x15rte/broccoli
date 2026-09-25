//! The navigation half of the screen-test fixture: boot a [`BootState`], size
//! the window, dismiss the first-run wizard and land on the screen under test.
//!
//! Opt-in beside `screen` (and only compiled by the binaries that declare it),
//! for the same reason: a binary that seeds state without navigating must not
//! carry the navigation as dead code.
//!
//! ```text
//! #[path = "common/screen.rs"]
//! mod screen;
//! #[path = "common/nav.rs"]
//! mod nav;
//! ```

use broccoli::app::BroccoliApp;
use broccoli::model::settings::Language;
use broccoli::ui::Screen;
use egui::accesskit::Role;
use egui_kittest::{Harness, kittest::Queryable as _};
use parking_lot::MutexGuard;

use crate::common::{TempEnvironment, dismiss_wizard};
use crate::screen::{BootState, boot_state};

/// Boot with a [`BootState`], size the window, dismiss the first-run wizard and
/// navigate to `screen` — the four steps every screen test opens with.
///
/// The window is sized before the first frame so the whole screen is laid out
/// (a taller window keeps sections below the fold in the AccessKit tree).
pub fn boot_screen(
    state: BootState,
    screen: Screen,
    size: egui::Vec2,
) -> (
    MutexGuard<'static, ()>,
    TempEnvironment,
    Harness<'static, BroccoliApp>,
) {
    let (lock, tmp, mut h) = boot_state(state, None);
    h.set_size(size);
    h.run();
    dismiss_wizard(&mut h);
    nav(&mut h, screen);
    (lock, tmp, h)
}

/// Navigate the booted app to `screen` through the sidebar.
///
/// The sidebar's labels collide with controls the dashboard renders (its mode
/// selector carries "TUN" with the same role), so the path stages through a
/// screen whose label is unique — one workaround, in one place, instead of one
/// per test file. The label is the shell's own (`Screen::label`), so a renamed
/// screen cannot leave a test clicking a label nothing renders.
pub fn nav(h: &mut Harness<'static, BroccoliApp>, screen: Screen) {
    if screen != Screen::Dns {
        h.get_by_role_and_label(Role::Button, Screen::Dns.label(Language::En))
            .click();
        h.run();
    }
    h.get_by_role_and_label(Role::Button, screen.label(Language::En))
        .click();
    h.run();
}
