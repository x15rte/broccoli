//! Opening the Servers screen's editor window from the full-app harnesses.
//!
//! Opt-in beside `common` (and only compiled by the binaries that declare it),
//! for the same reason as `screen` and `nav`: a binary that boots the app
//! without touching the editor must not carry the helper as dead code.

use broccoli::app::BroccoliApp;
use broccoli::i18n::{Key, t};
use broccoli::model::settings::Language;
use egui_kittest::{Harness, kittest::Queryable as _};

/// Open the Servers screen's editor window on one row through the row's Edit
/// command. A backend with no viewports folds the pop-up into the main window,
/// so the same body renders inside the harness. (The double click that opens
/// the same window is covered by the servers screen's own tests: kittest
/// advances one frame per pointer event, which puts the two presses outside
/// egui's double-click delay at this harness's frame step.)
pub fn open_server_editor(h: &mut Harness<'static, BroccoliApp>, name: &str) {
    h.get_by_label(name).click_secondary();
    h.run();
    h.get_all_by_label(t(Language::En, Key::SrvEdit))
        .last()
        .expect("the row menu offers Edit")
        .click();
    h.run();
    assert!(
        h.query_by_label(t(Language::En, Key::SrvValidateAndSave))
            .is_some(),
        "opening {name:?} must render the editor window"
    );
}
