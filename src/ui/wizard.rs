//! First-run wizard: download or import Broccoli's compiled-in pinned official
//! Xray core.

use crate::i18n::{Key, t, t_fmt};
use crate::sys;
use egui::RichText;

use crate::ui::{CoreSetupMount, UiCtx, show_core_setup};

#[derive(Default)]
pub struct WizardScreen {
    /// User chose "set up later" — the app keeps showing a banner instead.
    pub dismissed: bool,
    /// Core obtained through the pinned official release flow this session.
    pub done: bool,
}

impl WizardScreen {
    pub fn show(&mut self, ctx: &egui::Context, uictx: &mut UiCtx) {
        if self.done {
            return;
        }
        // Default modal frame (the app's native window look) over a dimmed
        // backdrop; blocks the rest of the app until the core is installed
        // or setup is deferred.
        egui::Modal::new(egui::Id::new("broccoli-first-run")).show(ctx, |ui| {
            let lang = uictx.settings.language;
            ui.set_max_width(560.0);
            ui.heading(t(lang, Key::WizardWelcome));
            ui.add_space(4.0);
            // The dialog names the state it is asking about: a first install
            // when no tree exists, an update with both versions when the
            // installed core does not match this build's pins.
            let intro = match uictx.core_setup.installed_version.as_deref() {
                Some(installed) if uictx.core_version.is_none() => t_fmt(
                    lang,
                    Key::WizardCoreUpdateRequired,
                    &[&installed, &sys::core_dl::pinned_core_version()],
                ),
                _ => t(lang, Key::WizardCoreMissing).to_owned(),
            };
            ui.add(egui::Label::new(RichText::new(intro).weak()).wrap());
            ui.add_space(10.0);

            let outcome = show_core_setup(ui, uictx, CoreSetupMount::Dialog);
            if outcome.continue_clicked {
                self.done = true;
            }
            if outcome.later_clicked {
                self.dismissed = true;
            }
        });
    }
}
