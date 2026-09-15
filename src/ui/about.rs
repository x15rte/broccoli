//! About screen: versions, upstream links, and the
//! bundled-component license notices.

use egui::{RichText, Ui};

use super::UiCtx;
use crate::i18n::{Key, t, t_fmt};
use crate::sys;

#[derive(Default)]
pub struct AboutScreen {}

impl AboutScreen {
    pub fn show(&mut self, ui: &mut Ui, ctx: &mut UiCtx) {
        let lang = ctx.settings.language;
        // The shell already wraps this screen in a vertical ScrollArea.
        ui.add_space(8.0);
        ui.heading(t_fmt(
            lang,
            Key::AboutBroccoliVersion,
            &[&env!("CARGO_PKG_VERSION")],
        ));
        ui.label(RichText::new(t(lang, Key::AboutTagline)).weak());
        ui.add_space(4.0);
        match &ctx.core_version {
            Some(v) => ui.label(t_fmt(lang, Key::AboutCoreVersion, &[&v])),
            None => ui.label(RichText::new(t(lang, Key::AboutCoreNotInstalled)).weak()),
        };
        ui.add_space(12.0);

        ui.hyperlink_to(
            t(lang, Key::AboutUpstreamLink),
            "https://github.com/XTLS/Xray-core",
        );
        if let Some(url) = sys::selfupd::repository_url() {
            ui.hyperlink_to(t(lang, Key::AboutRepoLink), url);
        }
        ui.add_space(12.0);
        ui.separator();

        ui.label(RichText::new(t(lang, Key::AboutLicenses)).strong());
        ui.label(t(lang, Key::AboutLicenseXray));
        ui.label(t(lang, Key::AboutLicenseWintun));
        ui.label(
            RichText::new(t_fmt(
                lang,
                Key::AboutLicenseTexts,
                &[&sys::paths::core_dir().display()],
            ))
            .weak()
            .small(),
        );
        ui.add_space(12.0);

        ui.label(RichText::new(t(lang, Key::AboutBuiltWith)).weak().small());
    }
}
