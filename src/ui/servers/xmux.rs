//! The XMUX editor shared by the transports that carry an `xmux` block.
//!
//! The connection limit is either `maxConcurrency` or `maxConnections`,
//! never both; the rest are H2/H3 knobs. The control owns the enable switch,
//! so a caller passes the transport's optional field and gets back whether
//! the model changed. Nothing here names a transport.

use crate::i18n::{Key, t};
use crate::model::settings::Language;
use crate::model::{Int32Range, XmuxConfig};
use crate::ui::status::status_colors_of;
use crate::ui::widgets;

/// Renders the `xmux` section over the caller's optional block and reports
/// whether any control wrote it.
pub(super) fn xmux_section(
    ui: &mut egui::Ui,
    lang: Language,
    xmux: &mut Option<XmuxConfig>,
) -> bool {
    let mut changed = false;
    widgets::section(ui, t(lang, Key::SrvXmux), |ui| {
        let mut has = xmux.is_some();
        if ui.checkbox(&mut has, t(lang, Key::SrvEnableXmux)).changed() {
            *xmux = if has {
                Some(XmuxConfig::default())
            } else {
                None
            };
            changed = true;
        }
        if let Some(x) = xmux.as_mut() {
            let original_choice = match (x.max_concurrency.is_some(), x.max_connections.is_some()) {
                (false, false) => 0,
                (true, false) => 1,
                (false, true) => 2,
                (true, true) => 3,
            };
            let mut choice = original_choice;
            let mut choice_changed = false;
            ui.horizontal(|ui| {
                ui.label(t(lang, Key::SrvConnectionLimit));
                choice_changed |= ui
                    .radio_value(&mut choice, 0, t(lang, Key::SrvCoreDefaults))
                    .changed();
                choice_changed |= ui
                    .radio_value(&mut choice, 1, t(lang, Key::SrvMaxConcurrency))
                    .changed();
                choice_changed |= ui
                    .radio_value(&mut choice, 2, t(lang, Key::SrvMaxConnections))
                    .changed();
            });
            if choice_changed {
                match choice {
                    0 => {
                        x.max_concurrency = None;
                        x.max_connections = None;
                    }
                    1 => {
                        x.max_connections = None;
                        x.max_concurrency
                            .get_or_insert_with(|| Int32Range::single(1));
                    }
                    2 => {
                        x.max_concurrency = None;
                        x.max_connections
                            .get_or_insert_with(|| Int32Range::single(1));
                    }
                    _ => unreachable!(),
                }
                changed = true;
            } else if original_choice == 3 {
                ui.colored_label(status_colors_of(ui).err, t(lang, Key::SrvMutuallyExclusive));
            }
            match choice {
                1 => {
                    changed |=
                        widgets::opt_range(ui, "maxConcurrency", &mut x.max_concurrency, 1..=1024);
                }
                2 => {
                    changed |=
                        widgets::opt_range(ui, "maxConnections", &mut x.max_connections, 1..=1024);
                }
                _ => {}
            }
            changed |=
                widgets::opt_range(ui, "cMaxReuseTimes", &mut x.c_max_reuse_times, 1..=10_000);
            changed |= widgets::opt_range(
                ui,
                "hMaxRequestTimes",
                &mut x.h_max_request_times,
                1..=10_000,
            );
            changed |= widgets::opt_range(
                ui,
                "hMaxReusableSecs",
                &mut x.h_max_reusable_secs,
                1..=86_400,
            );
            changed |= widgets::opt_num(
                ui,
                t(lang, Key::SrvHKeepAlivePeriodS),
                &mut x.h_keep_alive_period,
                0..=3600,
            );
        }
    });
    changed
}
