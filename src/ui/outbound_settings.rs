//! The Servers screen's Settings side: the latency-test settings and the
//! global subscription settings.
//!
//! One self-contained component with its own drafts and reveal state, so the
//! Settings screen no longer owns these controls and the Servers screen mounts
//! the same surface beside the servers they affect. The component edits through
//! the shared dirty hook, so the existing save/apply pipeline stays the only
//! writer — it never needs `SettingsCtx`.

use egui::{RichText, Ui};

use super::FrameHooks;
use super::widgets;
use crate::i18n::{Key, t};
use crate::model::Settings;
use crate::model::settings::{Language, ProbePath, RefreshPath};
use crate::sys::outbound_path::{effective_probe_path, effective_refresh_path};

/// The shared latency-test and subscription settings surface.
///
/// Mounted by the Servers screen's Settings side. A later wave adds the
/// `Table | Settings` switch; this type is the whole Settings side's content.
#[derive(Default)]
pub struct OutboundSettingsSection {
    /// Edit drafts for the optional SOCKS5 credentials. The model stores
    /// `Option<String>`, so a blank draft is the absent value; the drafts are
    /// seeded once and only a real edit commits them.
    socks5_username_buf: widgets::Draft,
    socks5_password_buf: widgets::Draft,
    /// Transient reveal state of the SOCKS5 password. Leaving and returning to
    /// the screen masks it again.
    revealed_password: bool,
}

impl OutboundSettingsSection {
    /// Render the latency-test section (probe URL, outbound path) and the
    /// subscription section (global User-Agent, outbound path, global SOCKS5
    /// fields). Every edit marks the settings dirty through `hooks`, so the
    /// shell's existing save/apply pipeline persists it.
    pub fn show(
        &mut self,
        ui: &mut Ui,
        settings: &mut Settings,
        hooks: &mut FrameHooks<'_>,
        tun_active: bool,
    ) {
        let lang = settings.language;
        let tun_on = tun_active;

        widgets::section(ui, t(lang, Key::SettingsLatencyTest), |ui| {
            if widgets::noted(ui, t(lang, Key::SettingsLatencyTestNote), |ui| {
                widgets::text_field(
                    ui,
                    t(lang, Key::ProbeUrl),
                    &mut settings.probe_url,
                    "https://www.google.com/generate_204",
                )
            }) {
                hooks.mark_dirty();
            }
            self.latency_path_control(ui, &mut *settings, tun_on, &mut *hooks);
        });

        widgets::section(ui, t(lang, Key::SettingsSubscriptions), |ui| {
            if widgets::text_field(
                ui,
                t(lang, Key::SettingsSubscriptionUserAgent),
                &mut settings.subscription_user_agent,
                "broccoli/0.0.0",
            ) {
                hooks.mark_dirty();
            }
            ui.label(RichText::new(t(lang, Key::SettingsSubscriptionUserAgentHint)).weak());
            self.subscription_path_control(ui, &mut *settings, tun_on, &mut *hooks);
            self.socks5_fields(ui, &mut *settings, &mut *hooks);
        });
    }

    /// The latency test's outbound path: Bind NIC and Native only. The latency
    /// probe never dials through SOCKS5.
    ///
    /// The control shows the effective path, so a stored Bind NIC preference
    /// reads as Native while TUN mode is off. Bind NIC is then disabled, and
    /// only an actual click writes: the stored preference stays until the user
    /// picks Native, which replaces it.
    fn latency_path_control(
        &mut self,
        ui: &mut Ui,
        settings: &mut Settings,
        tun_on: bool,
        hooks: &mut FrameHooks<'_>,
    ) {
        let lang = settings.language;
        let stored = settings.latency_test_path;
        let effective = effective_probe_path(stored, tun_on);
        let disabled = (!tun_on).then_some(Key::SettingsPathBindNicDisabledHint);
        let options = [
            (ProbePath::BindNic, Key::SettingsPathBindNic, disabled),
            (ProbePath::Native, Key::SettingsPathNative, None),
        ];
        if let Some(path) = path_control(ui, lang, effective, &options)
            && path != stored
        {
            settings.latency_test_path = path;
            hooks.mark_dirty();
        }
        ui.label(
            RichText::new(probe_path_note(lang, effective, stored))
                .small()
                .weak(),
        );
    }

    /// The subscription refresh's outbound path: Bind NIC, Native, and SOCKS5.
    /// The TUN-off rule matches the latency control: Native is shown, Bind NIC
    /// is disabled, and the stored preference is kept until the user replaces
    /// it.
    fn subscription_path_control(
        &mut self,
        ui: &mut Ui,
        settings: &mut Settings,
        tun_on: bool,
        hooks: &mut FrameHooks<'_>,
    ) {
        let lang = settings.language;
        let stored = settings.subscription_path;
        let effective = effective_refresh_path(stored, tun_on);
        let disabled = (!tun_on).then_some(Key::SettingsPathBindNicDisabledHint);
        let options = [
            (RefreshPath::BindNic, Key::SettingsPathBindNic, disabled),
            (RefreshPath::Native, Key::SettingsPathNative, None),
            (RefreshPath::Socks5, Key::SettingsPathSocks5, None),
        ];
        if let Some(path) = path_control(ui, lang, effective, &options)
            && path != stored
        {
            settings.subscription_path = path;
            hooks.mark_dirty();
        }
        ui.label(
            RichText::new(refresh_path_note(lang, effective, stored))
                .small()
                .weak(),
        );
    }

    /// The global SOCKS5 carrier the refresh's SOCKS5 path dials through.
    /// Address and port are required while the path is SOCKS5; the credentials
    /// are optional and travel together. The password is a secret field and
    /// only renders editable while revealed.
    fn socks5_fields(&mut self, ui: &mut Ui, settings: &mut Settings, hooks: &mut FrameHooks<'_>) {
        let lang = settings.language;
        let username = self.socks5_username_buf.begin(|| {
            settings
                .subscription_socks5
                .username
                .clone()
                .unwrap_or_default()
        });
        let password = self.socks5_password_buf.begin(|| {
            settings
                .subscription_socks5
                .password
                .clone()
                .unwrap_or_default()
        });
        if socks5_editor(
            ui,
            lang,
            &mut settings.subscription_socks5.host,
            &mut settings.subscription_socks5.port,
            username,
            password,
            &mut self.revealed_password,
        ) {
            settings.subscription_socks5.username = optional_field(username);
            settings.subscription_socks5.password = optional_field(password);
            hooks.mark_dirty();
        }
    }
}

/// The password field's own reveal control. The shared reveal toggle carries
/// the Servers credential note, which also names server information, so this
/// section states exactly what it reveals.
fn password_reveal(ui: &mut Ui, lang: Language, revealed: &mut bool) {
    let label = if *revealed {
        Key::SettingsSocks5HidePassword
    } else {
        Key::SettingsSocks5RevealPassword
    };
    if ui.button(t(lang, label)).clicked() {
        *revealed = !*revealed;
    }
}

/// One segment of an outbound-path control. A disabled segment stays visible
/// and keeps its selected state painted; the persistent note below the control
/// says why it cannot be picked, so the disabled state never relies on colour.
pub(crate) fn path_segment(
    ui: &mut Ui,
    selected: bool,
    enabled: bool,
    label: &str,
    disabled_hint: Option<&str>,
) -> bool {
    let response = ui
        .add_enabled_ui(enabled, |ui| ui.selectable_label(selected, label))
        .inner;
    match disabled_hint {
        Some(hint) => response.on_disabled_hover_text(hint),
        None => response,
    }
    .clicked()
}

/// One outbound-path control over either path vocabulary. The label and the
/// options are the only per-vocabulary input; the selected state, the TUN-off
/// disabled segment, and the pick result stay one implementation.
pub(crate) fn path_control<T: Copy + PartialEq>(
    ui: &mut Ui,
    lang: Language,
    effective: T,
    options: &[(T, Key, Option<Key>)],
) -> Option<T> {
    let mut picked = None;
    ui.horizontal(|ui| {
        ui.label(t(lang, Key::SettingsOutboundPath));
        for &(path, label, disabled) in options {
            let enabled = disabled.is_none();
            let disabled_hint = disabled.map(|key| t(lang, key));
            if path_segment(
                ui,
                effective == path,
                enabled,
                t(lang, label),
                disabled_hint,
            ) {
                picked = Some(path);
            }
        }
    });
    picked
}

/// The shared SOCKS5 editor for the global subscription settings and the
/// per-subscription dialog. The caller supplies its own field buffers and
/// reveal state; the labels, masking, and note live here once.
pub(crate) fn socks5_editor(
    ui: &mut Ui,
    lang: Language,
    host: &mut String,
    port: &mut u16,
    username: &mut String,
    password: &mut String,
    revealed: &mut bool,
) -> bool {
    let mut changed = widgets::text_field(ui, t(lang, Key::SettingsSocks5Host), host, "127.0.0.1");
    changed |= widgets::port_field(ui, t(lang, Key::SettingsSocks5Port), port);
    changed |= widgets::text_field(
        ui,
        t(lang, Key::SettingsSocks5Username),
        username,
        "proxy user",
    );
    changed |= widgets::masked_text_field(
        ui,
        t(lang, Key::SettingsSocks5Password),
        password,
        "proxy password",
        !*revealed,
    );
    password_reveal(ui, lang, revealed);
    ui.label(
        RichText::new(t(lang, Key::SettingsSocks5Note))
            .small()
            .weak(),
    );
    changed
}

/// The persistent note for the effective probe path. A stored Bind NIC
/// preference that the TUN-off rule hides reads as Native and says so.
fn probe_path_note(lang: Language, effective: ProbePath, stored: ProbePath) -> &'static str {
    match effective {
        ProbePath::BindNic => t(lang, Key::SettingsPathNoteBindNic),
        ProbePath::Native if stored == ProbePath::BindNic => {
            t(lang, Key::SettingsPathNoteBindNicTunOff)
        }
        ProbePath::Native => t(lang, Key::SettingsPathNoteNative),
    }
}

/// The persistent note for the effective refresh path.
pub(crate) fn refresh_path_note(
    lang: Language,
    effective: RefreshPath,
    stored: RefreshPath,
) -> &'static str {
    match effective {
        RefreshPath::BindNic => t(lang, Key::SettingsPathNoteBindNic),
        RefreshPath::Socks5 => t(lang, Key::SettingsSubscriptionPathNoteSocks5),
        RefreshPath::Native if stored == RefreshPath::BindNic => {
            t(lang, Key::SettingsPathNoteBindNicTunOff)
        }
        RefreshPath::Native => t(lang, Key::SettingsPathNoteNative),
    }
}

/// The optional-field value a draft holds: a blank draft is absent, anything
/// else is stored verbatim (a password may contain spaces).
fn optional_field(text: &str) -> Option<String> {
    (!text.trim().is_empty()).then(|| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::OutboundSettingsSection;
    use crate::i18n::{Key, t};
    use crate::model::Mode;
    use crate::model::settings::{Language, ProbePath, RefreshPath};
    use crate::ui::test_rig::{UiTestRig, harness_builder};
    use egui_kittest::Harness;
    use egui_kittest::kittest::{NodeT as _, Queryable as _};

    /// Render the component inside the shared rig's Settings slice. The
    /// component needs only the settings tree and the dirty hook, exactly as
    /// the Servers screen will mount it.
    fn harness(
        rig: UiTestRig,
        section: OutboundSettingsSection,
    ) -> Harness<'static, (OutboundSettingsSection, UiTestRig)> {
        harness_builder().build_ui_state(
            |ui, state: &mut (OutboundSettingsSection, UiTestRig)| {
                let mut uictx = state.1.ctx();
                let mut ctx = uictx.settings();
                let tun_active = ctx.settings.mode == Mode::Tun;
                state
                    .0
                    .show(ui, &mut *ctx.settings, &mut ctx.hooks, tun_active);
            },
            (section, rig),
        )
    }

    /// The first segment carrying `label`. Both settings sections render path
    /// segments, so a plain `get_by` would find two and panic.
    fn first_segment<'a>(
        harness: &'a Harness<'static, (OutboundSettingsSection, UiTestRig)>,
        label: &'static str,
    ) -> egui_kittest::Node<'a> {
        harness
            .get_all_by_role_and_label(egui::accesskit::Role::Button, label)
            .next()
            .expect("a path segment with this label")
    }

    /// The last segment carrying `label`: the subscription section renders
    /// after the latency section.
    fn last_segment<'a>(
        harness: &'a Harness<'static, (OutboundSettingsSection, UiTestRig)>,
        label: &'static str,
    ) -> egui_kittest::Node<'a> {
        harness
            .get_all_by_role_and_label(egui::accesskit::Role::Button, label)
            .last()
            .expect("a path segment with this label")
    }

    #[test]
    fn latency_section_binds_the_probe_url_and_marks_dirty() {
        let mut harness = harness(UiTestRig::default(), OutboundSettingsSection::default());
        harness.run();

        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsLatencyTest))
                .is_some(),
            "the latency test section must render"
        );
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("probe URL field")
            .click();
        harness.run();
        harness
            .get_all_by_role(egui::accesskit::Role::TextInput)
            .next()
            .expect("probe URL field keeps focus")
            .type_text("https://example.com/generate_204");
        harness.run_steps(4);

        assert_eq!(
            harness.state().1.settings.probe_url,
            "https://example.com/generate_204",
            "the typed URL lands in the settings tree"
        );
        assert!(
            harness.state().1.requests.dirty,
            "probe URL edits must mark the settings dirty"
        );
    }

    #[test]
    fn subscription_user_agent_binds_and_marks_dirty() {
        let mut harness = harness(UiTestRig::default(), OutboundSettingsSection::default());
        harness.run();

        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsSubscriptions))
                .is_some(),
            "the subscription section must render"
        );
        // The User-Agent field is labelled by its own text; replace the
        // shipped value so the assertion does not depend on the caret.
        let agent_label = t(Language::En, Key::SettingsSubscriptionUserAgent);
        harness
            .get_by_role_and_label(egui::accesskit::Role::TextInput, agent_label)
            .focus();
        harness.run();
        harness.key_press_modifiers(egui::Modifiers::COMMAND, egui::Key::A);
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::TextInput, agent_label)
            .type_text("feed-reader/1");
        harness.run_steps(4);

        assert_eq!(
            harness.state().1.settings.subscription_user_agent,
            "feed-reader/1"
        );
        assert!(harness.state().1.requests.dirty);
    }

    #[test]
    fn latency_path_shows_native_with_bind_nic_disabled_while_tun_is_off() {
        let mut rig = UiTestRig::default();
        rig.settings.mode = Mode::Off;
        rig.settings.latency_test_path = ProbePath::BindNic;
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        let bind_nic = t(Language::En, Key::SettingsPathBindNic);
        let native = t(Language::En, Key::SettingsPathNative);
        assert!(
            first_segment(&harness, bind_nic)
                .accesskit_node()
                .is_disabled(),
            "Bind NIC cannot bind while TUN mode is off"
        );
        assert!(
            !first_segment(&harness, native)
                .accesskit_node()
                .is_disabled(),
            "Native stays available"
        );
        assert!(
            harness
                .query_all_by_label(t(Language::En, Key::SettingsPathNoteBindNicTunOff))
                .next()
                .is_some(),
            "the note must explain the stored preference and the effective path"
        );
        // Clicking the disabled Bind NIC segment changes nothing.
        first_segment(&harness, bind_nic).click();
        harness.run();
        assert_eq!(
            harness.state().1.settings.latency_test_path,
            ProbePath::BindNic,
            "the stored preference must survive a TUN-off frame"
        );
        assert!(
            !harness.state().1.requests.dirty,
            "no preference may be written without a click"
        );

        // Selecting Native explicitly replaces the stored preference.
        first_segment(&harness, native).click();
        harness.run();
        assert_eq!(
            harness.state().1.settings.latency_test_path,
            ProbePath::Native
        );
        assert!(
            harness.state().1.requests.dirty,
            "the explicit Native choice is a settings edit"
        );
    }

    #[test]
    fn latency_path_enables_bind_nic_while_tun_is_on_and_writes_it() {
        let mut rig = UiTestRig::default();
        rig.settings.mode = Mode::Tun;
        rig.settings.latency_test_path = ProbePath::Native;
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        let bind_nic = t(Language::En, Key::SettingsPathBindNic);
        assert!(
            !first_segment(&harness, bind_nic)
                .accesskit_node()
                .is_disabled(),
            "Bind NIC is selectable while TUN mode is on"
        );
        first_segment(&harness, bind_nic).click();
        harness.run();
        assert_eq!(
            harness.state().1.settings.latency_test_path,
            ProbePath::BindNic
        );
        assert!(
            harness
                .query_all_by_label(t(Language::En, Key::SettingsPathNoteBindNic))
                .next()
                .is_some(),
            "the selected Bind NIC mode carries its own persistent note"
        );
    }

    #[test]
    fn latency_path_offers_no_socks5_segment() {
        let mut harness = harness(UiTestRig::default(), OutboundSettingsSection::default());
        harness.run();
        // The subscription section owns the only SOCKS5 segment; the latency
        // section must not render a second one.
        let socks5 = t(Language::En, Key::SettingsPathSocks5);
        assert_eq!(
            harness
                .get_all_by_role_and_label(egui::accesskit::Role::Button, socks5)
                .count(),
            1,
            "the latency path must offer Bind NIC and Native only"
        );
    }

    #[test]
    fn subscription_path_offers_three_segments_and_writes_socks5() {
        let mut rig = UiTestRig::default();
        rig.settings.mode = Mode::Off;
        rig.settings.subscription_path = RefreshPath::BindNic;
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        let socks5 = t(Language::En, Key::SettingsPathSocks5);
        assert!(
            !first_segment(&harness, socks5)
                .accesskit_node()
                .is_disabled(),
            "SOCKS5 does not need TUN mode"
        );
        last_segment(&harness, socks5).click();
        harness.run();
        assert_eq!(
            harness.state().1.settings.subscription_path,
            RefreshPath::Socks5
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsSubscriptionPathNoteSocks5))
                .is_some(),
            "the SOCKS5 mode carries its own persistent note"
        );
        assert!(harness.state().1.requests.dirty);
    }

    #[test]
    fn subscription_bind_nic_is_disabled_while_tun_is_off() {
        let mut rig = UiTestRig::default();
        rig.settings.mode = Mode::Off;
        rig.settings.subscription_path = RefreshPath::BindNic;
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        // Both sections render a Bind NIC segment; every one of them is
        // disabled while TUN mode is off.
        for node in harness.get_all_by_role_and_label(
            egui::accesskit::Role::Button,
            t(Language::En, Key::SettingsPathBindNic),
        ) {
            assert!(
                node.accesskit_node().is_disabled(),
                "Bind NIC cannot bind while TUN mode is off"
            );
        }
        assert_eq!(
            harness.state().1.settings.subscription_path,
            RefreshPath::BindNic,
            "the stored preference must survive a TUN-off frame"
        );
    }

    #[test]
    fn socks5_fields_commit_address_and_optional_credentials() {
        let mut rig = UiTestRig::default();
        rig.settings.subscription_path = RefreshPath::Socks5;
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        let host_label = t(Language::En, Key::SettingsSocks5Host);
        let port_label = t(Language::En, Key::SettingsSocks5Port);
        assert!(
            harness.query_by_label(port_label).is_some(),
            "the SOCKS5 port control must render"
        );
        harness
            .get_by_role_and_label(egui::accesskit::Role::TextInput, host_label)
            .click();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::TextInput, host_label)
            .type_text("proxy.example");
        harness.run_steps(4);
        assert_eq!(
            harness.state().1.settings.subscription_socks5.host,
            "proxy.example"
        );

        let user_label = t(Language::En, Key::SettingsSocks5Username);
        harness
            .get_by_role_and_label(egui::accesskit::Role::TextInput, user_label)
            .click();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::TextInput, user_label)
            .type_text("alice");
        harness.run_steps(4);
        assert_eq!(
            harness
                .state()
                .1
                .settings
                .subscription_socks5
                .username
                .as_deref(),
            Some("alice")
        );
        assert!(
            harness.state().1.requests.dirty,
            "SOCKS5 field edits mark the settings dirty"
        );
    }

    #[test]
    fn socks5_password_is_masked_until_revealed() {
        let mut rig = UiTestRig::default();
        rig.settings.subscription_socks5.password = Some("hunter2".into());
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        // The masked password renders no text input holding its value and no
        // label exposes it.
        assert!(
            !harness
                .get_all_by_role(egui::accesskit::Role::TextInput)
                .any(|node| node.value().as_deref() == Some("hunter2")),
            "the password must stay out of reach while masked"
        );
        assert!(
            harness
                .get_all_by_role(egui::accesskit::Role::Label)
                .all(|node| node.value().as_deref() != Some("hunter2")),
            "no label may expose the masked password"
        );

        harness
            .get_by_role_and_label(
                egui::accesskit::Role::Button,
                t(Language::En, Key::SettingsSocks5RevealPassword),
            )
            .click();
        harness.run();
        assert!(
            harness
                .get_all_by_role(egui::accesskit::Role::TextInput)
                .any(|node| node.value().as_deref() == Some("hunter2")),
            "revealing shows the stored password in its editable field"
        );
    }

    #[test]
    fn path_segments_take_keyboard_focus() {
        let mut rig = UiTestRig::default();
        rig.settings.mode = Mode::Tun;
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        let bind_nic = t(Language::En, Key::SettingsPathBindNic);
        first_segment(&harness, bind_nic).focus();
        harness.run();
        assert!(
            first_segment(&harness, bind_nic).is_focused(),
            "a path segment must take keyboard focus"
        );
        let socks5 = t(Language::En, Key::SettingsPathSocks5);
        first_segment(&harness, socks5).focus();
        harness.run();
        assert!(
            first_segment(&harness, socks5).is_focused(),
            "the SOCKS5 segment must take keyboard focus"
        );
    }
}
