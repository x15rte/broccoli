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
use crate::model::settings::{BindNicGate, Language, ProbePath, RefreshPath};
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
    /// Whether a password being typed into the empty field stays editable until
    /// the field loses focus; a stored password uses the masked stand-in.
    socks5_password_editing: bool,
}

impl OutboundSettingsSection {
    /// Mask the section's transient password state when the screen or the
    /// Settings side is left. The stored value stays in the model; only the
    /// reveal and in-progress editing state die with the visit.
    pub(crate) fn reset_transient(&mut self) {
        self.revealed_password = false;
        self.socks5_password_editing = false;
    }

    /// Render the latency-test section (probe URL, outbound path) and the
    /// subscription section (global User-Agent, outbound path, global SOCKS5
    /// fields). Every edit marks the settings dirty through `hooks`, so the
    /// shell's existing save/apply pipeline persists it.
    pub fn show(&mut self, ui: &mut Ui, settings: &mut Settings, hooks: &mut FrameHooks<'_>) {
        let lang = settings.language;
        let gate = settings.bind_nic_gate();

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
            self.latency_path_control(ui, &mut *settings, gate, &mut *hooks);
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
            self.subscription_path_editor(ui, &mut *settings, gate, &mut *hooks);
        });
    }

    /// The latency test's outbound path: Bind NIC and Native only. The latency
    /// probe never dials through SOCKS5.
    ///
    /// The control shows the effective path, so a stored Bind NIC preference
    /// reads as Native while the gate hides Bind NIC. Bind NIC is then
    /// disabled, and only an actual click writes: the stored preference stays
    /// until the user picks Native, which replaces it.
    fn latency_path_control(
        &mut self,
        ui: &mut Ui,
        settings: &mut Settings,
        gate: BindNicGate,
        hooks: &mut FrameHooks<'_>,
    ) {
        let lang = settings.language;
        let stored = settings.latency_test_path;
        let effective = effective_probe_path(stored, gate);
        let disabled = gate.blocks().then_some(bind_nic_hint(gate));
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
            RichText::new(probe_path_note(lang, effective, stored, gate))
                .small()
                .weak(),
        );
    }

    /// The subscription refresh's outbound path and its SOCKS5 carrier. The
    /// shared editor owns the three-segment control, the disabled hint, the
    /// note, the carrier's visibility, and the transient reveal reset. The
    /// credentials are drafts: a blank draft is the absent value, and only a
    /// real edit commits it to the model.
    fn subscription_path_editor(
        &mut self,
        ui: &mut Ui,
        settings: &mut Settings,
        gate: BindNicGate,
        hooks: &mut FrameHooks<'_>,
    ) {
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
        // A draft seeded from a value the model no longer holds must not
        // resurrect it as bullets: the model is the only source of truth.
        if settings
            .subscription_socks5
            .username
            .as_deref()
            .is_none_or(str::is_empty)
            && !username.is_empty()
        {
            username.clear();
        }
        if settings
            .subscription_socks5
            .password
            .as_deref()
            .is_none_or(str::is_empty)
            && !password.is_empty()
        {
            password.clear();
        }
        let edit = refresh_path_editor(
            ui,
            lang,
            gate,
            &mut settings.subscription_path,
            Socks5Fields {
                host: &mut settings.subscription_socks5.host,
                port: &mut settings.subscription_socks5.port,
                username: &mut *username,
                password: &mut *password,
                revealed: &mut self.revealed_password,
                editing: &mut self.socks5_password_editing,
            },
        );
        if edit.changed {
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

/// The hover hint a disabled Bind NIC segment carries. `Available` has no
/// disabled segment; it names the segment's own note so the mapping stays
/// total.
fn bind_nic_hint(gate: BindNicGate) -> Key {
    match gate {
        BindNicGate::TunOff => Key::SettingsPathBindNicDisabledHint,
        BindNicGate::LeakBlock => Key::SettingsPathBindNicLeakBlockHint,
        BindNicGate::Available => Key::SettingsPathNoteBindNic,
    }
}

/// The note a stored Bind NIC preference that reads as Native carries: the
/// reason the gate names. `Available` cannot hide Bind NIC, so it names the
/// Bind NIC note instead.
fn bind_nic_note(gate: BindNicGate) -> Key {
    match gate {
        BindNicGate::TunOff => Key::SettingsPathNoteBindNicTunOff,
        BindNicGate::LeakBlock => Key::SettingsPathNoteBindNicLeakBlock,
        BindNicGate::Available => Key::SettingsPathNoteBindNic,
    }
}

/// One segment of an outbound-path control. A disabled segment stays visible
/// and keeps its selected state painted; the persistent note below the control
/// says why it cannot be picked, so the disabled state never relies on colour.
fn path_segment(
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
/// options are the only per-vocabulary input; the selected state, the disabled
/// segment (TUN off or the leak block), and the pick result stay one
/// implementation.
fn path_control<T: Copy + PartialEq>(
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

/// The password buffer and its two transient states, bundled so the shared
/// editor keeps one slot for the value and one for what the user is doing with
/// it.
struct Socks5Password<'a> {
    pub value: &'a mut String,
    pub revealed: &'a mut bool,
    pub editing: &'a mut bool,
}

/// The shared SOCKS5 editor for the global subscription settings and the
/// per-subscription dialog. The caller supplies its own field buffers and the
/// password's state; the labels, masking, and note live here once.
fn socks5_editor(
    ui: &mut Ui,
    lang: Language,
    host: &mut String,
    port: &mut u16,
    username: &mut String,
    password: Socks5Password<'_>,
) -> bool {
    let mut changed = widgets::text_field(ui, t(lang, Key::SettingsSocks5Host), host, "127.0.0.1");
    changed |= widgets::port_field(ui, t(lang, Key::SettingsSocks5Port), port);
    changed |= widgets::text_field(
        ui,
        t(lang, Key::SettingsSocks5Username),
        username,
        "proxy user",
    );
    // An absent password is an empty, editable field: there is no secret to
    // hide, and the user must be able to type one. A new password stays
    // editable while it is being typed (and loses focus), then follows the
    // stored password's masked stand-in. An explicit reveal shows the value
    // regardless.
    if password.value.is_empty() || *password.editing || *password.revealed {
        let response = ui
            .horizontal(|ui| {
                let label = ui.label(t(lang, Key::SettingsSocks5Password));
                ui.add(
                    egui::TextEdit::singleline(password.value)
                        .hint_text("proxy password")
                        .desired_width(f32::INFINITY),
                )
                .labelled_by(label.id)
            })
            .inner;
        changed |= response.changed();
        if response.has_focus() || response.changed() {
            *password.editing = true;
        }
        if response.lost_focus() {
            *password.editing = false;
        }
    } else {
        changed |= widgets::masked_text_field(
            ui,
            t(lang, Key::SettingsSocks5Password),
            password.value,
            "proxy password",
            true,
        );
    }
    if !password.value.is_empty() && !*password.editing {
        password_reveal(ui, lang, password.revealed);
    }
    ui.label(
        RichText::new(t(lang, Key::SettingsSocks5Note))
            .small()
            .weak(),
    );
    changed
}

/// What one frame of the refresh-path editor settled: whether an edit landed,
/// and the effective path the control showed (a stored Bind NIC reads as
/// Native while the gate blocks).
pub(crate) struct RefreshPathEdit {
    pub changed: bool,
    pub effective: RefreshPath,
}

/// The SOCKS5 field holders one refresh-path editor edits: the caller owns the
/// buffers and the transient password state, so the same editor serves the
/// global subscription settings and the per-subscription dialog.
pub(crate) struct Socks5Fields<'a> {
    pub host: &'a mut String,
    pub port: &'a mut u16,
    pub username: &'a mut String,
    pub password: &'a mut String,
    pub revealed: &'a mut bool,
    pub editing: &'a mut bool,
}

/// The refresh-path editor: the `Bind NIC | Native | SOCKS5` control, its
/// disabled hint, its persistent note, and the SOCKS5 carrier exactly while
/// the effective path is SOCKS5. A path switch away from SOCKS5 drops the
/// transient reveal and empty-field editing state, so neither survives the
/// block it belonged to. Returns whether an edit landed and the effective path
/// the frame showed.
pub(crate) fn refresh_path_editor(
    ui: &mut Ui,
    lang: Language,
    gate: BindNicGate,
    stored: &mut RefreshPath,
    fields: Socks5Fields<'_>,
) -> RefreshPathEdit {
    let effective = effective_refresh_path(*stored, gate);
    let disabled = gate.blocks().then_some(bind_nic_hint(gate));
    let options = [
        (RefreshPath::BindNic, Key::SettingsPathBindNic, disabled),
        (RefreshPath::Native, Key::SettingsPathNative, None),
        (RefreshPath::Socks5, Key::SettingsPathSocks5, None),
    ];
    let mut changed = false;
    if let Some(path) = path_control(ui, lang, effective, &options)
        && path != *stored
    {
        *stored = path;
        changed = true;
    }
    ui.label(
        RichText::new(refresh_path_note(lang, effective, *stored, gate))
            .small()
            .weak(),
    );
    if effective == RefreshPath::Socks5 {
        changed |= socks5_editor(
            ui,
            lang,
            fields.host,
            fields.port,
            fields.username,
            Socks5Password {
                value: fields.password,
                revealed: fields.revealed,
                editing: fields.editing,
            },
        );
    } else {
        *fields.revealed = false;
        *fields.editing = false;
    }
    RefreshPathEdit { changed, effective }
}

/// The persistent note for the effective probe path. A stored Bind NIC
/// preference that the gate hides reads as Native and says why.
fn probe_path_note(
    lang: Language,
    effective: ProbePath,
    stored: ProbePath,
    gate: BindNicGate,
) -> &'static str {
    match effective {
        ProbePath::BindNic => t(lang, Key::SettingsPathNoteBindNic),
        ProbePath::Native if stored == ProbePath::BindNic && gate.blocks() => {
            t(lang, bind_nic_note(gate))
        }
        ProbePath::Native => t(lang, Key::SettingsPathNoteNative),
    }
}

/// The persistent note for the effective refresh path.
fn refresh_path_note(
    lang: Language,
    effective: RefreshPath,
    stored: RefreshPath,
    gate: BindNicGate,
) -> &'static str {
    match effective {
        RefreshPath::BindNic => t(lang, Key::SettingsPathNoteBindNic),
        RefreshPath::Socks5 => t(lang, Key::SettingsSubscriptionPathNoteSocks5),
        RefreshPath::Native if stored == RefreshPath::BindNic && gate.blocks() => {
            t(lang, bind_nic_note(gate))
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
                state.0.show(ui, &mut *ctx.settings, &mut ctx.hooks);
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
        rig.settings.tun.auto_system_wfp_block_leak.clear();
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
    fn bind_nic_is_disabled_while_the_leak_block_is_on() {
        let mut rig = UiTestRig::default();
        rig.settings.mode = Mode::Tun;
        rig.settings.latency_test_path = ProbePath::BindNic;
        rig.settings.subscription_path = RefreshPath::BindNic;
        assert!(
            !rig.settings.tun.auto_system_wfp_block_leak.is_empty(),
            "the seeded leak block is the state under test"
        );
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        let lang = Language::En;
        let bind_nic = t(lang, Key::SettingsPathBindNic);
        let segments: Vec<_> = harness
            .get_all_by_role_and_label(egui::accesskit::Role::Button, bind_nic)
            .collect();
        assert_eq!(segments.len(), 2, "both path controls must render");
        for node in &segments {
            assert!(
                node.accesskit_node().is_disabled(),
                "the leak block blocks every Bind NIC dial"
            );
        }
        assert!(
            harness
                .query_all_by_label(t(lang, Key::SettingsPathNoteBindNicLeakBlock))
                .next()
                .is_some(),
            "the note must name the leak block, not TUN mode"
        );
        assert!(
            harness
                .query_all_by_label(t(lang, Key::SettingsPathNoteBindNicTunOff))
                .next()
                .is_none(),
            "TUN is on, so the TUN-off note would be wrong"
        );

        // A disabled segment writes nothing; the stored preference stays.
        segments[0].click();
        harness.run();
        assert_eq!(
            harness.state().1.settings.latency_test_path,
            ProbePath::BindNic
        );
        assert!(!harness.state().1.requests.dirty);

        // Native remains available and replaces the stored preference.
        let native = t(lang, Key::SettingsPathNative);
        first_segment(&harness, native).click();
        harness.run();
        assert_eq!(
            harness.state().1.settings.latency_test_path,
            ProbePath::Native
        );
        assert!(harness.state().1.requests.dirty);
    }

    #[test]
    fn tun_off_names_its_own_reason_while_a_catch_all_leak_scope_is_stored() {
        let mut rig = UiTestRig::default();
        rig.settings.mode = Mode::Off;
        rig.settings.latency_test_path = ProbePath::BindNic;
        assert!(
            !rig.settings.tun.auto_system_wfp_block_leak.is_empty(),
            "the seeded leak block is in force too"
        );
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        let lang = Language::En;
        assert!(
            harness
                .query_all_by_label(t(lang, Key::SettingsPathNoteBindNicTunOff))
                .next()
                .is_some(),
            "TUN off is the broader rule and names the reason"
        );
        assert!(
            harness
                .query_all_by_label(t(lang, Key::SettingsPathNoteBindNicLeakBlock))
                .next()
                .is_none(),
            "the leak block would misname why Bind NIC is off"
        );
    }

    #[test]
    fn a_custom_leak_list_keeps_bind_nic_selectable() {
        let mut rig = UiTestRig::default();
        rig.settings.mode = Mode::Tun;
        rig.settings.tun.auto_system_wfp_block_leak = vec!["tcp/853".into()];
        rig.settings.latency_test_path = ProbePath::Native;
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        let bind_nic = t(Language::En, Key::SettingsPathBindNic);
        assert!(
            !first_segment(&harness, bind_nic)
                .accesskit_node()
                .is_disabled(),
            "a detail entry does not block every destination Bind NIC dials"
        );
        first_segment(&harness, bind_nic).click();
        harness.run();
        assert_eq!(
            harness.state().1.settings.latency_test_path,
            ProbePath::BindNic
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
    fn socks5_fields_render_only_while_the_effective_path_is_socks5() {
        let mut rig = UiTestRig::default();
        rig.settings.mode = Mode::Off;
        rig.settings.subscription_path = RefreshPath::Native;
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsSocks5Host))
                .is_none(),
            "Native must not render the SOCKS5 block"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsSocks5Password))
                .is_none(),
            "Native must not render the password row"
        );

        last_segment(&harness, t(Language::En, Key::SettingsPathSocks5)).click();
        harness.run();
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsSocks5Host))
                .is_some(),
            "the SOCKS5 path renders its block"
        );
    }

    #[test]
    fn an_empty_socks5_password_is_editable_without_a_reveal_button() {
        let mut rig = UiTestRig::default();
        rig.settings.subscription_path = RefreshPath::Socks5;
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        let password_label = t(Language::En, Key::SettingsSocks5Password);
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsSocks5RevealPassword))
                .is_none(),
            "an absent password has nothing to reveal"
        );
        let field = harness.get_by_role_and_label(egui::accesskit::Role::TextInput, password_label);
        field.click();
        harness.run();
        harness
            .get_by_role_and_label(egui::accesskit::Role::TextInput, password_label)
            .type_text("hunter2");
        harness.run_steps(4);

        assert_eq!(
            harness
                .state()
                .1
                .settings
                .subscription_socks5
                .password
                .as_deref(),
            Some("hunter2"),
            "the empty field accepts a new password"
        );

        // Leaving the field masks the freshly typed value and restores the
        // explicit Reveal control.
        harness
            .get_by_role_and_label(
                egui::accesskit::Role::TextInput,
                t(Language::En, Key::SettingsSocks5Username),
            )
            .click();
        harness.run();
        assert!(
            !harness
                .get_all_by_role(egui::accesskit::Role::TextInput)
                .any(|node| node.value().as_deref() == Some("hunter2")),
            "a typed password masks after focus leaves"
        );
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsSocks5RevealPassword))
                .is_some(),
            "the masked password offers Reveal again"
        );
    }

    #[test]
    fn clearing_the_model_password_resets_a_stale_draft() {
        let mut rig = UiTestRig::default();
        rig.settings.subscription_path = RefreshPath::Socks5;
        rig.settings.subscription_socks5.password = Some("stale".into());
        let mut harness = harness(rig, OutboundSettingsSection::default());
        harness.run();

        harness.state_mut().1.settings.subscription_socks5.password = None;
        harness.run();

        let password_label = t(Language::En, Key::SettingsSocks5Password);
        assert!(
            harness
                .query_by_label(t(Language::En, Key::SettingsSocks5RevealPassword))
                .is_none(),
            "an empty model value must not leave a revealable secret"
        );
        let field = harness.get_by_role_and_label(egui::accesskit::Role::TextInput, password_label);
        assert_eq!(
            field.value().as_deref(),
            Some(""),
            "the cleared model value must clear the seeded draft"
        );
    }

    #[test]
    fn socks5_password_is_masked_until_revealed() {
        let mut rig = UiTestRig::default();
        rig.settings.subscription_path = RefreshPath::Socks5;
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
        rig.settings.tun.auto_system_wfp_block_leak.clear();
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

    /// The gate, the displayed effective path, its note, and the fetch
    /// transport are one resolution: no combination of mode, live TUN, leak
    /// scope, stored path, and group override may disagree. No core or TUN
    /// session is involved — the settings tree and an adapter view are the only
    /// inputs.
    #[test]
    fn the_gate_path_note_and_transport_agree_over_the_matrix() {
        use crate::model::Settings;
        use crate::model::servers::Subscription;
        use crate::model::settings::{BindNicGate, Socks5Cfg};
        use crate::sys::netif::test_iface;
        use crate::sys::outbound_path::{OutboundPath, effective_refresh_path};
        use crate::sys::subscription::FetchTransport;

        let global_socks5 = Socks5Cfg {
            host: "global.example".into(),
            port: 1080,
            username: None,
            password: None,
        };
        let override_socks5 = Socks5Cfg {
            host: "override.example".into(),
            port: 9050,
            username: None,
            password: None,
        };
        let interfaces = [
            test_iface("broccoli0", 9, false, true, &["10.255.0.1"]),
            test_iface("Ethernet", 2, false, true, &["10.0.0.7"]),
        ];
        let leaks: [&[&str]; 3] = [&[], &["allexceptlan"], &["tcp/853"]];
        let stored_paths = [
            RefreshPath::BindNic,
            RefreshPath::Native,
            RefreshPath::Socks5,
        ];
        let overrides = [
            None,
            Some(RefreshPath::BindNic),
            Some(RefreshPath::Native),
            Some(RefreshPath::Socks5),
        ];

        for mode in [Mode::Off, Mode::Tun] {
            for live in [false, true] {
                for leak in leaks {
                    for stored in stored_paths {
                        for override_path in overrides {
                            let mut settings = Settings {
                                mode,
                                ..Settings::default()
                            };
                            settings.tun.auto_outbounds_interface = "Ethernet".into();
                            settings.tun.auto_system_wfp_block_leak =
                                leak.iter().map(|entry| (*entry).to_owned()).collect();
                            settings.subscription_path = stored;
                            settings.subscription_socks5 = global_socks5.clone();
                            let subscription = override_path.map(|path| Subscription {
                                outbound_custom: true,
                                outbound_path: path,
                                socks5: override_socks5.clone(),
                                ..Subscription::default()
                            });
                            let subscription_ref = subscription.as_ref();
                            let resolved = OutboundPath::resolve(&settings, live);
                            let gate = settings.bind_nic_gate();
                            let why = format!(
                                "mode={mode:?} live={live} leak={leak:?} stored={stored:?} \
                                 override={override_path:?}"
                            );

                            assert_eq!(resolved.gate(), gate, "{why}");

                            let (stored_in_force, socks5_in_force) = match subscription_ref {
                                Some(subscription) => subscription
                                    .effective_outbound(stored, &settings.subscription_socks5),
                                None => (stored, &settings.subscription_socks5),
                            };
                            let effective = effective_refresh_path(stored_in_force, gate);
                            assert_eq!(
                                resolved.refresh_path(subscription_ref),
                                effective,
                                "{why}: the displayed path is the render-gated one"
                            );

                            let note = match effective {
                                RefreshPath::BindNic => Key::SettingsPathNoteBindNic,
                                RefreshPath::Socks5 => Key::SettingsSubscriptionPathNoteSocks5,
                                RefreshPath::Native
                                    if stored_in_force == RefreshPath::BindNic && gate.blocks() =>
                                {
                                    match gate {
                                        BindNicGate::TunOff => Key::SettingsPathNoteBindNicTunOff,
                                        BindNicGate::LeakBlock => {
                                            Key::SettingsPathNoteBindNicLeakBlock
                                        }
                                        BindNicGate::Available => {
                                            unreachable!("a blocking gate cannot be Available")
                                        }
                                    }
                                }
                                RefreshPath::Native => Key::SettingsPathNoteNative,
                            };
                            assert_eq!(
                                super::refresh_path_note(
                                    Language::En,
                                    effective,
                                    stored_in_force,
                                    gate,
                                ),
                                t(Language::En, note),
                                "{why}: the note states the same gate and path"
                            );

                            let live_effective = if live {
                                effective
                            } else {
                                effective_refresh_path(stored_in_force, BindNicGate::TunOff)
                            };
                            let expected_transport = match live_effective {
                                RefreshPath::Native => Ok(FetchTransport::Native),
                                RefreshPath::Socks5 => Ok(FetchTransport::Socks5 {
                                    host: socks5_in_force.host.clone(),
                                    port: socks5_in_force.port,
                                    username: None,
                                    password: None,
                                }),
                                RefreshPath::BindNic => {
                                    Ok(FetchTransport::Bind("10.0.0.7".parse().expect("ipv4")))
                                }
                            };
                            assert_eq!(
                                resolved.refresh_transport(subscription_ref, &interfaces),
                                expected_transport,
                                "{why}: the transport follows the live capture"
                            );
                        }
                    }
                }
            }
        }
    }
}
