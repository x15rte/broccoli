//! TUN screen: full-tunnel inbound settings + elevation state.

use crate::i18n::{Key, safety_message, t, t_fmt, validation_message};
use crate::model::Mode;
use crate::model::TunCfg;
use crate::model::safety::SafetyVerdicts;
use crate::model::settings::Language;
use crate::model::validation::{ValidationCode, tun_ipv4_gateway};
use crate::rt::{CorePhase, CoreTransport};
use crate::sys::netif::{self, NetIf};
use crate::ui::UiCtx;
use crate::ui::inbounds::sniffing_editor;
use crate::ui::request::{Request, Terminal};
use crate::ui::status::status_colors_of;
use crate::ui::widgets;

/// Refresh interface list at most every 5 s.
const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Default)]
pub struct TunScreen {
    ifaces: Vec<NetIf>,
    /// Per-interface IP display text, pre-joined at refresh time — the grid
    /// renders these instead of re-joining on every frame. Always aligned
    /// with `ifaces`; both change only on the refresh cadence.
    iface_ips: Vec<String>,
    /// Next scheduled enumeration (wall clock); `None` until the first show.
    next_refresh_at: Option<std::time::Instant>,
    /// In-flight worker enumeration request; a worker that exits without
    /// a result clears it so the refresh cadence resumes.
    iface_request: Request<Vec<NetIf>>,
    /// Privacy-warning references, rebuilt when the model generation moves
    /// (the inbounds `ValidationCache` precedent) — never on idle repaint
    /// frames. `None` until the first frame.
    validation: Option<ValidationCache>,
}

/// One generation of the TUN screen's per-generation verdicts: the
/// pre-rendered privacy-warning message for the "tun" finding from
/// [`assess`] ("TUN mode with no DNS configuration") and the inline
/// validation error for a gateway list without an IPv4 entry — both
/// computed once per model generation.
struct ValidationCache {
    generation: u64,
    tun_warning: Option<String>,
    gateway_error: Option<String>,
}

/// The inline validation error for the gateways editor, or `None` when the
/// list is valid. The rule lives in the model verdict pass (TUN mode + no
/// IPv4 gateway → invalid): Apply/Connect are blocked through
/// `config_error`, and this screen renders that code's message under the
/// gateway list.
fn tun_gateway_error(lang: Language, mode: Mode, tun: &TunCfg) -> Option<String> {
    (mode == Mode::Tun && tun_ipv4_gateway(tun).is_none())
        .then(|| validation_message(&ValidationCode::TunIpv4GatewayRequired, lang))
}

impl TunScreen {
    /// Refresh the adapter list off the UI thread at most once per
    /// [`REFRESH_INTERVAL`]: a worker enumerates and delivers through a
    /// channel, so no frame ever blocks on `GetAdaptersAddresses`. An idle
    /// frame never enumerates: the request slot's state is the observable
    /// (a delivered fixture versus an idle slot).
    fn poll_ifaces(&mut self, ui: &egui::Ui) {
        match self.iface_request.poll() {
            Some(Terminal::Answered(ifaces)) => self.set_ifaces(ifaces),
            // A worker that exits without delivering clears the request so
            // the refresh cadence resumes: the next due tick enumerates
            // again instead of the list freezing on a dead worker.
            Some(Terminal::Exited) | None => {}
        }
        let now = std::time::Instant::now();
        let due = self.next_refresh_at.map(|at| now >= at).unwrap_or(true);
        if !self.iface_request.is_pending() && due {
            let repaint = ui.ctx().clone();
            match Request::worker("broccoli-netif", &repaint, move |_| Some(netif::list())) {
                Ok(request) => {
                    self.iface_request = request;
                    self.next_refresh_at = Some(now + REFRESH_INTERVAL);
                }
                Err(_) => {
                    // Thread-spawn failure (resource exhaustion): fall back to
                    // a synchronous enumeration so the list still refreshes.
                    self.set_ifaces(netif::list());
                    self.next_refresh_at = Some(now + REFRESH_INTERVAL);
                }
            }
        }
    }

    /// Replace the adapter list together with its pre-joined IP display
    /// text — the pair changes only at a refresh, never per frame.
    fn set_ifaces(&mut self, ifaces: Vec<NetIf>) {
        self.iface_ips = ifaces.iter().map(|i| i.ips.join(", ")).collect();
        self.ifaces = ifaces;
    }

    /// Seed an adapter snapshot and park the refresh cadence at the next
    /// interval, so a screen test renders the fixed-name verdict from fixture
    /// adapters instead of this machine's NICs.
    #[cfg(test)]
    pub(crate) fn seed_ifaces(&mut self, ifaces: Vec<NetIf>) {
        self.set_ifaces(ifaces);
        self.next_refresh_at = Some(std::time::Instant::now() + REFRESH_INTERVAL);
    }

    pub fn show(&mut self, ui: &mut egui::Ui, ctx: &mut UiCtx) {
        self.poll_ifaces(ui);

        // The privacy warning is rebuilt when the model generation moves —
        // the frame after any edit, never on idle repaint frames (the inbounds
        // ValidationCache precedent) — so the verdict lags an edit by at most
        // one frame, exactly like the inbounds posture banner. The mode is
        // read from the live model at rebuild time, so no second key is
        // needed for it.
        let lang = ctx.settings.language;
        let generation = *ctx.model_generation;
        if !matches!(&self.validation, Some(cache) if cache.generation == generation) {
            // One `assess` per model generation — never per-frame.
            let findings = SafetyVerdicts::of(ctx.servers, ctx.settings);
            self.validation = Some(ValidationCache {
                generation,
                tun_warning: findings
                    .tun_privacy()
                    .map(|finding| safety_message(&finding.code, lang)),
                gateway_error: tun_gateway_error(lang, ctx.settings.mode, &ctx.settings.tun),
            });
        }
        let tun_warning = match &self.validation {
            Some(cache) => cache.tun_warning.as_deref(),
            None => unreachable!("validation is built when absent, above"),
        };
        let gateway_error = match &self.validation {
            Some(cache) => cache.gateway_error.as_deref(),
            None => unreachable!("validation is built when absent, above"),
        };

        ui.add_space(4.0);
        let colors = status_colors_of(ui);
        let badge_key = tun_badge(ctx.phase, ctx.settings.mode, ctx.transport, ctx.is_elevated);
        // The healthy states — an elevated shell, or TUN already running
        // through the helper — read in the ok color; only the note about a
        // TUN start that has not happened yet warns.
        let badge_color = match badge_key {
            Key::TunBadgeNotElevated => colors.warn,
            _ => colors.ok,
        };
        let badge = egui::RichText::new(t(lang, badge_key)).color(badge_color);
        egui::Frame::new()
            .fill(ui.visuals().extreme_bg_color)
            .inner_margin(8.0)
            .show(ui, |ui| {
                ui.label(t(lang, Key::TunExplain));
                // The in-tun DNS listener answers on the adapter's gateway
                // address and is added to the running core once the adapter
                // exists (it never appears in the generated config the
                // preview shows), so the page states that lifecycle where
                // the settings driving it live: TUN on, a DNS module, and an
                // IPv4 gateway to bind.
                if ctx.settings.mode == Mode::Tun
                    && !ctx.settings.dns.is_effectively_empty()
                    && tun_ipv4_gateway(&ctx.settings.tun).is_some()
                {
                    ui.label(
                        egui::RichText::new(t(lang, Key::TunDnsListenerNote))
                            .weak()
                            .small(),
                    );
                }
                ui.label(badge);
            });
        ui.add_space(6.0);

        let mut changed = false;
        let fakedns_on = ctx.settings.dns.fakedns.enabled;
        let mut enabled = ctx.settings.mode == Mode::Tun;
        ui.horizontal(|ui| {
            if ui
                .checkbox(&mut enabled, t(lang, Key::TunEnableCheckbox))
                .changed()
            {
                let requested_mode = if enabled { Mode::Tun } else { Mode::Off };
                changed |= ctx.settings.set_mode(requested_mode);
            }
            if ctx.settings.mode == Mode::Tun {
                ui.weak(t(lang, Key::TunRestartHint));
            }
        });
        // The banner sits between the enable toggle and the sections: it is
        // the first thing seen when TUN runs without a DNS configuration.
        // The scope is pushed unconditionally so its auto-id slot is always
        // consumed: the sections below (CollapsingHeader internals wrap each
        // section in a saltless `ui.vertical`, whose id embeds the parent's
        // auto-id counter) would otherwise shift their widget ids when the
        // warning appears/disappears, dropping egui focus from an edited
        // field while the TUN toggle lands on a DNS-less configuration.
        ui.add_space(4.0);
        ui.push_id("tun-dns-privacy-banner", |ui| {
            if let Some(message) = tun_warning {
                ui.label(
                    egui::RichText::new(message)
                        .small()
                        .color(status_colors_of(ui).warn),
                );
            }
        });
        ui.add_space(4.0);
        let tun = &mut ctx.settings.tun;

        widgets::section(ui, t(lang, Key::TunSectionIdentity), |ui| {
            changed |= widgets::text_field(
                ui,
                t(lang, Key::TunIfaceNameLabel),
                &mut tun.name,
                "broccoli0",
            );
            changed |= widgets::text_field(ui, t(lang, Key::TunDescLabel), &mut tun.desc, "Wintun");
            let mut mtu = if tun.mtu == 0 { None } else { Some(tun.mtu) };
            if widgets::opt_u32(ui, t(lang, Key::TunMtuLabel), &mut mtu, 576..=9000) {
                tun.mtu = mtu.unwrap_or(0);
                changed = true;
            }
            changed |= widgets::opt_u32(
                ui,
                t(lang, Key::UserLevel),
                &mut tun.user_level,
                0..=u32::MAX,
            );
        });

        widgets::section(ui, t(lang, Key::TunSectionGateways), |ui| {
            changed |= widgets::string_list(
                ui,
                lang,
                t(lang, Key::TunGatewaysLabel),
                &mut tun.gateway,
                "10.255.0.1/30",
            );
            // Inline validation error, rendered under the list like the
            // model-layer warning banners: the generator rejects this state
            // (Apply/Connect are blocked through config_error), and the
            // screen mirrors that verdict exactly where the user can fix it.
            // A plain label consumes no egui auto-id slot, so the section's
            // widget ids never shift when the error appears or clears.
            if let Some(error) = gateway_error {
                ui.label(
                    egui::RichText::new(error)
                        .small()
                        .color(status_colors_of(ui).err),
                );
            }
        });

        changed |= sniffing_editor(ui, lang, &mut tun.sniffing, fakedns_on);

        widgets::section(ui, t(lang, Key::TunSectionAutoRoutes), |ui| {
            changed |= widgets::string_list(
                ui,
                lang,
                t(lang, Key::TunAutoRoutingTableLabel),
                &mut tun.auto_system_routing_table,
                "0.0.0.0/1",
            );
            // autoOutboundsInterface: combo of "auto" + live interface names;
            // down adapters are shown disabled — selecting one is a total
            // outage (Xray binds every dial to its index, and a down adapter
            // still binds, then every socket fails unreachable-host).
            ui.horizontal(|ui| {
                ui.label(t(lang, Key::TunAutoOutboundsLabel));
                egui::ComboBox::from_id_salt("auto-iface")
                    .selected_text(if tun.auto_outbounds_interface.is_empty() {
                        "auto"
                    } else {
                        &tun.auto_outbounds_interface
                    })
                    .show_ui(ui, |ui| {
                        if ui
                            .selectable_label(tun.auto_outbounds_interface == "auto", "auto")
                            .clicked()
                        {
                            tun.auto_outbounds_interface = "auto".into();
                            changed = true;
                        }
                        for i in &self.ifaces {
                            if i.up {
                                if ui
                                    .selectable_label(
                                        tun.auto_outbounds_interface == i.name,
                                        &i.name,
                                    )
                                    .clicked()
                                    && tun.auto_outbounds_interface != i.name
                                {
                                    tun.auto_outbounds_interface = i.name.clone();
                                    changed = true;
                                }
                            } else {
                                ui.add_enabled(
                                    false,
                                    egui::Label::new(format!(
                                        "{} ({})",
                                        i.name,
                                        t(lang, Key::LocalStatusDown)
                                    )),
                                );
                            }
                        }
                    });
                // A persisted fixed pick whose adapter is currently down or
                // missing is the outage trap above: surface it here (the
                // shared name verdict), and Apply/Connect rejects it
                // outright while TUN is active.
                let problem =
                    match netif::fixed_name_verdict(&tun.auto_outbounds_interface, &self.ifaces) {
                        netif::FixedNameVerdict::Down { name } => {
                            Some(t_fmt(lang, Key::TunAutoOutboundsDown, &[&name]))
                        }
                        netif::FixedNameVerdict::Missing { name } => {
                            Some(t_fmt(lang, Key::TunAutoOutboundsMissing, &[&name]))
                        }
                        netif::FixedNameVerdict::Unpinned | netif::FixedNameVerdict::Up => None,
                    };
                if let Some(message) = problem {
                    ui.colored_label(
                        ui.visuals().error_fg_color,
                        egui::RichText::new(message).small(),
                    );
                }
            });
            if tun.auto_outbounds_interface.is_empty() || tun.auto_outbounds_interface == "auto" {
                ui.label(
                    egui::RichText::new(t(lang, Key::TunAutoOutboundsHint))
                        .weak()
                        .small(),
                );
            }
        });

        if changed {
            ctx.mark_dirty();
        }

        ui.add_space(8.0);
        widgets::section(ui, t(lang, Key::TunSectionIfaces), |ui| {
            egui::Grid::new("tun-ifaces")
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    for (iface, ips) in self.ifaces.iter().zip(&self.iface_ips) {
                        ui.label(&iface.name);
                        ui.monospace(ips);
                        ui.end_row();
                    }
                });
        });
    }
}

/// The badge over the TUN screen: elevation is the shell's own fact, and
/// "the helper is carrying TUN" is the transport the running core owns —
/// read from the published transport, not re-derived from the mode setting,
/// so the badge never claims a capture the core does not have.
fn tun_badge(
    phase: &CorePhase,
    mode: Mode,
    transport: Option<CoreTransport>,
    is_elevated: bool,
) -> Key {
    if is_elevated {
        Key::TunBadgeElevated
    } else if mode == Mode::Tun
        && transport == Some(CoreTransport::Tun)
        && matches!(phase, CorePhase::Running)
    {
        Key::TunBadgeHelperActive
    } else {
        Key::TunBadgeNotElevated
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{Key, t_fmt};
    use crate::model::settings::Language;
    use crate::ui::test_rig::UiTestRig;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable as _;

    fn iface(name: &str, up: bool) -> NetIf {
        NetIf {
            name: name.to_string(),
            ips: Vec::new(),
            up,
        }
    }

    /// Render the screen over fixture adapters for one fixed uplink setting
    /// and assert the verdict it shows: `Some(text)` is the exact verdict
    /// label, `None` means no verdict label may appear. The texts are built
    /// from the same i18n keys the commit guard renders, so both surfaces
    /// answer the same fixture with the same verdict.
    fn assert_rendered_verdict(setting: &str, expected: Option<String>) {
        let mut screen = TunScreen::default();
        screen.seed_ifaces(vec![iface("Ethernet", true), iface("wired", false)]);
        let mut rig = UiTestRig::default();
        rig.settings.mode = Mode::Tun;
        rig.settings.tun.auto_outbounds_interface = setting.to_string();
        let mut harness =
            Harness::builder().build_ui_state(|ui, screen| screen.show(ui, &mut rig.ctx()), screen);
        harness.run();

        let down = t_fmt(Language::En, Key::TunAutoOutboundsDown, &[&setting]);
        let missing = t_fmt(Language::En, Key::TunAutoOutboundsMissing, &[&setting]);
        match expected {
            Some(expected) => assert!(
                harness.query_by_label(&expected).is_some(),
                "the TUN screen must render the shared verdict {expected:?}"
            ),
            None => assert!(
                harness.query_by_label(&down).is_none()
                    && harness.query_by_label(&missing).is_none(),
                "a usable fixed name must render no verdict"
            ),
        }
    }

    /// Render the screen once for a settings shape and assert whether the
    /// in-tun DNS listener note appears: `true` requires the exact note
    /// label, `false` forbids it.
    fn assert_rendered_listener_note(
        case: &str,
        configure: impl FnOnce(&mut UiTestRig),
        expected: bool,
    ) {
        let mut rig = UiTestRig::default();
        configure(&mut rig);
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.show(ui, &mut rig.ctx()),
            TunScreen::default(),
        );
        harness.run();
        let note = t(Language::En, Key::TunDnsListenerNote);
        assert_eq!(
            harness.query_by_label(note).is_some(),
            expected,
            "{case}: the listener note must follow the settings that drive the listener"
        );
    }

    /// Render the screen once for a mode/phase with the shell un-elevated
    /// (what `UiTestRig` models, and what the app always is) and assert the
    /// elevation badge: exactly `expected` of the three badge labels is on
    /// screen. The transport follows the phase the way the runtime publishes
    /// it: a running launch under a TUN setting owns the TUN transport.
    fn assert_rendered_badge(case: &str, mode: Mode, phase: CorePhase, expected: Key) {
        let mut rig = UiTestRig::default();
        rig.settings.mode = mode;
        rig.transport = matches!(phase, CorePhase::Running).then(|| {
            if mode == Mode::Tun {
                CoreTransport::Tun
            } else {
                CoreTransport::Direct
            }
        });
        rig.phase = phase;
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen| screen.show(ui, &mut rig.ctx()),
            TunScreen::default(),
        );
        harness.run();
        for key in [
            Key::TunBadgeElevated,
            Key::TunBadgeHelperActive,
            Key::TunBadgeNotElevated,
        ] {
            assert_eq!(
                harness.query_by_label(t(Language::En, key)).is_some(),
                key == expected,
                "{case}: the badge must state the one elevation state the screen is in"
            );
        }
    }

    #[test]
    fn dns_listener_note_follows_the_tun_and_module_settings() {
        // TUN on with the seeded module and gateway: the note states where
        // the listener binds and when it appears.
        assert_rendered_listener_note(
            "TUN on, module and gateway set",
            |rig| rig.settings.mode = Mode::Tun,
            true,
        );
        // TUN off: no adapter, nothing binds the gateway.
        assert_rendered_listener_note("TUN off", |_| {}, false);
        // No DNS module: the listener is never added. Clearing the server
        // list alone still leaves the parallel-query flag on the wire — a
        // module as far as the generator and the runtime are concerned — so
        // the no-module state clears both.
        assert_rendered_listener_note(
            "no module",
            |rig| {
                rig.settings.mode = Mode::Tun;
                rig.settings.dns.servers.clear();
                rig.settings.dns.enable_parallel_query = false;
            },
            false,
        );
        // No IPv4 gateway: generation is blocked and nothing binds.
        assert_rendered_listener_note(
            "no IPv4 gateway",
            |rig| {
                rig.settings.mode = Mode::Tun;
                rig.settings.tun.gateway.clear();
            },
            false,
        );
    }

    #[test]
    fn fixture_adapters_drive_the_tun_screen_fixed_name_verdict() {
        // One fixture snapshot, three settings: a down adapter and a vanished
        // name surface the shared verdict the commit guard blocks on, and the
        // adapter that is up stays silent — all through `&[NetIf]`, without
        // touching this machine's NICs.
        assert_rendered_verdict(
            "wired",
            Some(t_fmt(Language::En, Key::TunAutoOutboundsDown, &[&"wired"])),
        );
        assert_rendered_verdict(
            "ghost",
            Some(t_fmt(
                Language::En,
                Key::TunAutoOutboundsMissing,
                &[&"ghost"],
            )),
        );
        assert_rendered_verdict("Ethernet", None);
    }

    #[test]
    fn tun_badge_covers_elevation_and_tun_running_states() {
        let running = CorePhase::Running;
        let starting = CorePhase::Starting;
        let stopped = CorePhase::Stopped;
        let tun = Some(CoreTransport::Tun);
        let direct = Some(CoreTransport::Direct);

        // Elevation: the shell being elevated is the badge fact, whatever
        // the mode and phase.
        assert_eq!(
            tun_badge(&running, Mode::Tun, tun, true),
            Key::TunBadgeElevated
        );
        assert_eq!(
            tun_badge(&starting, Mode::Tun, None, true),
            Key::TunBadgeElevated
        );
        assert_eq!(
            tun_badge(&stopped, Mode::Tun, None, true),
            Key::TunBadgeElevated
        );
        assert_eq!(
            tun_badge(&running, Mode::Off, None, true),
            Key::TunBadgeElevated
        );

        // A TUN core the helper already runs: the app never elevates itself,
        // so the helper is what carries TUN — the note that TUN would start
        // through the helper would contradict the state on screen.
        assert_eq!(
            tun_badge(&running, Mode::Tun, tun, false),
            Key::TunBadgeHelperActive
        );
        // A running core the helper does not carry (direct child, or a mode
        // change not yet restarted) must keep the UAC note: the badge may not
        // claim a capture the core does not have.
        assert_eq!(
            tun_badge(&running, Mode::Tun, direct, false),
            Key::TunBadgeNotElevated
        );
        assert_eq!(
            tun_badge(&running, Mode::Tun, None, false),
            Key::TunBadgeNotElevated
        );

        // Not elevated, no running TUN core: the UAC note still describes
        // what a start would do.
        assert_eq!(
            tun_badge(&starting, Mode::Tun, tun, false),
            Key::TunBadgeNotElevated
        );
        assert_eq!(
            tun_badge(&stopped, Mode::Tun, None, false),
            Key::TunBadgeNotElevated
        );
        assert_eq!(
            tun_badge(&running, Mode::Off, None, false),
            Key::TunBadgeNotElevated
        );
    }

    /// Idle-frame purity: the worker enumerates on the 5 s cadence, so a
    /// frame inside the interval requests nothing — the request slot stays
    /// idle and the rendered list keeps the adapters the last enumeration
    /// delivered. A per-frame enumeration would leave a request in flight
    /// (and replace the fixture list).
    #[test]
    fn idle_frames_never_request_an_enumeration() {
        let mut screen = TunScreen::default();
        screen.seed_ifaces(vec![iface("Ethernet", true), iface("wired", false)]);
        // Park the cadence well past any test runtime, so the assertion
        // holds on a loaded machine too: the gate, not the clock, decides.
        screen.next_refresh_at = Some(std::time::Instant::now() + REFRESH_INTERVAL * 1_000);
        let mut rig = UiTestRig::default();
        let mut harness = Harness::builder().build_ui_state(
            |ui, screen: &mut TunScreen| screen.show(ui, &mut rig.ctx()),
            screen,
        );
        harness.run();

        assert!(
            !harness.state().iface_request.is_pending(),
            "a frame inside the refresh cadence must not request an enumeration"
        );
        let rendered = &harness.state().ifaces;
        assert_eq!(
            rendered
                .iter()
                .map(|iface| iface.name.as_str())
                .collect::<Vec<_>>(),
            ["Ethernet", "wired"],
            "idle frames must keep rendering the delivered adapter snapshot"
        );
    }

    #[test]
    fn a_running_tun_core_renders_the_helper_badge_not_the_uac_note() {
        // The app never runs elevated — the elevated helper owns the core —
        // so with TUN up, the badge states where TUN runs instead of
        // promising the UAC prompt that a start would bring.
        assert_rendered_badge(
            "TUN running",
            Mode::Tun,
            CorePhase::Running,
            Key::TunBadgeHelperActive,
        );
        // A TUN start that has not happened yet: the UAC note still applies.
        assert_rendered_badge(
            "TUN stopped",
            Mode::Tun,
            CorePhase::Stopped,
            Key::TunBadgeNotElevated,
        );
        assert_rendered_badge(
            "TUN starting",
            Mode::Tun,
            CorePhase::Starting,
            Key::TunBadgeNotElevated,
        );
        // No TUN: the note applies whatever the core is doing.
        assert_rendered_badge(
            "TUN off",
            Mode::Off,
            CorePhase::Running,
            Key::TunBadgeNotElevated,
        );
    }
}
