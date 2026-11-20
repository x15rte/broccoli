//! The outbound path shared by the latency probe and subscription refresh.
//!
//! Bind NIC uses the TUN screen's outbound-interface selection and the same
//! resolver the tunnel guard and the probe use; Native follows the OS stack,
//! which the tunnel captures while it is up. SOCKS5 exists on the refresh
//! side. One gate decides whether Bind NIC can bind: it needs TUN mode on,
//! whose capture it bypasses, and a leak scope that leaves a bypass — `all`
//! and `allexceptlan` block every destination outside the tunnel, while a
//! custom list names the dials it blocks. Before the tunnel connects, or under
//! a catch-all scope, Bind NIC and Native are the same OS path, so a probe or
//! refresh follows the stack instead of failing.
//!
//! [`OutboundPath`] is the one resolution a caller reads: the render gate the
//! path controls and their notes state, the probe's effective path and its
//! interface setting, the refresh path a fetch prefers, and the refresh
//! transport for one optional group override. The probe command carries the
//! render-gated binding, because it is sent before the tunnel exists and its
//! runtime re-checks the live capture; the refresh transport is resolved here,
//! where the live capture is known, so a stored Bind NIC choice under a dead
//! tunnel follows the OS stack.
//!
//! Every resolution that cannot produce its carrier fails loudly. The one
//! equivalent fallback is Bind NIC while no bypass is possible: with no TUN
//! traffic to bypass it and Native are the same OS path.

use crate::model::servers::Subscription;
use crate::model::{BindNicGate, ProbePath, RefreshPath, Settings, Socks5Cfg};
use crate::sys::netif::{NetIf, ProbeUplink, resolve_probe_uplink};
use crate::sys::subscription::FetchTransport;

/// The two path vocabularies' shared degradation rule: Bind NIC reads as
/// Native while the gate blocks; every other path stays as stored.
trait PathDegrade: Copy {
    fn native() -> Self;
    fn is_bind_nic(self) -> bool;
}

impl PathDegrade for ProbePath {
    fn native() -> Self {
        Self::Native
    }

    fn is_bind_nic(self) -> bool {
        self == Self::BindNic
    }
}

impl PathDegrade for RefreshPath {
    fn native() -> Self {
        Self::Native
    }

    fn is_bind_nic(self) -> bool {
        self == Self::BindNic
    }
}

fn effective_path<P: PathDegrade>(stored: P, gate: BindNicGate) -> P {
    if stored.is_bind_nic() && gate.blocks() {
        P::native()
    } else {
        stored
    }
}

/// The effective probe path under `gate`. Bind NIC binds the physical uplink
/// to bypass the TUN capture, which only exists while the tunnel is up; when
/// the gate blocks — TUN mode off, or a catch-all leak scope — the effective
/// path is Native.
pub(crate) fn effective_probe_path(stored: ProbePath, gate: BindNicGate) -> ProbePath {
    effective_path(stored, gate)
}

/// The effective refresh path under `gate`. Bind NIC behaves as it does for
/// the probe; Native and SOCKS5 stay as stored, because neither bypasses the
/// tunnel.
pub(crate) fn effective_refresh_path(stored: RefreshPath, gate: BindNicGate) -> RefreshPath {
    effective_path(stored, gate)
}

/// One resolution of the outbound paths in force. The settings tree answers
/// the render gate and both stored paths; `tun_live` says whether the running
/// core owns the TUN capture, which the refresh transport needs because Bind
/// NIC bypasses a capture that must exist.
///
/// The probe's binding is render-gated: the command can be sent before the
/// tunnel exists, and the probe runtime re-checks the live capture. The
/// refresh transport is live-gated here, where the fetch's worker starts, so
/// the resolved carrier is exactly what the fetch dials.
pub struct OutboundPath<'a> {
    settings: &'a Settings,
    tun_live: bool,
}

impl<'a> OutboundPath<'a> {
    /// Resolve the paths from the settings tree and whether the running core
    /// owns the live TUN capture.
    pub fn resolve(settings: &'a Settings, tun_live: bool) -> Self {
        Self { settings, tun_live }
    }

    /// The render gate: what the path controls, their disabled hints, and
    /// their persistent notes state. It reads the settings alone, because TUN
    /// mode — not the live connection — decides whether Bind NIC is a valid
    /// preference.
    pub fn gate(&self) -> BindNicGate {
        self.settings.bind_nic_gate()
    }

    /// The effective probe path the latency control shows and the probe
    /// command carries. Bind NIC reads as Native while the gate blocks.
    pub fn probe_path(&self) -> ProbePath {
        effective_probe_path(self.settings.latency_test_path, self.gate())
    }

    /// The probe command's `tun_outbound_interface` argument: Bind NIC carries
    /// the TUN screen's outbound interface, Native carries none. The probe
    /// runtime still gates the binding on its live backend ownership; without
    /// that capture the bind is treated as Native, which is the same OS path.
    pub fn probe_interface(&self) -> Option<String> {
        match self.probe_path() {
            ProbePath::BindNic => Some(self.settings.tun.auto_outbounds_interface.clone()),
            ProbePath::Native => None,
        }
    }

    /// The effective refresh path a fetch prefers for `subscription`: its
    /// override pair when the group has one, the global pair otherwise,
    /// degraded by the render gate. The transport additionally checks the live
    /// capture; the two agree whenever the tunnel is live.
    pub fn refresh_path(&self, subscription: Option<&Subscription>) -> RefreshPath {
        effective_refresh_path(self.refresh_pair(subscription).0, self.gate())
    }

    /// Resolve the effective refresh path into the fetch client's transport.
    /// The path and its SOCKS5 block are selected as one pair from the group's
    /// override, so a caller cannot dial the override's path through the
    /// global block. Bind NIC only binds while the live capture exists and no
    /// catch-all leak block is on; otherwise it and Native are the same OS
    /// path, so the fetch follows the stack instead of failing. `interfaces`
    /// is the caller's adapter view.
    pub fn refresh_transport(
        &self,
        subscription: Option<&Subscription>,
        interfaces: &[NetIf],
    ) -> Result<FetchTransport, PathError> {
        let (stored, socks5) = self.refresh_pair(subscription);
        match effective_refresh_path(stored, self.live_gate()) {
            RefreshPath::Native => Ok(FetchTransport::Native),
            RefreshPath::Socks5 => socks5_transport(socks5),
            RefreshPath::BindNic => self.bind_transport(interfaces),
        }
    }

    /// The refresh path and the SOCKS5 block in force, chosen together. A
    /// group's override replaces both; without one the global pair applies.
    fn refresh_pair<'s>(
        &'s self,
        subscription: Option<&'s Subscription>,
    ) -> (RefreshPath, &'s Socks5Cfg) {
        match subscription {
            Some(subscription) => subscription.effective_outbound(
                self.settings.subscription_path,
                &self.settings.subscription_socks5,
            ),
            None => (
                self.settings.subscription_path,
                &self.settings.subscription_socks5,
            ),
        }
    }

    /// The gate as the live capture makes it: without a live TUN there is no
    /// capture to bypass, so Bind NIC and Native are the same OS path.
    fn live_gate(&self) -> BindNicGate {
        if self.tun_live {
            self.gate()
        } else {
            BindNicGate::TunOff
        }
    }

    /// Bind the fetch to the adapter the TUN screen's outbound setting names.
    /// Only reached while the live gate leaves Bind NIC available.
    fn bind_transport(&self, interfaces: &[NetIf]) -> Result<FetchTransport, PathError> {
        let tun = &self.settings.tun;
        let tun_self_index = interfaces
            .iter()
            .find(|iface| iface.name == tun.effective_name())
            .map(|iface| iface.index);
        match resolve_probe_uplink(
            Some(&tun.auto_outbounds_interface),
            self.tun_live,
            tun_self_index,
            interfaces,
        ) {
            ProbeUplink::Unbound => Err(PathError::UplinkUnavailable(
                tun.auto_outbounds_interface.clone(),
            )),
            ProbeUplink::Interface(name) => interfaces
                .iter()
                .find(|iface| iface.name == name)
                .and_then(NetIf::bind_address)
                .map(FetchTransport::Bind)
                .ok_or_else(|| PathError::UplinkUnavailable(name.to_owned())),
            ProbeUplink::TunSelf { name } => Err(PathError::TunSelf(name.to_owned())),
            ProbeUplink::Down { name } => Err(PathError::UplinkDown(name.to_owned())),
            ProbeUplink::Missing { name } => Err(PathError::UplinkMissing(name.to_owned())),
        }
    }
}

/// Why a refresh path cannot carry a fetch. Every variant fails the fetch
/// loudly; none selects another carrier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathError {
    /// Bind NIC produced no source address: the TUN's outbound setting
    /// resolves to no adapter, or that adapter has no unicast address. The
    /// string is the configured setting (or the resolved adapter's name).
    UplinkUnavailable(String),
    /// The pinned adapter is the TUN's own adapter, which would send the
    /// fetch back into the tunnel.
    TunSelf(String),
    /// The pinned adapter exists but is down.
    UplinkDown(String),
    /// The pinned adapter is absent from the enumeration.
    UplinkMissing(String),
    /// The SOCKS5 host is blank.
    Socks5HostMissing,
    /// The SOCKS5 port is unset (0).
    Socks5PortMissing,
}

/// The SOCKS5 carrier's transport. Address and port are required; the
/// credentials are optional and travel together. A blank field fails loudly
/// instead of falling back to the OS stack.
fn socks5_transport(socks5: &Socks5Cfg) -> Result<FetchTransport, PathError> {
    let host = socks5.host.trim();
    if host.is_empty() {
        return Err(PathError::Socks5HostMissing);
    }
    if socks5.port == 0 {
        return Err(PathError::Socks5PortMissing);
    }
    let username = socks5
        .username
        .as_deref()
        .filter(|name| !name.trim().is_empty());
    let (username, password) = match username {
        Some(name) => (Some(name.to_owned()), socks5.password.clone()),
        // Credentials travel together: a password without a username is not a
        // usable SOCKS5 auth method.
        None => (None, None),
    };
    Ok(FetchTransport::Socks5 {
        host: host.to_owned(),
        port: socks5.port,
        username,
        password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::servers::Subscription;
    use crate::model::{Mode, Settings};
    use crate::sys::netif::test_iface;

    fn settings(mode: Mode, leak: &[&str], stored: RefreshPath) -> Settings {
        let mut settings = Settings {
            mode,
            ..Settings::default()
        };
        settings.tun.auto_outbounds_interface = "Ethernet".into();
        settings.tun.auto_system_wfp_block_leak =
            leak.iter().map(|entry| (*entry).to_owned()).collect();
        settings.subscription_path = stored;
        settings.subscription_socks5 = socks5("global.example", 1080, Some("gina"), Some("sealed"));
        settings
    }

    fn tun_and_ethernet() -> [NetIf; 2] {
        [
            test_iface("broccoli0", 9, false, true, &["10.255.0.1"]),
            test_iface("Ethernet", 2, false, true, &["10.0.0.7"]),
        ]
    }

    fn transport(
        settings: &Settings,
        tun_live: bool,
        subscription: Option<&Subscription>,
        interfaces: &[NetIf],
    ) -> Result<FetchTransport, PathError> {
        OutboundPath::resolve(settings, tun_live).refresh_transport(subscription, interfaces)
    }

    fn socks5(host: &str, port: u16, username: Option<&str>, password: Option<&str>) -> Socks5Cfg {
        Socks5Cfg {
            host: host.into(),
            port,
            username: username.map(str::to_owned),
            password: password.map(str::to_owned),
        }
    }

    #[test]
    fn bind_nic_degrades_to_native_while_the_tunnel_is_off() {
        let off = settings(Mode::Off, &[], RefreshPath::BindNic);
        assert_eq!(off.bind_nic_gate(), BindNicGate::TunOff);
        assert_eq!(
            effective_probe_path(ProbePath::BindNic, off.bind_nic_gate()),
            ProbePath::Native,
            "Bind NIC cannot bind while there is no capture to bypass"
        );
        let on = settings(Mode::Tun, &[], RefreshPath::BindNic);
        assert_eq!(
            effective_probe_path(ProbePath::BindNic, on.bind_nic_gate()),
            ProbePath::BindNic
        );
        assert_eq!(
            effective_probe_path(ProbePath::Native, on.bind_nic_gate()),
            ProbePath::Native,
            "an explicit Native preference stays Native"
        );

        assert_eq!(
            effective_refresh_path(RefreshPath::BindNic, off.bind_nic_gate()),
            RefreshPath::Native
        );
        assert_eq!(
            effective_refresh_path(RefreshPath::BindNic, on.bind_nic_gate()),
            RefreshPath::BindNic
        );
        // Native and SOCKS5 do not depend on the tunnel.
        for gate in [off.bind_nic_gate(), on.bind_nic_gate()] {
            assert_eq!(
                effective_refresh_path(RefreshPath::Native, gate),
                RefreshPath::Native
            );
            assert_eq!(
                effective_refresh_path(RefreshPath::Socks5, gate),
                RefreshPath::Socks5
            );
        }
    }

    #[test]
    fn bind_nic_degrades_to_native_while_the_leak_block_is_on() {
        let blocked = settings(Mode::Tun, &["allexceptlan"], RefreshPath::BindNic);
        let gate = blocked.bind_nic_gate();
        assert_eq!(gate, BindNicGate::LeakBlock);
        assert_eq!(
            effective_probe_path(ProbePath::BindNic, gate),
            ProbePath::Native,
            "the leak block drops every direct dial Bind NIC makes"
        );
        assert_eq!(
            effective_refresh_path(RefreshPath::BindNic, gate),
            RefreshPath::Native
        );
        assert_eq!(
            effective_probe_path(ProbePath::Native, gate),
            ProbePath::Native
        );
        assert_eq!(
            effective_refresh_path(RefreshPath::Socks5, gate),
            RefreshPath::Socks5,
            "SOCKS5 follows the OS stack, which the tunnel captures"
        );

        let off = settings(Mode::Off, &["allexceptlan"], RefreshPath::BindNic);
        assert_eq!(
            effective_probe_path(ProbePath::BindNic, off.bind_nic_gate()),
            ProbePath::Native,
            "TUN off already degrades, leak list or not"
        );
    }

    #[test]
    fn bind_nic_gate_names_tun_off_as_the_broader_reason() {
        assert_eq!(
            settings(Mode::Off, &[], RefreshPath::BindNic).bind_nic_gate(),
            BindNicGate::TunOff
        );
        assert_eq!(
            settings(Mode::Off, &["all"], RefreshPath::BindNic).bind_nic_gate(),
            BindNicGate::TunOff,
            "TUN off wins over the leak block"
        );
        assert_eq!(
            settings(Mode::Tun, &["allexceptlan"], RefreshPath::BindNic).bind_nic_gate(),
            BindNicGate::LeakBlock
        );
        assert_eq!(
            settings(Mode::Tun, &[], RefreshPath::BindNic).bind_nic_gate(),
            BindNicGate::Available
        );
        assert!(
            settings(Mode::Tun, &["all"], RefreshPath::BindNic)
                .bind_nic_gate()
                .blocks()
        );
        assert!(
            !settings(Mode::Tun, &[], RefreshPath::BindNic)
                .bind_nic_gate()
                .blocks()
        );
    }

    #[test]
    fn refresh_transport_follows_the_leak_block_when_bind_nic_is_stored() {
        let settings = settings(Mode::Tun, &["allexceptlan"], RefreshPath::BindNic);
        assert_eq!(
            transport(&settings, true, None, &tun_and_ethernet()),
            Ok(FetchTransport::Native),
            "a blocked bind must follow the tunnel, not fail the fetch"
        );
    }

    #[test]
    fn refresh_transport_keeps_bind_nic_for_a_custom_narrow_leak_list() {
        let settings = settings(Mode::Tun, &["tcp/853"], RefreshPath::BindNic);
        assert!(
            !settings.leak_block_blocks_bind_nic(),
            "a custom detail entry does not name every destination"
        );
        assert_eq!(
            transport(&settings, true, None, &tun_and_ethernet()),
            Ok(FetchTransport::Bind("10.0.0.7".parse().expect("ipv4"))),
            "an entry that cannot match the dial leaves Bind NIC working"
        );
    }

    #[test]
    fn probe_interface_maps_bind_nic_to_the_tun_selection() {
        let mut settings = settings(Mode::Tun, &[], RefreshPath::Native);
        settings.latency_test_path = ProbePath::BindNic;
        assert_eq!(
            OutboundPath::resolve(&settings, true).probe_interface(),
            Some("Ethernet".to_owned())
        );
        settings.tun.auto_outbounds_interface = "auto".into();
        assert_eq!(
            OutboundPath::resolve(&settings, true).probe_interface(),
            Some("auto".to_owned()),
            "the TUN screen's auto selection is passed through verbatim"
        );
        settings.latency_test_path = ProbePath::Native;
        assert_eq!(
            OutboundPath::resolve(&settings, true).probe_interface(),
            None
        );
    }

    #[test]
    fn native_and_socks5_refresh_transports_resolve_without_adapters() {
        let ethernet = test_iface("Ethernet", 2, false, true, &["10.0.0.7"]);
        let native = settings(Mode::Off, &[], RefreshPath::Native);
        assert_eq!(
            transport(&native, false, None, std::slice::from_ref(&ethernet)),
            Ok(FetchTransport::Native)
        );

        let mut socks = settings(Mode::Off, &[], RefreshPath::Socks5);
        socks.subscription_socks5 = socks5("proxy.example", 1080, Some("alice"), Some("s3cr3t"));
        assert_eq!(
            transport(&socks, false, None, &[ethernet]),
            Ok(FetchTransport::Socks5 {
                host: "proxy.example".into(),
                port: 1080,
                username: Some("alice".into()),
                password: Some("s3cr3t".into()),
            }),
            "SOCKS5 needs no TUN and no adapter binding"
        );
    }

    #[test]
    fn socks5_without_credentials_drops_a_stray_password() {
        let mut settings = settings(Mode::Off, &[], RefreshPath::Socks5);
        settings.subscription_socks5 = socks5(" proxy.example ", 1080, None, Some("ignored"));
        assert_eq!(
            transport(&settings, false, None, &[]),
            Ok(FetchTransport::Socks5 {
                host: "proxy.example".into(),
                port: 1080,
                username: None,
                password: None,
            })
        );

        settings.subscription_socks5 = socks5("proxy.example", 1080, Some("   "), Some("ignored"));
        assert_eq!(
            transport(&settings, false, None, &[]),
            Ok(FetchTransport::Socks5 {
                host: "proxy.example".into(),
                port: 1080,
                username: None,
                password: None,
            }),
            "a blank username counts as absent"
        );
    }

    #[test]
    fn socks5_missing_fields_fail_loudly() {
        let mut settings = settings(Mode::Off, &[], RefreshPath::Socks5);
        settings.subscription_socks5 = socks5("", 1080, None, None);
        assert_eq!(
            transport(&settings, false, None, &[]),
            Err(PathError::Socks5HostMissing),
            "a blank host must not fall back to the OS stack"
        );

        settings.subscription_socks5 = socks5("   ", 1080, None, None);
        assert_eq!(
            transport(&settings, false, None, &[]),
            Err(PathError::Socks5HostMissing)
        );

        settings.subscription_socks5 = socks5("proxy.example", 0, None, None);
        assert_eq!(
            transport(&settings, false, None, &[]),
            Err(PathError::Socks5PortMissing)
        );
    }

    #[test]
    fn bind_nic_binds_the_resolved_adapter_address() {
        let settings = settings(Mode::Tun, &[], RefreshPath::BindNic);
        let interfaces = [
            test_iface("broccoli0", 9, false, true, &["10.255.0.1"]),
            test_iface("Ethernet", 2, false, true, &["fe80::1", "10.0.0.7"]),
        ];
        assert_eq!(
            transport(&settings, true, None, &interfaces),
            Ok(FetchTransport::Bind("10.0.0.7".parse().expect("ipv4")))
        );
    }

    #[test]
    fn bind_nic_stays_a_preference_while_the_tunnel_is_off() {
        let settings = settings(Mode::Off, &[], RefreshPath::BindNic);
        let interfaces = [test_iface("Ethernet", 2, false, true, &["10.0.0.7"])];
        assert_eq!(
            transport(&settings, false, None, &interfaces),
            Ok(FetchTransport::Native),
            "the stored preference is retained, but the fetch follows the OS stack"
        );
        assert_eq!(
            settings.subscription_path,
            RefreshPath::BindNic,
            "resolving never rewrites the stored preference"
        );
    }

    #[test]
    fn bind_nic_before_the_tunnel_connects_follows_native() {
        let settings = settings(Mode::Tun, &[], RefreshPath::BindNic);
        let ethernet = test_iface("Ethernet", 2, false, true, &["10.0.0.7"]);
        assert_eq!(
            transport(&settings, false, None, std::slice::from_ref(&ethernet)),
            Ok(FetchTransport::Native),
            "without a live capture Bind NIC and Native are the same path"
        );
    }

    #[test]
    fn bind_nic_failures_are_loud() {
        let mut settings = settings(Mode::Tun, &[], RefreshPath::BindNic);
        settings.tun.auto_outbounds_interface = "ghost".into();
        assert_eq!(
            transport(&settings, true, None, &[]),
            Err(PathError::UplinkMissing("ghost".into()))
        );

        settings.tun.auto_outbounds_interface = "wired".into();
        let down = [test_iface("wired", 3, false, false, &[])];
        assert_eq!(
            transport(&settings, true, None, &down),
            Err(PathError::UplinkDown("wired".into()))
        );

        settings.tun.auto_outbounds_interface = "broccoli0".into();
        let tun_self = [
            test_iface("broccoli0", 9, false, true, &["10.255.0.1"]),
            test_iface("Ethernet", 2, false, true, &["10.0.0.7"]),
        ];
        assert_eq!(
            transport(&settings, true, None, &tun_self),
            Err(PathError::TunSelf("broccoli0".into()))
        );
    }

    #[test]
    fn an_unbound_bind_nic_uplink_fails_instead_of_falling_back() {
        // The adapter exists and is up, but carries no address to bind.
        let settings = settings(Mode::Tun, &[], RefreshPath::BindNic);
        let interfaces = [test_iface("Ethernet", 2, false, true, &[])];
        assert_eq!(
            transport(&settings, true, None, &interfaces),
            Err(PathError::UplinkUnavailable("Ethernet".into()))
        );
    }

    #[test]
    fn a_catch_all_leak_scope_never_binds_and_a_dead_tunnel_follows_the_os_stack() {
        let interfaces = tun_and_ethernet();
        for leak in [&["all"][..], &["allexceptlan"][..]] {
            let settings = settings(Mode::Tun, leak, RefreshPath::BindNic);
            assert_eq!(settings.bind_nic_gate(), BindNicGate::LeakBlock);
            assert_eq!(
                transport(&settings, true, None, &interfaces),
                Ok(FetchTransport::Native),
                "a catch-all scope blocks every Bind NIC dial, live capture or not"
            );
        }

        let open = settings(Mode::Tun, &[], RefreshPath::BindNic);
        assert_eq!(
            transport(&open, false, None, &interfaces),
            Ok(FetchTransport::Native),
            "with no live capture the transport follows the OS stack"
        );
        assert_eq!(
            transport(&open, true, None, &interfaces),
            Ok(FetchTransport::Bind("10.0.0.7".parse().expect("ipv4")))
        );
    }

    #[test]
    fn a_socks5_override_with_an_empty_host_fails_even_when_the_global_block_has_one() {
        let settings = settings(Mode::Tun, &[], RefreshPath::Socks5);
        let override_pair = Subscription {
            outbound_custom: true,
            outbound_path: RefreshPath::Socks5,
            socks5: Socks5Cfg::default(),
            ..Subscription::default()
        };
        assert_eq!(
            transport(&settings, true, Some(&override_pair), &[]),
            Err(PathError::Socks5HostMissing),
            "the override's empty carrier must not borrow the global host"
        );

        let no_override = Subscription::default();
        assert_eq!(
            transport(&settings, true, Some(&no_override), &[]),
            Ok(FetchTransport::Socks5 {
                host: "global.example".into(),
                port: 1080,
                username: Some("gina".into()),
                password: Some("sealed".into()),
            }),
            "without an override the global pair stays whole"
        );
    }
}
