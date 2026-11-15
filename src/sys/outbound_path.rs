//! The outbound path shared by the latency probe and subscription refresh.
//!
//! Bind NIC uses the TUN screen's outbound-interface selection and the same
//! resolver the tunnel guard and the probe use; Native follows the OS stack,
//! which the tunnel captures while it is up. SOCKS5 exists on the refresh
//! side. Bind NIC is usable only while TUN mode is on and the leak scope
//! leaves a bypass: `all` and `allexceptlan` block every destination outside
//! the tunnel, while a custom list names the dials it blocks. Before the
//! tunnel connects, or under a catch-all scope, Bind NIC and Native are the
//! same OS path, so a probe or refresh follows the stack instead of failing.
//!
//! Every resolution that cannot produce its carrier fails loudly. The one
//! equivalent fallback is Bind NIC while no bypass is possible: with no TUN
//! traffic to bypass it and Native are the same OS path.

use crate::model::{ProbePath, RefreshPath, Socks5Cfg, TunCfg};
use crate::sys::netif::{NetIf, ProbeUplink, resolve_probe_uplink};
use crate::sys::subscription::FetchTransport;

/// The two path vocabularies' shared degradation rule: Bind NIC reads as
/// Native when the tunnel cannot carry a bind or the leak scope blocks every
/// bypass; every other path stays as stored.
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

fn effective_path<P: PathDegrade>(stored: P, tun_enabled: bool, leak_block: bool) -> P {
    if stored.is_bind_nic() && (!tun_enabled || leak_block) {
        P::native()
    } else {
        stored
    }
}

/// The effective probe path. Bind NIC binds the physical uplink to bypass the
/// TUN capture, which only exists while the tunnel is up; when TUN mode is
/// off, or a catch-all leak scope blocks every bypass, the effective path is
/// Native.
pub fn effective_probe_path(stored: ProbePath, tun_enabled: bool, leak_block: bool) -> ProbePath {
    effective_path(stored, tun_enabled, leak_block)
}

/// The effective refresh path. Bind NIC behaves as it does for the probe;
/// Native and SOCKS5 stay as stored, because neither bypasses the tunnel.
pub fn effective_refresh_path(
    stored: RefreshPath,
    tun_enabled: bool,
    leak_block: bool,
) -> RefreshPath {
    effective_path(stored, tun_enabled, leak_block)
}

/// The probe command's `tun_outbound_interface` argument: Bind NIC carries the
/// TUN screen's outbound interface, Native carries none. The runtime still
/// gates the binding on its live backend ownership; without that capture the
/// bind is treated as Native, which is the same OS path.
pub fn probe_interface_setting(path: ProbePath, tun: &TunCfg) -> Option<String> {
    match path {
        ProbePath::BindNic => Some(tun.auto_outbounds_interface.clone()),
        ProbePath::Native => None,
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

/// Resolve the effective refresh path into the fetch client's transport.
/// `path` and `socks5` are the values in force (the global setting or the
/// override's). `tun_enabled` is the TUN mode switch and `tun_live` the live
/// TUN ownership the caller observes. `leak_block` is whether the emitted TUN
/// config carries a leak block that blocks every bypass. Bind NIC only binds
/// while the live capture exists and no such block is on; otherwise it and
/// Native are the same OS path, so the fetch follows the stack instead of
/// failing. `interfaces` is the caller's adapter view.
pub fn refresh_transport(
    path: RefreshPath,
    socks5: &Socks5Cfg,
    tun: &TunCfg,
    tun_enabled: bool,
    tun_live: bool,
    leak_block: bool,
    interfaces: &[NetIf],
) -> Result<FetchTransport, PathError> {
    match effective_refresh_path(path, tun_enabled && tun_live, leak_block) {
        RefreshPath::Native => Ok(FetchTransport::Native),
        RefreshPath::Socks5 => {
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
                // Credentials travel together: a password without a username
                // is not a usable SOCKS5 auth method.
                None => (None, None),
            };
            Ok(FetchTransport::Socks5 {
                host: host.to_owned(),
                port: socks5.port,
                username,
                password,
            })
        }
        RefreshPath::BindNic => {
            // The effective path says Bind NIC is selected and the live
            // capture exists; resolve the adapter it names.
            let tun_self_index = interfaces
                .iter()
                .find(|iface| iface.name == tun.effective_name())
                .map(|iface| iface.index);
            match resolve_probe_uplink(
                Some(&tun.auto_outbounds_interface),
                tun_live,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::netif::test_iface;

    /// The pre-liveness call shape: a path test that is not about the
    /// enabled/live split treats an enabled TUN as a live one.
    fn refresh_transport(
        path: RefreshPath,
        socks5: &Socks5Cfg,
        tun: &TunCfg,
        tun_active: bool,
        interfaces: &[NetIf],
    ) -> Result<FetchTransport, PathError> {
        super::refresh_transport(path, socks5, tun, tun_active, tun_active, false, interfaces)
    }

    fn tun(setting: &str) -> TunCfg {
        TunCfg {
            name: "broccoli0".into(),
            auto_outbounds_interface: setting.into(),
            // The seed leak list is non-empty; these tests isolate the path
            // rules, so the leak block is off unless a case turns it on.
            auto_system_wfp_block_leak: Vec::new(),
            ..Default::default()
        }
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
        assert_eq!(
            effective_probe_path(ProbePath::BindNic, false, false),
            ProbePath::Native,
            "Bind NIC cannot bind while there is no capture to bypass"
        );
        assert_eq!(
            effective_probe_path(ProbePath::BindNic, true, false),
            ProbePath::BindNic
        );
        assert_eq!(
            effective_probe_path(ProbePath::Native, true, false),
            ProbePath::Native,
            "an explicit Native preference stays Native"
        );

        assert_eq!(
            effective_refresh_path(RefreshPath::BindNic, false, false),
            RefreshPath::Native
        );
        assert_eq!(
            effective_refresh_path(RefreshPath::BindNic, true, false),
            RefreshPath::BindNic
        );
        // Native and SOCKS5 do not depend on the tunnel.
        for tun_active in [false, true] {
            assert_eq!(
                effective_refresh_path(RefreshPath::Native, tun_active, false),
                RefreshPath::Native
            );
            assert_eq!(
                effective_refresh_path(RefreshPath::Socks5, tun_active, false),
                RefreshPath::Socks5
            );
        }
    }

    #[test]
    fn bind_nic_degrades_to_native_while_the_leak_block_is_on() {
        assert_eq!(
            effective_probe_path(ProbePath::BindNic, true, true),
            ProbePath::Native,
            "the leak block drops every direct dial Bind NIC makes"
        );
        assert_eq!(
            effective_refresh_path(RefreshPath::BindNic, true, true),
            RefreshPath::Native
        );
        assert_eq!(
            effective_probe_path(ProbePath::Native, true, true),
            ProbePath::Native
        );
        assert_eq!(
            effective_refresh_path(RefreshPath::Socks5, true, true),
            RefreshPath::Socks5,
            "SOCKS5 follows the OS stack, which the tunnel captures"
        );
        assert_eq!(
            effective_probe_path(ProbePath::BindNic, false, true),
            ProbePath::Native,
            "TUN off already degrades, leak list or not"
        );
    }

    #[test]
    fn refresh_transport_follows_the_leak_block_when_bind_nic_is_stored() {
        let interfaces = [
            test_iface("broccoli0", 9, false, true, &["10.255.0.1"]),
            test_iface("Ethernet", 2, false, true, &["10.0.0.7"]),
        ];
        let mut tun = tun("Ethernet");
        tun.auto_system_wfp_block_leak = vec!["allexceptlan".into()];
        assert_eq!(
            super::refresh_transport(
                RefreshPath::BindNic,
                &Socks5Cfg::default(),
                &tun,
                true,
                true,
                true,
                &interfaces,
            ),
            Ok(FetchTransport::Native),
            "a blocked bind must follow the tunnel, not fail the fetch"
        );
    }

    #[test]
    fn refresh_transport_keeps_bind_nic_for_a_custom_narrow_leak_list() {
        let interfaces = [
            test_iface("broccoli0", 9, false, true, &["10.255.0.1"]),
            test_iface("Ethernet", 2, false, true, &["10.0.0.7"]),
        ];
        let mut tun = tun("Ethernet");
        tun.auto_system_wfp_block_leak = vec!["tcp/853".into()];
        let leak_block = tun.leak_scope_blocks_direct_dials();
        assert!(
            !leak_block,
            "a custom detail entry does not name every destination"
        );
        assert_eq!(
            super::refresh_transport(
                RefreshPath::BindNic,
                &Socks5Cfg::default(),
                &tun,
                true,
                true,
                leak_block,
                &interfaces,
            ),
            Ok(FetchTransport::Bind("10.0.0.7".parse().expect("ipv4"))),
            "an entry that cannot match the dial leaves Bind NIC working"
        );
    }

    #[test]
    fn probe_interface_setting_maps_bind_nic_to_the_tun_selection() {
        let tun_cfg = tun("Ethernet");
        assert_eq!(
            probe_interface_setting(ProbePath::BindNic, &tun_cfg),
            Some("Ethernet".to_owned())
        );
        assert_eq!(
            probe_interface_setting(ProbePath::BindNic, &tun("auto")),
            Some("auto".to_owned()),
            "the TUN screen's auto selection is passed through verbatim"
        );
        assert_eq!(probe_interface_setting(ProbePath::Native, &tun_cfg), None);
    }

    #[test]
    fn native_and_socks5_refresh_transports_resolve_without_adapters() {
        let ethernet = test_iface("Ethernet", 2, false, true, &["10.0.0.7"]);
        assert_eq!(
            refresh_transport(
                RefreshPath::Native,
                &Socks5Cfg::default(),
                &tun("Ethernet"),
                false,
                std::slice::from_ref(&ethernet),
            ),
            Ok(FetchTransport::Native)
        );

        assert_eq!(
            refresh_transport(
                RefreshPath::Socks5,
                &socks5("proxy.example", 1080, Some("alice"), Some("s3cr3t")),
                &tun("Ethernet"),
                false,
                &[ethernet],
            ),
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
        assert_eq!(
            refresh_transport(
                RefreshPath::Socks5,
                &socks5(" proxy.example ", 1080, None, Some("ignored")),
                &tun("Ethernet"),
                false,
                &[],
            ),
            Ok(FetchTransport::Socks5 {
                host: "proxy.example".into(),
                port: 1080,
                username: None,
                password: None,
            })
        );
        assert_eq!(
            refresh_transport(
                RefreshPath::Socks5,
                &socks5("proxy.example", 1080, Some("   "), Some("ignored")),
                &tun("Ethernet"),
                false,
                &[],
            ),
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
        let missing_host = socks5("", 1080, None, None);
        assert_eq!(
            refresh_transport(
                RefreshPath::Socks5,
                &missing_host,
                &tun("Ethernet"),
                false,
                &[],
            ),
            Err(PathError::Socks5HostMissing),
            "a blank host must not fall back to the OS stack"
        );

        let blank_host = socks5("   ", 1080, None, None);
        assert_eq!(
            refresh_transport(
                RefreshPath::Socks5,
                &blank_host,
                &tun("Ethernet"),
                false,
                &[],
            ),
            Err(PathError::Socks5HostMissing)
        );

        let missing_port = socks5("proxy.example", 0, None, None);
        assert_eq!(
            refresh_transport(
                RefreshPath::Socks5,
                &missing_port,
                &tun("Ethernet"),
                false,
                &[],
            ),
            Err(PathError::Socks5PortMissing)
        );
    }

    #[test]
    fn bind_nic_binds_the_resolved_adapter_address() {
        let interfaces = [
            test_iface("broccoli0", 9, false, true, &["10.255.0.1"]),
            test_iface("Ethernet", 2, false, true, &["fe80::1", "10.0.0.7"]),
        ];
        assert_eq!(
            refresh_transport(
                RefreshPath::BindNic,
                &Socks5Cfg::default(),
                &tun("Ethernet"),
                true,
                &interfaces,
            ),
            Ok(FetchTransport::Bind("10.0.0.7".parse().expect("ipv4")))
        );
    }

    #[test]
    fn bind_nic_stays_a_preference_while_the_tunnel_is_off() {
        let interfaces = [test_iface("Ethernet", 2, false, true, &["10.0.0.7"])];
        assert_eq!(
            refresh_transport(
                RefreshPath::BindNic,
                &Socks5Cfg::default(),
                &tun("Ethernet"),
                false,
                &interfaces,
            ),
            Ok(FetchTransport::Native),
            "the stored preference is retained, but the fetch follows the OS stack"
        );
    }

    #[test]
    fn bind_nic_before_the_tunnel_connects_follows_native() {
        let ethernet = test_iface("Ethernet", 2, false, true, &["10.0.0.7"]);
        let result = super::refresh_transport(
            RefreshPath::BindNic,
            &Socks5Cfg::default(),
            &tun("Ethernet"),
            true,
            false,
            false,
            std::slice::from_ref(&ethernet),
        );
        assert_eq!(
            result,
            Ok(FetchTransport::Native),
            "without a live capture Bind NIC and Native are the same path"
        );
    }

    #[test]
    fn bind_nic_failures_are_loud() {
        let missing = refresh_transport(
            RefreshPath::BindNic,
            &Socks5Cfg::default(),
            &tun("ghost"),
            true,
            &[],
        );
        assert_eq!(missing, Err(PathError::UplinkMissing("ghost".into())));

        let down = [test_iface("wired", 3, false, false, &[])];
        let down = refresh_transport(
            RefreshPath::BindNic,
            &Socks5Cfg::default(),
            &tun("wired"),
            true,
            &down,
        );
        assert_eq!(down, Err(PathError::UplinkDown("wired".into())));

        let tun_self = [
            test_iface("broccoli0", 9, false, true, &["10.255.0.1"]),
            test_iface("Ethernet", 2, false, true, &["10.0.0.7"]),
        ];
        let tun_self = refresh_transport(
            RefreshPath::BindNic,
            &Socks5Cfg::default(),
            &tun("broccoli0"),
            true,
            &tun_self,
        );
        assert_eq!(tun_self, Err(PathError::TunSelf("broccoli0".into())));
    }

    #[test]
    fn an_unbound_bind_nic_uplink_fails_instead_of_falling_back() {
        // The adapter exists and is up, but carries no address to bind.
        let interfaces = [test_iface("Ethernet", 2, false, true, &[])];
        assert_eq!(
            refresh_transport(
                RefreshPath::BindNic,
                &Socks5Cfg::default(),
                &tun("Ethernet"),
                true,
                &interfaces,
            ),
            Err(PathError::UplinkUnavailable("Ethernet".into()))
        );
    }
}
