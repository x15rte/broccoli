//! The in-tun DNS listeners: the inbounds the runtime adds to a *running*
//! core instead of emitting them into the generated config.
//!
//! Each listener is a dokodemo bound to one gateway address of the tunnel —
//! the IPv4 address the tun inbound pins the adapter DNS to, and the IPv6
//! gateway the same inbound assigns to the adapter. Those addresses exist
//! only after the tun inbound's `Start()` created the wintun adapter and
//! assigned them, and Xray starts tagged inbounds in Go map order, so a
//! listener emitted into the static config loses the ordering race in a
//! fraction of cold starts: `failed to listen TCP on 53 … The requested
//! address is not valid in its context`, the core dying pre-readiness. Adding
//! the listeners through the control plane, after the core is up, makes the
//! bind deterministic — the addresses the listeners need are the addresses
//! the running core already owns — and turns a start-order roll into a
//! bounded, retryable control-plane call.
//!
//! Both families are served because the system-DNS takeover points the other
//! adapters' server list for a family at the tunnel address of that same
//! family (`sys::dns_takeover`): an address with no listener answers nothing,
//! so leaving the IPv6 gateway unserved would send every IPv6 query of a
//! taken-over adapter to a dead server.
//!
//! The config still carries the module and its interception rule, so the
//! listeners' settings stay derivable from it: the in-tun addresses are the
//! ones the tun inbound assigns, and the `dns-in`/`dns-in6` rule is what
//! routes the listeners' queries into the DNS module.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::Value;

use super::grpc::pb;
use crate::r#gen::keys;
use crate::model::inbound::{DNS_INBOUND_TAG, DNS_INBOUND_V6_TAG};

/// The port the in-tun DNS listeners serve.
pub const PORT: u16 = 53;
/// The dokodemo's rewrite target: what the listener forwards queries to. The
/// module's interception rule matches the rewritten destination's port and
/// hands the query to `dns-out`, so only the port is load-bearing; the
/// address is a placeholder in place of which the module resolves.
pub(crate) const REWRITE: (Ipv4Addr, u16) = (Ipv4Addr::new(8, 8, 8, 8), 53);

/// The listeners one running core needs: the addresses the tunnel serves DNS
/// on. One per gateway address family the config carries, because the DNS
/// takeover points the other adapters' server list for a family at the tunnel
/// address of that same family — an address with no listener answers nothing,
/// and a family the tunnel cannot serve is left untouched on every adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listener {
    /// The address the tun inbound pins as the adapter DNS: the TUN gateway's
    /// IPv4 address.
    pub v4: Option<Ipv4Addr>,
    /// The tunnel's IPv6 gateway, when the config carries one.
    pub v6: Option<Ipv6Addr>,
}

impl Listener {
    /// The addresses to add, IPv4 first.
    pub(crate) fn addresses(&self) -> Vec<IpAddr> {
        self.v4
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.v6.map(IpAddr::V6))
            .collect()
    }
}

/// The tag one in-tun DNS listener binds under, by address family: Xray's
/// inbound manager keys handlers by tag, so the second listener needs its own,
/// and the emitted interception rule names both.
pub(crate) fn tag_of(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(_) => DNS_INBOUND_TAG,
        IpAddr::V6(_) => DNS_INBOUND_V6_TAG,
    }
}

/// The `HandlerService.AddInbound` payload for one listener address, shaped
/// exactly as the config loader builds it from an emitted inbound: receiver
/// listen address plus a single-port list, and the dokodemo rewrite target on
/// TCP and UDP.
pub(crate) fn inbound_config(address: IpAddr) -> pb::xray::core::InboundHandlerConfig {
    let receiver = pb::xray::app::proxyman::ReceiverConfig {
        port_list: Some(pb::xray::common::net::PortList {
            range: vec![pb::xray::common::net::PortRange {
                from: u32::from(PORT),
                to: u32::from(PORT),
            }],
        }),
        listen: Some(ip_or_domain(address)),
        ..Default::default()
    };
    let dokodemo = pb::xray::proxy::dokodemo::Config {
        allowed_networks: vec![
            pb::xray::common::net::Network::Tcp as i32,
            pb::xray::common::net::Network::Udp as i32,
        ],
        rewrite_address: Some(ip_or_domain(IpAddr::V4(REWRITE.0))),
        rewrite_port: u32::from(REWRITE.1),
        ..Default::default()
    };
    pb::xray::core::InboundHandlerConfig {
        tag: tag_of(address).to_string(),
        receiver_settings: Some(typed_message("xray.app.proxyman.ReceiverConfig", &receiver)),
        proxy_settings: Some(typed_message("xray.proxy.dokodemo.Config", &dokodemo)),
    }
}

/// The listener a core running `config` needs, or `None` when the config
/// carries no DNS module, no TUN inbound, or no address the runtime could
/// serve on. Mirrors the generator's emission gates: the module is the
/// top-level `dns` object (`gen::generate`), the tun inbound exists only in
/// TUN mode, and with the module on the tun inbound pins its adapter DNS to
/// the in-tun IPv4 address and assigns its IPv6 gateway to the adapter
/// (`gen::inbounds`), which are therefore the addresses the listeners bind.
pub fn listener_for_config(config: &Value) -> Option<Listener> {
    config.get(keys::DNS)?.as_object()?;
    let inbounds = config.get(keys::INBOUNDS)?.as_array()?;
    // A config that declares its own listener (a raw override writes the
    // config verbatim) owns that socket, whatever address family it names:
    // the runtime must neither add nor replace it. The check is per family, so
    // a config that declares only one still gets the other.
    let declared = |tag: &str| {
        inbounds
            .iter()
            .any(|inbound| inbound.get(keys::TAG).and_then(Value::as_str) == Some(tag))
    };
    let tun = inbounds
        .iter()
        .find(|inbound| inbound.get(keys::PROTOCOL).and_then(Value::as_str) == Some("tun"))?;
    let settings = tun.get(keys::SETTINGS)?;
    let v4 = (!declared(DNS_INBOUND_TAG))
        .then(|| adapter_dns_v4(settings))
        .flatten();
    let v6 = (!declared(DNS_INBOUND_V6_TAG))
        .then(|| gateway_ipv6(settings))
        .flatten();
    (v4.is_some() || v6.is_some()).then_some(Listener { v4, v6 })
}

/// The in-tun address the tun inbound pins as the adapter DNS.
fn adapter_dns_v4(settings: &Value) -> Option<Ipv4Addr> {
    settings
        .get(keys::DNS)?
        .as_array()?
        .first()?
        .as_str()?
        .parse()
        .ok()
}

/// The tunnel's first IPv6 gateway, without its prefix length: the adapter
/// address the tunnel serves IPv6 DNS on.
fn gateway_ipv6(settings: &Value) -> Option<Ipv6Addr> {
    settings
        .get(keys::GATEWAY)?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .find_map(|entry| entry.split('/').next()?.parse().ok())
}

/// [`listener_for_config`] over the raw bytes of a config file. Unparsable
/// bytes yield `None`: the core could not have started from them either, and
/// the add is best-effort by design.
pub(crate) fn listener_for_bytes(bytes: &[u8]) -> Option<Listener> {
    listener_for_config(&serde_json::from_slice(bytes).ok()?)
}

fn ip_or_domain(address: IpAddr) -> pb::xray::common::net::IpOrDomain {
    let octets = match address {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    pb::xray::common::net::IpOrDomain {
        address: Some(pb::xray::common::net::ip_or_domain::Address::Ip(octets)),
    }
}

/// Wrap one message in the `TypedMessage` the core resolves through its
/// protobuf registry; the type string must be the exact full name.
fn typed_message<T: prost::Message>(
    type_name: &str,
    message: &T,
) -> pb::xray::common::serial::TypedMessage {
    pb::xray::common::serial::TypedMessage {
        r#type: type_name.to_string(),
        value: message.encode_to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn listener_derives_from_the_module_and_the_tun_adapter_addresses() {
        let config = json!({
            "inbounds": [
                {
                    "protocol": "tun",
                    "settings": {
                        "name": "broccoli0",
                        "dns": ["10.255.0.1"],
                        "gateway": ["10.255.0.1/30", "fd00::1/64"],
                    },
                },
            ],
            "dns": { "servers": ["1.1.1.1"] },
        });
        assert_eq!(
            listener_for_config(&config),
            Some(Listener {
                v4: Some(Ipv4Addr::new(10, 255, 0, 1)),
                v6: Some("fd00::1".parse().unwrap()),
            })
        );
    }

    #[test]
    fn listener_carries_a_family_only_when_the_tunnel_assigns_one() {
        // A tunnel without an IPv6 gateway serves no IPv6 DNS, so the runtime
        // must not bind one there — and the takeover leaves IPv6 alone.
        let v4_only = json!({
            "inbounds": [
                {
                    "protocol": "tun",
                    "settings": { "name": "broccoli0", "dns": ["10.255.0.1"] },
                },
            ],
            "dns": { "servers": ["1.1.1.1"] },
        });
        assert_eq!(
            listener_for_config(&v4_only),
            Some(Listener {
                v4: Some(Ipv4Addr::new(10, 255, 0, 1)),
                v6: None,
            })
        );
    }

    #[test]
    fn listener_needs_both_the_module_and_a_tun_inbound() {
        let tun = json!({
            "inbounds": [
                { "protocol": "tun", "settings": { "name": "broccoli0", "dns": ["10.255.0.1"] } },
            ],
        });
        assert_eq!(listener_for_config(&tun), None, "no module, no listener");

        let mut null_module = tun;
        null_module["dns"] = Value::Null;
        assert_eq!(
            listener_for_config(&null_module),
            None,
            "a null dns block is not a module"
        );

        let module_only = json!({
            "inbounds": [{ "protocol": "socks", "settings": {} }],
            "dns": { "servers": ["1.1.1.1"] },
        });
        assert_eq!(
            listener_for_config(&module_only),
            None,
            "no tun inbound, no listener"
        );
    }

    #[test]
    fn listener_steps_aside_per_family_for_a_config_with_its_own_listener() {
        // A raw override carries the config verbatim, so it may declare the
        // listener itself — under a tag the runtime would use. The runtime
        // must leave that socket alone instead of removing and rebinding it,
        // and a family it does not declare still gets its listener.
        let v4_declared = json!({
            "inbounds": [
                {
                    "protocol": "tun",
                    "settings": {
                        "name": "broccoli0",
                        "dns": ["10.255.0.1"],
                        "gateway": ["10.255.0.1/30", "fd00::1/64"],
                    },
                },
                {
                    "protocol": "dokodemo-door",
                    "listen": "10.255.0.1",
                    "port": 53,
                    "tag": DNS_INBOUND_TAG,
                },
            ],
            "dns": { "servers": ["1.1.1.1"] },
        });
        assert_eq!(
            listener_for_config(&v4_declared),
            Some(Listener {
                v4: None,
                v6: Some("fd00::1".parse().unwrap()),
            }),
            "only the family the config declares is left alone"
        );

        let both = json!({
            "inbounds": [
                {
                    "protocol": "tun",
                    "settings": {
                        "name": "broccoli0",
                        "dns": ["10.255.0.1"],
                        "gateway": ["10.255.0.1/30", "fd00::1/64"],
                    },
                },
                { "protocol": "dokodemo-door", "port": 53, "tag": DNS_INBOUND_TAG },
                { "protocol": "dokodemo-door", "port": 53, "tag": DNS_INBOUND_V6_TAG },
            ],
            "dns": { "servers": ["1.1.1.1"] },
        });
        assert_eq!(listener_for_config(&both), None);
    }

    #[test]
    fn listener_skips_non_ipv4_or_empty_adapter_dns() {
        // Without the module the generator leaves the user's adapter DNS
        // list alone, so this shape is a real config state: nothing pins the
        // in-tun IPv4 address, and with no IPv6 gateway there is nothing to
        // add at all.
        let domain_dns = json!({
            "inbounds": [
                { "protocol": "tun", "settings": { "name": "broccoli0", "dns": ["localhost"] } },
            ],
            "dns": { "servers": ["1.1.1.1"] },
        });
        assert_eq!(listener_for_config(&domain_dns), None);

        let no_dns = json!({
            "inbounds": [{ "protocol": "tun", "settings": { "name": "broccoli0" } }],
            "dns": { "servers": ["1.1.1.1"] },
        });
        assert_eq!(listener_for_config(&no_dns), None);

        // The same config with an IPv6 gateway still owes the tunnel an IPv6
        // listener: that address is where the takeover sends IPv6 queries.
        let v6_only = json!({
            "inbounds": [
                {
                    "protocol": "tun",
                    "settings": {
                        "name": "broccoli0",
                        "dns": ["localhost"],
                        "gateway": ["fd00::1/64"],
                    },
                },
            ],
            "dns": { "servers": ["1.1.1.1"] },
        });
        assert_eq!(
            listener_for_config(&v6_only),
            Some(Listener {
                v4: None,
                v6: Some("fd00::1".parse().unwrap()),
            })
        );
    }

    #[test]
    fn inbound_config_matches_the_emitted_wire_shape() {
        use prost::Message as _;

        let inbound = inbound_config(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1)));
        assert_eq!(inbound.tag, DNS_INBOUND_TAG);

        let receiver = inbound.receiver_settings.expect("receiver settings");
        assert_eq!(receiver.r#type, "xray.app.proxyman.ReceiverConfig");
        let receiver = pb::xray::app::proxyman::ReceiverConfig::decode(receiver.value.as_slice())
            .expect("receiver settings decode");
        assert_eq!(
            receiver.listen,
            Some(ip_or_domain(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1))))
        );
        assert_eq!(
            receiver.port_list,
            Some(pb::xray::common::net::PortList {
                range: vec![pb::xray::common::net::PortRange {
                    from: u32::from(PORT),
                    to: u32::from(PORT),
                }],
            })
        );
        assert!(!receiver.receive_original_destination);

        let proxy = inbound.proxy_settings.expect("proxy settings");
        assert_eq!(proxy.r#type, "xray.proxy.dokodemo.Config");
        let dokodemo = pb::xray::proxy::dokodemo::Config::decode(proxy.value.as_slice())
            .expect("dokodemo settings decode");
        assert_eq!(
            dokodemo.allowed_networks,
            vec![
                pb::xray::common::net::Network::Tcp as i32,
                pb::xray::common::net::Network::Udp as i32,
            ]
        );
        assert_eq!(
            dokodemo.rewrite_address,
            Some(ip_or_domain(IpAddr::V4(REWRITE.0)))
        );
        assert_eq!(dokodemo.rewrite_port, u32::from(REWRITE.1));
    }

    #[test]
    fn the_ipv6_listener_binds_the_tunnel_gateway_under_its_own_tag() {
        use prost::Message as _;

        let address: IpAddr = "fd00::1".parse().unwrap();
        let inbound = inbound_config(address);
        assert_eq!(
            inbound.tag, DNS_INBOUND_V6_TAG,
            "a second tag: the manager keys handlers by tag"
        );

        let receiver = inbound.receiver_settings.expect("receiver settings");
        let receiver = pb::xray::app::proxyman::ReceiverConfig::decode(receiver.value.as_slice())
            .expect("receiver settings decode");
        assert_eq!(receiver.listen, Some(ip_or_domain(address)));
        assert_eq!(
            tag_of(address),
            DNS_INBOUND_V6_TAG,
            "the payload tag and the tag helper agree"
        );
        assert_eq!(tag_of(IpAddr::V4(Ipv4Addr::LOCALHOST)), DNS_INBOUND_TAG);
    }

    #[test]
    fn the_address_list_is_ipv4_first() {
        let listener = Listener {
            v4: Some(Ipv4Addr::new(10, 255, 0, 1)),
            v6: Some("fd00::1".parse().unwrap()),
        };
        assert_eq!(
            listener.addresses(),
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1)),
                IpAddr::V6("fd00::1".parse().unwrap()),
            ]
        );
        let v6_only = Listener {
            v4: None,
            v6: listener.v6,
        };
        assert_eq!(v6_only.addresses().len(), 1);
    }
}
