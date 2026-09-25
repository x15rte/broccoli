//! The in-tun DNS listener: the one inbound the runtime adds to a *running*
//! core instead of emitting it into the generated config.
//!
//! The listener is a dokodemo bound to the TUN gateway address — the address
//! the tun inbound pins the adapter DNS to. That address exists only after
//! the tun inbound's `Start()` created the wintun adapter and assigned it,
//! and Xray starts tagged inbounds in Go map order, so a listener emitted
//! into the static config loses the ordering race in a fraction of cold
//! starts: `failed to listen TCP on 53 … The requested address is not valid
//! in its context`, the core dying pre-readiness. Adding the listener
//! through the control plane, after the core is up, makes the bind
//! deterministic — the address the listener needs is the address the running
//! core already owns — and turns a start-order roll into a bounded,
//! retryable control-plane call.
//!
//! The config still carries the module and its interception rule, so the
//! listener's settings stay derivable from it: the in-tun address is the one
//! the adapter DNS points at, and the `dns-in` rule is what routes the
//! listener's queries into the DNS module.

use std::net::Ipv4Addr;

use serde_json::Value;

use super::grpc::pb;
use crate::r#gen::keys;
use crate::model::inbound::DNS_INBOUND_TAG;

/// The port the in-tun DNS listener serves.
pub const PORT: u16 = 53;
/// The dokodemo's rewrite target: what the listener forwards queries to. The
/// module's interception rule matches the rewritten destination's port and
/// hands the query to `dns-out`, so only the port is load-bearing; the
/// address is a placeholder in place of which the module resolves.
pub(crate) const REWRITE: (Ipv4Addr, u16) = (Ipv4Addr::new(8, 8, 8, 8), 53);

/// The listener one running core needs: where it binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listener {
    /// The address the listener binds — the TUN gateway, which is also the
    /// address the tun inbound pins as the adapter DNS.
    pub address: Ipv4Addr,
}

impl Listener {
    /// The tag the config's interception rule and the core's manager agree on.
    pub(crate) fn tag(&self) -> &'static str {
        DNS_INBOUND_TAG
    }

    /// The `HandlerService.AddInbound` payload for this listener, shaped
    /// exactly as the config loader builds it from an emitted inbound:
    /// receiver listen address plus a single-port list, and the dokodemo
    /// rewrite target on TCP and UDP.
    pub(crate) fn inbound_config(&self) -> pb::xray::core::InboundHandlerConfig {
        let receiver = pb::xray::app::proxyman::ReceiverConfig {
            port_list: Some(pb::xray::common::net::PortList {
                range: vec![pb::xray::common::net::PortRange {
                    from: u32::from(PORT),
                    to: u32::from(PORT),
                }],
            }),
            listen: Some(ip_or_domain(self.address)),
            ..Default::default()
        };
        let dokodemo = pb::xray::proxy::dokodemo::Config {
            allowed_networks: vec![
                pb::xray::common::net::Network::Tcp as i32,
                pb::xray::common::net::Network::Udp as i32,
            ],
            rewrite_address: Some(ip_or_domain(REWRITE.0)),
            rewrite_port: u32::from(REWRITE.1),
            ..Default::default()
        };
        pb::xray::core::InboundHandlerConfig {
            tag: self.tag().to_string(),
            receiver_settings: Some(typed_message("xray.app.proxyman.ReceiverConfig", &receiver)),
            proxy_settings: Some(typed_message("xray.proxy.dokodemo.Config", &dokodemo)),
        }
    }
}

/// The listener a core running `config` needs, or `None` when the config
/// carries no DNS module or no TUN inbound. Mirrors the generator's emission
/// gates: the module is the top-level `dns` object (`gen::generate`), the
/// tun inbound exists only in TUN mode, and with the module on the tun
/// inbound pins its adapter DNS to the in-tun address (`gen::inbounds`),
/// which is therefore the address the listener must bind.
pub fn listener_for_config(config: &Value) -> Option<Listener> {
    config.get(keys::DNS)?.as_object()?;
    let inbounds = config.get(keys::INBOUNDS)?.as_array()?;
    // A config that declares its own listener (a raw override writes the
    // config verbatim) owns that socket, whatever address family it names:
    // the runtime must neither add nor replace it.
    if inbounds
        .iter()
        .any(|inbound| inbound.get(keys::TAG).and_then(Value::as_str) == Some(DNS_INBOUND_TAG))
    {
        return None;
    }
    let tun = inbounds
        .iter()
        .find(|inbound| inbound.get(keys::PROTOCOL).and_then(Value::as_str) == Some("tun"))?;
    let address = tun
        .get(keys::SETTINGS)?
        .get(keys::DNS)?
        .as_array()?
        .first()?
        .as_str()?
        .parse::<Ipv4Addr>()
        .ok()?;
    Some(Listener { address })
}

/// [`listener_for_config`] over the raw bytes of a config file. Unparsable
/// bytes yield `None`: the core could not have started from them either, and
/// the add is best-effort by design.
pub(crate) fn listener_for_bytes(bytes: &[u8]) -> Option<Listener> {
    listener_for_config(&serde_json::from_slice(bytes).ok()?)
}

fn ip_or_domain(address: Ipv4Addr) -> pb::xray::common::net::IpOrDomain {
    pb::xray::common::net::IpOrDomain {
        address: Some(pb::xray::common::net::ip_or_domain::Address::Ip(
            address.octets().to_vec(),
        )),
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
    fn listener_derives_from_the_module_and_the_tun_adapter_dns() {
        let config = json!({
            "inbounds": [
                { "protocol": "tun", "settings": { "name": "broccoli0", "dns": ["10.255.0.1"] } },
            ],
            "dns": { "servers": ["1.1.1.1"] },
        });
        assert_eq!(
            listener_for_config(&config),
            Some(Listener {
                address: Ipv4Addr::new(10, 255, 0, 1)
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

        let mut null_module = tun.clone();
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
    fn listener_steps_aside_for_a_config_with_its_own_listener() {
        // A raw override carries the config verbatim, so it may declare the
        // listener itself — under the tag the runtime would use. The runtime
        // must leave that socket alone instead of removing and rebinding it.
        let config = json!({
            "inbounds": [
                { "protocol": "tun", "settings": { "name": "broccoli0", "dns": ["10.255.0.1"] } },
                {
                    "protocol": "dokodemo-door",
                    "listen": "10.255.0.1",
                    "port": 53,
                    "tag": DNS_INBOUND_TAG,
                },
            ],
            "dns": { "servers": ["1.1.1.1"] },
        });
        assert_eq!(listener_for_config(&config), None);
    }

    #[test]
    fn listener_skips_non_ipv4_or_empty_adapter_dns() {
        // Without the module the generator leaves the user's adapter DNS
        // list alone, so this shape is a real config state: nothing pins an
        // in-tun listener address, so there is nothing to add.
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
    }

    #[test]
    fn inbound_config_matches_the_emitted_wire_shape() {
        use prost::Message as _;

        let listener = Listener {
            address: Ipv4Addr::new(10, 255, 0, 1),
        };
        let inbound = listener.inbound_config();
        assert_eq!(inbound.tag, DNS_INBOUND_TAG);

        let receiver = inbound.receiver_settings.expect("receiver settings");
        assert_eq!(receiver.r#type, "xray.app.proxyman.ReceiverConfig");
        let receiver = pb::xray::app::proxyman::ReceiverConfig::decode(receiver.value.as_slice())
            .expect("receiver settings decode");
        assert_eq!(
            receiver.listen,
            Some(ip_or_domain(Ipv4Addr::new(10, 255, 0, 1)))
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
        assert_eq!(dokodemo.rewrite_address, Some(ip_or_domain(REWRITE.0)));
        assert_eq!(dokodemo.rewrite_port, u32::from(REWRITE.1));
    }
}
