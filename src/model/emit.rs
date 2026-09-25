//! The tag universe the running configuration carries.
//!
//! `gen` writes the document and owns every emission detail — entry order,
//! conditional inclusion, the settings each wire projection reads. Every
//! module that *judges* the document (the model validation pass, the safety
//! pass, the routing screen) asks these queries instead of re-deriving the tag
//! sets: a hand-kept copy keeps judging a configuration that no longer exists
//! once an emission gate moves.
//!
//! A query answers for the whole running configuration, not only the
//! `inbounds`/`outbounds` arrays: the control-plane listener is declared by the
//! top-level `api` object (`infra/conf/api.go` turns it into an inbound
//! carrying that tag), and the in-tun DNS listener is added to the running core
//! by the runtime (`rt::dns_in`) rather than emitted.

use std::collections::BTreeSet;

use super::inbound::{
    API_INBOUND_TAG, BLOCK_OUTBOUND_TAG, DIRECT_OUTBOUND_TAG, DNS_INBOUND_TAG, DNS_OUTBOUND_TAG,
    DokodemoCfg, LocalInboundCfg, LocalInboundProtocol, TUN_INBOUND_TAG,
};
use super::servers::{ServerProfile, ServersFile};
use super::settings::{Mode, Settings};

/// The outbounds every generated document carries, whatever the settings: the
/// `freedom` `direct` and `blackhole` `block` outbounds, in emission order
/// (`gen::append_builtin_outbounds` appends exactly these two).
pub const BUILTIN_OUTBOUNDS: [(&str, &str); 2] = [
    ("freedom", DIRECT_OUTBOUND_TAG),
    ("blackhole", BLOCK_OUTBOUND_TAG),
];

/// True when the document carries the top-level `dns` object: `DnsCfg::to_wire`
/// collapses an effectively empty configuration to nothing, and every DNS arm
/// of the generator keys on that same value.
fn dns_module_emitted(settings: &Settings) -> bool {
    !settings.dns.is_effectively_empty()
}

/// True when the tun inbound is emitted: TUN mode is what enables it.
pub fn tun_inbound_emitted(settings: &Settings) -> bool {
    settings.mode == Mode::Tun
}

/// The emitted SOCKS endpoints, in list order — the endpoints whose UDP:53
/// traffic the DNS module answers. HTTP endpoints are TCP-only, so they can
/// never carry DNS and never appear in the interception rules.
fn dns_capable_socks(settings: &Settings) -> impl Iterator<Item = &LocalInboundCfg> {
    settings.local_inbounds.iter().filter(|entry| {
        local_inbound_emitted(entry) && entry.protocol == LocalInboundProtocol::Socks
    })
}

/// The interception rules' inbound tags, in list order.
pub fn socks_inbound_tags(settings: &Settings) -> Vec<String> {
    dns_capable_socks(settings)
        .map(|entry| entry.tag.clone())
        .collect()
}

/// True when the DNS module answers intercepted port-53 traffic: a DNS
/// configuration plus an inbound that can carry UDP (the tun inbound, or an
/// enabled SOCKS endpoint). The `dns-out` outbound, the interception rules, the
/// TUN adapter-DNS pin and the runtime's in-tun listener all ride this one gate.
pub fn dns_intercept(settings: &Settings) -> bool {
    dns_module_emitted(settings)
        && (tun_inbound_emitted(settings) || dns_capable_socks(settings).next().is_some())
}

/// True when the running configuration carries the in-tun DNS listener: the DNS
/// module exists and so does the tun inbound. The generator deliberately does
/// not emit that listener — Xray starts tagged inbounds in Go map order, and a
/// listener binding the TUN gateway loses the race against the adapter's own
/// DNS queries on a fraction of cold starts — so the runtime adds it under
/// [`DNS_INBOUND_TAG`] while the interception rules hold.
pub fn dns_inbound_emitted(settings: &Settings) -> bool {
    tun_inbound_emitted(settings) && dns_module_emitted(settings)
}

/// The outbound tags of a profile list alone: every profile tag, then the
/// built-ins. Only the optional `dns-out` arm depends on the settings, so a
/// caller that judges a profile list without them — the profile verdict also
/// runs on a latency probe's ad-hoc list — reads this instead of
/// [`outbound_tags`].
pub fn profile_outbound_tags(profiles: &[ServerProfile]) -> BTreeSet<String> {
    profiles
        .iter()
        .map(ServerProfile::tag)
        .chain(BUILTIN_OUTBOUNDS.iter().map(|(_, tag)| (*tag).to_string()))
        .collect()
}

/// The outbound tags the generated document carries: every profile tag (Xray's
/// default route is the first outbound, which is why the profile list keeps the
/// active one first, so the emitted order and the GUI list can never disagree),
/// the built-in `direct`/`block`, and `dns-out` exactly when the DNS module
/// intercepts local port-53 traffic. `gen::outbounds` writes this set.
pub fn outbound_tags(servers: &ServersFile, settings: &Settings) -> BTreeSet<String> {
    let mut tags = profile_outbound_tags(&servers.profiles);
    if dns_intercept(settings) {
        tags.insert(DNS_OUTBOUND_TAG.into());
    }
    tags
}

/// True when a local endpoint reaches the wire: `gen::inbounds` emits the
/// enabled entries, in list order, and drops the rest.
pub fn local_inbound_emitted(entry: &LocalInboundCfg) -> bool {
    entry.enabled
}

/// True when a dokodemo listener reaches the wire: `gen::inbounds` emits the
/// enabled entries, in list order, and drops the rest.
pub fn dokodemo_emitted(entry: &DokodemoCfg) -> bool {
    entry.enabled
}

/// The inbound tags `gen::inbounds` writes besides the settings' entries, in
/// the order it appends them: the tun inbound in TUN mode, then the in-tun DNS
/// listener while [`dns_inbound_emitted`]. The control-plane listener is not
/// part of this list — the top-level `api` object carries [`API_INBOUND_TAG`]
/// ahead of every configured entry. A caller that walks the configured entries
/// for tag uniqueness reserves these after its walk, so the insert that fails —
/// the collision report — names the same arm this module carries.
pub fn appended_inbound_tags(settings: &Settings) -> impl Iterator<Item = &'static str> {
    tun_inbound_emitted(settings)
        .then_some(TUN_INBOUND_TAG)
        .into_iter()
        .chain(dns_inbound_emitted(settings).then_some(DNS_INBOUND_TAG))
}

/// The inbound tags the running configuration carries: the control-plane
/// listener, the tags [`appended_inbound_tags`] adds, every local endpoint
/// [`local_inbound_emitted`] keeps, and every dokodemo listener
/// [`dokodemo_emitted`] keeps. The same two predicates are what the collision
/// walk reads, so the readers of this universe can never disagree about which
/// entries are emitted.
pub fn inbound_tags(settings: &Settings) -> BTreeSet<String> {
    let mut tags = BTreeSet::from([API_INBOUND_TAG.to_string()]);
    tags.extend(appended_inbound_tags(settings).map(str::to_string));
    tags.extend(
        settings
            .local_inbounds
            .iter()
            .filter(|entry| local_inbound_emitted(entry))
            .map(|entry| entry.tag.clone()),
    );
    tags.extend(
        settings
            .dokodemo
            .iter()
            .filter(|entry| dokodemo_emitted(entry))
            .map(|entry| entry.tag.clone()),
    );
    tags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r#gen::keys;
    use crate::model::safety::assess;
    use crate::model::validation::{ValidationCode, validate_settings};
    use crate::model::{
        Balancer, DokodemoCfg, OutboundModel, Protocol, ProtocolSettings, Rule, VlessSettings,
    };
    use serde_json::{Map, Value};

    const ID: &str = "0123456789abcdef"; // tag: srv-01234567
    /// Deterministic control-plane port, as the generator fixtures use.
    const API_PORT: u16 = 10853;

    /// A VLESS profile whose outbound model passes the model pass: the
    /// canonical 4-part PQ encryption form, because Xray's conf parser reads a
    /// shorter part as padding and panics when no key part exists
    /// (infra/conf/vless.go).
    fn profile(id: &str) -> ServerProfile {
        let mut outbound = OutboundModel::new(Protocol::Vless);
        outbound.settings = ProtocolSettings::Vless(VlessSettings {
            address: "1.2.3.4".into(),
            port: 443,
            id: "11111111-2222-3333-4444-555555555555".into(),
            encryption:
                "mlkem768x25519plus.native.1rtt.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA".into(),
            ..Default::default()
        });
        ServerProfile {
            id: id.into(),
            name: "test".into(),
            outbound,
            latency_ms: None,
            extra: Map::new(),
        }
    }

    fn servers(profiles: Vec<ServerProfile>) -> ServersFile {
        ServersFile {
            version: 1,
            active: profiles.first().map(|profile| profile.id.clone()),
            profiles,
            extra: Map::new(),
        }
    }

    /// `settings` with the DNS module cleared: the seeded server list emptied
    /// and the storage-explicit parallel-query default unset, so `to_wire`
    /// collapses the object to nothing.
    fn without_dns_module(mut settings: Settings) -> Settings {
        settings.dns.servers.clear();
        settings.dns.enable_parallel_query = false;
        settings
    }

    fn rule(outbound_tag: &str) -> Rule {
        Rule {
            domain: vec!["domain:example.com".into()],
            outbound_tag: outbound_tag.into(),
            ..Default::default()
        }
    }

    /// One dokodemo listener; `enabled` decides whether it reaches the wire.
    fn dokodemo(tag: &str, enabled: bool) -> DokodemoCfg {
        DokodemoCfg {
            tag: tag.into(),
            enabled,
            listen_port: 5353,
            address: "8.8.8.8".into(),
            port: 53,
            ..Default::default()
        }
    }

    /// `settings` with every local endpoint disabled: no SOCKS listener is
    /// left to carry UDP:53, so DNS interception has no inbound to answer for.
    fn without_local_endpoints(mut settings: Settings) -> Settings {
        for entry in &mut settings.local_inbounds {
            entry.enabled = false;
        }
        settings
    }

    fn inbound_rule(inbound_tag: &str) -> Rule {
        Rule {
            domain: vec!["domain:example.com".into()],
            inbound_tag: vec![inbound_tag.into()],
            outbound_tag: DIRECT_OUTBOUND_TAG.into(),
            ..Default::default()
        }
    }

    fn emitted_tags(config: &Value, section: &str) -> BTreeSet<String> {
        config[section]
            .as_array()
            .expect("the emitted section is an array")
            .iter()
            .map(|entry| {
                entry[keys::TAG]
                    .as_str()
                    .expect("every emitted entry carries its tag")
                    .to_string()
            })
            .collect()
    }

    /// The document's own inbound universe: the `inbounds` array plus the two
    /// listeners that are not emitted as array entries — the control-plane
    /// listener the top-level `api` object declares, and the in-tun DNS
    /// listener the runtime adds.
    fn document_inbound_tags(config: &Value, settings: &Settings) -> BTreeSet<String> {
        let mut tags = emitted_tags(config, keys::INBOUNDS);
        tags.extend(config[keys::API][keys::TAG].as_str().map(str::to_string));
        if dns_inbound_emitted(settings) {
            tags.insert(DNS_INBOUND_TAG.into());
        }
        tags
    }

    /// Every gate the emission universe depends on: the DNS module on and off,
    /// endpoints on and off, dokodemo on and off, TUN mode with and without the
    /// module, and a balancer selector naming a profile tag.
    fn agreement_states() -> Vec<(&'static str, ServersFile, Settings)> {
        let mut states = Vec::new();

        // Seeded DNS module plus the enabled SOCKS endpoint: interception on.
        let mut seeded = Settings::default();
        seeded
            .routing
            .balancers
            .push(Balancer::new("bal".into(), "srv-".into()));
        states.push(("seeded", servers(vec![profile(ID)]), seeded));

        // The same state without the module: no dns-out, no dns-in.
        states.push((
            "no-dns-module",
            servers(vec![profile(ID)]),
            without_dns_module(Settings::default()),
        ));

        // The module with no inbound that can carry UDP:53 (every endpoint
        // disabled, no TUN): the `dns` object is emitted, interception is not.
        let mut module_only = without_local_endpoints(Settings::default());
        module_only.dokodemo = vec![dokodemo("in-doko-a", true)];
        states.push((
            "module-without-udp-inbound",
            servers(vec![profile(ID)]),
            module_only,
        ));

        // Endpoints off and one dokodemo listener on, one off: only enabled
        // entries reach the wire.
        let mut endpoints_off = without_local_endpoints(without_dns_module(Settings::default()));
        endpoints_off.dokodemo = vec![dokodemo("in-doko-a", true), dokodemo("in-doko-b", false)];
        states.push(("endpoints-off", servers(vec![profile(ID)]), endpoints_off));

        // TUN mode with the module: the interception rides the tun inbound.
        let tun = Settings {
            mode: Mode::Tun,
            ..Settings::default()
        };
        states.push(("tun", servers(vec![profile(ID)]), tun));

        // TUN mode without the module: neither dns-out nor dns-in.
        let mut tun_no_dns = without_dns_module(Settings::default());
        tun_no_dns.mode = Mode::Tun;
        states.push(("tun-no-dns", servers(vec![profile(ID)]), tun_no_dns));

        states
    }

    /// The queries and the emitted document answer the same tag sets for every
    /// state whose emission gates can move. A reader that keeps its own copy of
    /// the universe fails here as soon as an arm moves.
    #[test]
    fn queries_agree_with_the_emitted_document() {
        for (label, servers, settings) in agreement_states() {
            let config = crate::r#gen::generate_with_api_port(&servers, &settings, API_PORT)
                .unwrap_or_else(|error| panic!("{label}: the state must generate: {error}"));
            assert_eq!(
                emitted_tags(&config, keys::OUTBOUNDS),
                outbound_tags(&servers, &settings),
                "{label}: emitted outbound tags"
            );
            assert_eq!(
                document_inbound_tags(&config, &settings),
                inbound_tags(&settings),
                "{label}: emitted inbound tags"
            );
            // The in-tun DNS listener's own gate is the runtime's, derived
            // from the document it starts the core with: it must decide the
            // same thing as the query for every state.
            assert_eq!(
                crate::rt::dns_in::listener_for_config(&config).is_some(),
                dns_inbound_emitted(&settings),
                "{label}: the runtime's listener gate"
            );
        }
    }

    /// The readers accept exactly the tags the document carries: both rules
    /// below name tags only a TUN state with the DNS module emits, so the same
    /// rules are refused once the module is cleared.
    #[test]
    fn readers_agree_with_the_emitted_tags() {
        let servers = servers(vec![profile(ID)]);
        let mut settings = Settings {
            mode: Mode::Tun,
            ..Settings::default()
        };
        settings.routing.rules.push(rule(DNS_OUTBOUND_TAG));
        settings.routing.rules.push(inbound_rule(DNS_INBOUND_TAG));
        settings
            .routing
            .balancers
            .push(Balancer::new("bal".into(), "srv-".into()));

        // The document carries every tag the state names, and the balancer's
        // selector matches an emitted profile tag.
        let config = crate::r#gen::generate_with_api_port(&servers, &settings, API_PORT)
            .expect("the state must generate");
        assert_eq!(
            emitted_tags(&config, keys::OUTBOUNDS),
            outbound_tags(&servers, &settings)
        );
        assert!(
            validate_settings(&settings, &servers, API_PORT).is_empty(),
            "the document carries every tag the state names"
        );
        assert!(
            assess(&servers, &settings).is_empty(),
            "the balancer's selector matches an emitted profile tag"
        );

        // Clearing the module takes dns-out and dns-in off the wire, so the
        // very same rules are refused: the reader follows the emitter.
        let cleared = without_dns_module(settings);
        let issues = validate_settings(&cleared, &servers, API_PORT);
        assert!(issues.iter().any(|issue| issue.code
            == ValidationCode::RoutingRuleOutboundMissing(1, DNS_OUTBOUND_TAG.into())));
        assert!(issues.iter().any(|issue| issue.code
            == ValidationCode::RoutingRuleInboundMissing(2, DNS_INBOUND_TAG.into())));
    }
}
