//! The tag universe and emission gates the running configuration carries.
//!
//! `gen` writes the document, but the facts it emits from are composed here:
//! [`Emission`] computes every derived gate once per document (which families
//! reach the wire, which attach to the DNS module, which profiles the document
//! dials), and the queries below answer for the tag sets. Every module that
//! *judges* the document (the model validation pass, the safety pass, the
//! routing screen) asks these queries instead of re-deriving the tag sets: a
//! hand-kept copy keeps judging a configuration that no longer exists once an
//! emission gate moves.
//!
//! A query answers for the whole running configuration, not only the
//! `inbounds`/`outbounds` arrays: the control-plane listener is declared by the
//! top-level `api` object (`infra/conf/api.go` turns it into an inbound
//! carrying that tag), and the in-tun DNS listener is added to the running core
//! by the runtime (`rt::dns_in`) rather than emitted.

use std::collections::BTreeSet;

use super::addr;
use super::dial::DialGraph;
use super::dns::scoped_bootstrap_endpoint;
use super::inbound::{
    API_INBOUND_TAG, BLOCK_OUTBOUND_TAG, DIRECT_OUTBOUND_TAG, DNS_INBOUND_TAG, DNS_INBOUND_V6_TAG,
    DNS_OUTBOUND_TAG, DokodemoCfg, LocalInboundCfg, LocalInboundProtocol, TUN_INBOUND_TAG,
};
use super::servers::{ServerProfile, ServersFile, TAG_PREFIX};
use super::settings::{Mode, Settings};
use serde_json::{Value, json};

/// The outbounds every generated document carries, whatever the settings: the
/// `freedom` `direct` and `blackhole` `block` outbounds, in emission order
/// (`gen::append_builtin_outbounds` appends exactly these two).
pub const BUILTIN_OUTBOUNDS: [(&str, &str); 2] = [
    ("freedom", DIRECT_OUTBOUND_TAG),
    ("blackhole", BLOCK_OUTBOUND_TAG),
];

/// True when the fakeDNS pool is enabled: the top-level `fakeDns` object and
/// every inbound carrying a `sniffing.destOverride` read this one gate.
pub fn fakedns_enabled(settings: &Settings) -> bool {
    settings.dns.fakedns.enabled
}

/// True when the document carries the top-level `dns` object: `DnsCfg::to_wire`
/// collapses an effectively empty configuration to nothing, and every DNS arm
/// of the generator keys on that same value.
pub fn dns_module_emitted(settings: &Settings) -> bool {
    !settings.dns.is_effectively_empty()
}

/// True when the tun inbound is emitted: TUN mode is what enables it.
pub fn tun_inbound_emitted(settings: &Settings) -> bool {
    settings.mode == Mode::Tun
}

/// The emitted SOCKS endpoints, in list order — the endpoints whose port-53
/// traffic the DNS module answers. HTTP endpoints are not part of the
/// DNS-interception policy and never appear in the interception rules.
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
/// enabled SOCKS endpoint). The `dns-out` outbound, the TUN adapter-DNS pin and
/// the runtime's in-tun listener ride this gate; the generated interception
/// rules additionally require the user's `builtin.dns_interception` switch,
/// while the in-tun listener's own rule (`dns-in`/`dns-in6`) stays either way.
pub fn dns_intercept(settings: &Settings) -> bool {
    dns_module_emitted(settings)
        && (tun_inbound_emitted(settings) || dns_capable_socks(settings).next().is_some())
}

/// True when the running configuration carries the in-tun DNS listeners: the
/// DNS module exists and so does the tun inbound. The generator deliberately
/// does not emit them — Xray starts tagged inbounds in Go map order, and a
/// listener binding a TUN gateway loses the race against the adapter's own DNS
/// queries on a fraction of cold starts — so the runtime adds them under
/// [`DNS_INBOUND_TAG`] and [`super::inbound::DNS_INBOUND_V6_TAG`] while the
/// interception rules hold.
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
    let dns_listeners = dns_inbound_emitted(settings);
    tun_inbound_emitted(settings)
        .then_some(TUN_INBOUND_TAG)
        .into_iter()
        .chain(dns_listeners.then_some(DNS_INBOUND_TAG))
        .chain(dns_listeners.then_some(DNS_INBOUND_V6_TAG))
}

/// Which inbound-tag universe a caller asks [`inbound_tags`] about. The
/// two callers ask two different questions, and each scope names the
/// projection it wants instead of every caller rebuilding the list.
pub enum InboundScope {
    /// Every tag the settings model declares, emitted or not: all local
    /// endpoints in list order, the tun/dns/api listeners the app owns, and
    /// every dokodemo tag in list order. The TestRoute dialog offers this
    /// universe, because a trial rule may name a listener that is switched
    /// off right now.
    Declared,
    /// The listeners a user scopes a rule by: the enabled local endpoints and
    /// enabled dokodemo listeners, in list order. The app-owned `api`,
    /// `tun-in`, and in-tun DNS listeners are deliberately absent — they are
    /// not traffic a user routes.
    UserListeners,
}

/// The inbound tags `settings` carries, projected onto `scope`. Every
/// consumer's universe comes from here, so a new listener (or a changed
/// emission gate) reaches all of them at once.
pub fn inbound_tags(settings: &Settings, scope: InboundScope) -> Vec<String> {
    match scope {
        InboundScope::Declared => settings
            .local_inbounds
            .iter()
            .map(|entry| entry.tag.clone())
            .chain(
                [
                    TUN_INBOUND_TAG,
                    DNS_INBOUND_TAG,
                    DNS_INBOUND_V6_TAG,
                    API_INBOUND_TAG,
                ]
                .into_iter()
                .map(str::to_string),
            )
            .chain(settings.dokodemo.iter().map(|entry| entry.tag.clone()))
            .collect(),
        InboundScope::UserListeners => settings
            .local_inbounds
            .iter()
            .filter(|entry| local_inbound_emitted(entry))
            .map(|entry| entry.tag.clone())
            .chain(
                settings
                    .dokodemo
                    .iter()
                    .filter(|entry| dokodemo_emitted(entry))
                    .map(|entry| entry.tag.clone()),
            )
            .collect(),
    }
}

/// The proxy-server host of a profile when it is a domain (not an IP
/// literal). WireGuard's endpoint is `ServerProfile::server_address`'s
/// verbatim peer endpoint — `host` or `host:port` — and is included so its
/// peer dials can use the bootstrap resolver too; it never receives a
/// sockopt injection (its dial path honors `settings.domainStrategy`, not
/// sockopt, XTLS/Xray-core#5363).
pub(crate) fn profile_server_domain(profile: &ServerProfile) -> Option<String> {
    let address = profile.server_address()?;
    let host = match addr::split(&address) {
        Some(host_port)
            if host_port.port.is_none_or(|port| {
                !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit())
            }) =>
        {
            host_port.host
        }
        _ => address.as_str(),
    };
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let host = host.to_ascii_lowercase();
    // A trailing-dot address is the same fully-qualified name the importer
    // accepts and the dial uses, so it stays in the scope with that exact
    // spelling: Xray matches these `domains` entries textually against the
    // dialed address, and dropping the entry would send the server's own
    // resolution back through the DNS module it bootstraps.
    (!host.is_empty()
        && host.len() <= 255
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && host.contains('.')
        && !host.starts_with('.'))
    .then_some(host)
}

/// Derive the scoped `+local` bootstrap DNS server for proxy-server domains.
/// Queries are answered by dialing the endpoint DIRECTLY (no routing —
/// `https+local` & friends bypass the dispatcher,
/// app/dns/nameserver.go:60-68), so the tunnel chain can resolve its own
/// server without the OS resolver and without recursing back into the DNS
/// module. The endpoint is the GUI `bootstrap` override when set, else the
/// first configured DNS server (the auto-derive assumes that server is
/// reachable directly — on networks where it is blocked, e.g. Cloudflare
/// DoH behind the GFW, the override must name a reachable one). The
/// special override `localhost` asks the OS resolver: its entry is emitted
/// verbatim (no scheme rewrite, no IP-literal gate) and remains scoped to
/// the proxy-server domains. Any other endpoint is only emitted when its
/// host is an IP literal: a domain host would itself need resolution,
/// which re-enters the module through the TUN and deadlocks the bootstrap.
fn bootstrap_dns_server(settings: &Settings, domains: &[String]) -> Option<Value> {
    let override_address = settings.dns.bootstrap.trim();
    // Every emitted bootstrap entry is scoped to the proxy-server domains.
    let domains: Vec<Value> = domains
        .iter()
        .map(|domain| json!(format!("domain:{domain}")))
        .collect();
    // Special value (the DnsCfg::default bootstrap): ask the OS resolver.
    // The OS resolver is not an Xray endpoint, so it cannot take a
    // `+local` scheme rewrite and needs no IP-literal gate — the address
    // is emitted verbatim, still scoped to the proxy-server domains so
    // general queries never reach it (skipFallback, see below).
    if override_address == "localhost" {
        return Some(json!({
            "address": "localhost",
            "domains": domains,
            "skipFallback": true,
        }));
    }
    let (address, fallback_port) = if override_address.is_empty() {
        let first = settings.dns.servers.first()?;
        (first.address.trim(), first.port)
    } else {
        (override_address, None)
    };
    let scoped = scoped_bootstrap_endpoint(address, fallback_port)?;
    Some(json!({
        "address": format!("{}://{}", scoped.scheme, scoped.endpoint),
        "domains": domains,
        // Without this, Xray's DNS sortClients fallback appends EVERY
        // server to the query list — scoped ones included — so every
        // system query would be dialed DIRECTLY against this resolver
        // (the `+local` scheme bypasses routing), leaking all DNS out of
        // the tunnel. skipFallback restricts it to its matched domain.
        "skipFallback": true,
    }))
}

/// The derived facts every emission stage reads, computed once per document:
/// which families reach the wire and which of them attach to the DNS module.
/// The stages take this value instead of the positional booleans they used to
/// take (`bootstrap`, `dns_on`, `tun_on`), which a caller could swap without
/// the compiler noticing.
pub(crate) struct Emission {
    /// The tags this document dials — the default route and the profiles its
    /// rules, balancers and health engines reach, each mapped to its chain
    /// terminal — reduced to the `srv-` id prefix every tag carries
    /// ([`ServerProfile::tag_eq`] defines the equivalence). These are the only
    /// profiles whose server address this machine dials, so the only ones
    /// whose domain the bootstrap resolver may answer. Membership tests run
    /// against the profile's own id prefix, so a non-dialed profile costs no
    /// tag formatting.
    dialed: BTreeSet<String>,
    /// The scoped bootstrap resolver this document emits, if any: a DNS
    /// module exists, a dialed profile has a domain, and no DNS script owns
    /// resolution. `gen::dns` appends it to the DNS server list.
    bootstrap: Option<Value>,
    /// Whether the DNS module reaches the wire at all.
    pub(crate) dns_on: bool,
    /// Whether port-53 traffic is intercepted into the DNS module.
    pub(crate) dns_intercept: bool,
    /// The enabled SOCKS endpoints' tags, in list order.
    pub(crate) socks_tags: Vec<String>,
    /// Whether the TUN inbound reaches the wire.
    pub(crate) tun_on: bool,
    /// Whether the FakeDNS pool is enabled (every inbound that carries a
    /// `sniffing.destOverride` needs the same answer).
    pub(crate) fakedns: bool,
}

impl Emission {
    /// Compose the emission value for one document. Every gate lives here (or
    /// in the query it calls), so the stages cannot disagree about which
    /// families reach the wire.
    pub(crate) fn new(servers: &ServersFile, settings: &Settings) -> Emission {
        let fakedns = fakedns_enabled(settings);
        let dns_on = dns_module_emitted(settings);
        // `dialed_outbound_tags` only ever inserts `ServerProfile::tag`, so
        // every entry carries the prefix; the id behind it is what a profile
        // can reproduce without formatting its own tag.
        let dialed: BTreeSet<String> = DialGraph::for_profiles(&servers.profiles)
            .dialed_outbound_tags(settings)
            .into_iter()
            .map(|tag| {
                tag.strip_prefix(TAG_PREFIX)
                    .expect("a dialed outbound tag carries the `srv-` prefix")
                    .to_string()
            })
            .collect();
        let mut server_domains: Vec<String> = servers
            .profiles
            .iter()
            .filter(|profile| dialed.contains(profile.tag_id()))
            .filter_map(profile_server_domain)
            .collect();
        server_domains.sort();
        server_domains.dedup();
        // The scoped server must land inside an emitted `dns` object; without
        // a module there is nothing for it (or for useip dials) to attach to.
        // A DNS script owns resolution instead: the core refuses a server
        // carrying `domains`/`skipFallback` beside a script
        // (infra/conf/dns.go), so the app-owned scoped server — and with it
        // the half of the pair that pins profile dials to the module — is
        // omitted rather than emitted into a document the core would refuse.
        // The dialed profile's domain then resolves the way it does without a
        // module, through the OS resolver.
        let dns_script = settings
            .dns
            .script
            .as_deref()
            .is_some_and(|script| !script.is_empty());
        let bootstrap = (dns_on && !server_domains.is_empty() && !dns_script)
            .then(|| bootstrap_dns_server(settings, &server_domains))
            .flatten();
        Emission {
            dialed,
            bootstrap,
            dns_on,
            dns_intercept: dns_intercept(settings),
            socks_tags: socks_inbound_tags(settings),
            tun_on: tun_inbound_emitted(settings),
            fakedns,
        }
    }

    /// Whether this profile's own dial goes through the scoped bootstrap DNS
    /// server: only an outbound the document dials has its domain in the
    /// scope (a chained hop's server is reached through the chain and resolves
    /// on the far side, and a standby the document never dials resolves
    /// nothing before the tunnel — see [`crate::model::dial`]).
    pub(crate) fn bootstrap_reaches(&self, profile: &ServerProfile) -> bool {
        self.bootstrap.is_some() && self.dialed.contains(profile.tag_id())
    }

    /// The scoped bootstrap server to append to the DNS document, if one is
    /// emitted.
    pub(crate) fn bootstrap_server(&self) -> Option<&Value> {
        self.bootstrap.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r#gen::keys;
    use crate::model::safety::SafetyVerdicts;
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
    /// left to carry port-53 traffic, so DNS interception has no inbound to
    /// answer for.
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

    /// The emitted inbound universe, composed here rather than published: the
    /// oracle below is its only reader, so this stays test-local instead of a
    /// production query that exists for a test.
    fn emitted_inbound_tags(settings: &Settings) -> BTreeSet<String> {
        std::iter::once(API_INBOUND_TAG.to_string())
            .chain(appended_inbound_tags(settings).map(str::to_string))
            .chain(
                settings
                    .local_inbounds
                    .iter()
                    .filter(|entry| local_inbound_emitted(entry))
                    .map(|entry| entry.tag.clone()),
            )
            .chain(
                settings
                    .dokodemo
                    .iter()
                    .filter(|entry| dokodemo_emitted(entry))
                    .map(|entry| entry.tag.clone()),
            )
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
            tags.insert(DNS_INBOUND_V6_TAG.into());
        }
        tags
    }

    /// The three scopes answer the three questions their callers ask: the
    /// emitted set in emission order, every declared tag whether emitted or
    /// not, and only the listeners a user scopes a rule by.
    #[test]
    fn inbound_scopes_project_their_declared_orders() {
        let mut settings = Settings {
            mode: Mode::Tun,
            ..Settings::default()
        };
        settings.local_inbounds = vec![
            LocalInboundCfg::socks_default("in-socks"),
            LocalInboundCfg::http_default("in-http"),
            LocalInboundCfg {
                enabled: false,
                ..LocalInboundCfg::socks_default("in-socks-off")
            },
        ];
        settings.dokodemo = vec![dokodemo("in-doko-on", true), dokodemo("in-doko-off", false)];

        assert_eq!(
            inbound_tags(&settings, InboundScope::Declared),
            [
                "in-socks",
                "in-http",
                "in-socks-off",
                TUN_INBOUND_TAG,
                DNS_INBOUND_TAG,
                DNS_INBOUND_V6_TAG,
                API_INBOUND_TAG,
                "in-doko-on",
                "in-doko-off",
            ]
            .map(str::to_string)
        );
        assert_eq!(
            inbound_tags(&settings, InboundScope::UserListeners),
            ["in-socks", "in-http", "in-doko-on"].map(str::to_string)
        );
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

        // The module with no inbound that can carry port-53 traffic (every
        // endpoint disabled, no TUN): the `dns` object is emitted,
        // interception is not.
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
                emitted_inbound_tags(&settings),
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
            SafetyVerdicts::of(&servers, &settings).is_empty(),
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
