//! Config generator: GUI state → Xray `config.json`.
//! Thin conversion — the model structs already mirror the wire shape; this
//! module assembles the top-level document and injects tags. The document's
//! section and field names live in [`keys`].

pub mod keys;

use crate::diag::Diag;
use crate::i18n::{Key, t_fmt, validation_issue_message};
use crate::model::dns::DEFAULT_PLAINTEXT_RESOLVERS;
use crate::model::emit;
use crate::model::inbound::{API_INBOUND_TAG, DNS_INBOUND_TAG, DNS_OUTBOUND_TAG, TUN_INBOUND_TAG};
use crate::model::settings::Language;
use crate::model::validation::{
    ValidationIssue, Verdict, tun_ipv4_gateway, validate_profiles, validate_settings,
};
use crate::model::{
    DnsCfg, ProtocolSettings, RoutingCfg, ServerProfile, ServersFile, Settings, TunCfg,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// API services always enabled on the gRPC control plane. ObservatoryService
/// is appended only when an observatory/burstObservatory config is emitted —
/// it `RequireFeatures(extension.Observatory)` and the core fails with "not
/// all dependencies are resolved" otherwise (app/observatory/command/command.go:40).
const API_SERVICES: [&str; 5] = [
    "ReflectionService",
    "HandlerService",
    "LoggerService",
    "StatsService",
    "RoutingService",
];

/// A config-generation failure that has no language yet. `Display` renders
/// English for logs and tests; the display boundary renders the active
/// language with [`GenerateError::text`].
#[derive(Debug)]
pub enum GenerateError {
    /// `settings.raw_override` does not parse; the payload is the parser
    /// error, verbatim.
    RawOverride(serde_json::Error),
    /// The GUI state cannot generate a config; the message carries its key
    /// and values.
    InvalidModel(Diag),
    /// A model validation finding refused the GUI state. The finding renders
    /// in the active language at the display boundary.
    InvalidFinding(Box<ValidationIssue>),
    /// No loopback API port is free; the payload is the OS error, verbatim.
    ApiPort(std::io::Error),
}

impl GenerateError {
    /// Render the failure in `language`.
    pub fn text(&self, language: Language) -> String {
        match self {
            Self::RawOverride(error) => t_fmt(language, Key::GenRawOverride, &[error]),
            Self::InvalidModel(message) => message.text(language),
            // One renderer for every finding: `validation_issue_message`
            // prefixes a non-empty path as `"{location}: {message}"` and fills
            // the rule's placeholders, so a parameterized rule keeps the value
            // that names the fault.
            Self::InvalidFinding(issue) => validation_issue_message(issue, language),
            Self::ApiPort(error) => t_fmt(language, Key::GenApiPort, &[error]),
        }
    }
}

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text(Language::En))
    }
}

impl Error for GenerateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RawOverride(error) => Some(error),
            Self::ApiPort(error) => Some(error),
            Self::InvalidModel(_) | Self::InvalidFinding(_) => None,
        }
    }
}

/// Build the full Xray config from GUI state.
/// `settings.raw_override` = Some(text) → parsed and returned VERBATIM.
pub fn generate(servers: &ServersFile, settings: &Settings) -> Result<Value, GenerateError> {
    generate_with_api_port(servers, settings, pick_ephemeral_api_port()?)
}

/// Bind `127.0.0.1:0` to let the OS choose a free loopback port, read it, and
/// release the listener. The chosen port is embedded in the generated config
/// (the control plane is unauthenticated, so the port must not be
/// predictable from persisted state). There is a tiny TOCTOU window between
/// dropping the listener and the core binding the port — a same-user process
/// could race to bind it first; the owning-PID check at readiness
/// detects that spoofed listener, so this window does not weaken trust.
pub fn pick_ephemeral_api_port() -> Result<u16, GenerateError> {
    pick_ephemeral_api_port_inner(|addr| std::net::TcpListener::bind(addr))
}

/// `pick_ephemeral_api_port` with the bind step injected, so a failing bind
/// can be simulated in tests. A bind failure is a recoverable environment
/// condition, never a reason to panic the GUI: every caller
/// propagates [`GenerateError::ApiPort`] into a GUI error state instead.
fn pick_ephemeral_api_port_inner(
    bind: impl for<'a> Fn(&'a str) -> std::io::Result<std::net::TcpListener>,
) -> Result<u16, GenerateError> {
    let listener = bind("127.0.0.1:0").map_err(GenerateError::ApiPort)?;
    let port = listener
        .local_addr()
        .map_err(GenerateError::ApiPort)?
        .port();
    drop(listener);
    Ok(port)
}

/// `generate` with the API port injected. Tests use a fixed port for
/// deterministic goldens; production callers use [`generate`], which picks an
/// ephemeral port per launch.
pub fn generate_with_api_port(
    servers: &ServersFile,
    settings: &Settings,
    api_port: u16,
) -> Result<Value, GenerateError> {
    if api_port == 0 {
        return Err(GenerateError::InvalidModel(Diag::new(
            Key::GenApiListenerPortZero,
        )));
    }
    if let Some(raw) = &settings.raw_override {
        return serde_json::from_str(raw).map_err(GenerateError::RawOverride);
    }

    let fakedns = settings.dns.fakedns.enabled;
    let tun_on = emit::tun_inbound_emitted(settings);
    if let Some(error) = invalid_model_error(validate_settings(settings, servers, api_port)) {
        return Err(error);
    }
    let active = servers.active_profile();

    // Health engine: the ordinary observatory (user-selected, or emitted for
    // a balancer that reads live health data) or the burst observatory. A core
    // serves one `extension.Observatory`: `infra/conf/xray.go` appends
    // `observatory` before `burstObservatory`, so a hand-edited file that
    // enables both is answered by the ordinary one.
    let observatory_emitted = settings.routing.observatory_emitted();
    let burst_emitted = settings.routing.burst_observatory_emitted();

    let mut root = Map::new();

    // The user's policy document (levels included), written with the stats
    // switches by the control plane below.
    let mut policy = settings.policy.extra.clone();
    let levels: Map<String, Value> = settings
        .policy
        .levels
        .iter()
        .filter(|(_, level)| !level.is_empty())
        .map(|(name, level)| {
            (
                name.clone(),
                serde_json::to_value(level).expect(
                    "model serialization is infallible: PolicyLevelCfg fields are ints, \
                     bools, and string-keyed Value maps only",
                ),
            )
        })
        .collect();
    if !levels.is_empty() {
        policy.insert("levels".into(), Value::Object(levels));
    }
    let mut services: Vec<&str> = API_SERVICES.to_vec();
    if observatory_emitted || burst_emitted {
        services.push("ObservatoryService");
    }
    ControlPlane {
        api_port,
        log_level: &settings.log_level,
        access_log: settings.access_log,
        services,
        stats: true,
        policy,
    }
    .write(&mut root);

    let dns_wire = dns(&settings.dns, fakedns);
    // Enabled SOCKS entries (in list order) carry DNS UDP:53 to dns-out;
    // HTTP entries are TCP-only and never appear in the interception rules.
    let socks_tags = emit::socks_inbound_tags(settings);
    // Local DNS interception: when a DNS server list exists and a proxy
    // inbound can carry UDP, port-53 queries are answered by the DNS module
    // (dns-out) instead of traveling the tunnel as raw UDP. The gate has one
    // home (emit::dns_intercept), shared with every reader that judges the
    // emitted tags.
    let dns_intercept = emit::dns_intercept(settings);

    // Proxy-server bootstrap: a direct-dial outbound's domain resolves
    // through a scoped `+local` DNS server (direct dial) instead of the OS
    // resolver, so the tunnel chain can bootstrap itself. A chained hop's
    // domain stays out of the scope: that server is reached through the
    // chain and resolves on the far side. Both halves are load-bearing:
    // `useip` routes the server dial into the DNS module, and the scoped
    // server answers it without the tunnel; emitting one without the other
    // would leave the dial on the OS resolver or deadlock it inside the
    // module (the DoH dial needs the very chain the query is for).
    let direct_dial = direct_dial_outbound_tags(servers);
    let mut server_domains: Vec<String> = servers
        .profiles
        .iter()
        .filter(|profile| direct_dial.contains(&profile.tag()))
        .filter_map(profile_server_domain)
        .collect();
    server_domains.sort();
    server_domains.dedup();
    let dns_upstreams = dns_upstream_endpoints(settings);
    // The scoped server must land inside an emitted `dns` object; without a
    // module there is nothing for it (or for useip dials) to attach to.
    let bootstrap = if dns_wire.is_some() && !server_domains.is_empty() {
        bootstrap_dns_server(settings, &server_domains)
    } else {
        None
    };
    let mut dns_wire = dns_wire;
    if let Some(bootstrap) = &bootstrap
        && let Some(object) = dns_wire.as_mut().and_then(Value::as_object_mut)
    {
        let servers = object
            .entry(String::from("servers"))
            .or_insert_with(|| json!([]));
        servers
            .as_array_mut()
            .expect("servers is an array")
            .push(bootstrap.clone());
    }

    // The derived facts the stages read, assembled once: a stage asks this
    // value instead of receiving positional facts it could swap for one
    // another.
    let emission = Emission {
        direct_dial,
        bootstrap: bootstrap.is_some(),
        dns_on: dns_wire.is_some(),
        dns_intercept,
        socks_tags,
        dns_upstreams,
        tun_on,
        fakedns,
        active,
    };
    root.insert(keys::OUTBOUNDS.into(), outbounds(servers, &emission));
    root.insert(keys::INBOUNDS.into(), inbounds(settings, &emission));
    root.insert(keys::ROUTING.into(), routing(&settings.routing, &emission));
    if let Some(dns) = dns_wire {
        root.insert(keys::DNS.into(), dns);
    }

    let obs = &settings.routing.observatory;
    if observatory_emitted {
        // SSRF guard: the RUNNING core fetches probeURL
        // continuously while the observatory is emitted, so a hand-edited
        // settings.json must not be able to point it at loopback, link-local,
        // or cloud-metadata literals. Same classifier as the one-shot latency
        // probe; empty input passes (the key is omitted and the core uses its
        // public default).
        if let Some(class) = blocked_latency_probe_host_class(&obs.probe_url) {
            return Err(GenerateError::InvalidModel(
                Diag::new(Key::GenObservatoryProbeHostBlocked).arg(class),
            ));
        }
        // Dependency-forced observatory observes every profile; a
        // user-selected observatory keeps its own subjectSelector.
        let forced_subjects = (!obs.enabled).then(|| {
            servers
                .profiles
                .iter()
                .map(ServerProfile::tag)
                .collect::<Vec<String>>()
        });
        root.insert(
            keys::OBSERVATORY.into(),
            obs.to_wire(forced_subjects.as_deref()),
        );
    }
    if burst_emitted {
        root.insert(
            keys::BURST_OBSERVATORY.into(),
            settings.routing.burst_observatory.to_wire(),
        );
    }

    // fakeDns trio (1/3): top-level pool. (2/3) dns server + (3/3) sniffing
    // destOverride are handled in dns()/inbounds().
    if fakedns && let Some(wire) = settings.dns.fakedns.to_wire() {
        root.insert(keys::FAKE_DNS.into(), wire);
    }

    if !settings.env.is_empty() {
        let env: Map<String, Value> = settings
            .env
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        root.insert(keys::ENV.into(), Value::Object(env));
    }

    // Core-native `geodata` block: emitted only when at least one
    // dat URL is configured; the core itself downloads and reloads the files
    // on the cron schedule (broccoli never downloads anything). No URL → no key,
    // and the built-in dats bundled with the pinned core payload are used.
    if settings.geodata.is_configured() {
        let cron = settings
            .geodata
            .cron
            .as_deref()
            .filter(|c| !c.is_empty())
            .unwrap_or(crate::model::settings::DEFAULT_GEODATA_CRON);
        let mut assets = Vec::new();
        for (url, file) in [
            (&settings.geodata.geoip_url, "geoip.dat"),
            (&settings.geodata.geosite_url, "geosite.dat"),
        ] {
            if let Some(u) = url.as_deref().filter(|u| !u.is_empty()) {
                assets.push(json!({ keys::URL: u, "file": file }));
            }
        }
        root.insert(
            keys::GEODATA.into(),
            json!({ "cron": cron, keys::ASSETS: assets }),
        );
    }

    Ok(Value::Object(root))
}
/// Classify a latency probe URL's literal host as a blocked address class, or
/// `None` when the URL is acceptable under the static check. This is the SSRF
/// guard shared by config generation and the execution path
/// (`rt::latency::run`): loopback, link-local, and cloud-metadata literals are
/// rejected because probing them leaks reachability of local services and can
/// trigger internal endpoints. Non-IP hostnames pass — DNS resolution is out
/// of scope for a static check, which covers literals, the actual attack
/// surface here. Empty/whitespace input also passes because the generator
/// substitutes a public default URL.
pub(crate) fn blocked_latency_probe_host_class(probe_url: &str) -> Option<&'static str> {
    let trimmed = probe_url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let parsed = url::Url::parse(trimmed).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    match parsed.host()? {
        url::Host::Ipv4(ip) => classify_latency_probe_ipv4(ip),
        url::Host::Ipv6(ip) => classify_latency_probe_ipv6(ip),
        url::Host::Domain(_) => None,
    }
}

/// Classify a literal IPv4 probe host; `None` when the address is public.
fn classify_latency_probe_ipv4(ip: Ipv4Addr) -> Option<&'static str> {
    // Cloud metadata services (AWS/GCP/Azure 169.254.169.254; Aliyun
    // 100.100.100.200) sit in or near link-local space but get their own class
    // so the rejection message is unambiguous.
    const CLOUD_METADATA: [Ipv4Addr; 2] = [
        Ipv4Addr::new(169, 254, 169, 254),
        Ipv4Addr::new(100, 100, 100, 200),
    ];
    if CLOUD_METADATA.contains(&ip) {
        return Some("cloud-metadata");
    }
    if ip.is_loopback() {
        return Some("loopback");
    }
    if ip.is_link_local() {
        return Some("link-local");
    }
    None
}

/// The in-tun DNS address: the TUN gateway's IPv4 address (the model
/// predicate [`tun_ipv4_gateway`] is the shared fact). The WFP DNS shield
/// permits port-53 only when it egresses the TUN interface, so the adapter
/// DNS must live inside the TUN subnet — queries then route into the tunnel
/// (sing-box's in-tun DNS shape). The gateway's own address is the only
/// in-subnet address Xray's stack treats as local and the OS lets a
/// dokodemo bind; deriving it from the user-editable gateway keeps the two
/// coupled. Callers only reach this after [`validate_settings`] has
/// guaranteed an IPv4 gateway while TUN is on, so the old hardcoded
/// fallback (an address no adapter owns, silently blackholed DNS) is dead.
fn tun_dns_address(tun: &TunCfg) -> String {
    tun_ipv4_gateway(tun)
        .expect("validate_settings guarantees an IPv4 gateway while TUN is on")
        .to_string()
}

/// Classify a literal IPv6 probe host; IPv4-mapped forms are re-classified
/// through the IPv4 rules so `[::ffff:127.0.0.1]` cannot smuggle a blocked
/// address past a naive IPv6-only guard.
fn classify_latency_probe_ipv6(ip: Ipv6Addr) -> Option<&'static str> {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return classify_latency_probe_ipv4(mapped);
    }
    if ip.is_loopback() {
        return Some("loopback");
    }
    if ip.is_unicast_link_local() {
        return Some("link-local");
    }
    None
}

/// Build the app-owned configuration the core-update health gate starts: a
/// direct outbound plus the control-plane listener, nothing else. Like
/// [`generate_latency_probe`], this deliberately consults neither `Settings`
/// nor the server list — the gate answers only "does this installed core run
/// and answer", so no user profile or setting may decide whether an install
/// is accepted. The stats policy rides along because the gate's start is a
/// full managed-core start that the app polls like any other.
pub fn generate_core_gate(api_port: u16) -> Result<Value, GenerateError> {
    if api_port == 0 {
        return Err(GenerateError::InvalidModel(Diag::new(
            Key::GenApiListenerPortZero,
        )));
    }
    let mut root = Map::new();
    ControlPlane {
        api_port,
        // Access log pinned off: the gate's captured stdout is a failure
        // diagnostic, never a traffic record.
        log_level: "warning",
        access_log: false,
        services: API_SERVICES.to_vec(),
        stats: true,
        policy: Map::new(),
    }
    .write(&mut root);
    let mut out = Vec::new();
    append_builtin_outbounds(&mut out);
    root.insert(keys::OUTBOUNDS.into(), Value::Array(out));
    Ok(Value::Object(root))
}

/// Build the minimal temporary configuration used by the isolated latency
/// probe. This deliberately does not consult `Settings`, so raw overrides and
/// persistent observatory settings cannot leak into the one-shot child.
///
/// `interface` optionally binds every profile outbound to a network
/// interface via `streamSettings.sockopt.interface` (while the
/// main core's TUN is up, its split routes would otherwise recapture the
/// probe's dial and measure the main chain instead of the probed server).
/// `None` keeps the probe unbound — the historical behavior.
pub fn generate_latency_probe(
    profiles: &[ServerProfile],
    probe_url: &str,
    api_port: u16,
    interface: Option<&str>,
) -> Result<Value, GenerateError> {
    if api_port == 0 {
        return Err(GenerateError::InvalidModel(Diag::new(
            Key::GenProbePortZero,
        )));
    }
    if let Some(error) = invalid_model_error(validate_profiles(profiles, None, true)) {
        return Err(error);
    }

    let probe_url = probe_url.trim();
    let probe_url = if probe_url.is_empty() {
        "https://www.google.com/generate_204".to_string()
    } else {
        let parsed = url::Url::parse(probe_url).map_err(|error| {
            GenerateError::InvalidModel(Diag::new(Key::GenProbeUrlInvalid).arg(error))
        })?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(GenerateError::InvalidModel(Diag::new(
                Key::GenProbeUrlNotAbsolute,
            )));
        }
        if let Some(class) = blocked_latency_probe_host_class(probe_url) {
            return Err(GenerateError::InvalidModel(
                Diag::new(Key::GenProbeHostBlocked).arg(class),
            ));
        }
        probe_url.to_string()
    };

    let mut root = Map::new();
    ControlPlane {
        api_port,
        // Access log pinned off: the probe's stdout feeds failure
        // diagnostics, and the access channel is not gated by loglevel.
        log_level: "warning",
        access_log: false,
        services: vec!["ObservatoryService"],
        stats: false,
        policy: Map::new(),
    }
    .write(&mut root);
    root.insert(
        keys::OBSERVATORY.into(),
        json!({
            "subjectSelector": profiles.iter().map(ServerProfile::tag).collect::<Vec<_>>(),
            "probeURL": probe_url,
            "probeInterval": "1h",
            "enableConcurrency": true,
        }),
    );
    let policy = OutboundWirePolicy {
        interface,
        // The probe has no DNS module to bootstrap through.
        bootstrap: false,
    };
    let mut out: Vec<Value> = profiles
        .iter()
        .map(|profile| profile_wire_outbound(profile, policy))
        .collect();
    append_builtin_outbounds(&mut out);
    root.insert(keys::OUTBOUNDS.into(), Value::Array(out));
    Ok(Value::Object(root))
}

/// The verdict's first blocking finding as the generator's invalid-model
/// error; warning findings never gate generation. The tier rule itself lives
/// on the verdict.
fn invalid_model_error(verdict: Verdict) -> Option<GenerateError> {
    verdict
        .into_first_blocking()
        .map(|issue| GenerateError::InvalidFinding(Box::new(issue)))
}

/// Tags of the direct-dial outbounds: every profile whose server address the
/// local machine dials directly. The walk over dial-through references ends
/// on such a profile itself — either it names no target, or the target is a
/// builtin (`direct`/`block`), which has no server to reach. A reference
/// naming another profile excludes it: that hop's server is reached through
/// the chain and resolves on the far side.
fn direct_dial_outbound_tags(servers: &ServersFile) -> BTreeSet<String> {
    let tags = crate::model::emit::profile_outbound_tags(&servers.profiles);
    crate::model::dial::DialGraph::new(&servers.profiles, &tags).direct_dial_tags()
}

/// The proxy-server host of a profile when it is a domain (not an IP
/// literal). WireGuard's endpoint is `ServerProfile::server_address`'s
/// verbatim peer endpoint — `host` or `host:port` — and is included so its
/// peer dials can use the bootstrap resolver too; it never receives a
/// sockopt injection (its dial path honors `settings.domainStrategy`, not
/// sockopt, XTLS/Xray-core#5363).
fn profile_server_domain(profile: &ServerProfile) -> Option<String> {
    let address = profile.server_address()?;
    let host = if let Some((host, _)) = address
        .strip_prefix('[')
        .and_then(|address| address.split_once(']'))
    {
        host
    } else if let Some((host, port)) = address.rsplit_once(':')
        && !port.is_empty()
        && port.bytes().all(|byte| byte.is_ascii_digit())
    {
        host
    } else {
        address.as_str()
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
/// Host part of a `scheme://host[:port][/path]` endpoint.
fn scheme_host(rest: &str) -> &str {
    // Bracketed IPv6 literals contain colons; unbracket first.
    if let Some(host) = rest.strip_prefix('[').and_then(|r| r.split_once(']')) {
        return host.0;
    }
    // Unbracketed IPv6 literal without a port is a bare host.
    if rest.parse::<std::net::IpAddr>().is_ok() {
        return rest;
    }
    rest.split([':', '/']).next().unwrap_or(rest)
}
/// IP-literal upstream endpoints of scheme-based DNS servers, as (ip, port)
/// pairs for routing pinning. Only servers whose dials go out as TCP
/// (https/h2c/quic/tcp) qualify; bare hosts are UDP DNS, already pinned by
/// the UDP:53 interception rules. Domain hosts cannot be pinned by IP and
/// are skipped.
fn dns_upstream_endpoints(settings: &Settings) -> Vec<(String, u16)> {
    settings
        .dns
        .servers
        .iter()
        .filter_map(|server| {
            let address = server.address.trim();
            let (scheme, rest) = address.split_once("://")?;
            let port = match scheme {
                "https" | "h2c" | "quic" => 443,
                "tcp" => server.port.unwrap_or(53),
                _ => return None,
            };
            let host = scheme_host(rest)
                .parse::<std::net::IpAddr>()
                .ok()?
                .to_string();
            Some((host, port))
        })
        .collect()
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
    let (address, port) = if override_address.is_empty() {
        let first = settings.dns.servers.first()?;
        (first.address.trim(), first.port)
    } else {
        (override_address, None)
    };
    let (local_scheme, endpoint, host) = match address.split_once("://") {
        Some(("https", rest)) => ("https+local", rest.to_string(), scheme_host(rest)),
        Some(("h2c", rest)) => ("h2c+local", rest.to_string(), scheme_host(rest)),
        Some(("quic", rest)) => ("quic+local", rest.to_string(), scheme_host(rest)),
        Some(("tcp", rest)) => ("tcp+local", rest.to_string(), scheme_host(rest)),
        None => {
            // Bare host (UDP DNS default) bootstraps over TCP on the same
            // port; a bare host cannot carry a path.
            let (host, port) = match address.rsplit_once(':') {
                Some((host, port))
                    if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
                {
                    (host, port.to_string())
                }
                _ => (address, port.unwrap_or(53).to_string()),
            };
            ("tcp+local", format!("{host}:{port}"), host)
        }
        // localhost / fakedns / unknown schemes: no bootstrap possible.
        _ => return None,
    };
    if host.parse::<std::net::IpAddr>().is_err() {
        return None;
    }
    Some(json!({
        "address": format!("{local_scheme}://{endpoint}"),
        "domains": domains,
        // Without this, Xray's DNS sortClients fallback appends EVERY
        // server to the query list — scoped ones included — so every
        // system query would be dialed DIRECTLY against this resolver
        // (the `+local` scheme bypasses routing), leaking all DNS out of
        // the tunnel. skipFallback restricts it to its matched domain.
        "skipFallback": true,
    }))
}

/// Pin a profile outbound's server dial to the DNS module (sockopt
/// `useip`) unless the user already chose a strategy.
fn inject_server_domain_strategy(wire: &mut Value) {
    let Some(object) = wire.as_object_mut() else {
        return;
    };
    let stream = object
        .entry(keys::STREAM_SETTINGS)
        .or_insert_with(|| json!({}));
    let Some(stream_object) = stream.as_object_mut() else {
        return;
    };
    let sockopt = stream_object
        .entry(keys::SOCKOPT)
        .or_insert_with(|| json!({}));
    let Some(sockopt_object) = sockopt.as_object_mut() else {
        return;
    };
    if !sockopt_object.contains_key(keys::DOMAIN_STRATEGY) {
        sockopt_object.insert(keys::DOMAIN_STRATEGY.into(), json!("useip"));
    }
}

/// Bind a profile outbound's dial to a specific network interface
/// (sockopt `interface`), preserving every existing key: an outbound may
/// already carry `streamSettings` (security/transport) and `sockopt`
/// options, and only the missing levels are inserted.
fn inject_outbound_interface(wire: &mut Value, interface: &str) {
    let Some(object) = wire.as_object_mut() else {
        return;
    };
    let stream = object
        .entry(keys::STREAM_SETTINGS)
        .or_insert_with(|| json!({}));
    let Some(stream_object) = stream.as_object_mut() else {
        return;
    };
    let sockopt = stream_object
        .entry(keys::SOCKOPT)
        .or_insert_with(|| json!({}));
    let Some(sockopt_object) = sockopt.as_object_mut() else {
        return;
    };
    sockopt_object.insert(keys::INTERFACE.into(), json!(interface));
}

/// The caller-side wire policies the generator may apply to a profile
/// outbound after the model serializes it. Each generated document needs
/// its own policy — the main config pins domain-addressed server dials to
/// the DNS module, the latency probe binds dials to an interface — so every
/// call site states its policy and [`profile_wire_outbound`] is the only
/// place they are applied.
#[derive(Clone, Copy)]
struct OutboundWirePolicy<'a> {
    /// Network interface every profile dial binds to
    /// (`streamSettings.sockopt.interface`), or `None` to leave dials
    /// unbound. Only the latency probe passes one; the main config never
    /// binds dials to an interface.
    interface: Option<&'a str>,
    /// Resolve domain-addressed server dials through the DNS module
    /// (`sockopt.domainStrategy: "useip"`). Only the main config passes
    /// `true`, and only for a direct-dial outbound, only when the config
    /// emits a bootstrap resolver.
    bootstrap: bool,
}

/// Serialize one profile outbound and apply its [`OutboundWirePolicy`] —
/// the single owner of the caller-side outbound wire pass. The outbound
/// model (`OutboundModel`) owns its own envelope (its `Serialize`
/// implementation owns the `streamSettings` emit gate); everything the
/// generator patches into the serialized object lives here, so a call site
/// cannot emit a config with half its policy applied.
fn profile_wire_outbound(profile: &ServerProfile, policy: OutboundWirePolicy<'_>) -> Value {
    let mut wire = profile.outbound.to_wire(&profile.tag());
    // WireGuard's dial path ignores sockopt (XTLS/Xray-core#5363), so both
    // policies would be inert while looking effective: skip them rather
    // than pretend.
    if matches!(profile.outbound.settings, ProtocolSettings::Wireguard(_)) {
        return wire;
    }
    if policy.bootstrap && profile_server_domain(profile).is_some() {
        inject_server_domain_strategy(&mut wire);
    }
    if let Some(interface) = policy.interface {
        inject_outbound_interface(&mut wire, interface);
    }
    wire
}

fn append_builtin_outbounds(out: &mut Vec<Value>) {
    for (protocol, tag) in emit::BUILTIN_OUTBOUNDS {
        out.push(json!({ keys::PROTOCOL: protocol, keys::TAG: tag }));
    }
}

/// The user's server order, then the built-in `direct`/`block` tags and the
/// optional `dns-out`. Server profiles emit in list order, and the list keeps
/// the active (default) profile in its first slot — Xray's default route is
/// the first outbound — so the emitted order and the GUI list can never
/// disagree. The DNS outbound is appended last so the default outbound (the
/// first entry) is unchanged; it only ever receives UDP:53 via the
/// interception rules.
/// The derived facts every emission stage reads, computed once per document:
/// which families reach the wire and which of them attach to the DNS module.
/// The stages take this value instead of the positional booleans they used to
/// take (`bootstrap`, `dns_on`, `tun_on`), which a caller could swap without
/// the compiler noticing.
struct Emission<'a> {
    /// The direct-dial outbound tags: the only profiles whose server address
    /// this machine dials directly, so the only ones whose domain the
    /// bootstrap resolver may answer.
    direct_dial: BTreeSet<String>,
    /// Whether a scoped bootstrap resolver was emitted at all: a DNS module
    /// exists and a direct-dial server domain needs one.
    bootstrap: bool,
    /// Whether the DNS module reaches the wire at all.
    dns_on: bool,
    /// Whether port-53 traffic is intercepted into the DNS module.
    dns_intercept: bool,
    /// The enabled SOCKS endpoints' tags, in list order.
    socks_tags: Vec<String>,
    /// The DNS upstream endpoints the DoH outbound dials.
    dns_upstreams: Vec<(String, u16)>,
    /// Whether the TUN inbound reaches the wire.
    tun_on: bool,
    /// Whether the FakeDNS pool is enabled (every inbound that carries a
    /// `sniffing.destOverride` needs the same answer).
    fakedns: bool,
    /// The active profile, whose outbound is the document's default route.
    active: Option<&'a ServerProfile>,
}

impl Emission<'_> {
    /// Whether this profile's own dial goes through the scoped bootstrap DNS
    /// server: only a direct-dial outbound's domain is in its scope (a chained
    /// hop's server is reached through the chain and resolves on the far
    /// side — see [`crate::model::dial`]).
    fn bootstrap_reaches(&self, profile: &ServerProfile) -> bool {
        self.bootstrap && self.direct_dial.contains(&profile.tag())
    }
}

/// The control-plane blocks every generated document carries: the log pin, the
/// stats switch, the loopback API listener on the chosen port, and the stats
/// policy the app's polling reads. One builder for all three documents (the
/// full configuration, the core health gate, the latency probe), so the
/// services list is the only thing that differs between them — no document can
/// drift into a different listen address, log pin or stats policy.
struct ControlPlane<'a> {
    /// The port the API listener binds on loopback. The runtime learns it from
    /// the committed document, never from this value.
    api_port: u16,
    log_level: &'a str,
    /// Whether the core may write its access log. The GUI captures stdout for
    /// diagnostics; access logging is a separate channel `loglevel` cannot
    /// gate, so it is pinned off unless the user enabled it.
    access_log: bool,
    /// The gRPC services the document registers.
    services: Vec<&'a str>,
    /// Whether the document carries the `stats` switch and the stats policy.
    /// The documents the app polls a running managed core through (the full
    /// configuration and the core health gate) carry both; the one-shot probe
    /// child is minimal and carries neither.
    stats: bool,
    /// The user's `policy` document (levels included, when any level is set);
    /// the stats switches are added here.
    policy: Map<String, Value>,
}

impl ControlPlane<'_> {
    /// Whether the core may write its access log.
    fn log(&self) -> Value {
        if self.access_log {
            json!({ "loglevel": self.log_level })
        } else {
            json!({ "loglevel": self.log_level, "access": "none" })
        }
    }

    /// Write the four control-plane blocks into a document root.
    fn write(self, root: &mut Map<String, Value>) {
        root.insert(keys::LOG.into(), self.log());
        root.insert(
            keys::API.into(),
            json!({
                keys::TAG: API_INBOUND_TAG,
                keys::LISTEN: format!("127.0.0.1:{}", self.api_port),
                keys::SERVICES: self.services,
            }),
        );
        if !self.stats {
            return;
        }
        root.insert(keys::STATS.into(), json!({}));
        let mut policy = self.policy;
        policy.insert(
            "system".into(),
            json!({
                "statsInboundUplink": true,
                "statsInboundDownlink": true,
                "statsOutboundUplink": true,
                "statsOutboundDownlink": true,
            }),
        );
        root.insert(keys::POLICY.into(), Value::Object(policy));
    }
}

fn outbounds(servers: &ServersFile, emission: &Emission<'_>) -> Value {
    let mut out = Vec::new();
    for profile in &servers.profiles {
        let policy = OutboundWirePolicy {
            // The main config must not bind dials to an interface.
            interface: None,
            // A chained hop never dials its server from here: only a
            // direct-dial outbound resolves through the bootstrap.
            bootstrap: emission.bootstrap_reaches(profile),
        };
        out.push(profile_wire_outbound(profile, policy));
    }
    append_builtin_outbounds(&mut out);
    if emission.dns_intercept {
        out.push(json!({ keys::PROTOCOL: "dns", keys::TAG: DNS_OUTBOUND_TAG }));
    }
    Value::Array(out)
}

fn inbounds(settings: &Settings, emission: &Emission<'_>) -> Value {
    let mut list: Vec<Value> = Vec::new();

    // Local endpoints emit in list order; disabled entries stay off the wire.
    for entry in &settings.local_inbounds {
        if entry.enabled {
            list.push(entry.to_wire(emission.fakedns));
        }
    }
    // Enabled entries always carry a stable GUI-owned tag: validate_settings
    // rejects tagless dokodemo before generation runs.
    for d in settings.dokodemo.iter() {
        if !d.enabled {
            continue;
        }
        list.push(d.to_wire(&d.tag, emission.fakedns));
    }
    if emission.tun_on {
        let mut wire = settings.tun.to_wire(emission.fakedns);
        // With a DNS module the adapter DNS is pinned to the in-tun
        // listener — dnscache queries converge on the TUN gateway address
        // no matter which adapter it picks (the WFP DNS shield permits
        // port-53 only through the TUN interface), and the DNS module (DNS
        // tab) is the only place users customize resolution. Without a
        // module nothing listens there, so fall back to the previous
        // behavior (stored list, or plaintext resolvers when empty): leaky
        // but functional, as the TUN screen banner states.
        if emission.dns_on {
            if let Some(o) = wire.get_mut(keys::SETTINGS).and_then(Value::as_object_mut) {
                o.insert(keys::DNS.into(), json!([tun_dns_address(&settings.tun)]));
            }
        } else if settings.tun.dns.is_empty()
            && let Some(o) = wire.get_mut(keys::SETTINGS).and_then(Value::as_object_mut)
        {
            o.insert(keys::DNS.into(), json!(DEFAULT_PLAINTEXT_RESOLVERS));
        }
        list.push(wire);
    }
    // The in-tun DNS listener is deliberately NOT emitted here. It binds the
    // TUN gateway, an address that exists only after the core's tun inbound
    // started, and Xray starts tagged inbounds in Go map order — an emitted
    // listener loses that race in a fraction of cold starts and the core
    // dies pre-readiness. The runtime adds it to the running core instead
    // (src/rt/dns_in.rs) and derives it from the pieces emitted here: the
    // module, the adapter-DNS pin above, and the dns-in interception rule
    // (gen::routing).

    Value::Array(list)
}

fn routing(cfg: &RoutingCfg, emission: &Emission<'_>) -> Value {
    // The app's own rules are emitted FIRST and the user's configured rules
    // LAST: Xray's router takes the first match, and the interception rules
    // below own DNS for the intercepted inbounds — a user rule that matches
    // port-53 traffic ahead of them would shadow them and send those DNS
    // queries out of the tunnel as plaintext. Trial rules keep landing after
    // every configured rule either way, because Xray appends them (`AddRule`
    // with `shouldAppend=true`).
    let mut rules: Vec<Value> = Vec::new();
    // DoH ordering insurance: the DNS module's upstream TCP dials are
    // pinned to the active outbound by address+port, so a GUI reorder can
    // never send them direct. Regenerated whenever the active server
    // changes. (The module's own DoH dials also carry the originating
    // inbound, which would already fall through to the active outbound —
    // Xray's default route is the first outbound, the list's first profile,
    // which `ServersFile::activate` keeps the active one — so this rule only
    // makes that explicit. There is deliberately
    // no broader TUN catch-all: Xray's AddRule appends trial rules at the
    // END of the live rule list, and an unconditional in-tun catch-all
    // would swallow every TUN connection before an injected trial rule is
    // ever evaluated.)
    if emission.dns_on
        && let Some(tag) = emission.active.map(ServerProfile::tag)
    {
        for (host, port) in &emission.dns_upstreams {
            rules.push(json!({
                "ip": [host],
                "port": port.to_string(),
                "outboundTag": tag,
            }));
        }
    }
    // Local DNS interception rules: UDP port-53 from TUN/SOCKS is answered
    // by the DNS module (dns-out), and the loopback listener's TCP+UDP
    // queries are as well. The module's own upstream DoH traffic is
    // TCP:443, which never matches these rules and falls through
    // to the active outbound — no loop.
    if emission.dns_intercept {
        if emission.dns_on && emission.tun_on {
            rules.push(json!({
                "inboundTag": [DNS_INBOUND_TAG],
                "network": "udp,tcp",
                "port": "53",
                "outboundTag": DNS_OUTBOUND_TAG,
            }));
        }
        if emission.tun_on {
            rules.push(json!({
                "inboundTag": [TUN_INBOUND_TAG],
                "network": "udp",
                "port": "53",
                "outboundTag": DNS_OUTBOUND_TAG,
            }));
        }
        if !emission.socks_tags.is_empty() {
            rules.push(json!({
                "inboundTag": emission.socks_tags,
                "network": "udp",
                "port": "53",
                "outboundTag": DNS_OUTBOUND_TAG,
            }));
        }
    }
    // The user's rules, in model order, after every app-owned rule above —
    // none of them may shadow the pinned upstreams or the DNS interception.
    for r in &cfg.rules {
        rules.push(serde_json::to_value(r).expect(
            "model serialization is infallible: routing Rule fields are strings, \
                 string vecs, and string-keyed Value maps only",
        ));
    }
    let mut routing = Map::new();
    if cfg.domain_strategy != "AsIs" {
        routing.insert("domainStrategy".into(), json!(cfg.domain_strategy.clone()));
    }
    routing.insert("rules".into(), Value::Array(rules));
    if !cfg.balancers.is_empty() {
        routing.insert(
            "balancers".into(),
            serde_json::to_value(&cfg.balancers).expect(
                "model serialization is infallible: Balancer fields are strings, \
                 string-keyed Value maps, and editor-range-clamped finite floats only",
            ),
        );
    }
    Value::Object(routing)
}

/// dns object, or None when effectively empty. Strips the GUI-only `fakedns`
/// group; fakeDns trio (2/3): appends {"address":"fakedns"} when enabled.
fn dns(cfg: &DnsCfg, fakedns: bool) -> Option<Value> {
    cfg.to_wire(fakedns)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod stable_dokodemo_tag_tests {
    use super::generate;
    use crate::model::{DokodemoCfg, ServersFile, Settings};

    #[test]
    fn persisted_dokodemo_tag_does_not_depend_on_vector_position() {
        let mut settings = Settings {
            dokodemo: vec![
                DokodemoCfg {
                    tag: "in-doko-a".into(),
                    enabled: true,
                    listen_port: 20001,
                    ..Default::default()
                },
                DokodemoCfg {
                    tag: "in-doko-b".into(),
                    enabled: true,
                    listen_port: 20002,
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        settings.dokodemo.swap(0, 1);

        let generated = generate(&ServersFile::default(), &settings).expect("generate config");
        let tags: Vec<&str> = generated["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|inbound| inbound["protocol"] == "dokodemo-door")
            .filter_map(|inbound| inbound["tag"].as_str())
            .collect();
        assert_eq!(tags, ["in-doko-b", "in-doko-a"]);
    }
}

#[cfg(test)]
mod dokodemo_unix_tests {
    use super::generate_with_api_port;
    use crate::model::{DokodemoCfg, ServersFile, Settings};
    use serde_json::json;

    fn enabled_dokodemo(network: &str, socket_path: &str, listen_port: u16) -> DokodemoCfg {
        DokodemoCfg {
            tag: "in-doko-test".into(),
            enabled: true,
            listen_port,
            unix_socket_path: socket_path.into(),
            network: network.into(),
            address: "8.8.8.8".into(),
            port: 53,
            ..Default::default()
        }
    }

    fn generation_error(config: DokodemoCfg) -> String {
        let mut settings = Settings::default();
        settings.dokodemo.push(config);
        generate_with_api_port(&ServersFile::default(), &settings, 19999)
            .expect_err("invalid dokodemo must be rejected")
            .to_string()
    }

    #[test]
    fn unix_listener_uses_path_envelope_without_port() {
        let socket_path = r"C:\broccoli\sockets\dns.sock";
        let mut settings = Settings::default();
        settings
            .dokodemo
            .push(enabled_dokodemo("UNIX", socket_path, 5353));

        let generated = generate_with_api_port(&ServersFile::default(), &settings, 19999)
            .expect("generate UNIX listener");
        let inbound = generated["inbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|inbound| inbound["protocol"] == "dokodemo-door")
            .expect("dokodemo inbound");

        assert_eq!(inbound["listen"], json!(socket_path));
        assert!(inbound.get("port").is_none());
        assert_eq!(inbound["settings"]["network"], "unix");
        assert_eq!(inbound["settings"]["address"], "8.8.8.8");
        assert_eq!(inbound["settings"]["port"], 53);
    }

    #[test]
    fn malformed_unix_and_network_endpoints_are_rejected() {
        let cases = [
            (
                enabled_dokodemo("unix", "   ", 0),
                "needs a UNIX socket path",
            ),
            (
                enabled_dokodemo("unix,tcp", r"C:\broccoli\xray.sock", 5353),
                "UNIX cannot be mixed with TCP or UDP",
            ),
            (
                enabled_dokodemo("quic", r"C:\broccoli\xray.sock", 5353),
                "unknown token",
            ),
            (
                enabled_dokodemo("", r"C:\broccoli\xray.sock", 5353),
                "listener network is empty",
            ),
            (
                enabled_dokodemo("tcp,", r"C:\broccoli\xray.sock", 5353),
                "empty token",
            ),
            (
                enabled_dokodemo("tcp", r"C:\broccoli\xray.sock", 0),
                "needs a non-zero listen port",
            ),
        ];

        for (config, expected) in cases {
            let error = generation_error(config);
            assert!(
                error.contains(expected),
                "{error:?} did not contain {expected:?}"
            );
        }
    }

    #[test]
    fn enabled_dokodemo_collisions_are_rejected_by_protocol_or_unix_path() {
        let mut settings = Settings::default();
        settings.local_inbounds[1].enabled = false;
        settings.local_inbounds[0].udp = false;
        settings
            .dokodemo
            .push(enabled_dokodemo("udp", "", settings.local_inbounds[0].port));
        generate_with_api_port(&ServersFile::default(), &settings, 19999)
            .expect("UDP-only dokodemo may share a TCP-only SOCKS port");

        settings.dokodemo[0].network = "tcp".into();
        let error = generate_with_api_port(&ServersFile::default(), &settings, 19999)
            .expect_err("overlapping TCP listeners must fail")
            .to_string();
        assert!(error.contains("conflicts with local inbound"), "{error}");
        assert!(error.contains("in-socks"), "{error}");

        settings.local_inbounds[0].enabled = false;
        settings.dokodemo = vec![
            enabled_dokodemo("unix", r"C:\broccoli\sockets\.\xray.sock", 0),
            DokodemoCfg {
                tag: "in-doko-other".into(),
                ..enabled_dokodemo("unix", "c:/broccoli/sockets/xray.sock", 0)
            },
        ];
        let error = generate_with_api_port(&ServersFile::default(), &settings, 19999)
            .expect_err("normalized duplicate UNIX paths must fail")
            .to_string();
        assert!(error.contains("conflicts with"));
        assert!(error.contains("UNIX socket"));
    }

    #[test]
    fn api_port_validation_respects_dokodemo_listener_protocol() {
        let settings = Settings::default();
        let error = generate_with_api_port(&ServersFile::default(), &settings, 0)
            .expect_err("zero API port must fail")
            .to_string();
        assert!(error.contains("API listener needs a non-zero port"));

        let settings = Settings::default();
        let error = generate_with_api_port(
            &ServersFile::default(),
            &settings,
            settings.local_inbounds[0].port,
        )
        .expect_err("SOCKS/API collision must fail")
        .to_string();
        assert!(
            error.contains("conflicts") && error.contains("in-socks") && error.contains("API"),
            "collision error must identify both listeners: {error}"
        );

        let mut settings = Settings::default();
        settings.dokodemo.push(enabled_dokodemo("udp", "", 20099));
        generate_with_api_port(&ServersFile::default(), &settings, 20099)
            .expect("UDP-only dokodemo may share the TCP API port");

        settings.dokodemo[0].network = "tcp".into();
        let error = generate_with_api_port(&ServersFile::default(), &settings, 20099)
            .expect_err("TCP dokodemo/API collision must fail")
            .to_string();
        assert!(
            error.contains("conflicts") && error.contains("dokodemo") && error.contains("API"),
            "collision error must identify both listeners: {error}"
        );

        settings.dokodemo[0].network = "unix".into();
        settings.dokodemo[0].unix_socket_path = r"C:\broccoli\xray.sock".into();
        generate_with_api_port(&ServersFile::default(), &settings, 20099)
            .expect("UNIX listener does not occupy its inactive listen port");
    }
}

#[cfg(test)]
mod error_text_tests {
    use super::{Diag, GenerateError, Key, Language, ValidationIssue, validation_issue_message};
    use crate::i18n::{t_fmt, validation_message};
    use crate::model::validation::{Severity, ValidationCode};

    #[test]
    fn generate_error_text_renders_through_the_locale_table() {
        let error = GenerateError::InvalidModel(Diag::new(Key::GenProbePortZero));
        assert_eq!(
            error.text(Language::En),
            t_fmt(Language::En, Key::GenProbePortZero, &[])
        );
        assert_eq!(error.to_string(), error.text(Language::En));

        let error = GenerateError::ApiPort(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "port busy",
        ));
        assert_eq!(
            error.text(Language::En),
            t_fmt(Language::En, Key::GenApiPort, &[&"port busy"])
        );
    }

    #[test]
    fn invalid_finding_text_keeps_the_scoped_rule_path() {
        let path = "stream.xhttpSettings.downloadSettings";
        let code = ValidationCode::StreamOneNoDownload;
        let error = GenerateError::InvalidFinding(Box::new(ValidationIssue {
            code: code.clone(),
            path: Some(path.into()),
            severity: Severity::Error,
        }));
        assert_eq!(
            error.text(Language::En),
            format!("{path}: {}", validation_message(&code, Language::En))
        );
        assert_eq!(error.to_string(), error.text(Language::En));

        // A parameterized rule keeps the value that names the fault on the
        // scoped path too: the template's placeholder is filled, not printed.
        let scoped = GenerateError::InvalidFinding(Box::new(ValidationIssue {
            code: ValidationCode::FinalmaskUnknownUdpMask(Some("bogus".into())),
            path: Some(path.into()),
            severity: Severity::Error,
        }));
        let text = scoped.text(Language::En);
        assert!(text.starts_with(&format!("{path}: ")), "{text}");
        assert!(text.contains("Some(\"bogus\")"), "{text}");
        assert!(!text.contains("{:?}"), "{text}");

        let whole_model = GenerateError::InvalidFinding(Box::new(ValidationIssue {
            code,
            path: None,
            severity: Severity::Error,
        }));
        assert_eq!(
            whole_model.text(Language::En),
            validation_issue_message(
                &ValidationIssue {
                    code: ValidationCode::StreamOneNoDownload,
                    path: None,
                    severity: Severity::Error,
                },
                Language::En
            )
        );
    }
}
